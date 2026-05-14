package ratelimit

// TestCompileEndpointCosts_RoundTrip verifies that compileEndpointCosts
// produces matchers that correctly accept or reject sample paths for a variety
// of unusual glob patterns. This locks in the invariant documented on
// compileEndpointCosts: GlobToRegexString always produces valid regex so any
// future breakage in that function surfaces here (via MustCompile panic or
// incorrect match) rather than as a first-request process crash in production.
//
// Each sub-test includes the compiled regex in the failure message so
// regressions are easy to diagnose.
//
// Note on glob dialect (filter.GlobToRegexString):
//   - `*`  → `[^/]*`  (single segment wildcard, does not cross slashes)
//   - `**` → `(/.*)?' (zero-or-more path segments, INCLUDING the zero case)
//   - `?`  → `\?`     (literal question mark — ? is NOT a single-char wildcard
//                       in this dialect; it is regexp.QuoteMeta'd)
//   - `[`, `]`, `(`, `)`, `$`, `^`, `|`, `+`, `\` are all QuoteMeta'd
//
// Tests are written against the actual compiled output, not against assumed
// POSIX or filepath glob semantics.

import (
	"testing"
)

func TestCompileEndpointCosts_RoundTrip(t *testing.T) {
	type matchCase struct {
		path string
		want bool
	}

	tests := []struct {
		name    string
		glob    string
		methods []string // nil = match all
		cases   []matchCase
	}{
		{
			// * matches one segment (no slashes)
			name: "docker_api_version_prefix_single_star",
			glob: "/v*/containers/json",
			cases: []matchCase{
				{"/v1.45/containers/json", true},
				{"/v1.2/containers/json", true},
				{"/v1/containers/json", true},
				{"/containers/json", false},             // no version prefix
				{"/v1.45/containers/json/extra", false}, // trailing segment
				{"/v1.45/other/json", false},
			},
		},
		{
			// ** matches zero or more path segments (including the zero case)
			name: "double_star_nested",
			glob: "/v*/containers/**/json",
			cases: []matchCase{
				{"/v1.45/containers/abc/json", true},
				{"/v1.45/containers/a/b/c/json", true},
				// ** allows zero additional segments, so this also matches:
				{"/v1.45/containers/json", true},
				// But a completely different prefix does not:
				{"/containers/json", false},
			},
		},
		{
			// ** at start allows zero or more leading segments
			name: "double_star_prefix_logs",
			glob: "/**/logs",
			cases: []matchCase{
				{"/containers/abc123/logs", true},
				{"/a/b/c/d/logs", true},
				// ** allows zero segments: /**/logs matches /logs because (/.*)?
				// can collapse to empty.
				{"/logs", true},
				// Must end with /logs:
				{"/containers/logs/extra", false},
			},
		},
		{
			// /** at root: (/.*)?  matches everything including bare /
			name: "double_star_root",
			glob: "/**",
			cases: []matchCase{
				{"/anything", true},
				{"/a/b/c/d/e", true},
				// (/.*)?  matches the empty string, so / itself also matches.
				{"/", true},
			},
		},
		{
			// Single * matches the entire single segment (including empty)
			name: "single_star_segment",
			glob: "/images/*/json",
			cases: []matchCase{
				{"/images/nginx/json", true},
				{"/images/nginx%3Alatest/json", true},
				// * does not cross slashes:
				{"/images/json", false},
				{"/images/a/b/json", false},
			},
		},
		{
			// ? is treated as a literal question mark (QuoteMeta), not a
			// single-char wildcard. This is an important dialect distinction
			// vs. POSIX globs: ? in URL path globs usually appears as a query
			// separator, not a wildcard, so the QuoteMeta treatment is correct.
			name: "question_mark_is_literal",
			glob: "/build?foo",
			cases: []matchCase{
				{"/build?foo", true},  // literal ? matches
				{"/buildXfoo", false}, // ? is not a single-char wildcard here
				{"/buildfoo", false},
			},
		},
		{
			// Deeply nested double-star
			name: "exec_deep_wildcard",
			glob: "/containers/*/exec",
			cases: []matchCase{
				{"/containers/abc123/exec", true},
				{"/containers/very-long-container-id/exec", true},
				{"/containers/exec", false},   // * needs at least the one segment
				{"/containers/a/b/exec", false}, // * doesn't cross slashes
			},
		},
		{
			// Method-restricted rule: POST /containers/create costs 10
			name: "method_filter_post_only",
			glob: "/containers/create",
			methods: []string{"POST"},
			cases: []matchCase{
				{"/containers/create", true},
				{"/containers/json", false},
			},
		},
		{
			// Bracket characters are QuoteMeta'd — they appear as literals
			name: "bracket_characters_are_literal",
			glob: "/foo[bar]",
			cases: []matchCase{
				{"/foo[bar]", true},  // literal square brackets
				{"/foob", false},      // NOT a character class
				{"/foobar", false},
			},
		},
		{
			// Special regex metacharacters in path are escaped
			name: "dollar_caret_pipe_are_literal",
			glob: "/foo$bar",
			cases: []matchCase{
				{"/foo$bar", true},
				{"/foobar", false}, // $ is not end-of-string here
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			costs := []EndpointCost{{PathGlob: tt.glob, Methods: tt.methods, Cost: 2}}

			// Must not panic — this is the primary contract on MustCompile.
			compiled := compileEndpointCosts(costs)
			if len(compiled) != 1 {
				t.Fatalf("compileEndpointCosts(%q) returned %d entries, want 1", tt.glob, len(compiled))
			}
			ce := compiled[0]

			for _, mc := range tt.cases {
				got := ce.pathRE.MatchString(mc.path)
				if got != mc.want {
					t.Errorf("glob=%q path=%q: MatchString=%v, want %v (regex=%q)",
						tt.glob, mc.path, got, mc.want, ce.pathRE.String())
				}
			}

			// costFor round-trip: matching path at the right method must return 2.
			method := "GET"
			if len(tt.methods) > 0 {
				method = tt.methods[0]
			}
			cp := &compiledProfile{endpointCosts: compiled}

			for _, mc := range tt.cases {
				if mc.want {
					cost := cp.costFor(method, mc.path)
					if cost != 2 {
						t.Errorf("costFor(%q, %q) = %g, want 2 (cost from rule)", method, mc.path, cost)
					}
					break
				}
			}
		})
	}
}

// TestCompileEndpointCosts_EmptyInput verifies the nil-slice fast-path.
func TestCompileEndpointCosts_EmptyInput(t *testing.T) {
	if got := compileEndpointCosts(nil); got != nil {
		t.Fatalf("compileEndpointCosts(nil) = %v, want nil", got)
	}
	if got := compileEndpointCosts([]EndpointCost{}); got != nil {
		t.Fatalf("compileEndpointCosts([]) = %v, want nil", got)
	}
}
