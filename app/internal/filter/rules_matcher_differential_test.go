package filter

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestMidPathDoubleStarDenyMatchesDecodedControlBytes pins the "s" flag on the
// group "**" compiles to. net/http percent-decodes r.URL.Path exactly once
// before sockguard sees it, so a request for
// /containers/a%0Ab/exec arrives as a path carrying a real newline. Without
// (?s) the "." inside the mid-path "**" group does not match a newline, the
// deny rule misses, and evaluation falls through to the broader allow below
// it: a rule ordering that reads as "deny exec, allow everything else under
// /containers" would have admitted the exec.
//
// The pattern here is the one that takes the regex fallback (a "**" that is
// neither the whole pattern nor a trailing segment), which is the only matcher
// kind built on a compiled regex.
func TestMidPathDoubleStarDenyMatchesDecodedControlBytes(t *testing.T) {
	t.Parallel()

	deny, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/containers/**/exec", Action: ActionDeny, Reason: "no exec", Index: 0})
	if err != nil {
		t.Fatalf("CompileRule(deny): %v", err)
	}
	if deny.matcherKind != pathMatcherRegex {
		t.Fatalf("matcherKind = %d, want pathMatcherRegex (%d); this test is only meaningful on the regex fallback", deny.matcherKind, pathMatcherRegex)
	}
	allow, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/containers/**", Action: ActionAllow, Index: 1})
	if err != nil {
		t.Fatalf("CompileRule(allow): %v", err)
	}
	rules := []*CompiledRule{deny, allow}

	tests := []struct {
		name string
		path string
	}{
		{name: "plain", path: "/containers/abc/exec"},
		{name: "decoded newline", path: "/containers/ab\ncd/exec"},
		{name: "decoded carriage return", path: "/containers/ab\rcd/exec"},
		{name: "decoded crlf", path: "/containers/ab\r\ncd/exec"},
		{name: "newline alone as a segment", path: "/containers/\n/exec"},
		{name: "newline in a deeper path", path: "/containers/a/b\nc/d/exec"},
		{name: "decoded null byte", path: "/containers/a\x00b/exec"},
		{name: "unicode line separator", path: "/containers/a b/exec"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "http://sockguard.test/", nil)
			req.URL.Path = tt.path
			action, index, _ := Evaluate(rules, req)
			if action != ActionDeny {
				t.Fatalf("Evaluate(%q) = %v (rule %d), want deny; the allow below the deny was borrowed", tt.path, action, index)
			}
		})
	}
}

// differentialSegments is the path-segment alphabet the matcher differential
// draws from. It is deliberately hostile: decoded control bytes (what a
// percent-encoded %0A/%0D/%00 becomes after net/http's single decode), a
// still-encoded %2F (which net/http leaves in r.URL.Path when the client
// double-encodes it), multi-byte and invalid UTF-8, and the glob metacharacters
// themselves appearing as literal path content.
var differentialSegments = []string{
	"containers",
	"json",
	"exec",
	"abc",
	"",
	"a\nb",
	"\n",
	"a\rb",
	"a\r\nb",
	"a\x00b",
	"a%2Fb",
	"%2e%2e",
	"café",
	"日本",
	"a b",
	"\xff\xfe",
	"*",
	"**",
	".",
	"..",
	strings.Repeat("z", 40),
}

// differentialPaths builds the corpus: every one and two segment path over the
// alphabet, plus a strided sample of the three-segment space and a handful of
// deeper paths aimed at the multi-"**" patterns. Every raw path is mapped
// through both path views a compiled rule is ever handed — NormalizePath for
// ordinary policy matching, and NormalizePodmanRoutePath for the libpod
// image-SCP route view — so the domain covers everything production evaluates
// and nothing it does not.
//
// The route view is the reason the corpus is not NormalizePath-only. It keeps
// the trailing slash gorilla/mux routes on where path.Clean would strip it, so
// it is the only shape that reaches rule matching with an empty final segment.
// That segment is real: "/containers/*" must not match "/containers/a/", and
// "/*/*/*" must match "/a/b/", exactly as the anchored regex says, because a
// rule spelling N segments cannot be allowed to cover N+1 and a deny spelling
// N+1 cannot be dodged by leaving the last one empty. Each raw candidate is
// therefore also re-run with a trailing slash appended, which is how a client
// reaches that view.
func differentialPaths() []string {
	raw := make([]string, 0, 600)
	for _, a := range differentialSegments {
		raw = append(raw, "/"+a)
	}
	for _, a := range differentialSegments {
		for _, b := range differentialSegments {
			raw = append(raw, "/"+a+"/"+b)
		}
	}
	index := 0
	for _, a := range differentialSegments {
		for _, b := range differentialSegments {
			for _, c := range differentialSegments {
				index++
				if index%43 == 0 {
					raw = append(raw, "/"+a+"/"+b+"/"+c)
				}
			}
		}
	}
	// Deeper paths so the patterns carrying more than one "**", and the ones
	// ending in a literal segment, have something to match.
	raw = append(raw,
		"/containers/abc/json",
		"/containers/a\nb/json",
		"/containers/abc/logs",
		"/containers/abc/def/logs",
		"/containers/a\nb/def/logs",
		"/containers/abc/def/ghi/logs",
		"/a/b/c",
		"/a/x/b/c",
		"/a/x/b/y/c",
		"/a/x\ny/b/z/c",
		"/a/b/y/c",
		"/containers/abc/exec",
		"/containers/a\nb/exec",
		"/v1.53/containers/abc/exec",
		"/日本/abc/exec",
		"/libpod/images/scp/victim",
		"/libpod/images/scp/victim/push",
		"/v5.8.1/libpod/images/scp/acme/app",
	)

	seen := make(map[string]struct{}, 3*len(raw))
	paths := make([]string, 0, 3*len(raw))
	add := func(normalized string) {
		// NormalizePath("") is "" and no request path normalizes to it from a
		// non-empty input; the segment walkers and the regex disagree there
		// too, and it is not a path any rule is evaluated against.
		if normalized == "" {
			return
		}
		if _, dup := seen[normalized]; dup {
			return
		}
		seen[normalized] = struct{}{}
		paths = append(paths, normalized)
	}
	for _, candidate := range raw {
		add(NormalizePath(candidate))
		// The libpod image-SCP route view, both as the client sent it and with
		// a trailing slash appended, which is the only way an empty final
		// segment survives into rule matching.
		add(NormalizePodmanRoutePath(candidate))
		add(NormalizePodmanRoutePath(candidate + "/"))
	}
	return paths
}

// TestPathMatcherKindsAgreeWithRegexFallback is the differential between the
// four hand-written matchers CompileRule dispatches to and the regex the glob
// dialect compiles to. Every fast path exists purely to avoid regexp on the
// hot path, so "faster" is only correct if the verdict is identical; a fast
// path that answers differently from the dialect's own definition is a policy
// bypass wearing an optimization's clothes.
//
// The regex side is built here from GlobToRegexString rather than read off the
// compiled rule, so a pattern that never reaches pathMatcherRegex in
// production is still checked against what the dialect says it means.
func TestPathMatcherKindsAgreeWithRegexFallback(t *testing.T) {
	t.Parallel()

	patterns := []struct {
		pattern string
		kind    pathMatcherKind
	}{
		{pattern: "/containers/json", kind: pathMatcherLiteral},
		{pattern: "/**", kind: pathMatcherMatchAll},
		{pattern: "/containers/**", kind: pathMatcherTrailingDeep},
		{pattern: "/containers/json/**", kind: pathMatcherTrailingDeep},
		{pattern: "/containers/*", kind: pathMatcherSegmentGlob},
		{pattern: "/containers/*/json", kind: pathMatcherSegmentGlob},
		{pattern: "/*/json", kind: pathMatcherSegmentGlob},
		{pattern: "/containers/a*c", kind: pathMatcherSegmentGlob},
		{pattern: "/*/*/*", kind: pathMatcherSegmentGlob},
		{pattern: "/containers/**/exec", kind: pathMatcherRegex},
		{pattern: "/**/json", kind: pathMatcherRegex},
		{pattern: "/containers/**/*/logs", kind: pathMatcherRegex},
		{pattern: "/a/**/b/**/c", kind: pathMatcherRegex},
		{pattern: "/containers/a**c", kind: pathMatcherRegex},
	}
	paths := differentialPaths()
	if len(paths) < 300 {
		t.Fatalf("differential corpus has %d paths, want at least 300", len(paths))
	}
	// The trailing-slash half is the whole reason the corpus covers the libpod
	// route view. If a future NormalizePodmanRoutePath change stops producing
	// it, this differential goes quiet on exactly the shape it was widened for.
	trailingSlash := 0
	for _, path := range paths {
		if len(path) > 1 && strings.HasSuffix(path, "/") {
			trailingSlash++
		}
	}
	if trailingSlash < 100 {
		t.Fatalf("differential corpus has %d trailing-slash paths, want at least 100", trailingSlash)
	}

	methodBit := httpMethodBit(http.MethodGet)
	for _, tc := range patterns {
		t.Run(tc.pattern, func(t *testing.T) {
			t.Parallel()
			compiled, err := CompileRule(Rule{Methods: []string{"GET"}, Pattern: tc.pattern, Action: ActionAllow})
			if err != nil {
				t.Fatalf("CompileRule(%q): %v", tc.pattern, err)
			}
			if compiled.matcherKind != tc.kind {
				t.Fatalf("matcherKind for %q = %d, want %d; the dispatch changed and this table no longer covers what it claims", tc.pattern, compiled.matcherKind, tc.kind)
			}
			reference, err := regexp.Compile("^" + GlobToRegexString(tc.pattern) + "$")
			if err != nil {
				t.Fatalf("compile reference regex for %q: %v", tc.pattern, err)
			}

			matched := 0
			for _, path := range paths {
				got := compiled.matchesNormalizedUpperWithBit(http.MethodGet, methodBit, path)
				want := reference.MatchString(path)
				if got != want {
					t.Errorf("pattern %q path %q: matcher kind %d = %v, regex %q = %v",
						tc.pattern, path, compiled.matcherKind, got, reference, want)
				}
				if want {
					matched++
				}
			}
			if matched == 0 {
				t.Errorf("pattern %q matched nothing in the corpus; agreement on all-false is vacuous", tc.pattern)
			}
			if matched == len(paths) && tc.kind != pathMatcherMatchAll {
				t.Errorf("pattern %q matched every path in the corpus; agreement on all-true is vacuous", tc.pattern)
			}
		})
	}
}

// TestSegmentGlobCountsATrailingSlashAsAnEmptySegment names the two shapes the
// segment walker used to get wrong, plus the libpod route they are reachable
// through. It is the table-driven companion to the corpus differential above:
// the corpus proves agreement over a wide domain, this states what agreement
// means for the cases the fix is about, so a regression reads as a named
// expectation rather than one line lost in a sweep.
//
// Each row is also checked against the anchored regex the pattern compiles to,
// so the table cannot drift away from the dialect it is pinning.
func TestSegmentGlobCountsATrailingSlashAsAnEmptySegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{
			name:    "one star does not absorb a trailing slash",
			pattern: "/containers/*",
			path:    "/containers/a/",
			want:    false,
		},
		{
			name:    "one star still matches a single segment",
			pattern: "/containers/*",
			path:    "/containers/a",
			want:    true,
		},
		{
			name:    "three stars spend one on the empty segment",
			pattern: "/*/*/*",
			path:    "/a/b/",
			want:    true,
		},
		{
			name:    "three stars still need three segments",
			pattern: "/*/*/*",
			path:    "/a/b",
			want:    false,
		},
		{
			name:    "three stars still match three real segments",
			pattern: "/*/*/*",
			path:    "/a/b/c",
			want:    true,
		},
		{
			name:    "libpod scp source is one segment",
			pattern: "/libpod/images/scp/*",
			path:    "/libpod/images/scp/alpine",
			want:    true,
		},
		{
			name:    "libpod scp source with a trailing slash is two",
			pattern: "/libpod/images/scp/*",
			path:    "/libpod/images/scp/alpine/",
			want:    false,
		},
		{
			name:    "two-segment libpod scp rule reaches the empty second segment",
			pattern: "/libpod/images/scp/*/*",
			path:    "/libpod/images/scp/tenant/",
			want:    true,
		},
		{
			name:    "two-segment libpod scp rule matches a real slash-bearing source",
			pattern: "/libpod/images/scp/*/*",
			path:    "/libpod/images/scp/acme/app",
			want:    true,
		},
		{
			name:    "root path is one empty segment",
			pattern: "/*",
			path:    "/",
			want:    true,
		},
	}

	methodBit := httpMethodBit(http.MethodPost)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			compiled, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: tt.pattern, Action: ActionAllow})
			if err != nil {
				t.Fatalf("CompileRule(%q): %v", tt.pattern, err)
			}
			if compiled.matcherKind != pathMatcherSegmentGlob {
				t.Fatalf("matcherKind for %q = %d, want pathMatcherSegmentGlob (%d)", tt.pattern, compiled.matcherKind, pathMatcherSegmentGlob)
			}
			if got := compiled.matchesNormalizedUpperWithBit(http.MethodPost, methodBit, tt.path); got != tt.want {
				t.Errorf("pattern %q path %q = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}

			reference, err := regexp.Compile("^" + GlobToRegexString(tt.pattern) + "$")
			if err != nil {
				t.Fatalf("compile reference regex for %q: %v", tt.pattern, err)
			}
			if got := reference.MatchString(tt.path); got != tt.want {
				t.Errorf("regex %q path %q = %v, want %v; the table disagrees with the dialect", reference, tt.path, got, tt.want)
			}
		})
	}
}

// TestImageScpRouteViewHonorsTheTrailingSlashSegmentCount runs the fix through
// the production evaluator on the only path view that carries a trailing
// slash. Both halves of the old disagreement are policy bugs on this route:
// the walker absorbing the slash let a one-segment allow cover a two-segment
// source, and the walker refusing to spend a pattern segment on the empty one
// let a two-segment deny be dodged by a source that ends in "/".
func TestImageScpRouteViewHonorsTheTrailingSlashSegmentCount(t *testing.T) {
	t.Parallel()

	t.Run("one-segment allow does not cover a trailing-slash source", func(t *testing.T) {
		t.Parallel()
		rules := compileRulesForTest(t, []Rule{
			{Methods: []string{http.MethodPost}, Pattern: "/libpod/images/scp/*", Action: ActionAllow, Index: 0},
			{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "SCP route denied", Index: 1},
		})

		allowed := newParsedRequest(t, http.MethodPost, "/libpod/images/scp/alpine")
		if action, index, _ := Evaluate(rules, allowed); action != ActionAllow || index != 0 {
			t.Fatalf("Evaluate(/libpod/images/scp/alpine) = (%q, %d), want (%q, 0)", action, index, ActionAllow)
		}

		// gorilla/mux routes this as an SCP of the image "alpine/", not of
		// "alpine", so the one-segment allow above never described it.
		routed := newParsedRequest(t, http.MethodPost, "/v5.8.1/libpod/images/scp/alpine/")
		action, index, reason := Evaluate(rules, routed)
		if action != ActionDeny || index != 1 || reason != "SCP route denied" {
			t.Fatalf("Evaluate(/v5.8.1/libpod/images/scp/alpine/) = (%q, %d, %q), want (%q, 1, %q)",
				action, index, reason, ActionDeny, "SCP route denied")
		}
	})

	t.Run("two-segment deny is not dodged by an empty second segment", func(t *testing.T) {
		t.Parallel()
		rules := compileRulesForTest(t, []Rule{
			{Methods: []string{http.MethodPost}, Pattern: "/libpod/images/scp/*/*", Action: ActionDeny, Reason: "two-segment scp source denied", Index: 0},
			{Methods: []string{http.MethodPost}, Pattern: "/libpod/images/scp/**", Action: ActionAllow, Index: 1},
		})

		// Decoded, this is the one-segment source "tenant" and the deny above
		// does not describe it; on the route view it is "tenant/", two
		// segments, and the deny does.
		routed := newParsedRequest(t, http.MethodPost, "/libpod/images/scp/tenant/")
		action, index, reason := Evaluate(rules, routed)
		if action != ActionDeny || index != 0 || reason != "two-segment scp source denied" {
			t.Fatalf("Evaluate(/libpod/images/scp/tenant/) = (%q, %d, %q), want (%q, 0, %q)",
				action, index, reason, ActionDeny, "two-segment scp source denied")
		}

		// The bare one-segment source stays allowed, so the fix narrows only
		// the shape it is about.
		bare := newParsedRequest(t, http.MethodPost, "/libpod/images/scp/tenant")
		if action, index, _ := Evaluate(rules, bare); action != ActionAllow || index != 1 {
			t.Fatalf("Evaluate(/libpod/images/scp/tenant) = (%q, %d), want (%q, 1)", action, index, ActionAllow)
		}
	})
}
