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
// through NormalizePath before it is used, because that is the only thing a
// compiled rule is ever handed.
//
// Normalizing is what scopes the comparison to a domain where agreement is a
// real invariant. The one production caller that does NOT hand over
// NormalizePath output is the libpod image-SCP route view, which keeps a
// trailing slash on purpose (NormalizePodmanRoutePath), and the segment
// walkers and the regex genuinely disagree there: matchGlobSegments absorbs a
// trailing empty segment after its last pattern segment, so "/containers/*"
// matches "/containers/a/" where "^/containers/[^/]*$" does not, and it
// refuses to spend a pattern segment on that empty segment, so "/*/*/*" does
// not match "/a/b/" where the regex does. Which side is right for that view is
// a decision about Podman route semantics, not about this optimization, so
// this corpus does not claim to settle it.
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
	)

	seen := make(map[string]struct{}, len(raw))
	paths := make([]string, 0, len(raw))
	for _, candidate := range raw {
		normalized := NormalizePath(candidate)
		// NormalizePath("") is "" and no request path normalizes to it from a
		// non-empty input; the segment walkers and the regex disagree there
		// too, and it is not a path any rule is evaluated against.
		if normalized == "" {
			continue
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		paths = append(paths, normalized)
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
