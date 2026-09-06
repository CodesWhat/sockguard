package filter

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// rootedProbePaths are the shapes a real request produces: NormalizePath and
// NormalizePodmanRoutePath both keep the leading slash of an HTTP
// request-target, so every path rule matching is ever handed looks like one of
// these.
var rootedProbePaths = []string{
	"/",
	"/_ping",
	"/containers",
	"/containers/json",
	"/containers/abc/json",
	"/libpod/images/scp/team/alpine",
	"/libpod/images/scp/alpine/",
}

// TestRootlessSingleStarPatternsMatchNoRootedPath is the regression for the
// widening a rootless single-star pattern used to buy. The segment-glob fast
// path stripped one leading slash from the pattern and one from the request
// path, so "*" matched "/containers" and "containers/*" matched
// "/containers/json" — neither of which the anchored regex those patterns
// compile to accepts, because "[^/]*" cannot cross a separator.
//
// On an allow rule that is a policy bypass: a pattern the operator wrote as one
// segment silently covered a rooted request. The evaluator is driven end to end
// here (CompileRule then Evaluate on a real *http.Request) rather than through
// the walker directly, because the bug was only visible once the compiled rule
// and the normalized path met.
//
// This covers single-star patterns whose leading segment is not itself a bare
// "*", so the leading "/" of a rooted path has no empty segment for the
// pattern to consume. A rootless pattern that starts with "*" is a different
// case — its leading "*" can eat that empty segment — and gets its own test
// below (TestRootlessSingleStarPatternWithLeadingWildcardDoesMatchRootedPath).
// A rootless pattern carrying "**" is different again and gets the test after
// that: it matches rooted paths, and correctly so.
func TestRootlessSingleStarPatternsMatchNoRootedPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rootless string
		// rootedTwin is the same pattern written the way an operator has to
		// write it now. It has to still match matchesRootedTwin, so this test
		// cannot pass by the patterns having become meaningless.
		rootedTwin        string
		matchesRootedTwin string
	}{
		{rootless: "*", rootedTwin: "/*", matchesRootedTwin: "/containers"},
		{rootless: "containers/**", rootedTwin: "/containers/**", matchesRootedTwin: "/containers/json"},
		{rootless: "containers/*", rootedTwin: "/containers/*", matchesRootedTwin: "/containers/json"},
		{rootless: "*libpod/images/scp/team/*", rootedTwin: "/*libpod/images/scp/team/*", matchesRootedTwin: "/libpod/images/scp/team/alpine"},
	}

	for _, tt := range tests {
		t.Run(tt.rootless, func(t *testing.T) {
			t.Parallel()

			compiled, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: tt.rootless, Action: ActionAllow, Index: 0})
			if err != nil {
				t.Fatalf("CompileRule(%q): %v", tt.rootless, err)
			}
			reference, err := regexp.Compile("^" + GlobToRegexString(tt.rootless) + "$")
			if err != nil {
				t.Fatalf("compile reference regex for %q: %v", tt.rootless, err)
			}

			rules := []*CompiledRule{compiled}
			for _, path := range rootedProbePaths {
				request := httptest.NewRequest(http.MethodGet, "http://sockguard.test/", nil)
				request.URL.Path = path
				if action, index, _ := Evaluate(rules, request); action != ActionDeny || index != -1 {
					t.Errorf("Evaluate(%q) with rootless pattern %q = (%q, %d), want (%q, -1)",
						path, tt.rootless, action, index, ActionDeny)
				}
				// The regex is the dialect's own definition of the pattern, so
				// it has to agree that nothing rooted matches. If it ever does,
				// the expectation above is wrong rather than the matcher.
				if reference.MatchString(NormalizePath(path)) {
					t.Errorf("regex %q matched %q; the rootless pattern is not dead after all", reference, path)
				}
			}

			twin, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: tt.rootedTwin, Action: ActionAllow, Index: 0})
			if err != nil {
				t.Fatalf("CompileRule(%q): %v", tt.rootedTwin, err)
			}
			request := httptest.NewRequest(http.MethodGet, "http://sockguard.test/", nil)
			request.URL.Path = tt.matchesRootedTwin
			if action, _, _ := Evaluate([]*CompiledRule{twin}, request); action != ActionAllow {
				t.Errorf("Evaluate(%q) with rooted pattern %q = %q, want %q; the fix narrowed more than the leading slash",
					tt.matchesRootedTwin, tt.rootedTwin, action, ActionAllow)
			}
		})
	}
}

// TestRootlessSingleStarPatternWithLeadingWildcardDoesMatchRootedPath is the
// exception the table above deliberately excludes. "*/json" splits into the
// pattern segments ["*", "json"]; against the rooted path "/json" the walker
// cuts on the leading "/" and hands the first segment an empty string, which
// the bare "*" pattern segment accepts, leaving "json" to match "json"
// exactly. So "*/json", despite being rootless, matches "/json" — not because
// the leading-slash fix missed a case, but because a leading "*" is defined to
// consume an empty segment same as any other. It still does not match
// "/containers/json", which is two segments after the leading slash and
// leaves a "/" in what the second (and last) pattern segment has to consume
// whole.
//
// This is exactly why the entry points reject every rootless pattern rather
// than trying to special-case the "safe" ones: "matches nothing" is not a
// property a rootless single-star pattern can be relied on to have.
func TestRootlessSingleStarPatternWithLeadingWildcardDoesMatchRootedPath(t *testing.T) {
	t.Parallel()

	const pattern = "*/json"

	compiled, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: pattern, Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule(%q): %v", pattern, err)
	}
	reference, err := regexp.Compile("^" + GlobToRegexString(pattern) + "$")
	if err != nil {
		t.Fatalf("compile reference regex for %q: %v", pattern, err)
	}

	rules := []*CompiledRule{compiled}
	check := func(path string, want Action) {
		request := httptest.NewRequest(http.MethodGet, "http://sockguard.test/", nil)
		request.URL.Path = path
		if action, _, _ := Evaluate(rules, request); action != want {
			t.Errorf("Evaluate(%q) with %q = %q, want %q", path, pattern, action, want)
		}
		if got := reference.MatchString(NormalizePath(path)); got != (want == ActionAllow) {
			t.Errorf("regex %q on %q = %v, want %v; the matcher and the dialect disagree",
				reference, path, got, want == ActionAllow)
		}
	}

	check("/json", ActionAllow)
	check("/containers/json", ActionDeny)
}

// TestRootlessDeepWildcardPatternsDoMatchRootedPaths states the truth the
// leading-slash fix does not change, so nothing downstream can be written
// against a comfortable but wrong belief that "rootless means dead".
//
// "**" is defined by the dialect as any sequence of characters including "/",
// so it compiles to "^(?s:.*)$" and matches every rooted path. "**/json" and
// "*/**" reach across the leading slash the same way. The walker agrees with
// the regex on all three — there is no matcher bug here and nothing to narrow;
// a bare "**" really is a catch-all, just an unrooted spelling of one.
//
// That is precisely why refusing the shape is the enforcement, not the matcher.
// Both entry points that accept a pattern from an operator reject a rootless
// one: config.validateRules / validateRuleConfigs for match.path, and
// clientacl.compileContainerLabelRules for a container-label grant, which never
// passes through config validation at all. A label reading
// `com.sockguard.allow.get=**` would otherwise grant every GET the global
// policy allows.
func TestRootlessDeepWildcardPatternsDoMatchRootedPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		matches []string
		misses  []string
	}{
		{pattern: "**", matches: []string{"/", "/_ping", "/containers", "/containers/json"}},
		{pattern: "**/json", matches: []string{"/containers/json", "/containers/abc/json"}, misses: []string{"/_ping", "/containers"}},
		{pattern: "*/**", matches: []string{"/", "/_ping", "/containers", "/containers/json"}},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			t.Parallel()

			compiled, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: tt.pattern, Action: ActionAllow, Index: 0})
			if err != nil {
				t.Fatalf("CompileRule(%q): %v", tt.pattern, err)
			}
			reference, err := regexp.Compile("^" + GlobToRegexString(tt.pattern) + "$")
			if err != nil {
				t.Fatalf("compile reference regex for %q: %v", tt.pattern, err)
			}

			rules := []*CompiledRule{compiled}
			check := func(path string, want Action) {
				request := httptest.NewRequest(http.MethodGet, "http://sockguard.test/", nil)
				request.URL.Path = path
				if action, _, _ := Evaluate(rules, request); action != want {
					t.Errorf("Evaluate(%q) with %q = %q, want %q", path, tt.pattern, action, want)
				}
				if got := reference.MatchString(NormalizePath(path)); got != (want == ActionAllow) {
					t.Errorf("regex %q on %q = %v, want %v; the matcher and the dialect disagree",
						reference, path, got, want == ActionAllow)
				}
			}
			for _, path := range tt.matches {
				check(path, ActionAllow)
			}
			for _, path := range tt.misses {
				check(path, ActionDeny)
			}
		})
	}
}

// rootlessDifferentialPatterns builds the pattern corpus: every one and two
// segment pattern over a small alphabet plus a strided sample of the
// three-segment space, each in both its rootless and its rooted spelling. The
// rootless half is the point — it is the half the matcher used to read as
// rooted — but the rooted half rides along so a change that fixes rootless
// patterns by breaking rooted ones cannot pass.
//
// Patterns carrying more than one "**" are excluded. Stacked "**" has its own
// open question about the literal-prefix gate, tracked separately; folding it
// in here would make this differential fail for a reason that has nothing to do
// with the leading slash.
func rootlessDifferentialPatterns() []string {
	alphabet := []string{"containers", "json", "*", "a*c", "*json", "json*", "**"}

	raw := make([]string, 0, 512)
	for _, a := range alphabet {
		raw = append(raw, a)
		for _, b := range alphabet {
			raw = append(raw, a+"/"+b)
		}
	}
	index := 0
	for _, a := range alphabet {
		for _, b := range alphabet {
			for _, c := range alphabet {
				index++
				if index%3 == 0 {
					raw = append(raw, a+"/"+b+"/"+c)
				}
			}
		}
	}

	seen := make(map[string]struct{}, 2*len(raw))
	patterns := make([]string, 0, 2*len(raw))
	for _, candidate := range raw {
		if strings.Count(candidate, "**") > 1 {
			continue
		}
		for _, spelling := range []string{candidate, "/" + candidate} {
			if _, dup := seen[spelling]; dup {
				continue
			}
			seen[spelling] = struct{}{}
			patterns = append(patterns, spelling)
		}
	}
	return patterns
}

// TestRootlessAndRootedPatternsAgreeWithRegexAndLiteralPrefixGate is the
// differential the leading-slash fix is pinned by. For every pattern in the
// corpus — rootless and rooted, across all five matcher kinds CompileRule
// dispatches to — the hand-written matcher, the literal-prefix gate that fronts
// two of those kinds, and the anchored regex the dialect compiles the pattern
// to have to give the same answer on every probe path.
//
// The existing corpus differential (TestPathMatcherKindsAgreeWithRegexFallback)
// is rooted-only on both sides, which is exactly why it never saw this: the two
// leading-slash strips canceled for a rooted pattern and only diverged for a
// rootless one.
//
// The gate is checked separately from the matcher because it can only ever fail
// one way. It is an early-out, so a gate that rejects a path the regex accepts
// is a silent policy bypass that the matcher's own verdict would then hide.
func TestRootlessAndRootedPatternsAgreeWithRegexAndLiteralPrefixGate(t *testing.T) {
	t.Parallel()

	patterns := rootlessDifferentialPatterns()
	if len(patterns) < 250 {
		t.Fatalf("pattern corpus has %d entries, want at least 250", len(patterns))
	}
	rootless := 0
	for _, pattern := range patterns {
		if !strings.HasPrefix(pattern, "/") {
			rootless++
		}
	}
	if rootless < 125 {
		t.Fatalf("pattern corpus has %d rootless patterns, want at least 125; the half this pins went missing", rootless)
	}

	// The rooted probes are every path view production evaluates: differentialPaths
	// maps its raw candidates through both NormalizePath and
	// NormalizePodmanRoutePath, which is the whole domain rule matching sees.
	rootedPaths := differentialPaths()

	// The rootless probes are not reachable through either — no HTTP
	// request-target produces a path without a leading slash — but they are what
	// a rootless pattern is actually defined against, so probing them keeps
	// "matches nothing" honest: such a pattern is dead because no request looks
	// like that, not because the matcher gave up on it.
	//
	// pathMatcherMatchAll is excluded from them. "/**" compiles to the
	// unconditional `return true` fast path while its regex, "^(/(?s:.*))?$",
	// requires an empty or rooted path, so the two differ on a rootless one.
	// That divergence predates this fix, is not the leading-slash strip, and is
	// unreachable for the same reason these probes are synthetic: every path the
	// fast path is ever handed is rooted or empty, and on empty the two agree.
	rootlessPaths := []string{"containers", "containers/json", "json", "_ping", "a/b/c"}

	kinds := make(map[pathMatcherKind]int, 5)
	methodBit := httpMethodBit(http.MethodGet)
	for _, pattern := range patterns {
		compiled, err := CompileRule(Rule{Methods: []string{"GET"}, Pattern: pattern, Action: ActionAllow})
		if err != nil {
			t.Fatalf("CompileRule(%q): %v", pattern, err)
		}
		kinds[compiled.matcherKind]++

		reference, err := regexp.Compile("^" + GlobToRegexString(pattern) + "$")
		if err != nil {
			t.Fatalf("compile reference regex for %q: %v", pattern, err)
		}
		gatePrefix := literalPrefixForPattern(pattern)

		paths := rootedPaths
		if compiled.matcherKind != pathMatcherMatchAll {
			paths = append(append([]string{}, rootedPaths...), rootlessPaths...)
		}
		for _, path := range paths {
			want := reference.MatchString(path)

			if got := compiled.matchesNormalizedUpperWithBit(http.MethodGet, methodBit, path); got != want {
				t.Fatalf("pattern %q path %q: matcher kind %d = %v, regex %q = %v",
					pattern, path, compiled.matcherKind, got, reference, want)
			}
			if want && gatePrefix != "" && !strings.HasPrefix(path, gatePrefix) {
				t.Fatalf("pattern %q path %q: literal-prefix gate %q rejects a path the regex %q accepts",
					pattern, path, gatePrefix, reference)
			}
		}
	}

	// Agreement is only worth anything if the corpus actually reached every
	// matcher kind; a dispatch change that funneled everything through the
	// regex fallback would otherwise make this pass vacuously.
	for _, kind := range []pathMatcherKind{
		pathMatcherLiteral,
		pathMatcherMatchAll,
		pathMatcherTrailingDeep,
		pathMatcherSegmentGlob,
		pathMatcherRegex,
	} {
		if kinds[kind] == 0 {
			t.Errorf("pattern corpus never produced matcher kind %d", kind)
		}
	}
}
