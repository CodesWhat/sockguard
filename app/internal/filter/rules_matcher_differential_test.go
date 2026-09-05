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
		// The bare literal head of a pattern whose "/**" groups can all
		// collapse, and the same head with the next literal run welded
		// straight onto it. Both are what a stacked-"/**" pattern's own regex
		// still matches, and neither is reachable from the segment alphabet
		// above.
		"/containers/secret",
		"/containersjson",
		"/containers/secretjson",
		"/containers/secret/json",
		"/containers/secret/a/json",
		"/libpod/images/scp",
		"/libpod/images/scpjson",
		"/ajson",
		"/a/bjson",
		// Heads that only stop being distinct once Go's regexp has decoded
		// them. Every byte that is not part of a well-formed UTF-8 sequence
		// steps as U+FFFD with width one, so an anchored regex carrying a
		// single U+FFFD accepts all three of the first spellings here, while
		// strings.HasPrefix and the byte-comparing matchers tell them apart.
		// The two-error head is the negative: one U+FFFD in the pattern
		// cannot consume two in the path.
		"/con\uFFFDtainers",
		"/con\uFFFDtainers/json",
		"/con\uFFFDtainers/a/b",
		"/con\xfftainers",
		"/con\xfftainers/json",
		"/con\xfftainers/a/b",
		"/con\xfetainers",
		"/con\xfetainers/json",
		"/con\xfe\xfftainers",
		"/con\xfe\xfftainers/json",
		"/\uFFFD",
		"/\xff",
		// Regex metacharacters that carry no meaning in this dialect and are
		// literal path content on both sides. A client reaches them by
		// percent-encoding; the gate compares them as bytes and the regex
		// only agrees because ToRegexString quotes them.
		"/a?b",
		"/a?b/json",
		"/a[bc]d",
		"/a[bc]d/json",
		"/a{b,c}d",
		"/a{b,c}d/json",
		"/a\\b",
		"/a\\b/json",
	)

	seen := make(map[string]struct{}, 3*len(raw))
	paths := make([]string, 0, 3*len(raw))
	add := func(normalized string) {
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
	for _, unrooted := range unrootedRequestTargetPaths {
		add(NormalizePath(unrooted))
	}
	return paths
}

// unrootedRequestTargetPaths are the normalized paths an unrooted HTTP
// request-target reaches rule matching as. NormalizePath preserves both
// shapes: "*" from a non-OPTIONS asterisk-form request line, and "" from an
// absolute-form line with no path, an opaque target, or a CONNECT
// authority-form line. The rest are the rootless spellings a pattern could
// have been written as, kept here so the corpus states the whole unrooted
// domain rather than the two request forms alone.
//
// They belong in the differential because a matcher's whole job is to answer
// what its own anchored regex answers, and the catch-all fast path used to
// answer an unconditional true. "^(/(?s:.*))?$" accepts "" and nothing else
// unrooted, so before the fix "/**" allowed "*" and the regex did not — which
// is what let a catch-all allow rule admit "GET *". The proxy now rejects an
// unrooted target at the edge (withRequestTargetGuard), so keeping them here
// is what stops the matcher from quietly drifting back if that guard ever
// moves.
var unrootedRequestTargetPaths = []string{
	"",
	"*",
	"**",
	".",
	"..",
	"_ping",
	"json",
	"containers",
	"containers/json",
	"containers/abc/json",
	"*/json",
	"a\nb",
	"v1.45/containers/json",
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
			// No exemption for the match-all kind. The corpus carries the
			// unrooted request-target shapes now, and "/**" has to refuse
			// those exactly as "^(/(?s:.*))?$" does, so a pattern that still
			// matches everything here is one whose fast path stopped tracking
			// its regex.
			if matched == len(paths) {
				t.Errorf("pattern %q matched every path in the corpus; agreement on all-true is vacuous", tc.pattern)
			}
		})
	}
}

// TestMatchAllFastPathRefusesUnrootedRequestTargets names the case the corpus
// differential above sweeps over. "/**" is the one pattern that compiles to a
// matcher with no path test at all, and an unconditional true is wider than
// the "^(/(?s:.*))?$" it stands for by exactly the unrooted paths: "*", which
// Go's server hands the handler for a non-OPTIONS asterisk-form request line,
// and every rootless spelling below.
//
// It matters because "/**" is the catch-all every permissive policy is written
// with, so the divergence turned "allow everything under the API" into "allow
// a request target the API cannot even name" — and then forwarded it as a
// different target than the one policy evaluated, since url.URL.RequestURI
// substitutes "/" for an empty path.
//
// The empty path stays a match on purpose. The regex's group is optional, so
// "" is inside the pattern's language; the guard is "rooted or empty", not
// "rooted", because the fast path has to answer what the regex answers and
// nothing else.
func TestMatchAllFastPathRefusesUnrootedRequestTargets(t *testing.T) {
	t.Parallel()

	compiled, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionAllow})
	if err != nil {
		t.Fatalf("CompileRule(%q): %v", "/**", err)
	}
	if compiled.matcherKind != pathMatcherMatchAll {
		t.Fatalf("matcherKind for %q = %d, want pathMatcherMatchAll (%d)", "/**", compiled.matcherKind, pathMatcherMatchAll)
	}
	reference := regexp.MustCompile("^" + GlobToRegexString("/**") + "$")

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "asterisk form request target", path: "*", want: false},
		{name: "rootless double star", path: "**", want: false},
		{name: "rootless single segment", path: "_ping", want: false},
		{name: "rootless multi segment", path: "containers/json", want: false},
		{name: "rootless dot segment", path: ".", want: false},
		{name: "rootless parent segment", path: "..", want: false},
		{name: "rootless with a decoded newline", path: "a\nb", want: false},
		{name: "empty path", path: "", want: true},
		{name: "root", path: "/", want: true},
		{name: "ordinary docker path", path: "/containers/json", want: true},
		{name: "path with a decoded newline", path: "/containers/a\nb/json", want: true},
		{name: "doubled leading slash", path: "//evil/containers/json", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := compiled.matchesNormalizedUpperWithBit(http.MethodGet, httpMethodBit(http.MethodGet), tt.path)
			if got != tt.want {
				t.Fatalf("match-all matcher on %q = %v, want %v", tt.path, got, tt.want)
			}
			if want := reference.MatchString(tt.path); want != tt.want {
				t.Fatalf("this table drifted from the dialect: regex %q on %q = %v, table says %v", reference, tt.path, want, tt.want)
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

// literalPrefixPatternStems are the literal heads the prefix differential
// builds its patterns on: the collection routes and nested routes real
// policies spell, the libpod prefix the shipped presets deny, and the bare
// slash.
//
// Every stem is rooted, because a rootless pattern reaches a divergence this
// test is not about: matchGlobSegments strips a leading "/" from the path
// unconditionally, so the segment walker reads "*" as matching "/containers"
// where "^[^/]*$" does not. That is the walker's own rootedness assumption,
// not the prefix derivation, and NormalizePath never produces an unrooted
// path for it to be reached with.
//
// The last six stems are the heads whose bytes and whose compiled regex do not
// line up one to one. A literal U+FFFD and a lone malformed byte both reach
// regexp as the same rune, so a prefix taken from either one is not what the
// regex matches there; the four metacharacter stems are the control, literal
// path content in this dialect that only stays literal because ToRegexString
// quotes it before the regex sees it.
var literalPrefixPatternStems = []string{
	"/",
	"/containers",
	"/containers/secret",
	"/libpod/images/scp",
	"/a",
	"/a/b",
	"/con\uFFFDtainers",
	"/con\xfftainers",
	"/a?b",
	"/a[bc]d",
	"/a{b,c}d",
	"/a\\b",
}

// literalPrefixPatternTails are the wildcard tails each stem is crossed with.
// The list is built around what the prefix derivation has to reason about:
// how many "/**" groups stack up, whether the text after the first one is
// itself optional, and whether it resumes with a "/" or welds a literal run
// straight onto the head.
var literalPrefixPatternTails = []string{
	"",
	"*",
	"**",
	"/*",
	"/**",
	"/**/",
	"/***",
	"/**/*",
	"/**/**",
	"/**/***",
	"/**/**/**",
	"/**json",
	"/**/**json",
	"/**/json",
	"/**/**/json",
	"/*/**",
	"/*/**/**",
	"/**/*/**",
	"/**/exec",
	"/**/**/exec",
	"/a/**",
	"/a/**/**",
}

// literalPrefixNamedPatterns are the patterns this package's other tests and
// the shipped presets actually spell, kept alongside the generated cross
// product so the differential covers the catalog as well as the corners.
var literalPrefixNamedPatterns = []string{
	"/_ping",
	"/**",
	"/*",
	"/containers/json",
	"/containers/**",
	"/containers/*",
	"/containers/*/json",
	"/containers/*/exec",
	"/containers/*/logs",
	"/containers/*/*/top",
	"/containers/a*c",
	"/containers/a**c",
	"/containers/**/exec",
	"/containers/**/json",
	"/containers/**/*/logs",
	"/**/json",
	"/*/json",
	"/*/*/*",
	"/a/**/b/**/c",
	"/a/*/b/*/c",
	"/**/x/**/y/**",
	"/libpod/images/scp/*",
	"/libpod/images/scp/*/*",
	"/libpod/images/scp/**",
}

func literalPrefixPatterns() []string {
	size := len(literalPrefixPatternStems)*len(literalPrefixPatternTails) + len(literalPrefixNamedPatterns)
	seen := make(map[string]struct{}, size)
	patterns := make([]string, 0, size)
	add := func(pattern string) {
		if pattern == "" {
			return
		}
		if _, dup := seen[pattern]; dup {
			return
		}
		seen[pattern] = struct{}{}
		patterns = append(patterns, pattern)
	}
	for _, stem := range literalPrefixPatternStems {
		for _, tail := range literalPrefixPatternTails {
			add(stem + tail)
		}
	}
	for _, pattern := range literalPrefixNamedPatterns {
		add(pattern)
	}
	return patterns
}

// TestLiteralPrefixGateNeverRejectsARegexMatch is the differential between the
// literal-prefix fast reject and the anchored regex the same pattern compiles
// to. The prefix exists only to skip work: a path the regex accepts must never
// be turned away by the gate in front of it. A gate that is even one byte too
// long is not an optimization, it is a policy change, and on a deny rule it is
// the dangerous direction — the rejected path falls through to whatever allow
// sits below.
//
// It is generated rather than tabulated because the shape that broke (S17d,
// a pattern whose text after the first "/**" is itself entirely optional) is
// one nobody would think to write down. The full matcher verdict is checked
// against the same regex on the way past, so a fix that widens the prefix
// cannot quietly break the matcher it guards.
func TestLiteralPrefixGateNeverRejectsARegexMatch(t *testing.T) {
	t.Parallel()

	patterns := literalPrefixPatterns()
	if len(patterns) < 120 {
		t.Fatalf("pattern corpus has %d patterns, want at least 120", len(patterns))
	}
	paths := differentialPaths()

	methodBit := httpMethodBit(http.MethodGet)
	regexKinds, matches := 0, 0
	for _, pattern := range patterns {
		compiled, err := CompileRule(Rule{Methods: []string{http.MethodGet}, Pattern: pattern, Action: ActionAllow})
		if err != nil {
			t.Fatalf("CompileRule(%q): %v", pattern, err)
		}
		reference, err := regexp.Compile("^" + GlobToRegexString(pattern) + "$")
		if err != nil {
			t.Fatalf("compile reference regex for %q: %v", pattern, err)
		}
		if compiled.matcherKind == pathMatcherRegex {
			regexKinds++
		}

		for _, path := range paths {
			want := reference.MatchString(path)
			if want {
				matches++
				if !strings.HasPrefix(path, compiled.literalPrefix) {
					t.Errorf("pattern %q: regex %q matches %q, but the literal prefix %q rejects it",
						pattern, reference, path, compiled.literalPrefix)
				}
			}
			if got := compiled.matchesNormalizedUpperWithBit(http.MethodGet, methodBit, path); got != want {
				t.Errorf("pattern %q path %q: matcher kind %d = %v, regex %q = %v",
					pattern, path, compiled.matcherKind, got, reference, want)
			}
		}
	}

	// Agreement is only worth asserting over a domain the patterns reach, and
	// the gate only runs on the regex and segment-glob kinds.
	if regexKinds < 40 {
		t.Errorf("corpus compiled %d patterns to pathMatcherRegex, want at least 40", regexKinds)
	}
	if matches < 1000 {
		t.Errorf("corpus produced %d pattern/path matches, want at least 1000", matches)
	}
}

// TestFilterLiteralPrefixNarrowsStackedDoubleStar is the named regression for
// the shape the differential above was written for, stated as the policy it
// breaks rather than as an invariant over a corpus.
//
// A pattern ending in two or more consecutive "/**" compiles to
// pathMatcherRegex, whose anchored regex matches the bare literal head:
// every "/**" is an optional group, so "^/containers/secret(/(?s:.*))?(/(?s:.*))?$"
// matches "/containers/secret". The literal-prefix gate in front of it
// disagreed. literalPrefixForPattern kept the trailing slash whenever the text
// after the first "/**" started with "/", so the gate demanded
// "/containers/secret/" and rejected "/containers/secret" before the regex was
// ever consulted.
//
// The direction is what makes it a policy hole rather than a slow path. On a
// deny rule the narrowed gate does not deny less loudly, it hands the request
// to whatever allow sits below: "deny /containers/secret/**/**" above
// "allow /containers/**" admitted GET /containers/secret.
func TestFilterLiteralPrefixNarrowsStackedDoubleStar(t *testing.T) {
	t.Parallel()

	rules := compileRulesForTest(t, []Rule{
		{Methods: []string{"*"}, Pattern: "/containers/secret/**/**", Action: ActionDeny, Reason: "secret containers denied", Index: 0},
		{Methods: []string{"*"}, Pattern: "/containers/**", Action: ActionAllow, Index: 1},
	})

	tests := []struct {
		name   string
		path   string
		want   Action
		reason string
	}{
		{
			name: "the bare head the stacked groups collapse to",
			path: "/containers/secret",
			want: ActionDeny,
		},
		{
			name: "a descendant of that head",
			path: "/containers/secret/json",
			want: ActionDeny,
		},
		{
			name: "a deeper descendant, where both groups are spent",
			path: "/containers/secret/a/json",
			want: ActionDeny,
		},
		{
			// The fix widens a gate, so the thing worth pinning next to it is
			// that it did not widen the rule: a sibling the deny never
			// described still reaches the allow below.
			name: "a sibling the deny never described",
			path: "/containers/other",
			want: ActionAllow,
		},
		{
			name: "a head the deny's own literal run does not reach",
			path: "/containers/secretive",
			want: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			action, index, _ := Evaluate(rules, newParsedRequest(t, http.MethodGet, tt.path))
			if action != tt.want {
				t.Fatalf("Evaluate(GET %q) = %v (rule %d), want %v", tt.path, action, index, tt.want)
			}
		})
	}
}

// TestFilterLiteralPrefixStopsAtAReplacementRune is the named regression for
// the byte-versus-rune split, stated as the policy it breaks.
//
// glob.ToRegexString decodes the pattern before it quotes it, so a deny
// spelling "/containers/sec\uFFFDret/*" compiles to
// "^/containers/sec\x{FFFD}ret/[^/]*$", and regexp decodes the request path the
// same way: every byte that is not part of a well-formed UTF-8 sequence steps
// as U+FFFD with width one. That regex therefore covers
// GET /containers/sec%FFret/json. Nothing in front of it did. The literal
// prefix was the pattern's own bytes up to the "*", so the gate demanded the
// three-byte U+FFFD encoding and turned the request away before the regex was
// consulted, and the segment walker this pattern used to compile to compares
// bytes as well, so it would have said no a second time.
//
// A gate that turns a request away does not deny it. It hands it to whatever
// allow sits below, which is how "deny /containers/sec\uFFFDret/*" above
// "allow /containers/**" admitted the request the deny describes.
func TestFilterLiteralPrefixStopsAtAReplacementRune(t *testing.T) {
	t.Parallel()

	rules := compileRulesForTest(t, []Rule{
		{Methods: []string{"*"}, Pattern: "/containers/sec\uFFFDret/*", Action: ActionDeny, Reason: "secret containers denied", Index: 0},
		{Methods: []string{"*"}, Pattern: "/containers/**", Action: ActionAllow, Index: 1},
	})

	// Reported rather than fatal so the table below still runs. A regression
	// should name the requests that changed hands, not only the internal that
	// changed.
	if rules[0].matcherKind != pathMatcherRegex {
		t.Errorf("matcherKind = %d, want pathMatcherRegex (%d); a byte-comparing matcher cannot answer for this pattern", rules[0].matcherKind, pathMatcherRegex)
	}
	if rules[0].literalPrefix != "/containers/sec" {
		t.Errorf("literalPrefix = %q, want %q; the gate has to stop where the bytes and the regex stop agreeing", rules[0].literalPrefix, "/containers/sec")
	}

	tests := []struct {
		name string
		path string
		want Action
	}{
		{
			name: "the pattern's own spelling",
			path: "/containers/sec%EF%BF%BDret/json",
			want: ActionDeny,
		},
		{
			name: "a malformed byte where the pattern has U+FFFD",
			path: "/containers/sec%FFret/json",
			want: ActionDeny,
		},
		{
			name: "a different malformed byte, which decodes to the same rune",
			path: "/containers/sec%FEret/json",
			want: ActionDeny,
		},
		{
			// The fix widens a gate, so what is worth pinning beside it is
			// that it did not widen the rule. One U+FFFD in the pattern is one
			// rune and cannot consume two.
			name: "two malformed bytes, which one U+FFFD cannot consume",
			path: "/containers/sec%FE%FFret/json",
			want: ActionAllow,
		},
		{
			name: "a sibling with nothing at all where the deny wants a rune",
			path: "/containers/secret/json",
			want: ActionAllow,
		},
		{
			name: "a well-formed rune the deny never described",
			path: "/containers/sec%C3%A9ret/json",
			want: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			action, index, _ := Evaluate(rules, newParsedRequest(t, http.MethodGet, tt.path))
			if action != tt.want {
				t.Fatalf("Evaluate(GET %q) = %v (rule %d), want %v", tt.path, action, index, tt.want)
			}
		})
	}
}
