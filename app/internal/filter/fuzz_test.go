package filter

import (
	"net/http"
	pathpkg "path"
	"regexp"
	"strings"
	"testing"
)

// podmanVersionPrefix mirrors VersionedPath's v5.8.1 route grammar. Podman
// accepts any version beginning with a digit followed by digits, ASCII letters,
// dots, or hyphens, including prerelease and four-component spellings.
var podmanVersionPrefix = regexp.MustCompile(`^/v[0-9][0-9A-Za-z.-]*/`)

// referenceNormalizePath is an independent re-implementation of NormalizePath
// used by FuzzNormalizePath as a differential oracle. Like NormalizePath it
// path-cleans then strips the version prefix and does not percent-decode; it
// calls path.Clean unconditionally so the fuzzer also exercises the
// pathNeedsClean fast path NormalizePath uses.
func referenceNormalizePath(p string) string {
	if p == "" {
		return ""
	}
	return podmanVersionPrefix.ReplaceAllString(pathpkg.Clean(p), "/")
}

// FuzzPathMatch fuzzes the full path-matching pipeline: NormalizePath + compiled
// rule matching. Ensures no panics and that a catch-all rule always matches.
func FuzzPathMatch(f *testing.F) {
	// Seed with realistic Docker API paths.
	seeds := []struct {
		method string
		path   string
	}{
		{"GET", "/containers/json"},
		{"GET", "/v1.45/containers/json"},
		{"POST", "/containers/create"},
		{"DELETE", "/v1.47/containers/abc123"},
		{"GET", "/_ping"},
		{"PUT", "/v1.45/containers/abc123/rename"},
		{"GET", "/"},
		{"GET", ""},
		{"POST", "/v999.999/images/build"},
		{"GET", "/containers/abc/def/ghi/jkl"},
		{"GET", "/containers/../images/json"},
		{"GET", "/../../etc/passwd"},
		{"GET", "//containers///json"},
		{"GET", "/v1.45/../containers/json"},
		{"GET", "/containers%2Fjson"},
		{"GET", "/containers%252Fjson"},
		{"GET", "/containers/%2e%2e/images/json"},
		{"GET", "/containers/%252e%252e/images/json"},
		{"GET", "/v1.45%2Fcontainers/json"},
		{"POST", "/containers%252Fcreate"},
		{"POST", "/v1.55/session"},
		{"POST", "/v1.55/grpc"},
		{"POST", "/session"},
		{"POST", "/grpc"},
		{"GET", "/v5.0.0/libpod/containers/json"},
		{"GET", "/v5.8.1-dev/libpod/manifests/app/json"},
		{"POST", "/v5.8.1.2/libpod/images/scp/app"},
		{"GET", "/v5.8.1-dev/libpod/images/load"},
		{"POST", "/v5.8.1.2/libpod/images/import"},
		{"POST", "/v5.0.0/libpod/pods/create"},
		{"POST", "/v5.0.0/libpod/play/kube"},
		{"GET", "/v5.0.0/libpod/generate/kube"},
		{"POST", "/v1.45/libpod/containers/create"},
		// Trailing slashes. NormalizePath cleans these away, but the libpod
		// image-SCP route view keeps them, and there the empty final segment
		// is part of the image name Podman routes on.
		{"GET", "/containers/abc/"},
		{"GET", "/a/b/"},
		{"POST", "/libpod/images/scp/alpine/"},
		{"POST", "/libpod/images/scp/tenant/"},
		{"POST", "/libpod/images/scp/victim/push/"},
		{"POST", "/v5.8.1/libpod/images/scp/acme/app/"},
		{"POST", "/v5.8.1-dev/libpod/images/scp/foreign%2Fpush/"},
		{"GET", "//"},
		{"GET", "/containers//"},
		// Rootless request-target shapes, which the rooted-view invariant
		// below deliberately skips. The asterisk-form entries are the ones a
		// client can actually put on the wire: Go's server answers "OPTIONS *"
		// itself, so a non-OPTIONS method is how "*" reaches rule matching.
		{"GET", "../00/"},
		{"OPTIONS", "*"},
		{"GET", "*"},
		{"POST", "*"},
		{"CONNECT", ""},
		{"GET", "containers/json"},
	}
	for _, s := range seeds {
		f.Add(s.method, s.path)
	}

	// Pre-compile a catch-all rule: any method, any path.
	catchAll, err := CompileRule(Rule{
		Methods: []string{"*"},
		Pattern: "/**",
		Action:  ActionDeny,
		Index:   0,
	})
	if err != nil {
		f.Fatalf("CompileRule catch-all: %v", err)
	}
	if catchAll.matcherKind != pathMatcherMatchAll {
		f.Fatalf("matcherKind for %q = %d, want pathMatcherMatchAll (%d)", "/**", catchAll.matcherKind, pathMatcherMatchAll)
	}
	catchAllRegex, err := regexp.Compile("^" + GlobToRegexString("/**") + "$")
	if err != nil {
		f.Fatalf("compile reference regex for %q: %v", "/**", err)
	}

	// Pre-compile a specific rule.
	containers, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		f.Fatalf("CompileRule containers: %v", err)
	}

	// Segment-glob rules and the anchored regex their patterns compile to. The
	// walker is only an optimization, so it has to answer identically on both
	// path views production hands it: NormalizePath, which cleans a trailing
	// slash away, and NormalizePodmanRoutePath, which keeps the one
	// gorilla/mux routes on for the libpod image-SCP endpoint. "[^/]*" matches
	// a newline, so unlike the "**" group above these need no newline carve-out.
	//
	// The last three are rootless. Config validation refuses that shape, but the
	// walker is what makes the refusal safe rather than a behavior change, and
	// it is reachable without config validation through the container-label
	// ACLs, whose patterns come off a container and go straight to CompileRule.
	segmentGlobs := make([]*CompiledRule, 0, 6)
	segmentGlobRegexes := make([]*regexp.Regexp, 0, 6)
	for _, pattern := range []string{
		"/containers/*", "/*/*/*", "/libpod/images/scp/*/*",
		"containers/*", "*/json", "*",
	} {
		compiled, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: pattern, Action: ActionAllow, Index: 2})
		if err != nil {
			f.Fatalf("CompileRule(%q): %v", pattern, err)
		}
		if compiled.matcherKind != pathMatcherSegmentGlob {
			f.Fatalf("matcherKind for %q = %d, want pathMatcherSegmentGlob (%d)", pattern, compiled.matcherKind, pathMatcherSegmentGlob)
		}
		reference, err := regexp.Compile("^" + GlobToRegexString(pattern) + "$")
		if err != nil {
			f.Fatalf("compile reference regex for %q: %v", pattern, err)
		}
		segmentGlobs = append(segmentGlobs, compiled)
		segmentGlobRegexes = append(segmentGlobRegexes, reference)
	}

	f.Fuzz(func(t *testing.T, method, path string) {
		// NormalizePath must never panic.
		normalized := NormalizePath(path)
		upperMethod := upperHTTPMethodASCII(method)
		methodBit := httpMethodBit(upperMethod)

		// Matches must never panic.
		catchAll.matches(method, path)
		containers.matches(method, path)

		// Invariant: catch-all rule matches every non-empty normalized path
		// that starts with "/" and contains no newlines. Go's regexp ".*"
		// does not match \n, and newlines are invalid in HTTP paths anyway.
		if len(normalized) > 0 && normalized[0] == '/' && !containsNewline(normalized) {
			if !catchAll.matches(method, path) {
				t.Errorf("catch-all did not match method=%q path=%q (normalized=%q)", method, path, normalized)
			}
		}

		// Invariant: the match-all fast path answers exactly what "/**"'s own
		// anchored regex answers, on every path view including the unrooted
		// ones. It has no path test to get wrong except its bounds, and it used
		// to have no bounds at all: an unconditional true made a catch-all
		// allow rule admit "*", the request target Go's server produces from a
		// non-OPTIONS asterisk-form request line, which "^(/(?s:.*))?$" does
		// not match. This is not scoped to rooted views for that exact reason.
		for _, view := range []string{normalized, NormalizePodmanRoutePath(path)} {
			got := catchAll.matchesNormalizedUpperWithBit(upperMethod, methodBit, view)
			if want := catchAllRegex.MatchString(view); got != want {
				t.Errorf("match-all on %q (from %q) = %v, regex %q = %v", view, path, got, catchAllRegex, want)
			}
		}

		// Invariant: on both production path views, the segment walker agrees
		// with the anchored regex its pattern compiles to. Scoped to rooted
		// views, which is every path an HTTP request-target produces bar the
		// asterisk-form and absolute-form-with-empty-path edges. The walker
		// used to drop one leading "/" from both the pattern and the path
		// before comparing, so it read a rootless pattern as rooted where the
		// regex does not — "*" matched "/_ping". Neither drop happens now, so
		// the rootless patterns above have to answer false on every rooted view
		// here, exactly as their regexes do.
		for _, view := range []string{normalized, NormalizePodmanRoutePath(path)} {
			if !strings.HasPrefix(view, "/") {
				continue
			}
			for i, compiled := range segmentGlobs {
				got := compiled.matchesNormalizedUpperWithBit(upperMethod, methodBit, view)
				want := segmentGlobRegexes[i].MatchString(view)
				if got != want {
					t.Errorf("segment glob %q path %q (from %q) = %v, regex %q = %v",
						compiled.segmentPatterns, view, path, got, segmentGlobRegexes[i], want)
				}
			}
		}
	})
}

// FuzzGlobToRegex fuzzes glob-to-regex conversion. Every glob pattern must
// produce a valid, compilable regular expression.
func FuzzGlobToRegex(f *testing.F) {
	seeds := []string{
		"/containers/**",
		"/containers/*/json",
		"/_ping",
		"/**",
		"/",
		"",
		"/images/*/tag",
		"/networks/**",
		"/v1.45/containers",
		"*",
		"**",
		"***",
		"/a/b/c/d/e/f/g",
		"/containers/[abc]", // brackets are literal in our glob
		"/path with spaces",
		"/path(parens)",
		"/path{braces}",
		"/path+plus",
		"/path.dots.here",
		"/path$dollar",
		"/path^caret",
		"/path|pipe",
		"/path?question",
		"/v1.55/session",
		"/session/**",
		"/grpc/**",
		// Trailing slashes, on both sides of the dialect: a pattern that ends
		// in one spells a final empty segment, which is what the libpod
		// image-SCP route view can present.
		"/containers/",
		"/containers/*/",
		"/containers/**/",
		"/libpod/images/scp/*",
		"/libpod/images/scp/*/",
		"/libpod/images/scp/*/*",
		"//",
		"*/",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		// globToRegex must never panic.
		regexStr := globToRegex(pattern)

		// The resulting regex must always compile.
		anchored := "^" + regexStr + "$"
		compiled, err := regexp.Compile(anchored)
		if err != nil {
			t.Errorf("globToRegex(%q) produced invalid regex %q: %v", pattern, anchored, err)
			return
		}

		// Invariant: a literal ASCII pattern (no * chars) must match itself
		// exactly. Non-ASCII bytes can mismatch due to regexp.QuoteMeta
		// operating on UTF-8, which is fine — Docker paths are always ASCII.
		if !containsStar(pattern) && isASCII(pattern) {
			if !compiled.MatchString(pattern) {
				t.Errorf("literal pattern %q does not match itself via regex %q", pattern, anchored)
			}
		}
	})
}

// FuzzNormalizePath fuzzes path normalization in isolation. The result must
// stay equivalent to a reference implementation that path-cleans and strips
// the version prefix without percent-decoding.
func FuzzNormalizePath(f *testing.F) {
	seeds := []string{
		"/containers/json",
		"/v1.45/containers/json",
		"/v1/containers/json",
		"/v999.0/images/build",
		"/_ping",
		"/v1.45/_ping",
		"",
		"/",
		"/v/containers/json",    // "/v" alone is not a version prefix
		"/vX/containers/json",   // first char after v must be a digit
		"/v1.45",                // version prefix with no trailing path
		"/v1.45/",               // version prefix with just trailing slash
		"/version",              // starts with /v but not a version prefix
		"/v1./containers",       // trailing dot is in Podman's class -- strips
		"/v.1/containers",       // no digit right after v -- not a prefix
		"/containers/../images", // path traversal
		"/../../etc/passwd",     // escape attempt
		"//containers///json",   // redundant slashes
		"/containers/./json",    // dot segment
		"/containers%2Fjson",
		"/containers%252Fjson",
		"/containers/%2e/json",   // single-encoded dot — stays literal, no collapse
		"/containers/%252e/json", // double-encoded dot — must not decode to "."
		"/containers/%2e%2e/images/json",
		"/containers/%252e%252e/images/json",
		"/v1.45%2Fcontainers/json",
		"/v1.45/%252e%252e/containers/json",
		"/v1.55/session",
		"/v1.55/grpc",
		"/v1.55/containers/json",
		// Three-part semver (#148): Podman's libpod bindings send the full
		// daemon version, unlike Docker's vN / vN.N.
		"/v4.9.3/libpod/containers/json",
		"/v5.0.0/libpod/containers/json",
		"/v5.0.0/",    // three-part prefix with just trailing slash
		"/v5.0.0",     // three-part prefix with no trailing path
		"/v5.0./x",    // trailing dot is in Podman's class -- strips
		"/v1.2.3.4/x", // Podman's class has no part-count limit -- strips
		"/v5.8.1-dev/libpod/images/load",
		"/v5.8.1_rc/libpod/images/load", // underscore is not accepted
		"/v5.8.1-dev/libpod/manifests/app/json",
		"/v5.8.1_rc/libpod/manifests/app/json", // underscore is not accepted
		"/v99999999999999999999.99999999999999999999.99999999999999999999/x", // adversarial digit runs
		// Podman prerelease / dev builds (this fix): VersionedPath is
		// [0-9][0-9A-Za-z.-]*, admitting "-dev", "-rc1", trailing '.'/'-',
		// but not '+' (semver build metadata) or '_'.
		"/v5.8.1-dev/libpod/networks/x/connect",
		"/v5.8.1-rc1/libpod/containers/json",
		"/v5.8.1+build.7/libpod/containers/json", // '+' not in class -- unchanged
		"/v1.45./containers/json",                // trailing dot
		"/v1.45-/containers/json",                // trailing dash
		"/v1.45-foo/../containers/create",        // prerelease suffix + traversal
		"/v5.8.1-dev",                            // no trailing slash
		"/v5.8.1-dev/",                           // root path after prefix
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		normalized := NormalizePath(path)
		want := referenceNormalizePath(path)
		if normalized != want {
			t.Errorf("NormalizePath(%q) = %q, want reference-normalized %q", path, normalized, want)
		}
	})
}

// compileRulePatternTokens is the alphabet FuzzCompileRule expands a fuzzer
// seed into a rule pattern with. A byte-per-token mapping is what keeps the
// target out of the literal-only space a raw string mutator sits in: reaching
// "/containers/**/*" by chance takes a byte mutator a very long time, and
// every divergence this target exists to find so far (the stacked-"/**"
// literal prefix, the rootless segment walker, the replacement-rune prefix)
// lived in the interaction between a "/**" group, a "*" and a literal run.
//
// Every feature of the dialect is here, and so is every shape the entry
// points reject but CompileRule still compiles: a rootless head, an API
// version prefix, and a literal "%". Those are not exemptions. config.Validate
// refuses them on match.path and clientacl refuses them on a container-label
// grant, but CompileRule returns no error for any of them, and the
// container-label ACLs hand it patterns that never passed config validation,
// so the matchers still have to answer what the dialect says. The only
// exemption the differential grants is a CompileRule that actually returns an
// error, which is a regexp compilation failure and nothing else.
var compileRulePatternTokens = []string{
	"/", "*", "**", "/**", "/*", "***", "**/",
	"containers", "json", "exec", "libpod", "images", "scp", "_ping",
	"a", "b", "-",
	"?", "[abc]", "{a,b}", "\\", ".", "..",
	"%", "%2F", "%2e%2e",
	"v1.45", "/v1.45", "/v5.8.1-dev",
	"é", "日本", "\uFFFD", "\xff", "\xfe\xff", "\xc3",
	"\n", "\r", "\x00", " ",
}

// compileRulePathTokens is the same idea on the path side, drawn from the
// segment alphabet the table-driven matcher differential already uses: decoded
// control bytes (what a percent-encoded %0A/%0D/%00 becomes after net/http's
// single decode), a still-encoded %2F, multi-byte and invalid UTF-8, and the
// glob metacharacters appearing as literal path content.
var compileRulePathTokens = []string{
	"/", "", "containers", "json", "exec", "abc", "_ping",
	"libpod", "images", "scp", "a", "b",
	"*", "**", ".", "..",
	"?", "[abc]", "{a,b}", "\\",
	"%2F", "%2e%2e", "%",
	"é", "日本", "\uFFFD", "\xff", "\xfe\xff", "\xc3",
	"\n", "\r", "\x00", " ",
	"v1.45", "v5.8.1-dev",
}

// compileRuleGlobExpansion substitutes a concrete string for each wildcard
// token of a pattern, so a path derived from the pattern is a near miss rather
// than an unrelated string. Independent pattern and path mutation almost never
// produces a pair the regex matches, and agreement on a pair neither side
// matches is vacuous.
type compileRuleGlobExpansion struct {
	slashDoubleStar string
	doubleStar      string
	star            string
}

// compileRuleGlobExpansions covers the three answers that separate the
// matchers: a "/**" that expands to real segments, one that collapses to
// nothing (the case the stacked-"/**" literal prefix got wrong), and one whose
// text only a decoding matcher reads the same way as a byte-comparing one.
var compileRuleGlobExpansions = []compileRuleGlobExpansion{
	{slashDoubleStar: "/x/y", doubleStar: "x/y", star: "seg"},
	{slashDoubleStar: "", doubleStar: "", star: ""},
	{slashDoubleStar: "/\n", doubleStar: "\xff", star: "é"},
}

// compileRuleMaxSeedTokens bounds how much of a fuzzer seed is expanded into
// tokens, and compileRuleMaxRawBytes bounds the raw seed used verbatim. Both
// exist so a mutator that grows an input cannot turn one execution into a
// multi-second regexp compilation and starve the run.
const (
	compileRuleMaxSeedTokens = 24
	compileRuleMaxRawBytes   = 256
)

func expandCompileRuleTokens(seed string, tokens []string) string {
	var b strings.Builder
	limit := min(len(seed), compileRuleMaxSeedTokens)
	for i := 0; i < limit; i++ {
		b.WriteString(tokens[int(seed[i])%len(tokens)])
	}
	return b.String()
}

func truncateCompileRuleSeed(seed string) string {
	if len(seed) > compileRuleMaxRawBytes {
		return seed[:compileRuleMaxRawBytes]
	}
	return seed
}

// compileRuleFuzzPatterns turns one seed into the patterns a single execution
// checks: the seed verbatim, which is what keeps the original "arbitrary input
// must not panic" property, and its token expansion, which is what reaches the
// dialect.
func compileRuleFuzzPatterns(seed string) []string {
	raw := truncateCompileRuleSeed(seed)
	expanded := expandCompileRuleTokens(seed, compileRulePatternTokens)
	if expanded == raw {
		return []string{raw}
	}
	return []string{raw, expanded}
}

// expandCompileRuleGlob rewrites a pattern's wildcard tokens into literal text
// using the same tokenization glob.ToRegexString applies, so the result is a
// string the pattern plausibly matches. Decoding through []rune is deliberate:
// it maps a malformed byte in the pattern to a literal U+FFFD in the path,
// which is exactly the pair the anchored regex reads as equal and every
// byte-comparing matcher reads as different.
func expandCompileRuleGlob(pattern string, expansion compileRuleGlobExpansion) string {
	var b strings.Builder
	runes := []rune(pattern)
	for i := 0; i < len(runes); {
		switch {
		case i+2 < len(runes) && runes[i] == '/' && runes[i+1] == '*' && runes[i+2] == '*':
			b.WriteString(expansion.slashDoubleStar)
			i += 3
		case i+1 < len(runes) && runes[i] == '*' && runes[i+1] == '*':
			b.WriteString(expansion.doubleStar)
			i += 2
		case runes[i] == '*':
			b.WriteString(expansion.star)
			i++
		default:
			b.WriteRune(runes[i])
			i++
		}
	}
	return b.String()
}

// compileRuleFuzzPathViews builds the path domain one execution sweeps. Each
// raw candidate is mapped through both normalizations production hands a
// compiled rule — NormalizePath for ordinary policy matching and
// NormalizePodmanRoutePath for the libpod image-SCP route view, the only shape
// that reaches rule matching with a trailing slash — and is also kept raw.
//
// Raw is not an oversight. An unrooted request target reaches Evaluate exactly
// as the client sent it: "*" from a non-OPTIONS asterisk-form request line and
// "" from an absolute-form line with no path, an opaque target, or a CONNECT
// authority-form line. withRequestTargetGuard now answers 400 for those before
// any layer evaluates them, so keeping them in the domain is what stops a
// matcher from drifting wider than its regex again if that guard ever moves.
func compileRuleFuzzPathViews(pattern, seed string) []string {
	raw := make([]string, 0, 2+len(compileRuleGlobExpansions))
	raw = append(raw, truncateCompileRuleSeed(seed), expandCompileRuleTokens(seed, compileRulePathTokens))
	for _, expansion := range compileRuleGlobExpansions {
		raw = append(raw, expandCompileRuleGlob(pattern, expansion))
	}

	seen := make(map[string]struct{}, 4*len(raw))
	views := make([]string, 0, 4*len(raw))
	add := func(view string) {
		if _, dup := seen[view]; dup {
			return
		}
		seen[view] = struct{}{}
		views = append(views, view)
	}
	for _, candidate := range raw {
		add(candidate)
		add(NormalizePath(candidate))
		add(NormalizePodmanRoutePath(candidate))
		add(NormalizePodmanRoutePath(candidate + "/"))
	}
	return views
}

// assertCompiledRuleAgreesWithItsRegex is the gate-vs-regex invariant. Every
// fast path CompileRule dispatches to exists only to avoid regexp on the hot
// path, so "faster" is correct only if the verdict is identical to
// "^" + glob.ToRegexString(pattern) + "$". A fast path that answers differently
// is a policy bypass wearing an optimization's clothes, and on a deny rule it
// is the dangerous direction: the request the gate turns away is not denied,
// it falls through to whatever allow sits below.
//
// Three things are checked per path, not one. The dispatcher's verdict is the
// end-to-end answer. The literal-prefix gate is checked on its own, because a
// gate one byte too long rejects a path the regex accepts and the dispatcher
// would report that as ordinary disagreement without naming the cause. And
// each matcher is then run with the gate taken out of the way, because a
// walker that is wider than its regex is latent as long as the gate happens to
// cover for it, and the gate is derived from the same pattern.
func assertCompiledRuleAgreesWithItsRegex(t *testing.T, pattern string, views []string) {
	t.Helper()

	compiled, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: pattern, Action: ActionAllow, Index: 0})
	if err != nil {
		// The only error CompileRule returns is a regexp compilation failure,
		// and a pattern whose regex does not compile has no dialect meaning to
		// compare against. Nothing else is exempt: a rootless, version-prefixed
		// or percent-bearing pattern compiles fine and is checked like any other.
		return
	}
	anchored := "^" + GlobToRegexString(pattern) + "$"
	reference, err := regexp.Compile(anchored)
	if err != nil {
		t.Fatalf("pattern %q compiled to a rule but its own anchored regex %q does not compile: %v", pattern, anchored, err)
	}

	methodBit := httpMethodBit(http.MethodGet)
	for _, view := range views {
		want := reference.MatchString(view)

		if got := compiled.matchesNormalizedUpperWithBit(http.MethodGet, methodBit, view); got != want {
			t.Errorf("pattern %q path %q: matcher kind %d = %v, regex %q = %v",
				pattern, view, compiled.matcherKind, got, reference, want)
		}

		if want && !strings.HasPrefix(view, compiled.literalPrefix) {
			t.Errorf("pattern %q: regex %q matches %q, but the literal prefix %q rejects it",
				pattern, reference, view, compiled.literalPrefix)
		}

		var bare bool
		switch compiled.matcherKind {
		case pathMatcherLiteral:
			bare = view == compiled.literal
		case pathMatcherMatchAll:
			bare = isRootedOrEmptyPath(view)
		case pathMatcherTrailingDeep:
			bare = matchTrailingDoubleStar(compiled.trailingPrefix, view)
		case pathMatcherSegmentGlob:
			bare = matchGlobSegments(compiled.segmentPatterns, view)
		case pathMatcherRegex:
			bare = compiled.pattern.MatchString(view)
		default:
			t.Fatalf("pattern %q compiled to unknown matcher kind %d", pattern, compiled.matcherKind)
		}
		if bare != want {
			t.Errorf("pattern %q path %q: matcher kind %d without the literal-prefix gate = %v, regex %q = %v",
				pattern, view, compiled.matcherKind, bare, reference, want)
		}
	}
}

// compileRuleSeed is one FuzzCompileRule seed. The path is a seed for the path
// domain, not the only path checked: each execution also derives paths from the
// pattern itself, so a seed that names only a pattern still produces matches.
type compileRuleSeed struct {
	method  string
	pattern string
	path    string
}

// compileRuleFuzzSeeds is the seed corpus, shared between the fuzz target and
// TestCompileRuleFuzzCorpusReachesEveryMatcherKind so the corpus cannot go
// blind to a matcher kind without a test saying so. The named rows are the
// ones the table-driven S17 tests spell, plus the committed seeds of the two
// sibling targets over the same dialect (FuzzGlobToRegexString and
// FuzzNormalizePath); the generated tail is the literal-prefix pattern corpus,
// which is where the stacked-"/**" shape lives.
func compileRuleFuzzSeeds() []compileRuleSeed {
	seeds := []compileRuleSeed{
		{method: "GET", pattern: "/containers/**", path: "/containers/abc/json"},
		{method: "*", pattern: "/**", path: "*"},
		{method: "POST", pattern: "/containers/create", path: "/containers/create"},
		{method: "GET", pattern: "/_ping", path: "/_ping"},
		{method: "DELETE", pattern: "/containers/*", path: "/containers/abc/"},
		{method: "GET", pattern: "", path: ""},
		{method: "", pattern: "/containers/json", path: "/containers/json"},
		{method: "GET,POST", pattern: "/images/**", path: "/images/json"},
		{method: "POST", pattern: "/session", path: "/session"},
		{method: "POST", pattern: "/grpc", path: "/grpc"},

		// The matcher-kind table from TestPathMatcherKindsAgreeWithRegexFallback,
		// one row per kind the dispatcher can pick.
		{method: "GET", pattern: "/containers/json", path: "/containers/json"},
		{method: "GET", pattern: "/containers/json/**", path: "/containers/json"},
		{method: "GET", pattern: "/containers/*/json", path: "/containers/abc/json"},
		{method: "GET", pattern: "/*/json", path: "/a/json"},
		{method: "GET", pattern: "/containers/a*c", path: "/containers/abc"},
		{method: "GET", pattern: "/*/*/*", path: "/a/b/"},
		{method: "GET", pattern: "/containers/**/exec", path: "/containers/a\nb/exec"},
		{method: "GET", pattern: "/**/json", path: "/json"},
		{method: "GET", pattern: "/containers/**/*/logs", path: "/containers/abc/def/logs"},
		{method: "GET", pattern: "/a/**/b/**/c", path: "/a/x/b/y/c"},
		{method: "GET", pattern: "/containers/a**c", path: "/containers/abc"},

		// The stacked-"/**" literal prefix, whose regex matches the bare head.
		{method: "*", pattern: "/containers/secret/**/**", path: "/containers/secret"},
		{method: "*", pattern: "/containers/secret/**/**", path: "/containers/secretjson"},

		// Rootless patterns. Config validation refuses this shape, but a
		// container-label grant reaches CompileRule without it.
		{method: "*", pattern: "*", path: "/_ping"},
		{method: "*", pattern: "containers/*", path: "/containers/json"},
		{method: "*", pattern: "containers/**", path: "/containers/json"},
		{method: "*", pattern: "*/json", path: "/json"},
		{method: "*", pattern: "*libpod/images/scp/team/*", path: "/libpod/images/scp/team/alpine"},

		// Patterns whose text does not survive UTF-8 decoding unchanged, in
		// both spellings, against paths carrying the other one.
		{method: "*", pattern: "/containers/sec\uFFFDret/*", path: "/containers/sec\xffret/json"},
		{method: "*", pattern: "/containers/sec\xffret/*", path: "/containers/sec\uFFFDret/json"},
		{method: "*", pattern: "/con\xfe\xfftainers/**", path: "/con\uFFFD\uFFFDtainers/json"},
		{method: "*", pattern: "/con\xfftainers/**/json", path: "/con\xfetainers/a/json"},

		// Unrooted request targets, kept raw on purpose.
		{method: "GET", pattern: "/**", path: ""},
		{method: "CONNECT", pattern: "/**", path: ""},
		{method: "GET", pattern: "/**", path: "containers/json"},
		{method: "GET", pattern: "/**", path: "**"},

		// The libpod image-SCP route view, where a trailing slash is a real
		// empty final segment rather than punctuation.
		{method: "POST", pattern: "/libpod/images/scp/*", path: "/libpod/images/scp/alpine/"},
		{method: "POST", pattern: "/libpod/images/scp/*/*", path: "/libpod/images/scp/tenant/"},
		{method: "POST", pattern: "/libpod/images/scp/**", path: "/libpod/images/scp/victim/push"},

		// Shapes config validation rejects that CompileRule still compiles.
		{method: "GET", pattern: "/v1.45/containers/json", path: "/containers/json"},
		{method: "GET", pattern: "/containers/%2Fjson", path: "/containers/%2Fjson"},
		{method: "GET", pattern: "/containers/%252e%252e/json", path: "/containers/%252e%252e/json"},

		// The committed seed corpora of the two sibling targets over the same
		// dialect, lifted so a crasher found there is also a pattern here.
		{method: "GET", pattern: "/**/abc/**.tar.gz", path: "/abc.tar.gz"},
		{method: "GET", pattern: "****", path: "/a"},
		{method: "GET", pattern: "/path/with.(special|chars)/and+escapes\\", path: "/path/with.(special|chars)/and+escapes\\"},
		{method: "GET", pattern: "/éclair/\u202etrojan/\x00null", path: "/éclair/\u202etrojan/\x00null"},
		{method: "GET", pattern: "/V0/0", path: "/V0/0"},
		{method: "GET", pattern: "/v9999/containers/json", path: "/containers/json"},
		{method: "GET", pattern: "/containers/%2e%2e/json", path: "/containers/%2e%2e/json"},
		{method: "GET", pattern: "/containers/%252e/json", path: "/containers/%252e/json"},
	}

	for _, pattern := range literalPrefixPatterns() {
		seeds = append(seeds, compileRuleSeed{method: "GET", pattern: pattern})
	}
	return seeds
}

// FuzzCompileRule fuzzes rule compilation and holds every fast-path matcher to
// the anchored regex its own pattern compiles to.
//
// Compilation itself must not panic and a compiled rule must not panic on
// matching, which is what this target originally asserted. The differential is
// the rest: for each pattern, the four allocation-free matchers
// (pathMatcherLiteral, the "/**" match-all fast path, matchTrailingDoubleStar
// and the matchGlobSegments walker), the literal-prefix gate in front of the
// two kinds that carry one, and the compiled regex itself all have to answer
// exactly what "^" + glob.ToRegexString(pattern) + "$" answers, on every path
// view production hands them.
//
// The three divergences fixed before this target existed were each found by
// review rather than by fuzzing, which is what it is for. Patterns come from a
// token alphabet rather than raw bytes so the search is not stuck in a
// literal-only space, and paths are derived from the pattern as well as from
// the seed so the pairs are near misses rather than unrelated strings.
//
// The two committed seeds under testdata/fuzz/FuzzCompileRule name the fourth,
// which this target's first run found: matchGlobSegment used to test literal
// byte equality before it tested for '*', so a path segment carrying a
// literal '*' consumed the pattern's own '*' as a literal and never recorded
// the star anchor to backtrack to. "/containers/web-*/stop" did not match
// "/containers/web-*1/stop", which "^/containers/web-[^/]*/stop$" does, and on
// a deny rule that handed the request to whatever allow sat below it. Fixed
// in the same change (the star branch now runs first) and pinned by the
// segment-star-matched-as-literal table case; the seeds stay so the target
// keeps proving it.
func FuzzCompileRule(f *testing.F) {
	for _, seed := range compileRuleFuzzSeeds() {
		f.Add(seed.method, seed.pattern, seed.path)
	}

	f.Fuzz(func(t *testing.T, method, patternSeed, pathSeed string) {
		for _, pattern := range compileRuleFuzzPatterns(patternSeed) {
			rule, err := CompileRule(Rule{
				Methods: []string{method},
				Pattern: pattern,
				Action:  ActionAllow,
				Index:   0,
			})
			if err != nil {
				// Compilation failure is acceptable — just ensure no panic.
				continue
			}

			// If compilation succeeded, matching must never panic.
			rule.matches("GET", "/containers/json")
			rule.matches("POST", "/v1.45/containers/create")
			rule.matches(method, "/"+pattern)
			rule.matches("", "")

			assertCompiledRuleAgreesWithItsRegex(t, pattern, compileRuleFuzzPathViews(pattern, pathSeed))
		}
	})
}

// TestCompileRuleFuzzCorpusReachesEveryMatcherKind keeps FuzzCompileRule's
// differential from going quiet. Agreement is only worth asserting over a
// domain the corpus reaches, and the failure mode of a generated corpus is
// silent: a token dropped from the alphabet or a seed row deleted narrows what
// the target covers without failing anything.
//
// It pins the three mechanisms the fixed divergences lived in, not just the
// five matcher kinds: the "/**" carve-out in literalPrefixForPattern (a first
// star whose slash does not survive into the prefix), the demotion of a
// pattern carrying a rune regexp reads as U+FFFD to the regex matcher, and a
// non-vacuous count of pattern/path pairs the regex actually matches.
func TestCompileRuleFuzzCorpusReachesEveryMatcherKind(t *testing.T) {
	t.Parallel()

	kinds := make(map[pathMatcherKind]int, 5)
	carveOuts, demotions, matches := 0, 0, 0

	record := func(pattern string) {
		compiled, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: pattern, Action: ActionAllow})
		if err != nil {
			return
		}
		kinds[compiled.matcherKind]++

		star := strings.IndexByte(pattern, '*')
		if star > 0 && pattern[star-1] == '/' && compiled.literalPrefix != pattern[:star] {
			carveOuts++
		}
		if firstReplacementRuneIndex(pattern) >= 0 && strings.Contains(pattern, "*") &&
			compiled.matcherKind == pathMatcherRegex && !strings.Contains(pattern, "**") {
			demotions++
		}
	}

	for _, seed := range compileRuleFuzzSeeds() {
		for _, pattern := range compileRuleFuzzPatterns(seed.pattern) {
			record(pattern)

			reference, err := regexp.Compile("^" + GlobToRegexString(pattern) + "$")
			if err != nil {
				t.Fatalf("compile reference regex for %q: %v", pattern, err)
			}
			for _, view := range compileRuleFuzzPathViews(pattern, seed.path) {
				if reference.MatchString(view) {
					matches++
				}
			}
		}
	}

	// The alphabet has to reach the dialect on its own, not only through the
	// named seeds, because that is the space the mutator searches.
	for _, head := range compileRulePatternTokens {
		for _, tail := range compileRulePatternTokens {
			record(head + tail)
		}
	}

	for _, kind := range []pathMatcherKind{
		pathMatcherLiteral, pathMatcherMatchAll, pathMatcherTrailingDeep,
		pathMatcherSegmentGlob, pathMatcherRegex,
	} {
		if kinds[kind] == 0 {
			t.Errorf("no seed or alphabet pattern compiles to matcher kind %d; the differential is blind to it", kind)
		}
	}
	if carveOuts == 0 {
		t.Error("no pattern exercises the \"/**\" carve-out in literalPrefixForPattern")
	}
	if demotions == 0 {
		t.Error("no pattern is demoted to the regex matcher by a rune regexp reads as U+FFFD")
	}
	if matches < 500 {
		t.Errorf("seed corpus produced %d pattern/path matches, want at least 500; agreement on all-false is vacuous", matches)
	}
}

// containsStar returns true if s contains a '*' character.
func containsStar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '*' {
			return true
		}
	}
	return false
}

// containsNewline returns true if s contains a newline character.
func containsNewline(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return true
		}
	}
	return false
}

// isASCII returns true if every byte in s is in the ASCII range.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
