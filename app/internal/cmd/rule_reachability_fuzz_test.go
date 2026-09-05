package cmd

import (
	"net/http"
	"net/url"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// maxCatalogFuzzRules bounds the generated rule list. The reachability search
// walks a DFA product over the catalog, its exclusions, and every applicable
// rule up to the target allow, so the state space grows with the rule count
// and a wider list buys pathological runtimes rather than coverage.
const maxCatalogFuzzRules = 6

// maxCatalogFuzzIdentifier and maxCatalogFuzzPattern bound the two inputs that
// set the depth of that walk. Length is not what makes a route or a pattern
// interesting here, and letting either run to a few hundred bytes costs whole
// seconds per execution: a kilobyte-long identifier reused as a literal rule
// pattern measured 7.5s for one firstAllowedCatalogPath call. Real container
// IDs and registry references sit well inside these caps.
const (
	maxCatalogFuzzIdentifier = 48
	maxCatalogFuzzPattern    = 64
)

// catalogFuzzTrailingSlashBit is the selector bit that asks for the libpod
// image-SCP dual-view request shape (see catalogFuzzRequestRoute). It carries
// no catalog-row information, so catalogFuzzEntryIndex masks it out before
// picking a row.
const catalogFuzzTrailingSlashBit uint16 = 0x8000

// catalogFuzzPlaceholder is the identifier stand-in every catalog template
// spells. compileCatalogMachine splits templates on it and drops the
// identifier language into each gap.
const catalogFuzzPlaceholder = "sockguard-test"

// catalogFuzzTruncate cuts a string to at most limit bytes without splitting a
// rune, so a truncated input stays valid UTF-8.
func catalogFuzzTruncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

// catalogFuzzMethods are the rule methods FuzzCatalogReachability draws from.
// They are all ASCII on purpose. configuredRuleMatchesMethod compares with
// strings.EqualFold while filter.CompileRule ASCII-uppercases and then looks
// the method up, and the two only disagree on non-ASCII spellings whose
// Unicode simple fold reaches an ASCII letter. Mixing those in would make the
// target report a divergence that is about method spelling, not about the
// route-language search this fuzzer exists to check.
var catalogFuzzMethods = []string{"GET", "POST", "PUT", "DELETE", "*", "GET,POST", "get", "post"}

// catalogFuzzEntry is one row of the sensitive-endpoint catalogs, flattened so
// the write and read catalogs can be fuzzed through one selector. Reading the
// production tables rather than a hand-copied list means a catalog entry added
// later is fuzzed the day it lands.
type catalogFuzzEntry struct {
	method          string
	path            string
	identifierShape catalogIdentifierShape
	exclusions      []catalogPathExclusion
}

func catalogFuzzEntries() []catalogFuzzEntry {
	entries := make([]catalogFuzzEntry, 0, len(bodySensitiveWriteEndpoints)+len(sensitiveExfilEndpoints))
	for _, endpoint := range bodySensitiveWriteEndpoints {
		entries = append(entries, catalogFuzzEntry(endpoint))
	}
	for _, endpoint := range sensitiveExfilEndpoints {
		entries = append(entries, catalogFuzzEntry(endpoint))
	}
	return entries
}

// catalogFuzzEntryIndex picks the catalog row a selector names. The dual-view
// bit has to come off first: it asks for a request shape, not for a different
// row, and a plain `int(selector) % len(entries)` reads 0x8000 as row
// arithmetic and slides every seed that sets it eight rows down the flattened
// catalog. The fuzz body and TestCatalogFuzzSeedSelectorsLandOnTheirRow both go
// through this function so the seeds are checked against the expression that
// actually runs.
func catalogFuzzEntryIndex(selector uint16, entries []catalogFuzzEntry) int {
	return int(selector&^catalogFuzzTrailingSlashBit) % len(entries)
}

// catalogFuzzSegment turns fuzzer bytes into one member of the resource
// identifier segment language compileCatalogMachine builds: non-empty, free of
// "/", and neither "." nor "..". Appending "a" to the three rejected spellings
// keeps dot-leading identifiers ("..a", ".a") in the corpus instead of
// collapsing them to a plain word.
func catalogFuzzSegment(seed string) string {
	segment := strings.ReplaceAll(seed, "/", "")
	switch segment {
	case "", ".", "..":
		segment += "a"
	}
	return segment
}

// catalogFuzzIdentifier builds an identifier for the given shape. A segment
// shape gets one clean segment; both path shapes get a "/"-joined run of them,
// which is what Docker's {name:.*} and Podman's registry-qualified route
// variables accept. catalogIdentifierRoutePath is built the same way as
// catalogIdentifierPath on purpose. The empty final segment that shape also
// admits belongs to the request spelling rather than to the identifier, so
// catalogFuzzRequestRoute appends it and the route this returns stays the
// in-catalog decoded path policy matches, unchanged by NormalizePath. The width
// cap keeps the DFA product cheap.
func catalogFuzzIdentifier(seed string, shape catalogIdentifierShape) string {
	if shape == catalogIdentifierSegment {
		return catalogFuzzSegment(seed)
	}

	segments := strings.Split(seed, "/")
	if len(segments) > 4 {
		segments = segments[:4]
	}
	for i := range segments {
		segments[i] = catalogFuzzSegment(segments[i])
	}
	return strings.Join(segments, "/")
}

// catalogFuzzRoute substitutes an identifier into every "sockguard-test"
// placeholder of a catalog template. Membership in the catalog's route
// language is established by this construction, not by inspecting the result:
// a suffix or prefix check on an arbitrary fuzzer string would not prove the
// probe is a route the catalog entry actually stands for.
func catalogFuzzRoute(template string, shape catalogIdentifierShape, seeds []string) string {
	parts := strings.Split(template, catalogFuzzPlaceholder)
	var route strings.Builder
	for i, part := range parts {
		if i > 0 {
			route.WriteString(catalogFuzzIdentifier(seeds[(i-1)%len(seeds)], shape))
		}
		route.WriteString(part)
	}
	return route.String()
}

// catalogFuzzRequestRoute turns an in-catalog route into the raw request line a
// client would send. The two are the same string everywhere except one shape:
// on POST /libpod/images/scp/..., appending a trailing slash produces a request
// whose two evaluated views differ. path.Clean strips the slash, so the decoded
// policy view stays the in-catalog route, while NormalizePodmanRoutePath keeps
// it because gorilla/mux routes on it (filter/rules.go's evaluateRequestPolicy
// and NormalizePodmanRoutePath). That trailing empty segment is what separates
// Podman's image-SCP catch-all from the push/tag/untag routes registered
// earlier, so it is the one place the generator has to be able to spell a
// request whose decoded view and route view are two different in-catalog
// strings. Both are in the catalog language, because both SCP rows are spelled
// with catalogIdentifierRoutePath, but only one of them is what the exclusions
// remove: .../{name}/push is the image-push route, .../{name}/push/ is not.
//
// Every other catalog row ignores the bit: a trailing slash there is cleaned
// away before any matcher sees it, so the request would be a duplicate of the
// route and would only cost fuzz throughput.
func catalogFuzzRequestRoute(method, route string, trailingSlash bool) string {
	if !trailingSlash {
		return route
	}
	if candidate := route + "/"; catalogFuzzEncodedRouteView(method, candidate) {
		return candidate
	}
	return route
}

// catalogFuzzCleanSegment reports whether one "/"-separated segment belongs to
// compileCatalogMachine's segment language, spelled from the documented rule
// rather than from that regex: a segment is any non-empty string that is
// neither "." nor "..". ("/" cannot occur, the caller having split on it.)
func catalogFuzzCleanSegment(segment string) bool {
	return segment != "" && segment != "." && segment != ".."
}

// catalogFuzzTemplateMatches is the independent membership oracle for catalog
// and exclusion templates. It walks "/"-separated segments and touches none of
// compileCatalogMachine, compileReachabilityProgram, or the reachability state
// helpers, so a production catalog language that is wrong cannot suppress its
// own counterexamples. The case that motivates it: an exclusion matcher loose
// enough to read "/team/pusher" as "/{id}/push" would make the validator
// discard an exposed route, and an oracle driving the same compiler would
// discard it too, leaving the bypass invisible.
//
// A literal segment must match byte for byte. A placeholder segment consumes
// exactly one clean segment for catalogIdentifierSegment, or a non-empty run of
// them for catalogIdentifierPath, which is upstream's {name:.*} shape. Two
// placeholders in one template leave the run width ambiguous, so the walk
// backtracks. Placeholders are whole segments in every catalog row; a future
// row that embeds one inside a segment fails loudly here rather than being
// silently mismatched.
//
// catalogIdentifierRoutePath is that run as gorilla/mux resolves it, and the
// two libpod image-SCP rows are spelled with it: the last segment the
// placeholder consumes may be empty instead of clean, which covers both the
// trailing slash a route view keeps ("victim", "") and the identifier being
// absent altogether, where the bare /libpod/images/scp/ leaves one empty
// segment ("") behind the separator.
func catalogFuzzTemplateMatches(t *testing.T, template string, shape catalogIdentifierShape, candidate string) bool {
	t.Helper()
	templateSegments := strings.Split(template, "/")
	for _, segment := range templateSegments {
		if segment != catalogFuzzPlaceholder && strings.Contains(segment, catalogFuzzPlaceholder) {
			t.Fatalf("catalog template %q embeds %q inside segment %q, which the structural oracle does not model",
				template, catalogFuzzPlaceholder, segment)
		}
	}
	return catalogFuzzMatchSegments(templateSegments, strings.Split(candidate, "/"), shape)
}

func catalogFuzzMatchSegments(template, candidate []string, shape catalogIdentifierShape) bool {
	if len(template) == 0 {
		return len(candidate) == 0
	}
	if template[0] != catalogFuzzPlaceholder {
		if len(candidate) == 0 || candidate[0] != template[0] {
			return false
		}
		return catalogFuzzMatchSegments(template[1:], candidate[1:], shape)
	}
	for width := 1; width <= len(candidate); width++ {
		clean := catalogFuzzCleanSegment(candidate[width-1])
		// The empty segment is only ever the route view's last one: `.*`
		// swallows the trailing slash, and it matches the empty string, but
		// neither reading lets a second empty segment through — a doubled
		// slash is not a shape any normalized route view has.
		emptyFinal := !clean && shape == catalogIdentifierRoutePath && candidate[width-1] == ""
		if !clean && !emptyFinal {
			return false
		}
		if catalogFuzzMatchSegments(template[1:], candidate[width:], shape) {
			return true
		}
		if !clean || shape == catalogIdentifierSegment {
			return false
		}
	}
	return false
}

// catalogFuzzAccepts reports whether a compiled catalog machine accepts a
// string. It drives the production NFA helpers, so it is the thing under test
// here, never the oracle: every call sits behind a differential comparison
// against catalogFuzzTemplateMatches.
func catalogFuzzAccepts(program *syntax.Prog, candidate string) bool {
	state := reachabilityStart(program)
	for _, r := range candidate {
		state = reachabilityAdvance(program, state, r)
		if reachabilityEmpty(state) {
			return false
		}
	}
	return reachabilityAccepts(program, state)
}

// catalogFuzzOracle holds one execution's compiled catalog and exclusion
// machines so the differential membership checks do not recompile them per
// probe.
type catalogFuzzOracle struct {
	entry      catalogFuzzEntry
	catalog    *syntax.Prog
	exclusions []*syntax.Prog
}

func newCatalogFuzzOracle(t *testing.T, entry catalogFuzzEntry) catalogFuzzOracle {
	t.Helper()
	catalog, err := compileCatalogMachine(entry.path, entry.identifierShape)
	if err != nil {
		t.Fatalf("compileCatalogMachine(%q) error = %v, want nil for a catalog entry", entry.path, err)
	}
	oracle := catalogFuzzOracle{entry: entry, catalog: catalog.program}
	for _, exclusion := range entry.exclusions {
		machine, err := compileCatalogMachine(exclusion.path, exclusion.identifierShape)
		if err != nil {
			t.Fatalf("compileCatalogMachine(%q) error = %v, want nil for a catalog exclusion", exclusion.path, err)
		}
		oracle.exclusions = append(oracle.exclusions, machine.program)
	}
	return oracle
}

// catalogFuzzMembership compares the compiled machine's verdict with the
// independent structural oracle's and fails on disagreement, then returns the
// verdict they agree on. Running both is what makes invariant (1) meaningful:
// the compiler under test never gets to answer a membership question on its
// own.
func catalogFuzzMembership(t *testing.T, template string, shape catalogIdentifierShape, program *syntax.Prog, candidate string) bool {
	t.Helper()
	compiled := catalogFuzzAccepts(program, candidate)
	structural := catalogFuzzTemplateMatches(t, template, shape, candidate)
	if compiled != structural {
		t.Fatalf("catalog language for template %q (shape %d): compiled machine accepts %q = %t, structural oracle = %t",
			template, shape, candidate, compiled, structural)
	}
	return compiled
}

func (o catalogFuzzOracle) inCatalog(t *testing.T, candidate string) bool {
	t.Helper()
	return catalogFuzzMembership(t, o.entry.path, o.entry.identifierShape, o.catalog, candidate)
}

// excluded reports whether a route falls into one of the catalog entry's
// exclusions, which takes it outside the language the reachability verdict
// describes. Each exclusion carries its own identifier shape, and the libpod
// image-SCP ones keep the decoded spelling even though the catalog entry above
// them is a route path: .../{name}/push is Podman's image-push route and really
// is excluded, while .../{name}/push/ misses that anchored route and falls
// through to the SCP catch-all, so it is not.
func (o catalogFuzzOracle) excluded(t *testing.T, candidate string) bool {
	t.Helper()
	for i, exclusion := range o.entry.exclusions {
		if catalogFuzzMembership(t, exclusion.path, exclusion.identifierShape, o.exclusions[i], candidate) {
			return true
		}
	}
	return false
}

// catalogFuzzPattern builds a rule pattern. Most modes are derived from the
// catalog template so the generated policies actually reach the route under
// test; a purely random pattern almost never allows a specific path, and a
// fuzzer that never produces an allow proves nothing about the unreachable
// verdict. The last mode spells the raw request line, which is the only way to
// write a rule that covers the libpod image-SCP trailing-slash route view.
func catalogFuzzPattern(mode byte, payload, template, route, requestRoute string) string {
	switch mode % 9 {
	case 0:
		return catalogFuzzTruncate(catalogFuzzRootedPattern(payload), maxCatalogFuzzPattern)
	case 1:
		return strings.ReplaceAll(template, catalogFuzzPlaceholder, "*")
	case 2:
		return strings.ReplaceAll(template, catalogFuzzPlaceholder, "**")
	case 3:
		return strings.ReplaceAll(template, catalogFuzzPlaceholder, "*/*")
	case 4:
		return "/**"
	case 5:
		return route
	case 6:
		return catalogFuzzPrefixGlob(template)
	case 7:
		return strings.TrimSuffix(template, "/"+lastCatalogSegment(template)) + "/**"
	default:
		return requestRoute
	}
}

// catalogFuzzRootedPattern roots the one pattern mode that spells fuzzer bytes
// straight into a match.path. Every other mode is derived from a catalog
// template and is rooted already. config.ValidateStructural refuses a rootless
// match.path outright, because the segment walker no longer trims a leading
// slash off either side and such a pattern can only ever be dead, and the fuzz
// body drops any execution whose config does not validate. An unrooted payload
// would therefore throw the whole input away and take every other rule in it
// along, which is how a corpus goes vacuous without anything saying so.
func catalogFuzzRootedPattern(pattern string) string {
	if pattern == "" || strings.HasPrefix(pattern, "/") {
		return pattern
	}
	return "/" + pattern
}

func catalogFuzzPrefixGlob(template string) string {
	segments := strings.Split(strings.TrimPrefix(template, "/"), "/")
	if len(segments) > 2 {
		segments = segments[:2]
	}
	return "/" + strings.Join(segments, "/") + "/**"
}

func lastCatalogSegment(template string) string {
	if index := strings.LastIndex(template, "/"); index >= 0 {
		return template[index+1:]
	}
	return template
}

// catalogFuzzRules decodes the rule blob. Each non-empty line carries a method
// selector, an action selector, a pattern mode, and a payload.
func catalogFuzzRules(spec string, entry catalogFuzzEntry, route, requestRoute string) []config.RuleConfig {
	rules := make([]config.RuleConfig, 0, maxCatalogFuzzRules)
	for _, line := range strings.Split(spec, "\n") {
		if len(rules) == maxCatalogFuzzRules || len(line) < 3 {
			continue
		}
		pattern := catalogFuzzPattern(line[2], line[3:], entry.path, route, requestRoute)
		if pattern == "" {
			continue
		}
		action := "deny"
		if line[1]%2 == 0 {
			action = "allow"
		}
		rules = append(rules, config.RuleConfig{
			Match: config.MatchConfig{
				Method: catalogFuzzMethods[int(line[0])%len(catalogFuzzMethods)],
				Path:   pattern,
			},
			Action: action,
		})
	}
	return rules
}

// catalogFuzzEncodedRouteView reports whether filter.evaluateRequestPolicy
// takes its dual-view branch for a path: a POST whose gorilla/mux route view
// differs from its decoded one and lands on Podman's image-SCP catch-all. There
// both views have to allow, while firstAllowedCatalogPath searches one language
// and says so in its own doc comment.
//
// It gates two things: which requests catalogFuzzRequestRoute may spell with a
// trailing empty segment, and the witness re-check below. An exemption that is
// wider than the branch it stands for hides real divergences, so this mirrors
// filter.normalizedLibpodImageScpRoutePath and filter.isLibpodImageScpRoutePath
// exactly, including the action suffixes Podman registers ahead of the
// catch-all. It is the one place in this file that copies production logic
// instead of deriving its own, and it decides no membership question.
func catalogFuzzEncodedRouteView(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	routeView := filter.NormalizePodmanRoutePath((&url.URL{Path: path}).EscapedPath())
	if routeView == filter.NormalizePath(path) {
		return false
	}
	rest, ok := strings.CutPrefix(routeView, "/libpod/images/scp/")
	if !ok {
		return false
	}
	for _, action := range []string{"push", "tag", "untag"} {
		if rest == action || strings.HasSuffix(rest, "/"+action) {
			return false
		}
	}
	return true
}

// catalogFuzzWitnessCandidates are the in-catalog routes an allowed request can
// stand for. Its decoded view always qualifies, because every request is
// decided on that view. On the libpod image-SCP dual view the request spelling
// itself qualifies as well: the route view is in the catalog language in its
// own right (catalogIdentifierRoutePath), and evaluateRequestPolicy allowed the
// request only by allowing that spelling too.
func catalogFuzzWitnessCandidates(route, requestRoute string) []string {
	if requestRoute == route {
		return []string{route}
	}
	return []string{route, requestRoute}
}

func catalogFuzzRowSelector(tb testing.TB, entries []catalogFuzzEntry, method, path string) uint16 {
	tb.Helper()
	for i, entry := range entries {
		if entry.method == method && entry.path == path {
			return uint16(i)
		}
	}
	tb.Fatalf("seed catalog entry %s %s is no longer in the catalog", method, path)
	return 0
}

// catalogFuzzSeedSelector packs a seed's catalog row and request shape into the
// selector the fuzz body decodes.
func catalogFuzzSeedSelector(tb testing.TB, entries []catalogFuzzEntry, seed catalogFuzzSeed) uint16 {
	tb.Helper()
	selector := catalogFuzzRowSelector(tb, entries, seed.method, seed.path)
	if seed.trailingSlash {
		selector |= catalogFuzzTrailingSlashBit
	}
	return selector
}

// catalogFuzzRuleLine spells one line of the rule blob for a seed.
func catalogFuzzRuleLine(method, action, mode byte, payload string) string {
	return string([]byte{method, action, mode}) + payload
}

// catalogFuzzSeed is one entry of the seed corpus. It sits at package scope so
// TestCatalogFuzzSeedSelectorsLandOnTheirRow can put every seed through the
// same selector arithmetic the fuzz body uses, and
// TestCatalogFuzzSeedsBuildLoadablePolicies through the same generator.
type catalogFuzzSeed struct {
	method        string
	path          string
	identifier    string
	rules         string
	trailingSlash bool
}

// catalogFuzzSeeds is one seed per catalog shape: no placeholder, a single
// segment-shaped identifier, a single slash-bearing identifier, two identifiers
// in one template, an exclusion-bearing template, and a body-write catalog
// entry. The rule blobs cover the policy shapes the existing table tests
// exercise: an open allow, a shadowed allow, and the deny-broad-then-allow-
// narrow pattern that leaves another identifier reachable. The last three seeds
// take the trailing-slash request shape into the libpod image-SCP dual view,
// including the two-allow policy that covers both views at once.
func catalogFuzzSeeds() []catalogFuzzSeed {
	allowAnything := catalogFuzzRuleLine(4, 0, 4, "")
	denyCatalogGlob := catalogFuzzRuleLine(0, 1, 1, "")
	allowCatalogGlob := catalogFuzzRuleLine(0, 0, 1, "")
	denyPrefixGlob := catalogFuzzRuleLine(0, 1, 6, "")
	allowSlashBearingGlob := catalogFuzzRuleLine(0, 0, 3, "")
	denyEverything := catalogFuzzRuleLine(4, 1, 4, "")
	allowExactRoute := catalogFuzzRuleLine(0, 0, 5, "")
	allowExactRequest := catalogFuzzRuleLine(0, 0, 8, "")

	return []catalogFuzzSeed{
		{method: http.MethodGet, path: "/images/get", identifier: "", rules: allowAnything},
		{method: http.MethodPost, path: "/swarm/init", identifier: "", rules: denyCatalogGlob + "\n" + allowAnything},
		{method: http.MethodGet, path: "/containers/sockguard-test/logs", identifier: "web", rules: denyCatalogGlob + "\n" + allowCatalogGlob},
		{method: http.MethodGet, path: "/containers/sockguard-test/logs", identifier: "..a", rules: denyPrefixGlob + "\n" + allowCatalogGlob},
		{method: http.MethodGet, path: "/containers/sockguard-test/top", identifier: "registry.example.com/team/app", rules: denyCatalogGlob + "\n" + allowSlashBearingGlob},
		{method: http.MethodPost, path: "/images/sockguard-test/push", identifier: "ghcr.io/codeswhat/sockguard", rules: denyCatalogGlob + "\n" + allowSlashBearingGlob},
		{method: http.MethodPost, path: "/libpod/manifests/sockguard-test/registry/sockguard-test", identifier: "app\x00registry.example.com/dest", rules: allowCatalogGlob + "\n" + denyEverything},
		{method: http.MethodPost, path: "/libpod/manifests/sockguard-test/push", identifier: "app", rules: denyCatalogGlob + "\n" + allowSlashBearingGlob},
		{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test", identifier: "victim", rules: denyPrefixGlob + "\n" + allowSlashBearingGlob},
		{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test", identifier: "victim/push", rules: allowCatalogGlob + "\n" + denyEverything},
		{method: http.MethodPost, path: "/containers/sockguard-test/exec", identifier: "abc123", rules: denyCatalogGlob + "\n" + allowCatalogGlob + "\n" + denyEverything},
		{method: http.MethodGet, path: "/libpod/containers/sockguard-test/export", identifier: "abc123", rules: catalogFuzzRuleLine(0, 0, 0, "/libpod/containers/*/export")},
		{method: http.MethodGet, path: "/containers/sockguard-test/archive", identifier: "abc123", rules: catalogFuzzRuleLine(0, 0, 5, "") + "\n" + denyEverything},
		{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test", identifier: "victim", rules: allowCatalogGlob + "\n" + denyEverything, trailingSlash: true},
		{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test", identifier: "victim", rules: allowExactRoute + "\n" + allowExactRequest + "\n" + denyEverything, trailingSlash: true},
		{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test", identifier: "victim/push", rules: allowExactRoute + "\n" + allowExactRequest + "\n" + denyEverything, trailingSlash: true},
	}
}

// FuzzCatalogReachability is the differential fuzzer for the read-exfiltration
// validator's bounded route-reachability search (firstAllowedCatalogPath in
// rule_reachability.go), raised by CodeRabbit on #383.
//
// allowedCatalogPaths reads catalogUnreachable as "no route in this catalog
// entry is exposed" and reports nothing, so an unsound unreachable verdict
// lets an allow rule slip past the insecure_allow_read_exfiltration
// acknowledgment without an operator ever seeing the endpoint listed. The
// invariants below are ordered by what a violation would cost:
//
//  1. Soundness of catalogUnreachable. A route built by substituting a valid
//     identifier into the catalog template, outside every exclusion, whose
//     request filter.Evaluate allows, forbids a catalogUnreachable verdict.
//     This is the security property; a counterexample is a live bypass.
//  2. Witness validity. A catalogReachable verdict must name a route that is
//     in the catalog language, outside every exclusion, stable under the route
//     view's normalization, and allowed by the production evaluator. A witness
//     the evaluator denies means the automata mirroring of filter's glob
//     dialect has drifted. One shape is exempt: a witness on the libpod
//     image-SCP dual view, which firstAllowedCatalogPath documents itself as
//     not modeling. There the target asserts allowedCatalogPaths' fallback to
//     the catalog spelling instead, so the over-report that exemption allows
//     can never turn into an under-report.
//  3. Catalog-language fidelity and determinism. Every membership question is
//     answered twice, once by the production catalog compiler and once by
//     catalogFuzzTemplateMatches, an independent segment walker, and the two
//     must agree. By-construction routes must survive NormalizePath unchanged
//     (allowedCatalogPaths hands a witness straight to the evaluator), and
//     repeated calls must agree, since a validator that flips verdict between
//     boots turns a startup refusal into a coin toss.
//
// Rules are put through config.ValidateStructural before use so a reported
// counterexample is a policy an operator could actually load.
func FuzzCatalogReachability(f *testing.F) {
	entries := catalogFuzzEntries()
	for _, seed := range catalogFuzzSeeds() {
		f.Add(catalogFuzzSeedSelector(f, entries, seed), seed.identifier, seed.rules)
	}

	f.Fuzz(func(t *testing.T, selector uint16, identifierSeed, ruleSpec string) {
		// Policy comes from YAML and request paths arrive already decoded, so
		// both sides are UTF-8 in production. Invalid UTF-8 would only make the
		// automata (which decode runes, mapping a bad byte to U+FFFD) disagree
		// with filter's byte-exact literal matcher on inputs that cannot occur.
		if !utf8.ValidString(identifierSeed) || !utf8.ValidString(ruleSpec) {
			return
		}

		entry := entries[catalogFuzzEntryIndex(selector, entries)]
		identifierSeeds := strings.Split(catalogFuzzTruncate(identifierSeed, maxCatalogFuzzIdentifier), "\x00")
		route := catalogFuzzRoute(entry.path, entry.identifierShape, identifierSeeds)
		requestRoute := catalogFuzzRequestRoute(entry.method, route, selector&catalogFuzzTrailingSlashBit != 0)

		rules := catalogFuzzRules(ruleSpec, entry, route, requestRoute)
		if len(rules) == 0 {
			return
		}
		for _, rule := range rules {
			// A rootless match.path is a config validation error, and the
			// refusal below throws the whole execution away with every other
			// rule in it. Nothing here may spell one; see
			// catalogFuzzRootedPattern.
			if !strings.HasPrefix(rule.Match.Path, "/") {
				t.Fatalf("generated rule pattern %q is rootless, which config.ValidateStructural refuses, so this execution would exercise nothing", rule.Match.Path)
			}
		}
		cfg := config.Defaults()
		cfg.Rules = rules
		if err := config.ValidateStructural(&cfg); err != nil {
			return
		}
		compiled, err := compileConfiguredRules(cfg.Rules)
		if err != nil {
			return
		}

		oracle := newCatalogFuzzOracle(t, entry)
		if !oracle.inCatalog(t, route) {
			t.Fatalf("catalog language for %q rejects in-shape route %q", entry.path, route)
		}
		if normalized := filter.NormalizePath(route); normalized != route {
			t.Fatalf("in-shape route %q normalizes to %q, so the catalog language admits routes the evaluator never sees", route, normalized)
		}
		// The raw request may differ from its in-catalog decoded view only by
		// the documented libpod image-SCP trailing empty segment. Anything
		// else would mean the generator had drifted off the catalog language
		// without saying so. Asserting the text is route+"/" is not enough on
		// its own: what the pairing relies on is that the two normalizations
		// filter.evaluateRequestPolicy applies really do split that request
		// the way the dual view needs. path.Clean has to take it back to the
		// in-catalog route, and NormalizePodmanRoutePath has to keep the empty
		// final segment gorilla/mux routes on while changing nothing else, so
		// the slash is the single difference between the two views. The route
		// view is compared against the route's own escaped spelling rather
		// than against the raw text, because url.URL escapes an identifier
		// byte like " " into "%20" on both sides of the pair and that is the
		// view Podman routes on.
		if requestRoute != route {
			if requestRoute != route+"/" {
				t.Fatalf("request %q is neither in-catalog route %q nor its trailing-slash route view", requestRoute, route)
			}
			if decoded := filter.NormalizePath(requestRoute); decoded != route {
				t.Fatalf("request %q has decoded view %q, want the in-catalog route %q", requestRoute, decoded, route)
			}
			view := filter.NormalizePodmanRoutePath((&url.URL{Path: requestRoute}).EscapedPath())
			want := filter.NormalizePodmanRoutePath((&url.URL{Path: route}).EscapedPath()) + "/"
			if view != want {
				t.Fatalf("request %q has route view %q, want %q: the pair only stands for the dual view if the empty final segment is the one thing that separates the two views",
					requestRoute, view, want)
			}
		}

		witness, result := firstAllowedCatalogPath(entry.method, entry.path, entry.identifierShape, entry.exclusions, cfg.Rules)
		repeatWitness, repeatResult := firstAllowedCatalogPath(entry.method, entry.path, entry.identifierShape, entry.exclusions, cfg.Rules)
		if witness != repeatWitness || result != repeatResult {
			t.Fatalf("firstAllowedCatalogPath(%s %q) = (%q, %v) then (%q, %v), want a deterministic verdict",
				entry.method, entry.path, witness, result, repeatWitness, repeatResult)
		}

		// A request the evaluator allows carries both of the views
		// evaluateRequestPolicy checks with it: the dual-view branch requires
		// the decoded path and the gorilla/mux route view to allow, and every
		// other request is decided on the decoded view alone. Either of those
		// views, if it is in the catalog language and outside every exclusion,
		// is a witness the search has to be able to produce, so an unreachable
		// verdict over it is unsound. The route view is the half that matters
		// on POST /libpod/images/scp/...: .../{name}/push/ misses Podman's
		// anchored push route and falls into the SCP catch-all, so it is in
		// the catalog while the decoded .../{name}/push its own exclusions
		// remove is not.
		if result == catalogUnreachable && policyAllowsPath(entry.method, requestRoute, compiled) {
			for _, candidate := range catalogFuzzWitnessCandidates(route, requestRoute) {
				if oracle.inCatalog(t, candidate) && !oracle.excluded(t, candidate) {
					t.Fatalf("firstAllowedCatalogPath(%s %q) = unreachable, but the evaluator allows request %q whose in-catalog route %q is outside every exclusion, under rules %s",
						entry.method, entry.path, requestRoute, candidate, catalogFuzzRuleSummary(cfg.Rules))
				}
			}
		}

		if result != catalogReachable {
			return
		}
		if !oracle.inCatalog(t, witness) {
			t.Fatalf("firstAllowedCatalogPath(%s %q) witness %q is outside the catalog language", entry.method, entry.path, witness)
		}
		if oracle.excluded(t, witness) {
			t.Fatalf("firstAllowedCatalogPath(%s %q) witness %q is an excluded route", entry.method, entry.path, witness)
		}
		// A witness may legitimately end on the empty final segment a trailing
		// slash leaves, since catalogIdentifierRoutePath puts that spelling in
		// the catalog language for both libpod image-SCP rows. So the
		// normalization pinned here is the route view's, which keeps that
		// segment; NormalizePath would strip it and report the shape the
		// catalog deliberately admits as unnormalized.
		if normalized := filter.NormalizePodmanRoutePath(witness); normalized != witness {
			t.Fatalf("firstAllowedCatalogPath(%s %q) witness %q normalizes to %q, so the reported route is not the one policy matched",
				entry.method, entry.path, witness, normalized)
		}
		if policyAllowsPath(entry.method, witness, compiled) {
			return
		}

		// A witness the evaluator denies is normally dialect drift between the
		// automata and filter's matchers, and that is a failure. The exception
		// is a witness that lands on the libpod image-SCP dual view, where
		// evaluateRequestPolicy demands a second view allow as well and
		// firstAllowedCatalogPath's own doc comment says it does not model
		// that view. Two witness shapes reach it. One ends on the empty
		// segment, where the automata modeled the route view and the decoded
		// view is free to deny. One carries a byte url.URL escapes, "é" say,
		// where they modeled the decoded view and the percent-escaped route
		// view is free to deny. Neither is drift, and neither can hide
		// exposure, because allowedCatalogPaths re-runs the witness through
		// the evaluator and falls back to the catalog spelling. That fallback
		// is what gets asserted, so the exemption cannot quietly become an
		// under-report: the endpoint still gets named, just conservatively.
		if catalogFuzzEncodedRouteView(entry.method, witness) {
			exposed := allowedCatalogPaths(entry.method, entry.path, entry.identifierShape, entry.exclusions, cfg.Rules, compiled)
			if !slices.Equal(exposed, []string{entry.path}) {
				t.Fatalf("allowedCatalogPaths(%s %q) = %v for evaluator-denied dual-view witness %q, want the catalog spelling as the conservative fallback, under rules %s",
					entry.method, entry.path, exposed, witness, catalogFuzzRuleSummary(cfg.Rules))
			}
			return
		}
		t.Fatalf("firstAllowedCatalogPath(%s %q) = reachable with witness %q, but the evaluator denies it under rules %s",
			entry.method, entry.path, witness, catalogFuzzRuleSummary(cfg.Rules))
	})
}

func catalogFuzzRuleSummary(rules []config.RuleConfig) string {
	summaries := make([]string, 0, len(rules))
	for _, rule := range rules {
		summaries = append(summaries, rule.Action+" "+rule.Match.Method+" "+rule.Match.Path)
	}
	return "[" + strings.Join(summaries, " | ") + "]"
}

// TestCatalogFuzzTemplateMatches pins the independent membership oracle down
// on its own. A fuzz oracle that is never tested is just a second unverified
// implementation, and this one exists precisely because the production
// compiler cannot be trusted to check itself.
func TestCatalogFuzzTemplateMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		template  string
		shape     catalogIdentifierShape
		candidate string
		want      bool
	}{
		{"literal template matches itself", "/images/get", catalogIdentifierSegment, "/images/get", true},
		{"literal template rejects a suffix", "/images/get", catalogIdentifierSegment, "/images/get/x", false},
		{"segment shape takes one segment", "/containers/sockguard-test/logs", catalogIdentifierSegment, "/containers/web/logs", true},
		{"segment shape refuses two", "/containers/sockguard-test/logs", catalogIdentifierSegment, "/containers/a/b/logs", false},
		{"path shape takes two", "/containers/sockguard-test/logs", catalogIdentifierPath, "/containers/a/b/logs", true},
		{"empty segment is not clean", "/containers/sockguard-test/logs", catalogIdentifierPath, "/containers//logs", false},
		{"dot segment is not clean", "/containers/sockguard-test/logs", catalogIdentifierPath, "/containers/./logs", false},
		{"dot-dot segment is not clean", "/containers/sockguard-test/logs", catalogIdentifierPath, "/containers/../logs", false},
		{"three dots is clean", "/containers/sockguard-test/logs", catalogIdentifierPath, "/containers/.../logs", true},
		{"dot-leading is clean", "/containers/sockguard-test/logs", catalogIdentifierPath, "/containers/.a/logs", true},
		{"segment shape refuses an empty segment", "/containers/sockguard-test/logs", catalogIdentifierSegment, "/containers//logs", false},
		{"path shape refuses the trailing empty segment", "/libpod/images/scp/sockguard-test", catalogIdentifierPath, "/libpod/images/scp/victim/", false},
		{"path shape refuses the bare route", "/libpod/images/scp/sockguard-test", catalogIdentifierPath, "/libpod/images/scp/", false},
		{"scp catch-all takes a run", "/libpod/images/scp/sockguard-test", catalogIdentifierPath, "/libpod/images/scp/victim/push", true},
		// The route-path shape is what gorilla/mux resolves {name:.*} to and
		// what NormalizePodmanRoutePath preserves, so it is the language both
		// libpod image-SCP rows are compiled against.
		{"route view keeps a single-segment name", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp/victim", true},
		{"route view keeps a slash-bearing name", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp/victim/push", true},
		{"route view admits the trailing empty segment", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp/victim/push/", true},
		{"route view admits the bare route", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp/", true},
		{"route view refuses the prefix without its separator", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp", false},
		{"route view refuses a doubled slash", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp/victim//", false},
		{"route view refuses a leading empty segment", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp//victim", false},
		{"route view refuses a dot segment", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp/./push", false},
		{"route view refuses a dot-dot segment", "/libpod/images/scp/sockguard-test", catalogIdentifierRoutePath, "/libpod/images/scp/../push", false},
		{"exclusion pins the action suffix", "/libpod/images/scp/sockguard-test/push", catalogIdentifierPath, "/libpod/images/scp/victim/push", true},
		{"exclusion does not match a longer word", "/libpod/images/scp/sockguard-test/push", catalogIdentifierPath, "/libpod/images/scp/team/pusher", false},
		{"two placeholders backtrack", "/libpod/manifests/sockguard-test/registry/sockguard-test", catalogIdentifierPath, "/libpod/manifests/a/registry/b/registry/c", true},
		{"two placeholders need the literal", "/libpod/manifests/sockguard-test/registry/sockguard-test", catalogIdentifierPath, "/libpod/manifests/a/b", false},
		{"relative path is not a route", "/images/get", catalogIdentifierSegment, "images/get", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := catalogFuzzTemplateMatches(t, test.template, test.shape, test.candidate); got != test.want {
				t.Fatalf("catalogFuzzTemplateMatches(%q, %d, %q) = %t, want %t",
					test.template, test.shape, test.candidate, got, test.want)
			}
			machine, err := compileCatalogMachine(test.template, test.shape)
			if err != nil {
				t.Fatalf("compileCatalogMachine(%q) error = %v, want nil", test.template, err)
			}
			if got := catalogFuzzAccepts(machine.program, test.candidate); got != test.want {
				t.Fatalf("compiled catalog machine for %q accepts %q = %t, want %t",
					test.template, test.candidate, got, test.want)
			}
		})
	}
}

// TestCatalogFuzzRequestRouteReachesTheSCPDualView proves the generator can
// spell the one request shape whose two evaluated views are different strings:
// POST /libpod/images/scp/{name}/. Without this the trailing-slash bit would be
// dead weight and nothing would say so.
func TestCatalogFuzzRequestRouteReachesTheSCPDualView(t *testing.T) {
	t.Parallel()
	const route = "/libpod/images/scp/victim/push"

	request := catalogFuzzRequestRoute(http.MethodPost, route, true)
	if request != route+"/" {
		t.Fatalf("catalogFuzzRequestRoute(POST, %q, true) = %q, want the trailing-slash route view", route, request)
	}
	if got := filter.NormalizePath(request); got != route {
		t.Fatalf("NormalizePath(%q) = %q, want the in-catalog route %q", request, got, route)
	}
	if got := filter.NormalizePodmanRoutePath((&url.URL{Path: request}).EscapedPath()); got != request {
		t.Fatalf("NormalizePodmanRoutePath(%q) = %q, want the trailing slash kept", request, got)
	}

	// Every other catalog shape ignores the bit: path.Clean removes the slash
	// before any matcher sees it, so the request would duplicate the route.
	if got := catalogFuzzRequestRoute(http.MethodGet, "/containers/web/logs", true); got != "/containers/web/logs" {
		t.Fatalf("catalogFuzzRequestRoute(GET, /containers/web/logs, true) = %q, want the route unchanged", got)
	}
}

// TestCatalogFuzzSeedSelectorsLandOnTheirRow is the regression for the seed
// selector bug. The three dual-view seeds OR catalogFuzzTrailingSlashBit into
// their selector, and the row lookup was `int(selector) % len(entries)` with no
// mask, so 0x8000 was read as row arithmetic and slid each of them eight rows
// down the flattened catalog: every seed that asked for the libpod image-SCP
// request shape was handed to an unrelated entry, whose row then ignored the
// bit. Each selector goes through catalogFuzzEntryIndex here, which is the
// expression the fuzz body runs.
func TestCatalogFuzzSeedSelectorsLandOnTheirRow(t *testing.T) {
	t.Parallel()
	entries := catalogFuzzEntries()
	dualView := 0
	for _, seed := range catalogFuzzSeeds() {
		selector := catalogFuzzSeedSelector(t, entries, seed)
		entry := entries[catalogFuzzEntryIndex(selector, entries)]
		if entry.method != seed.method || entry.path != seed.path {
			t.Fatalf("seed %s %q with selector %#04x lands on catalog row %s %q, want its own row",
				seed.method, seed.path, selector, entry.method, entry.path)
		}
		if !seed.trailingSlash {
			continue
		}
		dualView++
		if entry.path != scpDualViewCatalogPath {
			t.Fatalf("dual-view seed lands on catalog row %q, want the libpod image-SCP row %q", entry.path, scpDualViewCatalogPath)
		}
		if entry.identifierShape != catalogIdentifierRoutePath {
			t.Fatalf("dual-view seed lands on a row with identifier shape %d, want catalogIdentifierRoutePath, which is the shape that puts the trailing empty segment in the catalog language",
				entry.identifierShape)
		}
	}
	if dualView == 0 {
		t.Fatal("no seed sets catalogFuzzTrailingSlashBit, so the image-SCP dual-view request shape is never seeded")
	}
}

// TestCatalogFuzzSeedsBuildLoadablePolicies keeps the seed corpus from going
// vacuous. config.ValidateStructural refuses a rootless match.path, an API
// version prefix and a literal "%", and the fuzz body drops any execution whose
// config does not validate, so a seed that trips one of those exercises
// nothing at all while still looking like coverage.
func TestCatalogFuzzSeedsBuildLoadablePolicies(t *testing.T) {
	t.Parallel()
	entries := catalogFuzzEntries()
	for _, seed := range catalogFuzzSeeds() {
		selector := catalogFuzzSeedSelector(t, entries, seed)
		entry := entries[catalogFuzzEntryIndex(selector, entries)]
		identifierSeeds := strings.Split(catalogFuzzTruncate(seed.identifier, maxCatalogFuzzIdentifier), "\x00")
		route := catalogFuzzRoute(entry.path, entry.identifierShape, identifierSeeds)
		requestRoute := catalogFuzzRequestRoute(entry.method, route, seed.trailingSlash)

		rules := catalogFuzzRules(seed.rules, entry, route, requestRoute)
		if len(rules) == 0 {
			t.Fatalf("seed %s %q produced no rules, so the execution returns before reaching the search", seed.method, seed.path)
		}
		cfg := config.Defaults()
		cfg.Rules = rules
		if err := config.ValidateStructural(&cfg); err != nil {
			t.Fatalf("seed %s %q builds rules %s: ValidateStructural error = %v, want nil",
				seed.method, seed.path, catalogFuzzRuleSummary(rules), err)
		}
		if seed.trailingSlash && requestRoute != route+"/" {
			t.Fatalf("seed %s %q asks for the dual-view request shape but generated %q for route %q",
				seed.method, seed.path, requestRoute, route)
		}
	}
}

// TestCatalogFuzzPatternIsAlwaysRooted pins the generator against the config
// validation a rootless pattern now fails. Mode 0 is the only mode that spells
// fuzzer bytes straight into a match.path; every other mode is derived from a
// catalog template and is rooted by construction. A rootless pattern does not
// produce an interesting counterexample, it produces a validation error that
// discards the entire execution, so the corpus quietly stops testing anything.
func TestCatalogFuzzPatternIsAlwaysRooted(t *testing.T) {
	t.Parallel()
	payloads := []string{"", "containers/*", "**", "*/json", "a", "/containers/**", "é"}
	for _, entry := range catalogFuzzEntries() {
		route := catalogFuzzRoute(entry.path, entry.identifierShape, []string{"victim"})
		requestRoute := catalogFuzzRequestRoute(entry.method, route, true)
		for mode := 0; mode < 9; mode++ {
			for _, payload := range payloads {
				pattern := catalogFuzzPattern(byte(mode), payload, entry.path, route, requestRoute)
				if pattern != "" && !strings.HasPrefix(pattern, "/") {
					t.Fatalf("catalogFuzzPattern(mode %d, payload %q, template %q) = %q, which config.ValidateStructural refuses as rootless",
						mode, payload, entry.path, pattern)
				}
			}
		}
	}
}

// TestCatalogFuzzDualViewWitnessNeedsItsExemption is the evidence for the one
// exemption left in the target's witness check, and the reason it is not a
// leftover of S17b. S17b was about the catalog language: firstAllowedCatalogPath
// could not spell the image-SCP route view at all, and catalogIdentifierRoutePath
// fixed that. What remains is a different thing, stated in that function's own
// doc comment — the search walks one language while
// filter.evaluateRequestPolicy insists on two views agreeing, so a witness the
// search is right about on the view it modeled can still be denied on the view
// it did not.
//
// Both concrete shapes are pinned. The rules are otherwise identical, and each
// pair carries the twin whose views do not diverge, so a fix that narrowed
// everything would fail here rather than pass.
func TestCatalogFuzzDualViewWitnessNeedsItsExemption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		allowed     string
		wantWitness string
	}{
		{
			// The automata modeled the route view: "/libpod/images/scp/victim/"
			// is in the catalog language and the allow rule spells it exactly.
			// evaluateRequestPolicy then also requires the decoded view
			// "/libpod/images/scp/victim", which that rule does not match.
			name:        "witness ending on the empty segment",
			allowed:     "/libpod/images/scp/victim/",
			wantWitness: "/libpod/images/scp/victim/",
		},
		{
			// The automata modeled the decoded view. url.URL escapes the "é",
			// so the route view is "/libpod/images/scp/%C3%A9" and the allow
			// rule, spelled in decoded bytes, does not match it.
			name:        "witness carrying a byte url.URL escapes",
			allowed:     "/libpod/images/scp/é",
			wantWitness: "/libpod/images/scp/é",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Rules = []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: test.allowed}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			}
			if err := config.ValidateStructural(&cfg); err != nil {
				t.Fatalf("ValidateStructural error = %v, want nil", err)
			}
			compiled, err := compileConfiguredRules(cfg.Rules)
			if err != nil {
				t.Fatalf("compileConfiguredRules error = %v, want nil", err)
			}

			var entry catalogFuzzEntry
			for _, candidate := range catalogFuzzEntries() {
				if candidate.path == scpDualViewCatalogPath && candidate.identifierShape == catalogIdentifierRoutePath {
					entry = candidate
					break
				}
			}
			if entry.path == "" {
				t.Fatalf("%q is no longer a route-path catalog row", scpDualViewCatalogPath)
			}

			witness, result := firstAllowedCatalogPath(entry.method, entry.path, entry.identifierShape, entry.exclusions, cfg.Rules)
			if result != catalogReachable || witness != test.wantWitness {
				t.Fatalf("firstAllowedCatalogPath(%s %q) = (%q, %v), want (%q, reachable)",
					entry.method, entry.path, witness, result, test.wantWitness)
			}
			if !catalogFuzzEncodedRouteView(entry.method, witness) {
				t.Fatalf("witness %q does not reach filter's dual-view branch, so it needs no exemption and the target should be asserting the evaluator allows it", witness)
			}
			if policyAllowsPath(entry.method, witness, compiled) {
				t.Fatalf("the evaluator allows witness %q, so this shape no longer needs the exemption and it should be deleted", witness)
			}
			// The over-report never becomes an under-report: the endpoint is
			// still named, under its catalog spelling rather than as an
			// evaluator-confirmed path.
			exposed := allowedCatalogPaths(entry.method, entry.path, entry.identifierShape, entry.exclusions, cfg.Rules, compiled)
			if !slices.Equal(exposed, []string{entry.path}) {
				t.Fatalf("allowedCatalogPaths(%s %q) = %v, want the catalog spelling as the conservative fallback", entry.method, entry.path, exposed)
			}
		})
	}
}
