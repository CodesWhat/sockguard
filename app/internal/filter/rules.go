package filter

import (
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/codeswhat/sockguard/app/internal/glob"
)

// regexpCompileHook is the package-level hook for regexp compilation.
// Tests can swap this to inject errors; production always uses regexp.Compile.
// All tests in this package are sequential (no t.Parallel on tests that swap
// the hook), so no additional synchronization is needed.
var regexpCompileHook = regexp.Compile

// Action represents the result of a rule evaluation.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// ReasonNoMatchingAllowRule is the human-readable reason stamped on the
// default-deny outcome (no rule matched). Exported so the reason-code
// classifier can compare against a constant rather than a magic string;
// changing this string requires updating both this constant and the
// downstream classifier.
const ReasonNoMatchingAllowRule = "no matching allow rule"

// Rule represents a single access control rule.
type Rule struct {
	Methods []string
	Pattern string
	Action  Action
	Reason  string
	Index   int
}

type httpMethodMask uint16

const (
	httpMethodMaskGet httpMethodMask = 1 << iota
	httpMethodMaskHead
	httpMethodMaskPost
	httpMethodMaskPut
	httpMethodMaskDelete
	httpMethodMaskPatch
	httpMethodMaskOptions
	httpMethodMaskConnect
	httpMethodMaskTrace
)

type pathMatcherKind uint8

const (
	pathMatcherLiteral pathMatcherKind = iota
	pathMatcherMatchAll
	pathMatcherTrailingDeep
	pathMatcherSegmentGlob
	pathMatcherRegex
)

// CompiledRule is a rule with pre-compiled matchers for efficient evaluation.
type CompiledRule struct {
	methodMask      httpMethodMask
	unknownMethods  []string
	matchAllMethods bool
	matcherKind     pathMatcherKind
	literal         string
	literalPrefix   string
	trailingPrefix  string
	segmentPatterns []string
	pattern         *regexp.Regexp
	// Action is returned when this rule matches.
	Action Action
	// Reason is attached to the decision metadata when this rule matches.
	Reason string
	// Index is the original position of the source rule in the configured rule list.
	Index int
}

// NormalizePath canonicalizes a request path into the form policy rules are
// matched against: it resolves "." and ".." segments and collapses redundant
// slashes (path.Clean), then strips a leading Docker or Podman API version
// prefix.
//
// It deliberately does NOT percent-decode. The path it receives is r.URL.Path,
// which net/http's request parser has already decoded exactly once — the same
// single decode the Docker daemon's request parser applies. Decoding again
// would let sockguard resolve an escape the daemon leaves literal: a
// double-encoded "%252e", for instance, would become a "." segment that
// path.Clean collapses for sockguard while the daemon still routes it as a
// real path segment, so the two would disagree on which endpoint the request
// targets. evaluateRequestPolicy handles Podman's UseEncodedPath exception for
// the image-SCP route before policy matching.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	return stripVersionPrefix(canonicalizePath(p))
}

// canonicalizePath resolves "." / ".." segments and collapses redundant
// slashes via path.Clean, fronted by the allocation-free pathNeedsClean fast
// path. It does not percent-decode — see NormalizePath for why.
func canonicalizePath(p string) string {
	if pathNeedsClean(p) {
		p = path.Clean(p)
	}
	return p
}

// pathNeedsClean is a zero-allocation fast path in front of path.Clean so
// the overwhelmingly common case — paths that are already clean, like
// `/containers/json` or `/v1.45/_ping` — skips Clean's string allocation
// entirely. `BenchmarkNormalizePath/bare` and `/clean` report 0 B/op when
// this guard returns false; calling path.Clean unconditionally made that
// ~200ns and added two heap allocations per request. We only return true
// when the path actually has a trailing slash, a doubled slash, or a `.`
// or `..` segment — exactly the cases Clean would change.
func pathNeedsClean(p string) bool {
	if p == "/" {
		return false
	}
	if len(p) > 1 && p[len(p)-1] == '/' {
		return true
	}

	absolutePath := strings.HasPrefix(p, "/")
	hasNormalSegment := false
	segmentStart := 0
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}

		needsClean, normalSegment := pathSegmentNeedsClean(p, segmentStart, i, absolutePath, hasNormalSegment, true)
		if needsClean {
			return true
		}
		hasNormalSegment = hasNormalSegment || normalSegment
		segmentStart = i + 1
	}

	needsClean, _ := pathSegmentNeedsClean(p, segmentStart, len(p), absolutePath, hasNormalSegment, false)
	return needsClean
}

func pathSegmentNeedsClean(p string, start, end int, absolutePath, hasNormalSegment, hasMoreSegments bool) (needsClean bool, normalSegment bool) {
	if end == start {
		return start != 0, false
	}

	segmentLen := end - start
	if segmentLen == 1 && p[start] == '.' {
		// WHY: A lone relative "." is already clean because path.Clean(".") == ".".
		// Only dotted segments that would collapse with surrounding path context
		// should take the allocation-heavy Clean path.
		if start == 0 && !absolutePath && !hasMoreSegments {
			return false, false
		}
		return true, false
	}
	if segmentLen == 2 && p[start] == '.' && p[start+1] == '.' {
		return absolutePath || hasNormalSegment, false
	}

	return false, true
}

// stripVersionPrefix removes a leading API version prefix, returning the
// path from the first slash after the version. Uses a hand-rolled byte loop
// so the common case (no prefix) avoids regexp overhead and allocation
// entirely.
//
// Docker's own router only accepts /vN or /vN.N (a single optional minor
// component, digits and a dot only). Podman's libpod bindings send the
// daemon's full three-part semver, e.g. /v5.0.0/libpod/containers/json
// (#148), and its API server registers versioned routes with the regex
// `[0-9][0-9A-Za-z.-]*` (see moby/moby vendor of containers/podman's
// pkg/api/server VersionedPath), which also admits prerelease/build
// suffixes like /v5.8.1-dev/ and /v5.8.1-rc1/. sockguard mirrors that exact
// character class — first char after "v" a digit, then any run of
// [0-9A-Za-z.-] — so its policy view of a path stays byte-identical to
// Podman's own routing view. A wider or narrower class would leave some
// versioned libpod paths unstripped, falling through to a catch-all rule
// with rule matching, body inspection, ownership, visibility and redaction
// all skipped.
func stripVersionPrefix(p string) string {
	// Minimum version prefix is /vN/ (4 chars). Docker and Podman both use
	// lowercase 'v' only.
	if len(p) < 4 || p[0] != '/' || p[1] != 'v' {
		return p
	}
	i := 2
	// First character after "v" must be a digit.
	if p[i] < '0' || p[i] > '9' {
		return p
	}
	i++
	// Consume the rest of Podman's VersionedPath class: [0-9A-Za-z.-]*.
	for i < len(p) {
		c := p[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' {
			i++
			continue
		}
		break
	}
	// Must end with /
	if i >= len(p) || p[i] != '/' {
		return p
	}
	return p[i:]
}

// HasVersionPrefix reports whether p begins with a daemon API version prefix
// (e.g. "/v1.45/") that NormalizePath strips before rule matching. A rule
// pattern carrying such a prefix can never match real traffic — the request
// path is normalized first — so it is almost always an authoring mistake worth
// flagging.
func HasVersionPrefix(p string) bool {
	return stripVersionPrefix(p) != p
}

// CompileRule compiles a Rule into a CompiledRule for efficient matching.
func CompileRule(r Rule) (*CompiledRule, error) {
	var methodMask httpMethodMask
	var unknownMethods []string
	matchAllMethods := false
	for _, m := range r.Methods {
		if m == "*" {
			matchAllMethods = true
			methodMask = 0
			unknownMethods = nil
			break
		}

		upperMethod := upperHTTPMethodASCII(m)
		if bit := httpMethodBit(upperMethod); bit != 0 {
			methodMask |= bit
			continue
		}
		if !slices.Contains(unknownMethods, upperMethod) {
			unknownMethods = append(unknownMethods, upperMethod)
		}
	}

	cr := &CompiledRule{
		methodMask:      methodMask,
		unknownMethods:  unknownMethods,
		matchAllMethods: matchAllMethods,
		literalPrefix:   literalPrefixForPattern(r.Pattern),
		Action:          r.Action,
		Reason:          r.Reason,
		Index:           r.Index,
	}

	if !strings.Contains(r.Pattern, "*") {
		cr.matcherKind = pathMatcherLiteral
		cr.literal = r.Pattern
		return cr, nil
	}
	if r.Pattern == "/**" {
		cr.matcherKind = pathMatcherMatchAll
		return cr, nil
	}
	if isTrailingDoubleStarPattern(r.Pattern) {
		cr.matcherKind = pathMatcherTrailingDeep
		cr.trailingPrefix = strings.TrimSuffix(r.Pattern, "/**")
		return cr, nil
	}
	if !strings.Contains(r.Pattern, "**") {
		cr.matcherKind = pathMatcherSegmentGlob
		cr.segmentPatterns = splitGlobSegments(r.Pattern)
		return cr, nil
	}

	// Convert glob pattern to regex.
	regexPattern := globToRegex(r.Pattern)
	compiled, err := regexpCompileHook("^" + regexPattern + "$")
	if err != nil {
		return nil, err
	}
	cr.matcherKind = pathMatcherRegex
	cr.pattern = compiled

	return cr, nil
}

func (cr *CompiledRule) matchesNormalizedUpperWithBit(upperMethod string, methodBit httpMethodMask, normalizedPath string) bool {
	// Check method
	if !cr.matchAllMethods {
		if methodBit != 0 {
			if cr.methodMask&methodBit == 0 {
				return false
			}
		} else if !slices.Contains(cr.unknownMethods, upperMethod) {
			return false
		}
	}

	switch cr.matcherKind {
	case pathMatcherLiteral:
		return normalizedPath == cr.literal
	case pathMatcherMatchAll:
		return true
	case pathMatcherTrailingDeep:
		return matchTrailingDoubleStar(cr.trailingPrefix, normalizedPath)
	case pathMatcherSegmentGlob:
		if cr.literalPrefix != "" && !strings.HasPrefix(strings.TrimPrefix(normalizedPath, "/"), strings.TrimPrefix(cr.literalPrefix, "/")) {
			return false
		}
		return matchGlobSegments(cr.segmentPatterns, normalizedPath)
	case pathMatcherRegex:
		if cr.literalPrefix != "" && !strings.HasPrefix(normalizedPath, cr.literalPrefix) {
			return false
		}
		return cr.pattern.MatchString(normalizedPath)
	default:
		return false
	}
}

// Evaluate evaluates a request against an ordered list of compiled rules.
// Returns the action and the matched rule index. If no rule matches, returns deny.
func Evaluate(rules []*CompiledRule, r *http.Request) (Action, int, string) {
	action, index, reason, _ := evaluateRequestPolicy(rules, r, NormalizePath(r.URL.Path))
	return action, index, reason
}

// evaluateRequestPolicy evaluates the decoded canonical path used by policy
// rules and, for an encoded libpod image-SCP route, the EscapedPath view used
// by Podman's gorilla/mux router. Both views must allow the request. This keeps
// an encoded action suffix from borrowing an earlier push/tag/untag allow while
// also preventing an encoded alias from bypassing a canonical decoded deny.
// The rejecting view owns denial metadata; when both allow, the encoded route
// view owns metadata and the path handed to request inspectors.
func evaluateRequestPolicy(rules []*CompiledRule, r *http.Request, normalizedPath string) (Action, int, string, string) {
	routePath, encodedScp := normalizedLibpodImageScpRoutePath(r)
	if !encodedScp {
		action, index, reason := evaluateNormalized(rules, r.Method, normalizedPath)
		return action, index, reason, normalizedPath
	}

	decodedPath := NormalizePath(r.URL.Path)
	action, index, reason := evaluateNormalized(rules, r.Method, decodedPath)
	if action != ActionAllow {
		return action, index, reason, decodedPath
	}

	action, index, reason = evaluateNormalized(rules, r.Method, routePath)
	return action, index, reason, routePath
}

func normalizedLibpodImageScpRoutePath(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil || r.Method != http.MethodPost {
		return "", false
	}
	decodedPath := NormalizePath(r.URL.Path)
	routePath := NormalizePodmanRoutePath(r.URL.EscapedPath())
	if routePath == decodedPath || !isLibpodImageScpRoutePath(routePath) {
		return "", false
	}
	return routePath, true
}

// NormalizePodmanRoutePath keeps the trailing slash that gorilla/mux includes
// in route matching while applying the same API-version and clean-path rules
// used for policy paths. A trailing slash is security-significant for Podman's
// anchored push/tag/untag routes: .../push/ misses the earlier action route and
// falls through to the later image-SCP catch-all.
//
// It is exported because the ownership middleware has to compute the same
// route view this package does. NormalizePath is not a substitute there:
// path.Clean strips the trailing slash, so a caller using it reads
// POST /libpod/images/scp/victim/push/ as a push of an image named
// "scp/victim" while the daemon routes it as an SCP of "victim/push/".
func NormalizePodmanRoutePath(p string) string {
	hasTrailingSlash := len(p) > 1 && strings.HasSuffix(p, "/")
	normalized := NormalizePath(p)
	if hasTrailingSlash && normalized != "/" && !strings.HasSuffix(normalized, "/") {
		normalized += "/"
	}
	return normalized
}

func isLibpodImageScpRoutePath(routePath string) bool {
	rest, ok := strings.CutPrefix(routePath, libpodPathPrefix+"images/scp/")
	if !ok || rest == "" {
		return false
	}
	for _, action := range []string{"push", "tag", "untag"} {
		if rest == action || strings.HasSuffix(rest, "/"+action) {
			return false
		}
	}
	return true
}

func evaluateNormalized(rules []*CompiledRule, method, normalizedPath string) (Action, int, string) {
	upperMethod := upperHTTPMethodASCII(method)
	methodBit := httpMethodBit(upperMethod)
	for _, rule := range rules {
		if rule.matchesNormalizedUpperWithBit(upperMethod, methodBit, normalizedPath) {
			return rule.Action, rule.Index, rule.Reason
		}
	}
	return ActionDeny, -1, ReasonNoMatchingAllowRule
}

func httpMethodBit(method string) httpMethodMask {
	switch method {
	case http.MethodGet:
		return httpMethodMaskGet
	case http.MethodHead:
		return httpMethodMaskHead
	case http.MethodPost:
		return httpMethodMaskPost
	case http.MethodPut:
		return httpMethodMaskPut
	case http.MethodDelete:
		return httpMethodMaskDelete
	case http.MethodPatch:
		return httpMethodMaskPatch
	case http.MethodOptions:
		return httpMethodMaskOptions
	case http.MethodConnect:
		return httpMethodMaskConnect
	case http.MethodTrace:
		return httpMethodMaskTrace
	default:
		return 0
	}
}

func upperHTTPMethodASCII(method string) string {
	firstLower := -1
	for i := 0; i < len(method); i++ {
		c := method[i]
		switch {
		case c >= utf8.RuneSelf:
			return strings.ToUpper(method)
		case 'a' <= c && c <= 'z':
			if firstLower == -1 {
				firstLower = i
			}
		}
	}

	if firstLower == -1 {
		return method
	}

	buf := make([]byte, len(method))
	copy(buf, method)
	for i := firstLower; i < len(buf); i++ {
		if 'a' <= buf[i] && buf[i] <= 'z' {
			buf[i] -= 'a' - 'A'
		}
	}
	return string(buf)
}

func isTrailingDoubleStarPattern(pattern string) bool {
	return strings.HasSuffix(pattern, "/**") && !strings.Contains(pattern[:len(pattern)-3], "*")
}

func splitGlobSegments(pattern string) []string {
	return strings.Split(strings.TrimPrefix(pattern, "/"), "/")
}

func matchTrailingDoubleStar(prefix, path string) bool {
	if prefix == "" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func matchGlobSegments(patternSegments []string, path string) bool {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return len(patternSegments) == 1 && matchGlobSegment(patternSegments[0], "")
	}

	for _, patternSegment := range patternSegments {
		if path == "" {
			return false
		}

		segment, rest, hasMore := strings.Cut(path, "/")
		if !matchGlobSegment(patternSegment, segment) {
			return false
		}
		if !hasMore {
			path = ""
			continue
		}
		path = rest
	}

	return path == ""
}

func matchGlobSegment(pattern, segment string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == segment
	}

	segmentIndex := 0
	patternIndex := 0
	starIndex := -1
	segmentRetry := 0
	for segmentIndex < len(segment) {
		if patternIndex < len(pattern) && pattern[patternIndex] == segment[segmentIndex] {
			patternIndex++
			segmentIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex] == '*' {
			starIndex = patternIndex
			patternIndex++
			segmentRetry = segmentIndex
			continue
		}
		if starIndex == -1 {
			return false
		}
		patternIndex = starIndex + 1
		segmentRetry++
		segmentIndex = segmentRetry
	}

	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
}

func literalPrefixForPattern(pattern string) string {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '*' {
			continue
		}

		prefix := pattern[:i]
		if i > 0 && pattern[i-1] == '/' && i+1 < len(pattern) && pattern[i+1] == '*' {
			suffix := pattern[i+2:]
			if suffix == "" || suffix[0] != '/' {
				return strings.TrimSuffix(prefix, "/")
			}
		}
		return prefix
	}
	return pattern
}

// GlobToRegexString converts the sockguard glob dialect to a regex string.
// Kept as a thin re-export of glob.ToRegexString for callers that already
// depend on the filter package.
func GlobToRegexString(pattern string) string {
	return glob.ToRegexString(pattern)
}

func globToRegex(pattern string) string {
	return glob.ToRegexString(pattern)
}
