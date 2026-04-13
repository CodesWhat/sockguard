package filter

import (
	"net/http"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

type ruleDeps struct {
	regexpCompile func(string) (*regexp.Regexp, error)
}

func newRuleDeps() *ruleDeps {
	return &ruleDeps{
		regexpCompile: regexp.Compile,
	}
}

// Action represents the result of a rule evaluation.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

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

// CompiledRule is a rule with pre-compiled matchers for efficient evaluation.
type CompiledRule struct {
	methodMask      httpMethodMask
	unknownMethods  []string
	matchAllMethods bool
	literal         string
	literalPrefix   string
	pattern         *regexp.Regexp
	// Action is returned when this rule matches.
	Action Action
	// Reason is attached to the decision metadata when this rule matches.
	Reason string
	// Index is the original position of the source rule in the configured rule list.
	Index int
}

// NormalizePath sanitizes and strips the Docker API version prefix from a path.
// It resolves ".." and "." segments and collapses redundant slashes before
// stripping the version prefix, preventing path traversal bypasses.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	if pathNeedsClean(p) {
		p = path.Clean(p)
	}
	return stripVersionPrefix(p)
}

func pathNeedsClean(p string) bool {
	if p == "/" {
		return false
	}
	if len(p) > 1 && p[len(p)-1] == '/' {
		return true
	}

	segmentStart := 0
	for i := 0; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		if i == segmentStart {
			if i == 0 {
				segmentStart = 1
				continue
			}
			return true
		}

		switch p[segmentStart:i] {
		case ".", "..":
			return true
		}
		segmentStart = i + 1
	}

	return false
}

// stripVersionPrefix removes a leading /vN.N/ or /vN/ prefix, returning the
// path from the first slash after the version. Uses a hand-rolled check so the
// common case (no prefix) avoids regexp overhead entirely.
func stripVersionPrefix(p string) string {
	// Minimum version prefix is /vN/ (4 chars).
	if len(p) < 4 || p[0] != '/' || p[1] != 'v' {
		return p
	}
	i := 2
	// Consume digits.
	for i < len(p) && p[i] >= '0' && p[i] <= '9' {
		i++
	}
	if i == 2 {
		return p // no digits after /v
	}
	// Optional .N
	if i < len(p) && p[i] == '.' {
		j := i + 1
		for j < len(p) && p[j] >= '0' && p[j] <= '9' {
			j++
		}
		if j > i+1 {
			i = j
		}
	}
	// Must end with /
	if i >= len(p) || p[i] != '/' {
		return p
	}
	return p[i:]
}

// CompileRule compiles a Rule into a CompiledRule for efficient matching.
func CompileRule(r Rule) (*CompiledRule, error) {
	return compileRuleWithDeps(r, newRuleDeps())
}

func compileRuleWithDeps(r Rule, deps *ruleDeps) (*CompiledRule, error) {
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
		if !containsString(unknownMethods, upperMethod) {
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
		cr.literal = r.Pattern
		return cr, nil
	}

	// Convert glob pattern to regex.
	regexPattern := globToRegex(r.Pattern)
	compiled, err := deps.regexpCompile("^" + regexPattern + "$")
	if err != nil {
		return nil, err
	}
	cr.pattern = compiled

	return cr, nil
}

// matches returns true if the request matches this rule.
// It normalizes the path and uppercases the method internally, so callers
// don't need to pre-process inputs.
func (cr *CompiledRule) matches(method, path string) bool {
	upperMethod := upperHTTPMethodASCII(method)
	return cr.matchesNormalizedUpperWithBit(upperMethod, httpMethodBit(upperMethod), NormalizePath(path))
}

// matchesNormalizedUpper returns true when an already-uppercased method and an
// already-normalized path match this rule. Use this in hot loops where the
// method has been uppercased once outside the loop.
func (cr *CompiledRule) matchesNormalizedUpper(upperMethod, normalizedPath string) bool {
	return cr.matchesNormalizedUpperWithBit(upperMethod, httpMethodBit(upperMethod), normalizedPath)
}

func (cr *CompiledRule) matchesNormalizedUpperWithBit(upperMethod string, methodBit httpMethodMask, normalizedPath string) bool {
	// Check method
	if !cr.matchAllMethods {
		if methodBit != 0 {
			if cr.methodMask&methodBit == 0 {
				return false
			}
		} else if !containsString(cr.unknownMethods, upperMethod) {
			return false
		}
	}

	if cr.pattern == nil {
		return normalizedPath == cr.literal
	}
	if cr.literalPrefix != "" && !strings.HasPrefix(normalizedPath, cr.literalPrefix) {
		return false
	}

	return cr.pattern.MatchString(normalizedPath)
}

// Evaluate evaluates a request against an ordered list of compiled rules.
// Returns the action and the matched rule index. If no rule matches, returns deny.
func Evaluate(rules []*CompiledRule, r *http.Request) (Action, int, string) {
	return evaluateNormalized(rules, r.Method, NormalizePath(r.URL.Path))
}

func evaluateNormalized(rules []*CompiledRule, method, normalizedPath string) (Action, int, string) {
	upperMethod := upperHTTPMethodASCII(method)
	methodBit := httpMethodBit(upperMethod)
	for _, rule := range rules {
		if rule.matchesNormalizedUpperWithBit(upperMethod, methodBit, normalizedPath) {
			return rule.Action, rule.Index, rule.Reason
		}
	}
	return ActionDeny, -1, "no matching allow rule"
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

// globToRegex converts a simple glob pattern to a regex string.
// Supports * (single path segment) and ** (any path segments).
// The sequence /** also matches the bare path without the trailing slash,
// so /containers/** matches both /containers and /containers/anything.
func globToRegex(pattern string) string {
	var b strings.Builder
	runes := []rune(pattern)
	i := 0
	for i < len(runes) {
		switch {
		case i+2 < len(runes) && runes[i] == '/' && runes[i+1] == '*' && runes[i+2] == '*':
			// /** matches the bare path OR /anything/deeper
			b.WriteString("(/.*)?")
			i += 3
		case i+1 < len(runes) && runes[i] == '*' && runes[i+1] == '*':
			b.WriteString(".*")
			i += 2
		case runes[i] == '*':
			b.WriteString("[^/]*")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(runes[i])))
			i++
		}
	}
	return b.String()
}
