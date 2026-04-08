package filter

import (
	"net/http"
	"path"
	"regexp"
	"strings"
)

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

// CompiledRule is a rule with pre-compiled matchers for efficient evaluation.
type CompiledRule struct {
	methods map[string]bool
	pattern *regexp.Regexp
	Action  Action
	Reason  string
	Index   int
}

// APIVersionPrefix matches Docker API version prefixes like /v1.45/
var APIVersionPrefix = regexp.MustCompile(`^/v\d+(\.\d+)?/`)

// NormalizePath sanitizes and strips the Docker API version prefix from a path.
// It resolves ".." and "." segments and collapses redundant slashes before
// stripping the version prefix, preventing path traversal bypasses.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	cleaned := path.Clean(p)
	return APIVersionPrefix.ReplaceAllString(cleaned, "/")
}

// CompileRule compiles a Rule into a CompiledRule for efficient matching.
func CompileRule(r Rule) (*CompiledRule, error) {
	// Convert glob pattern to regex
	regexPattern := globToRegex(r.Pattern)
	compiled, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return nil, err
	}

	methods := make(map[string]bool)
	for _, m := range r.Methods {
		if m == "*" {
			methods = nil // nil means match all
			break
		}
		methods[strings.ToUpper(m)] = true
	}

	return &CompiledRule{
		methods: methods,
		pattern: compiled,
		Action:  r.Action,
		Reason:  r.Reason,
		Index:   r.Index,
	}, nil
}

// Matches returns true if the request matches this rule.
// It normalizes the path and uppercases the method internally, so callers
// don't need to pre-process inputs.
func (cr *CompiledRule) Matches(method, path string) bool {
	return cr.matchesNormalizedUpper(strings.ToUpper(method), NormalizePath(path))
}

// matchesNormalizedUpper returns true when an already-uppercased method and an
// already-normalized path match this rule. Use this in hot loops where the
// method has been uppercased once outside the loop.
func (cr *CompiledRule) matchesNormalizedUpper(upperMethod, normalizedPath string) bool {
	// Check method
	if cr.methods != nil {
		if !cr.methods[upperMethod] {
			return false
		}
	}

	return cr.pattern.MatchString(normalizedPath)
}

// Evaluate evaluates a request against an ordered list of compiled rules.
// Returns the action and the matched rule index. If no rule matches, returns deny.
func Evaluate(rules []*CompiledRule, r *http.Request) (Action, int, string) {
	return evaluateNormalized(rules, r.Method, NormalizePath(r.URL.Path))
}

func evaluateNormalized(rules []*CompiledRule, method, normalizedPath string) (Action, int, string) {
	upperMethod := strings.ToUpper(method)
	for _, rule := range rules {
		if rule.matchesNormalizedUpper(upperMethod, normalizedPath) {
			return rule.Action, rule.Index, rule.Reason
		}
	}
	return ActionDeny, -1, "no matching allow rule"
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
