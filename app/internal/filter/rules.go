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

// apiVersionPrefix matches Docker API version prefixes like /v1.45/
var apiVersionPrefix = regexp.MustCompile(`^/v\d+(\.\d+)?/`)

// NormalizePath sanitizes and strips the Docker API version prefix from a path.
// It resolves ".." and "." segments and collapses redundant slashes before
// stripping the version prefix, preventing path traversal bypasses.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	cleaned := path.Clean(p)
	return apiVersionPrefix.ReplaceAllString(cleaned, "/")
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
func (cr *CompiledRule) Matches(method, path string) bool {
	return cr.matchesNormalized(method, NormalizePath(path))
}

// matchesNormalized returns true when method and an already-normalized path match.
func (cr *CompiledRule) matchesNormalized(method, normalizedPath string) bool {
	// Check method
	if cr.methods != nil {
		if !cr.methods[strings.ToUpper(method)] {
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
	for _, rule := range rules {
		if rule.matchesNormalized(method, normalizedPath) {
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
	i := 0
	for i < len(pattern) {
		switch {
		case i+2 < len(pattern) && pattern[i] == '/' && pattern[i+1] == '*' && pattern[i+2] == '*':
			// /** matches the bare path OR /anything/deeper
			b.WriteString("(/.*)?")
			i += 3
		case i+1 < len(pattern) && pattern[i] == '*' && pattern[i+1] == '*':
			b.WriteString(".*")
			i += 2
		case pattern[i] == '*':
			b.WriteString("[^/]*")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
			i++
		}
	}
	return b.String()
}
