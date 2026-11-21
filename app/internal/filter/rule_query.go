package filter

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// queryConstraint is one compiled `match.query` entry: the key has to be
// present and every occurrence of it (under any letter case) has to match one
// of patterns.
type queryConstraint struct {
	key      string
	patterns []string
}

// ValidateQueryConstraints reports why a rule's query constraint map cannot be
// compiled, or nil. The config validator and CompileRule share it so an
// authoring mistake is refused with the same wording wherever it is caught.
// The returned error names the offending key; callers prefix their own field
// path.
func ValidateQueryConstraints(query map[string][]string) error {
	seen := make(map[string]string, len(query))
	for key, patterns := range query {
		folded := strings.ToLower(key)
		if other, dup := seen[folded]; dup {
			a, b := other, key
			if a > b {
				a, b = b, a
			}
			return fmt.Errorf("query keys %q and %q differ only in letter case, which is ambiguous", a, b)
		}
		seen[folded] = key
		if key == "" {
			return fmt.Errorf("query key must not be empty")
		}
		if hasControlChar(key) {
			return fmt.Errorf("query key %q must not contain control characters", key)
		}
		if len(patterns) == 0 {
			return fmt.Errorf("query %q needs at least one pattern", key)
		}
		for _, pattern := range patterns {
			if hasControlChar(pattern) {
				return fmt.Errorf("query %q pattern %q must not contain control characters", key, pattern)
			}
		}
	}
	return nil
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func compileQueryConstraints(query map[string][]string) ([]queryConstraint, error) {
	if len(query) == 0 {
		return nil, nil
	}
	if err := ValidateQueryConstraints(query); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	compiled := make([]queryConstraint, 0, len(keys))
	for _, key := range keys {
		compiled = append(compiled, queryConstraint{key: key, patterns: slices.Clone(query[key])})
	}
	return compiled, nil
}

// matchesValues reports whether the request's parameters satisfy the
// constraint. Occurrences are every parameter whose name equals the key under
// case-insensitive comparison, because Podman reads some names that way.
//
// An allow rule narrows, so every occurrence has to match at least one pattern
// and at least one occurrence has to be spelled exactly like the key (Docker
// reads names case-sensitively and would see a lone "Signal=USR1" as no signal
// at all). A repeated or differently cased key cannot smuggle a second value
// past it.
//
// A deny rule widens, so it fails closed the other way: it matches when any
// occurrence, under any letter case, matches a pattern.
func (c queryConstraint) matchesValues(values url.Values, action Action) bool {
	exact := false
	for name, vals := range values {
		if !strings.EqualFold(name, c.key) {
			continue
		}
		if name == c.key {
			exact = true
		}
		for _, value := range vals {
			if c.matchesValue(value) {
				if action == ActionDeny {
					return true
				}
			} else if action != ActionDeny {
				return false
			}
		}
	}
	return action != ActionDeny && exact
}

// matchesValue treats "*" as a run of any characters, empty included, and
// nothing else as special. Unlike a path glob it has no notion of "/", so
// matchGlobSegment's byte-wise walker is exactly the dialect.
func (c queryConstraint) matchesValue(value string) bool {
	for _, pattern := range c.patterns {
		if matchGlobSegment(pattern, value) {
			return true
		}
	}
	return false
}

// HasQuery reports whether the rule carries query constraints.
func (cr *CompiledRule) HasQuery() bool {
	return len(cr.query) > 0
}

// requestQuery lazily parses a request's raw query once for the whole rule
// walk. static switches rule evaluation into the over-approximating mode the
// startup analyses use (see EvaluateStatic).
type requestQuery struct {
	raw    string
	values url.Values
	err    error
	parsed bool
	static bool
}

func (q *requestQuery) parse() {
	if q.parsed {
		return
	}
	q.parsed = true
	q.values, q.err = url.ParseQuery(q.raw)
}

// matchesQuery reports whether the rule's query constraints hold. A rule
// without constraints always passes.
//
// A query url.ParseQuery rejects (bad percent-encoding, a ";" separator) is
// not trusted either way, so it fails closed: an allow rule does not match and
// a deny rule does.
//
// In static mode (no real request, only a path probe) the rule cannot be
// evaluated, so it is read pessimistically for exposure: an allow rule counts
// as matching because some query could satisfy it, and a deny rule does not
// because some query could dodge it.
func (cr *CompiledRule) matchesQuery(q *requestQuery) bool {
	if len(cr.query) == 0 {
		return true
	}
	if q.static {
		return cr.Action == ActionAllow
	}
	q.parse()
	if q.err != nil {
		return cr.Action == ActionDeny
	}
	for _, c := range cr.query {
		if !c.matchesValues(q.values, cr.Action) {
			return false
		}
	}
	return true
}

// EvaluateStatic evaluates rules the way the startup exposure analyses need:
// query constraints are ignored in the direction that over-reports. A
// query-constrained allow rule matches on method and path alone, and a
// query-constrained deny rule is skipped, so a conditional allow is never
// reported as unreachable and a conditional deny never shadows an allow.
func EvaluateStatic(rules []*CompiledRule, r *http.Request) (Action, int, string) {
	routePath, encodedScp := normalizedLibpodImageScpRoutePath(r)
	q := &requestQuery{static: true}
	action, index, reason, _ := evaluateRequestPolicyQuery(rules, r, q, NormalizePath(r.URL.Path), routePath, encodedScp)
	return action, index, reason
}

// FormatQuery renders the constraints in a stable, human-readable form for
// rule listings, e.g. `signal=USR1|SIGUSR1`. Empty when there are none.
func FormatQuery(query map[string][]string) string {
	if len(query) == 0 {
		return ""
	}
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strings.Join(query[key], "|"))
	}
	return strings.Join(parts, "&")
}
