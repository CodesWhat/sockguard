package filter

import (
	"net/http/httptest"
	"testing"
)

// Realistic rule basket modeling a production-ish policy:
// several allow rules with nested globs, Docker API version prefixes,
// and a final default-deny.
func buildRealisticRules(tb testing.TB) []*CompiledRule {
	tb.Helper()
	specs := []Rule{
		{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0},
		{Methods: []string{"GET"}, Pattern: "/version", Action: ActionAllow, Index: 1},
		{Methods: []string{"GET"}, Pattern: "/info", Action: ActionAllow, Index: 2},
		{Methods: []string{"GET"}, Pattern: "/events", Action: ActionAllow, Index: 3},
		{Methods: []string{"GET"}, Pattern: "/containers/json", Action: ActionAllow, Index: 4},
		{Methods: []string{"GET"}, Pattern: "/containers/*/json", Action: ActionAllow, Index: 5},
		{Methods: []string{"GET"}, Pattern: "/containers/*/logs", Action: ActionAllow, Index: 6},
		{Methods: []string{"GET"}, Pattern: "/containers/*/stats", Action: ActionAllow, Index: 7},
		{Methods: []string{"GET"}, Pattern: "/containers/*/top", Action: ActionAllow, Index: 8},
		{Methods: []string{"GET"}, Pattern: "/images/json", Action: ActionAllow, Index: 9},
		{Methods: []string{"GET"}, Pattern: "/images/*/json", Action: ActionAllow, Index: 10},
		{Methods: []string{"GET"}, Pattern: "/networks/**", Action: ActionAllow, Index: 11},
		{Methods: []string{"GET"}, Pattern: "/volumes/**", Action: ActionAllow, Index: 12},
		{Methods: []string{"POST"}, Pattern: "/containers/create", Action: ActionAllow, Index: 13},
		{Methods: []string{"POST"}, Pattern: "/containers/*/start", Action: ActionAllow, Index: 14},
		{Methods: []string{"POST"}, Pattern: "/containers/*/stop", Action: ActionAllow, Index: 15},
		{Methods: []string{"POST"}, Pattern: "/containers/*/restart", Action: ActionAllow, Index: 16},
		{Methods: []string{"POST"}, Pattern: "/containers/*/kill", Action: ActionAllow, Index: 17},
		{Methods: []string{"POST"}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 18},
		{Methods: []string{"POST"}, Pattern: "/exec/*/start", Action: ActionAllow, Index: 19},
		{Methods: []string{"POST"}, Pattern: "/build", Action: ActionAllow, Index: 20},
		{Methods: []string{"DELETE"}, Pattern: "/containers/*", Action: ActionAllow, Index: 21},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 22},
	}
	rules := make([]*CompiledRule, len(specs))
	for i, s := range specs {
		cr, err := CompileRule(s)
		if err != nil {
			tb.Fatalf("compile rule %d: %v", i, err)
		}
		rules[i] = cr
	}
	return rules
}

// Warm match: pre-compiled rules, realistic basket of paths.
func BenchmarkEvaluateRealisticBasket(b *testing.B) {
	rules := buildRealisticRules(b)
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"containers_json_bare", "GET", "/containers/json"},
		{"containers_json_versioned", "GET", "/v1.45/containers/json"},
		{"containers_exec", "POST", "/containers/abc123def456/exec"},
		{"exec_start", "POST", "/exec/xxxxxxxx/start"},
		{"build", "POST", "/build"},
		{"events", "GET", "/events"},
		{"networks_deep", "GET", "/networks/user-defined-overlay-42/endpoints/abc"},
		{"volumes_deep", "GET", "/volumes/some-volume/members/deeply/nested"},
		{"deny_fallthrough", "DELETE", "/secrets/foo"},
		{"ping_first_rule", "GET", "/_ping"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			norm := NormalizePath(c.path)
			for b.Loop() {
				evaluateNormalized(rules, c.method, norm)
			}
		})
	}
}

// Cold-compile: cost of compiling the realistic rule set from scratch.
func BenchmarkCompileRealisticBasket(b *testing.B) {
	specs := []Rule{
		{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow},
		{Methods: []string{"GET"}, Pattern: "/version", Action: ActionAllow},
		{Methods: []string{"GET"}, Pattern: "/info", Action: ActionAllow},
		{Methods: []string{"GET"}, Pattern: "/containers/*/json", Action: ActionAllow},
		{Methods: []string{"GET"}, Pattern: "/containers/*/logs", Action: ActionAllow},
		{Methods: []string{"GET"}, Pattern: "/networks/**", Action: ActionAllow},
		{Methods: []string{"GET"}, Pattern: "/volumes/**", Action: ActionAllow},
		{Methods: []string{"POST"}, Pattern: "/containers/*/start", Action: ActionAllow},
		{Methods: []string{"POST"}, Pattern: "/containers/*/exec", Action: ActionAllow},
		{Methods: []string{"POST"}, Pattern: "/exec/*/start", Action: ActionAllow},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny},
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, s := range specs {
			if _, err := CompileRule(s); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// Adversarial NormalizePath inputs: many segments, traversal, long paths.
func BenchmarkNormalizePathAdversarial(b *testing.B) {
	cases := []struct {
		name string
		path string
	}{
		{"long_versioned", "/v1.45/containers/abc123def456ghi789jkl012mno345pqr678/exec/0123456789abcdef/start"},
		{"many_traversals", "/v1.45/containers/../../../../../etc/passwd"},
		{"deeply_nested", "/v1.45/networks/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t"},
		{"double_slashes", "/v1.45//containers////json"},
		{"no_prefix_long", "/containers/abc123def456ghi789/exec/0123456789abcdef/start"},
		{"short_clean", "/_ping"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				NormalizePath(c.path)
			}
		})
	}
}

// Cold Evaluate() measures cost of http.Request wrapping + normalize + eval.
func BenchmarkEvaluateRequest(b *testing.B) {
	rules := buildRealisticRules(b)
	req := httptest.NewRequest("GET", "/v1.45/containers/json", nil)
	b.ReportAllocs()
	for b.Loop() {
		Evaluate(rules, req)
	}
}

// Glob-to-regex for deeply-nested double-star patterns.
func BenchmarkGlobToRegexDeep(b *testing.B) {
	patterns := []string{
		"/a/**",
		"/a/*/b/*/c/*/d",
		"/a/**/b/**/c/**",
		"/v1.*/containers/*/exec/*/start",
	}
	for _, p := range patterns {
		b.Run(p, func(b *testing.B) {
			for b.Loop() {
				globToRegex(p)
			}
		})
	}
}
