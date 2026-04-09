package filter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestStripVersionPrefix(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "no prefix", path: "/containers/json", want: "/containers/json"},
		{name: "valid major version", path: "/v1/containers/json", want: "/containers/json"},
		{name: "valid major minor version", path: "/v1.45/containers/json", want: "/containers/json"},
		{name: "invalid missing digits after v", path: "/v/x", want: "/v/x"},
		{name: "invalid missing minor digits", path: "/v1./x", want: "/v1./x"},
		{name: "invalid no trailing slash", path: "/v1.45", want: "/v1.45"},
		{name: "version root path", path: "/v1.45/", want: "/"},
		{name: "double prefix strips only first", path: "/v1.45/v1.46/containers/json", want: "/v1.46/containers/json"},
		{name: "invalid prefix without slash after digits", path: "/v1x/containers/json", want: "/v1x/containers/json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripVersionPrefix(tt.path)
			if got != tt.want {
				t.Errorf("stripVersionPrefix(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestStripVersionPrefixMatchesLegacyRegex(t *testing.T) {
	legacyVersionPrefix := regexp.MustCompile(`^/v\d+(\.\d+)?/`)
	paths := []string{
		"",
		"/",
		"/containers/json",
		"/_ping",
		"/v/x",
		"/v1",
		"/v1/",
		"/v1/containers/json",
		"/v1.45",
		"/v1.45/",
		"/v1.45/containers/json",
		"/v1.45/_ping",
		"/v1.45/v1.46/containers/json",
		"/v1./x",
		"/v1..45/x",
		"/v.1/x",
		"/v1x/containers/json",
		"/v001.002/images/build",
		"/v999.0/../containers/json",
		"/version",
		"v1.45/containers/json",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			want := legacyVersionPrefix.ReplaceAllString(path, "/")
			got := stripVersionPrefix(path)
			if got != want {
				t.Errorf("stripVersionPrefix(%q) = %q, want legacy regex result %q", path, got, want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"no version prefix", "/containers/json", "/containers/json"},
		{"v1.45 prefix", "/v1.45/containers/json", "/containers/json"},
		{"v1 prefix", "/v1/containers/json", "/containers/json"},
		{"ping", "/_ping", "/_ping"},
		{"versioned ping", "/v1.45/_ping", "/_ping"},
		{"nested path", "/v1.47/containers/abc123/start", "/containers/abc123/start"},
		// Path traversal hardening
		{"dot-dot collapse", "/containers/../images/json", "/images/json"},
		{"dot-dot at root", "/../../etc/passwd", "/etc/passwd"},
		{"versioned dot-dot", "/v1.45/../containers/json", "/containers/json"},
		{"redundant slashes", "//containers///json", "/containers/json"},
		{"dot segment", "/containers/./json", "/containers/json"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePath(tt.path)
			if got != tt.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		pattern string
		match   string
		want    bool
	}{
		{"/containers/json", "/containers/json", true},
		{"/containers/json", "/containers/other", false},
		{"/containers/*", "/containers/json", true},
		{"/containers/*", "/containers/abc123", true},
		{"/containers/*", "/containers/abc/def", false},
		{"/containers/**", "/containers/json", true},
		{"/containers/**", "/containers/abc/start", true},
		{"/containers/**", "/containers/abc/def/ghi", true},
		// /** also matches the bare path (no trailing segment)
		{"/containers/**", "/containers", true},
		{"/networks/**", "/networks", true},
		{"/volumes/**", "/volumes", true},
		{"/**", "/anything/at/all", true},
		{"/**", "/", true},
		{"/_ping", "/_ping", true},
		{"/_ping", "/version", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"->"+tt.match, func(t *testing.T) {
			regex := "^" + globToRegex(tt.pattern) + "$"
			compiled := regexp.MustCompile(regex)
			got := compiled.MatchString(tt.match)
			if got != tt.want {
				t.Errorf("pattern %q match %q = %v, want %v", tt.pattern, tt.match, got, tt.want)
			}
		})
	}
}

func TestCompiledRuleMatches(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{"GET containers list", "GET", "/containers/json", true},
		{"GET container inspect", "GET", "/v1.45/containers/abc123/json", true},
		{"GET bare containers", "GET", "/containers", true},
		{"POST containers", "POST", "/containers/create", false},
		{"GET images", "GET", "/images/json", false},
		// Path traversal should be normalized before matching
		{"GET traversal escape", "GET", "/containers/../images/json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.Matches(tt.method, tt.path)
			if got != tt.want {
				t.Errorf("Matches(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestCompileRuleLiteralPatternUsesFastPath(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/_ping",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if rule.pattern != nil {
		t.Fatal("literal pattern should not compile a regexp")
	}
	if rule.literal != "/_ping" {
		t.Fatalf("literal = %q, want %q", rule.literal, "/_ping")
	}
	if !rule.Matches("GET", "/_ping") {
		t.Fatal("literal fast path should match exact path")
	}
	if !rule.Matches("GET", "/v1.45/_ping") {
		t.Fatal("literal fast path should match normalized versioned path")
	}
}

func TestCompileRuleRegexCompileError(t *testing.T) {
	originalCompile := regexpCompile
	regexpCompile = func(string) (*regexp.Regexp, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() {
		regexpCompile = originalCompile
	})

	_, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
	})
	if err == nil {
		t.Fatal("expected CompileRule() to fail when regexp compilation fails")
	}
}

func TestWildcardMethodRule(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"*"},
		Pattern: "/**",
		Action:  ActionDeny,
		Reason:  "catch-all deny",
		Index:   99,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if !rule.Matches("GET", "/anything") {
		t.Error("wildcard method should match GET")
	}
	if !rule.Matches("POST", "/anything") {
		t.Error("wildcard method should match POST")
	}
	if !rule.Matches("DELETE", "/anything") {
		t.Error("wildcard method should match DELETE")
	}
}

func TestEvaluate(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/containers/**", Action: ActionAllow, Index: 1})
	r3, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 2})
	rules := []*CompiledRule{r1, r2, r3}

	tests := []struct {
		name       string
		method     string
		path       string
		wantAction Action
		wantIndex  int
	}{
		{"ping allowed", "GET", "/_ping", ActionAllow, 0},
		{"containers allowed", "GET", "/v1.45/containers/json", ActionAllow, 1},
		{"POST denied", "POST", "/containers/create", ActionDeny, 2},
		{"images denied", "GET", "/images/json", ActionDeny, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			action, index, _ := Evaluate(rules, req)
			if action != tt.wantAction {
				t.Errorf("action = %v, want %v", action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Errorf("index = %d, want %d", index, tt.wantIndex)
			}
		})
	}
}

func TestMethodEdgeCases(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{"empty method", "", false},
		{"lowercase get", "get", true},
		{"method with leading space", " GET", false},
		{"method with trailing space", "GET ", false},
		{"method with surrounding spaces", " GET ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.Matches(tt.method, "/containers/json")
			if got != tt.want {
				t.Errorf("Matches(%q, /containers/json) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	action, index, reason := Evaluate(nil, req)

	if action != ActionDeny {
		t.Errorf("expected deny, got %v", action)
	}
	if index != -1 {
		t.Errorf("expected index -1, got %d", index)
	}
	if reason != "no matching allow rule" {
		t.Errorf("expected reason 'no matching allow rule', got %q", reason)
	}
}
