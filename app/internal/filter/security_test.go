package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func compileRulesForTest(t *testing.T, rules []Rule) []*CompiledRule {
	t.Helper()

	compiled := make([]*CompiledRule, 0, len(rules))
	for _, rule := range rules {
		cr, err := CompileRule(rule)
		if err != nil {
			t.Fatalf("CompileRule(%+v) failed: %v", rule, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled
}

func newParsedRequest(t *testing.T, method, rawPath string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, "http://example.com"+rawPath, nil)
}

func TestNormalizePathAdversarialEncodings(t *testing.T) {
	tests := []struct {
		name    string
		rawPath string
		want    string
	}{
		{
			name:    "single encoded slash decodes once at the HTTP boundary",
			rawPath: "/containers%2Fjson",
			want:    "/containers/json",
		},
		{
			name:    "double encoded slash remains encoded after normalization",
			rawPath: "/containers%252Fjson",
			want:    "/containers%2Fjson",
		},
		{
			name:    "single encoded dot-dot collapses after one decode",
			rawPath: "/containers/%2e%2e/images/json",
			want:    "/images/json",
		},
		{
			name:    "double encoded dot-dot does not collapse via double decoding",
			rawPath: "/containers/%252e%252e/images/json",
			want:    "/containers/%2e%2e/images/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			got := NormalizePath(req.URL.Path)
			if got != tt.want {
				t.Fatalf("NormalizePath(parsed %q) = %q, want %q", tt.rawPath, got, tt.want)
			}
		})
	}
}

func TestEvaluateEncodedPathBypassResistance(t *testing.T) {
	containerRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/containers/**", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})
	imageRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/images/**", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		rules      []*CompiledRule
		rawPath    string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "single encoded slash matches the slash-delimited allow rule after one decode",
			rules:      containerRules,
			rawPath:    "/containers%2Fjson",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			name:       "double encoded slash does not bypass into the containers allow rule",
			rules:      containerRules,
			rawPath:    "/containers%252Fjson",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "single encoded dot-dot normalizes to the actual target path once",
			rules:      imageRules,
			rawPath:    "/containers/%2e%2e/images/json",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			name:       "double encoded dot-dot does not bypass into the images allow rule",
			rules:      imageRules,
			rawPath:    "/containers/%252e%252e/images/json",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			action, index, _ := Evaluate(tt.rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate(%q) action = %v, want %v", tt.rawPath, action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate(%q) index = %d, want %d", tt.rawPath, index, tt.wantIndex)
			}
		})
	}
}

func TestEvaluateUnicodeNormalizationBypassResistance(t *testing.T) {
	precomposedRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/caf\u00e9", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})
	decomposedRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/cafe\u0301", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		rules      []*CompiledRule
		rawPath    string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "precomposed path matches the precomposed allow rule",
			rules:      precomposedRules,
			rawPath:    "/caf%C3%A9",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			name:       "decomposed path does not bypass a visually equivalent precomposed allow rule",
			rules:      precomposedRules,
			rawPath:    "/cafe\u0301",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "precomposed path does not bypass a visually equivalent decomposed allow rule",
			rules:      decomposedRules,
			rawPath:    "/caf%C3%A9",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			action, index, _ := Evaluate(tt.rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate(%q) action = %v, want %v", tt.rawPath, action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate(%q) index = %d, want %d", tt.rawPath, index, tt.wantIndex)
			}
		})
	}
}

func TestConfiguredMethodCaseNormalization(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"gEt", "PoSt"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   0,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{name: "uppercase GET", method: "GET", want: true},
		{name: "mixed case GET", method: "gEt", want: true},
		{name: "lowercase POST", method: "post", want: true},
		{name: "mixed case POST", method: "pOsT", want: true},
		{name: "unlisted method stays denied", method: "DeLeTe", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.Matches(tt.method, "/containers/json")
			if got != tt.want {
				t.Fatalf("Matches(%q, /containers/json) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}
