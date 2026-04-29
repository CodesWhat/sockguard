package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
			name:    "double encoded slash canonicalizes before normalization",
			rawPath: "/containers%252Fjson",
			want:    "/containers/json",
		},
		{
			name:    "single encoded dot-dot collapses after one decode",
			rawPath: "/containers/%2e%2e/images/json",
			want:    "/images/json",
		},
		{
			name:    "double encoded dot-dot collapses before normalization",
			rawPath: "/containers/%252e%252e/images/json",
			want:    "/images/json",
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

func TestNormalizePathUnicodeEncoding(t *testing.T) {
	tests := []struct {
		name    string
		rawPath string
		want    string
	}{
		{
			name:    "single encoded cjk segment stays decoded",
			rawPath: "/%E6%97%A5%E6%9C%AC/containers/json",
			want:    "/日本/containers/json",
		},
		{
			name:    "double encoded cyrillic segment canonicalizes before normalization",
			rawPath: "/%25D1%2582%25D0%25B5%25D1%2581%25D1%2582/images/json",
			want:    "/тест/images/json",
		},
		{
			name:    "versioned double encoded arabic segment strips prefix after decode",
			rawPath: "/v1.45/%25D9%2585%25D8%25B1%25D8%25AD%25D8%25A8%25D8%25A7/json",
			want:    "/مرحبا/json",
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
			name:       "double encoded slash canonicalizes into the containers allow rule",
			rules:      containerRules,
			rawPath:    "/containers%252Fjson",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			name:       "single encoded dot-dot normalizes to the actual target path once",
			rules:      imageRules,
			rawPath:    "/containers/%2e%2e/images/json",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			name:       "double encoded dot-dot canonicalizes into the target allow rule",
			rules:      imageRules,
			rawPath:    "/containers/%252e%252e/images/json",
			wantAction: ActionAllow,
			wantIndex:  0,
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

func TestContainerCreatePolicyInspectCanonicalizesDoubleEncodedPath(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"http://example.com/containers%252Fcreate",
		strings.NewReader(`{"HostConfig":{"Privileged":true}}`),
	)
	policy := newContainerCreatePolicy(ContainerCreateOptions{})

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "container create denied: privileged containers are not allowed" {
		t.Fatalf("inspect() reason = %q, want privileged denial", reason)
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
			got := rule.matches(tt.method, "/containers/json")
			if got != tt.want {
				t.Fatalf("matches(%q, /containers/json) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestEvaluateNullBytePathBypassResistance(t *testing.T) {
	rules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/containers/json", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		rawPath    string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "encoded null appended to literal path does not bypass allow rule",
			rawPath:    "/containers/json%00/extra",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "encoded null inside path segment does not bypass allow rule",
			rawPath:    "/containers%00/json",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "encoded null in nested segment does not bypass allow rule",
			rawPath:    "/containers/%00/json",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			action, index, _ := Evaluate(rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate(%q) action = %v, want %v", tt.rawPath, action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate(%q) index = %d, want %d", tt.rawPath, index, tt.wantIndex)
			}
			if got := NormalizePath(req.URL.Path); got == "/containers/json" {
				t.Fatalf("NormalizePath(%q) = %q, want null byte to remain non-matching", tt.rawPath, got)
			}
		})
	}
}

func TestEvaluateIgnoresMethodOverrideHeaders(t *testing.T) {
	rules := compileRulesForTest(t, []Rule{
		{Methods: []string{"POST"}, Pattern: "/containers/create", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		headerName string
		headerVal  string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "x http method override is ignored",
			headerName: "X-HTTP-Method-Override",
			headerVal:  http.MethodPost,
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "x method override is ignored",
			headerName: "X-Method-Override",
			headerVal:  http.MethodPost,
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, "/containers/create")
			req.Header.Set(tt.headerName, tt.headerVal)

			action, index, _ := Evaluate(rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate() action = %v, want %v", action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate() index = %d, want %d", index, tt.wantIndex)
			}
		})
	}
}
