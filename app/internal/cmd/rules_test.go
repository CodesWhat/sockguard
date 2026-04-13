package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

func useRuleDeps(t *testing.T) {
	t.Helper()

	originalValidateConfig := validateConfig
	originalCompileFilterRule := compileFilterRule

	t.Cleanup(func() {
		validateConfig = originalValidateConfig
		compileFilterRule = originalCompileFilterRule
	})
}

func TestValidateAndCompileRulesReturnsCompiledRules(t *testing.T) {
	cfg := config.Defaults()

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsContainerCreateWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsBodySensitiveWriteRulesWithExplicitOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.InsecureAllowBodyBlindWrites = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesRejectsBroadContainerWriteRulesWithoutExplicitOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/containers/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected broad container write validation to fail")
	}
	if !strings.Contains(err.Error(), "POST /containers/sockguard-test/exec") {
		t.Fatalf("expected exec endpoint in error, got: %v", err)
	}
	if strings.Contains(err.Error(), "POST /containers/create") {
		t.Fatalf("did not expect create endpoint in error once request body inspection exists, got: %v", err)
	}
}

func TestCompileConfiguredRulesCommaSeparatedMethods(t *testing.T) {
	compiled, err := compileConfiguredRules([]config.RuleConfig{{
		Match:  config.MatchConfig{Method: "POST,PUT,DELETE", Path: "/**"},
		Action: "deny",
	}})
	if err != nil {
		t.Fatalf("compileConfiguredRules() error = %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled %d rules, want 1", len(compiled))
	}
	req := httptest.NewRequest(http.MethodDelete, "/containers/test", nil)
	action, _, _ := filter.Evaluate(compiled, req)
	if action != filter.ActionDeny {
		t.Fatalf("action = %v, want %v", action, filter.ActionDeny)
	}
}

func TestCompileConfiguredRulesHonorsFirstMatchWinsForOverlappingAllowAndDenyRules(t *testing.T) {
	cases := []struct {
		name    string
		rules   []config.RuleConfig
		want    filter.Action
		wantIdx int
	}{
		{
			name: "allow before deny",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/json"}, Action: "deny"},
			},
			want:    filter.ActionAllow,
			wantIdx: 0,
		},
		{
			name: "deny before allow",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/json"}, Action: "deny"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
			},
			want:    filter.ActionDeny,
			wantIdx: 0,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := compileConfiguredRules(tt.rules)
			if err != nil {
				t.Fatalf("compileConfiguredRules() error = %v", err)
			}

			action, index, _ := filter.Evaluate(compiled, req)
			if action != tt.want {
				t.Fatalf("action = %v, want %v", action, tt.want)
			}
			if index != tt.wantIdx {
				t.Fatalf("index = %d, want %d", index, tt.wantIdx)
			}
		})
	}
}

func TestSplitMethodsHandlesEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty string", in: "", want: []string{}},
		{name: "whitespace only", in: "  \t  ", want: []string{}},
		{name: "trailing comma", in: "GET,", want: []string{"GET"}},
		{name: "adjacent whitespace", in: "GET, PUT", want: []string{"GET", "PUT"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := splitMethods(tt.in)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("splitMethods(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestCompileConfiguredRulesWrapsRuleError(t *testing.T) {
	useRuleDeps(t)

	compileFilterRule = func(filter.Rule) (*filter.CompiledRule, error) {
		return nil, errors.New("boom")
	}

	_, err := compileConfiguredRules([]config.RuleConfig{{
		Match:  config.MatchConfig{Method: http.MethodGet, Path: "/_ping"},
		Action: "allow",
	}})
	if err == nil {
		t.Fatal("expected compileConfiguredRules() to fail")
	}
	if !strings.Contains(err.Error(), "rule 1: boom") {
		t.Fatalf("expected wrapped rule error, got: %v", err)
	}
}

func TestValidateAndCompileRulesReturnsConfigValidationError(t *testing.T) {
	useRuleDeps(t)

	validateConfig = func(*config.Config) error {
		return errors.New("boom")
	}

	cfg := config.Defaults()
	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected validateAndCompileRules() to fail")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected config validation error, got: %v", err)
	}
}

func TestValidateAndCompileRulesReturnsCompileError(t *testing.T) {
	useRuleDeps(t)

	validateConfig = func(*config.Config) error {
		return nil
	}
	compileFilterRule = func(filter.Rule) (*filter.CompiledRule, error) {
		return nil, errors.New("boom")
	}

	cfg := config.Defaults()
	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected validateAndCompileRules() to fail")
	}
	if !strings.Contains(err.Error(), "rule 1: boom") {
		t.Fatalf("expected wrapped compile error, got: %v", err)
	}
}
