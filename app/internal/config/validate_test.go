package config

import (
	"strings"
	"testing"
)

func TestValidateDefaults(t *testing.T) {
	cfg := Defaults()
	if err := Validate(&cfg); err != nil {
		t.Errorf("Validate(Defaults()) = %v, want nil", err)
	}
}

func TestValidateMissingUpstream(t *testing.T) {
	cfg := Defaults()
	cfg.Upstream.Socket = ""
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for missing upstream")
	}
	if !strings.Contains(err.Error(), "upstream.socket") {
		t.Errorf("error should mention upstream.socket, got: %v", err)
	}
}

func TestValidateMissingListeners(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = ""
	cfg.Listen.Address = ""
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for missing listeners")
	}
	if !strings.Contains(err.Error(), "listener") {
		t.Errorf("error should mention listener, got: %v", err)
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Level = "verbose"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
	if !strings.Contains(err.Error(), "log level") {
		t.Errorf("error should mention log level, got: %v", err)
	}
}

func TestValidateInvalidLogFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Format = "xml"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid log format")
	}
	if !strings.Contains(err.Error(), "log format") {
		t.Errorf("error should mention log format, got: %v", err)
	}
}

func TestValidateInvalidLogOutput(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Output = "   "
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid log output")
	}
	if !strings.Contains(err.Error(), "log output") {
		t.Errorf("error should mention log output, got: %v", err)
	}
}

func TestValidateRejectsNonLocalLogOutputPath(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Output = "../sockguard.log"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for non-local log output path")
	}
	if !strings.Contains(err.Error(), "local file path") {
		t.Errorf("error should mention local file path validation, got: %v", err)
	}
}

func TestValidateEmptyRules(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = nil
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
	if !strings.Contains(err.Error(), "rule") {
		t.Errorf("error should mention rule, got: %v", err)
	}
}

func TestValidateInvalidAction(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleConfig{
		{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "permit"},
	}
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
	if !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("error should mention invalid action, got: %v", err)
	}
}

func TestValidateInvalidHealthPath(t *testing.T) {
	cfg := Defaults()
	cfg.Health.Path = "health"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid health path")
	}
	if !strings.Contains(err.Error(), "health path") {
		t.Errorf("error should mention health path, got: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := Defaults()
	cfg.Upstream.Socket = ""
	cfg.Log.Level = "verbose"
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Errors) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(ve.Errors))
	}
}

func TestValidateCommaSeparatedMethods(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleConfig{
		{Match: MatchConfig{Method: "GET,HEAD", Path: "/containers/**"}, Action: "allow"},
		{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	if err := Validate(&cfg); err != nil {
		t.Errorf("Validate() = %v, want nil for comma-separated methods", err)
	}
}

func TestCompileRules(t *testing.T) {
	rules := Defaults().Rules
	compiled, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("CompileRules() error = %v", err)
	}
	if len(compiled) != len(rules) {
		t.Errorf("got %d compiled rules, want %d", len(compiled), len(rules))
	}
}

func TestCompileRulesCommaSeparated(t *testing.T) {
	rules := []RuleConfig{
		{Match: MatchConfig{Method: "POST,PUT,DELETE", Path: "/**"}, Action: "deny"},
	}
	compiled, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("CompileRules() error = %v", err)
	}
	if len(compiled) != 1 {
		t.Errorf("got %d rules, want 1", len(compiled))
	}
}

func TestValidateAndCompile(t *testing.T) {
	cfg := Defaults()

	compiled, err := ValidateAndCompile(&cfg)
	if err != nil {
		t.Fatalf("ValidateAndCompile() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Errorf("got %d compiled rules, want %d", len(compiled), len(cfg.Rules))
	}
}
