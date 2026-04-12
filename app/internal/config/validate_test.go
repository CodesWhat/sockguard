package config

import (
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/testcert"
)

func TestValidateDefaults(t *testing.T) {
	cfg := Defaults()
	if err := Validate(&cfg); err != nil {
		t.Errorf("Validate(Defaults()) = %v, want nil", err)
	}
}

func TestValidateRejectsNonLoopbackPlainTCPWithoutExplicitInsecureOptIn(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = ":2375"
	cfg.Listen.Socket = ""

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for non-loopback plaintext TCP")
	}
	if !strings.Contains(err.Error(), "listen.tls") {
		t.Fatalf("expected mTLS requirement in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "listen.insecure_allow_plain_tcp") {
		t.Fatalf("expected insecure opt-in hint in error, got: %v", err)
	}
}

func TestValidateAllowsNonLoopbackPlainTCPWithExplicitInsecureOptIn(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = ":2375"
	cfg.Listen.Socket = ""
	cfg.Listen.InsecureAllowPlainTCP = true

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsIncompleteMutualTLSConfig(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = ":2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.CertFile = "/tmp/server-cert.pem"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for incomplete listen.tls config")
	}
	if !strings.Contains(err.Error(), "listen.tls") {
		t.Fatalf("expected listen.tls error, got: %v", err)
	}
}

func TestValidateAcceptsNonLoopbackTCPWithMutualTLS(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cfg := Defaults()
	cfg.Listen.Address = ":2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.CertFile = bundle.ServerCertFile
	cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
	cfg.Listen.TLS.ClientCAFile = bundle.CAFile

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
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
	cfg.Rules = []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "permit"}}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
	if !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("error should mention invalid action, got: %v", err)
	}
}

func TestValidateMissingRuleFields(t *testing.T) {
	cfg := Defaults()
	cfg.Rules = []RuleConfig{{Match: MatchConfig{Method: "", Path: ""}, Action: "allow"}}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for missing rule fields")
	}
	if !strings.Contains(err.Error(), "match.method is required") {
		t.Fatalf("error should mention missing match.method, got: %v", err)
	}
	if !strings.Contains(err.Error(), "match.path is required") {
		t.Fatalf("error should mention missing match.path, got: %v", err)
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

func TestValidateInvalidDenyResponseVerbosity(t *testing.T) {
	cfg := Defaults()
	cfg.Response.DenyVerbosity = "chatty"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid deny response verbosity")
	}
	if !strings.Contains(err.Error(), "deny response verbosity") {
		t.Errorf("error should mention deny response verbosity, got: %v", err)
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
