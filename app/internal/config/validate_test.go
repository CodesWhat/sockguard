package config

import (
	"os"
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

func TestValidateRejectsCompleteButInvalidMutualTLSConfig(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	invalidCA := dir + "/invalid-ca.pem"
	if err := os.WriteFile(invalidCA, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := Defaults()
	cfg.Listen.Address = ":2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.CertFile = bundle.ServerCertFile
	cfg.Listen.TLS.KeyFile = bundle.ServerKeyFile
	cfg.Listen.TLS.ClientCAFile = invalidCA

	err = Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "no PEM certificates found") {
		t.Fatalf("expected TLS parse error, got: %v", err)
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

func TestValidateAllowsAbsoluteContainerCreateBindMountAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{"/srv/data", "/var/lib/sockguard"}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsRelativeContainerCreateBindMountAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{"srv/data"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for relative bind mount allowlist entry")
	}
	if !strings.Contains(err.Error(), "request_body.container_create.allowed_bind_mounts") {
		t.Fatalf("expected request_body.container_create.allowed_bind_mounts in error, got: %v", err)
	}
}

func TestValidateRejectsOwnershipWithoutOwner(t *testing.T) {
	cfg := Defaults()
	cfg.Ownership.Owner = "ci-job-123"
	cfg.Ownership.LabelKey = ""

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty ownership label key")
	}
	if !strings.Contains(err.Error(), "ownership.label_key") {
		t.Fatalf("expected ownership.label_key in error, got: %v", err)
	}
}

func TestValidateAllowsClientCIDRACLs(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8", "192.0.2.0/24"}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsInvalidClientCIDRACLs(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.AllowedCIDRs = []string{"definitely-not-a-cidr"}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid client CIDR")
	}
	if !strings.Contains(err.Error(), "clients.allowed_cidrs") {
		t.Fatalf("expected clients.allowed_cidrs in error, got: %v", err)
	}
}

func TestValidateRejectsEnabledClientContainerLabelsWithoutPrefix(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.ContainerLabels.Enabled = true
	cfg.Clients.ContainerLabels.LabelPrefix = ""

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty client container label prefix")
	}
	if !strings.Contains(err.Error(), "clients.container_labels.label_prefix") {
		t.Fatalf("expected clients.container_labels.label_prefix in error, got: %v", err)
	}
}

func TestValidateRejectsClientACLsOnUnixSocketListener(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
	cfg.Clients.ContainerLabels.Enabled = true

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for client ACLs on unix socket listener")
	}
	if !strings.Contains(err.Error(), "clients.allowed_cidrs") && !strings.Contains(err.Error(), "clients.container_labels") {
		t.Fatalf("expected client ACL error, got: %v", err)
	}
}

func TestNormalizeAllowedBindMount(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "empty", input: "", want: "", ok: false},
		{name: "relative", input: "srv/data", want: "", ok: false},
		{name: "root", input: "/", want: "/", ok: true},
		{name: "absolute clean", input: "/srv/data", want: "/srv/data", ok: true},
		{name: "absolute cleaned", input: "/srv/../srv/data", want: "/srv/data", ok: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeAllowedBindMount(tt.input)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("normalizeAllowedBindMount(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.ok)
			}
		})
	}
}
