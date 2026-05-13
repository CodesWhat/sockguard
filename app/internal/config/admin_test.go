package config

import (
	"strings"
	"testing"
)

func TestDefaultsIncludesAdminBlock(t *testing.T) {
	d := Defaults()
	if d.Admin.Enabled {
		t.Fatalf("Admin.Enabled = true in defaults, want false (opt-in)")
	}
	if d.Admin.Path != "/admin/validate" {
		t.Fatalf("Admin.Path = %q, want %q", d.Admin.Path, "/admin/validate")
	}
	if d.Admin.MaxBodyBytes <= 0 {
		t.Fatalf("Admin.MaxBodyBytes = %d, want > 0", d.Admin.MaxBodyBytes)
	}
	if d.Admin.PolicyVersionPath != "/admin/policy/version" {
		t.Fatalf("Admin.PolicyVersionPath = %q, want %q", d.Admin.PolicyVersionPath, "/admin/policy/version")
	}
}

func TestValidateAdminRejectsRelativePolicyVersionPath(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.PolicyVersionPath = "admin/policy/version"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.policy_version_path must start with /") {
		t.Fatalf("Validate() = %v, want policy_version_path slash error", err)
	}
}

func TestValidateAdminRejectsPolicyVersionPathEqualsAdminPath(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.PolicyVersionPath = cfg.Admin.Path

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.policy_version_path must not equal admin.path") {
		t.Fatalf("Validate() = %v, want policy_version_path/admin.path collision error", err)
	}
}

func TestValidateAdminRejectsPolicyVersionPathConflictWithHealth(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.PolicyVersionPath = cfg.Health.Path

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.policy_version_path must not equal health.path") {
		t.Fatalf("Validate() = %v, want policy_version_path/health collision error", err)
	}
}

func TestValidateAdminRejectsPolicyVersionPathConflictWithMetrics(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Metrics.Enabled = true
	cfg.Admin.PolicyVersionPath = cfg.Metrics.Path

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.policy_version_path must not equal metrics.path") {
		t.Fatalf("Validate() = %v, want policy_version_path/metrics collision error", err)
	}
}

func TestValidateAdminRejectsRelativePath(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Path = "admin/validate"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.path must start with /") {
		t.Fatalf("Validate() = %v, want admin.path error", err)
	}
}

func TestValidateAdminRejectsNonPositiveMaxBody(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.MaxBodyBytes = 0

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.max_body_bytes must be > 0") {
		t.Fatalf("Validate() = %v, want max_body_bytes error", err)
	}
}

func TestValidateAdminRejectsConflictWithHealthPath(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Path = "/health"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.path must not equal health.path") {
		t.Fatalf("Validate() = %v, want admin/health conflict error", err)
	}
}

func TestValidateAdminRejectsConflictWithMetricsPath(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Metrics.Enabled = true
	cfg.Admin.Path = "/metrics"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.path must not equal metrics.path") {
		t.Fatalf("Validate() = %v, want admin/metrics conflict error", err)
	}
}

func TestValidateAdminAllowsDisabledMisconfig(t *testing.T) {
	// When Admin.Enabled=false, misconfigured path/body must not block
	// validation — operators commonly leave the block empty.
	cfg := Defaults()
	cfg.Admin.Enabled = false
	cfg.Admin.Path = ""
	cfg.Admin.MaxBodyBytes = 0

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil when admin disabled", err)
	}
}

func TestLoadBytesAppliesDefaultsForEmptyInput(t *testing.T) {
	cfg, err := LoadBytes(nil)
	if err != nil {
		t.Fatalf("LoadBytes(nil) = %v", err)
	}
	if cfg.Listen.Address != "127.0.0.1:2375" {
		t.Fatalf("Listen.Address = %q, want default", cfg.Listen.Address)
	}
	if len(cfg.Rules) == 0 {
		t.Fatalf("Rules empty, want default rule set")
	}
	if cfg.Admin.Path != "/admin/validate" {
		t.Fatalf("Admin.Path = %q, want default", cfg.Admin.Path)
	}
}

func TestLoadBytesOverridesDefaultsFromYAML(t *testing.T) {
	yaml := []byte(`
admin:
  enabled: true
  path: /custom/validate
  max_body_bytes: 1024
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`)
	cfg, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("LoadBytes() = %v", err)
	}
	if !cfg.Admin.Enabled {
		t.Fatalf("Admin.Enabled = false, want true")
	}
	if cfg.Admin.Path != "/custom/validate" {
		t.Fatalf("Admin.Path = %q, want /custom/validate", cfg.Admin.Path)
	}
	if cfg.Admin.MaxBodyBytes != 1024 {
		t.Fatalf("Admin.MaxBodyBytes = %d, want 1024", cfg.Admin.MaxBodyBytes)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("Rules = %d entries, want 1", len(cfg.Rules))
	}
}

func TestLoadBytesIgnoresSockguardEnv(t *testing.T) {
	// Set an env var that Load would honor; LoadBytes must NOT apply it,
	// because /admin/validate must judge the YAML as-written.
	t.Setenv("SOCKGUARD_LISTEN_ADDRESS", "0.0.0.0:9999")

	cfg, err := LoadBytes(nil)
	if err != nil {
		t.Fatalf("LoadBytes() = %v", err)
	}
	if cfg.Listen.Address != "127.0.0.1:2375" {
		t.Fatalf("Listen.Address = %q, want default (env ignored)", cfg.Listen.Address)
	}
}

func TestLoadBytesRejectsMalformedYAML(t *testing.T) {
	_, err := LoadBytes([]byte("rules: [oops"))
	if err == nil {
		t.Fatalf("LoadBytes(malformed) = nil, want error")
	}
}
