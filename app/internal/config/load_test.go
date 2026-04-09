package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Load with non-existent file — should return defaults
	cfg, err := Load("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	defaults := Defaults()
	if cfg.Listen.Socket != defaults.Listen.Socket {
		t.Errorf("Listen.Socket = %q, want %q", cfg.Listen.Socket, defaults.Listen.Socket)
	}
	if cfg.Upstream.Socket != defaults.Upstream.Socket {
		t.Errorf("Upstream.Socket = %q, want %q", cfg.Upstream.Socket, defaults.Upstream.Socket)
	}
	if cfg.Log.Level != defaults.Log.Level {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, defaults.Log.Level)
	}
	if cfg.Log.Format != defaults.Log.Format {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, defaults.Log.Format)
	}
	if cfg.Log.Output != defaults.Log.Output {
		t.Errorf("Log.Output = %q, want %q", cfg.Log.Output, defaults.Log.Output)
	}
	if cfg.Response.DenyVerbosity != defaults.Response.DenyVerbosity {
		t.Errorf("Response.DenyVerbosity = %q, want %q", cfg.Response.DenyVerbosity, defaults.Response.DenyVerbosity)
	}
	if len(cfg.Rules) != len(defaults.Rules) {
		t.Errorf("got %d rules, want %d", len(cfg.Rules), len(defaults.Rules))
	}
}

func TestLoadYAMLOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")

	yaml := `
upstream:
  socket: /custom/docker.sock
log:
  level: debug
response:
  deny_verbosity: minimal
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Upstream.Socket != "/custom/docker.sock" {
		t.Errorf("Upstream.Socket = %q, want /custom/docker.sock", cfg.Upstream.Socket)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.Response.DenyVerbosity != "minimal" {
		t.Errorf("Response.DenyVerbosity = %q, want minimal", cfg.Response.DenyVerbosity)
	}
	// YAML provided rules should override defaults
	if len(cfg.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(cfg.Rules))
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("SOCKGUARD_UPSTREAM_SOCKET", "/env/docker.sock")
	t.Setenv("SOCKGUARD_LOG_LEVEL", "warn")
	t.Setenv("SOCKGUARD_LOG_OUTPUT", "stdout")
	t.Setenv("SOCKGUARD_RESPONSE_DENY_VERBOSITY", "minimal")

	cfg, err := Load("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Upstream.Socket != "/env/docker.sock" {
		t.Errorf("Upstream.Socket = %q, want /env/docker.sock", cfg.Upstream.Socket)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("Log.Level = %q, want warn", cfg.Log.Level)
	}
	if cfg.Log.Output != "stdout" {
		t.Errorf("Log.Output = %q, want stdout", cfg.Log.Output)
	}
	if cfg.Response.DenyVerbosity != "minimal" {
		t.Errorf("Response.DenyVerbosity = %q, want minimal", cfg.Response.DenyVerbosity)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")

	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadEmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	// Should have defaults
	if cfg.Listen.Socket != Defaults().Listen.Socket {
		t.Errorf("expected default listen socket")
	}
}
