package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzLoadYAML(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("listen:\n  address: 127.0.0.1:2375\n"))
	f.Add([]byte("rules:\n  - match: { method: GET, path: /_ping }\n    action: allow\n"))
	f.Add([]byte("rules: definitely-not-a-list\n"))

	f.Fuzz(func(t *testing.T, yaml []byte) {
		restoreEnv := snapshotSockguardEnv(t)
		defer restoreEnv()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(cfgPath, yaml, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		_, _ = Load(cfgPath)
	})
}

func snapshotSockguardEnv(t *testing.T) func() {
	t.Helper()

	type envVar struct {
		name    string
		value   string
		present bool
	}

	var saved []envVar
	for _, kv := range os.Environ() {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, "SOCKGUARD_") {
			continue
		}
		saved = append(saved, envVar{name: name, value: value, present: true})
	}

	return func() {
		for _, kv := range os.Environ() {
			name, _, ok := strings.Cut(kv, "=")
			if ok && strings.HasPrefix(name, "SOCKGUARD_") {
				_ = os.Unsetenv(name)
			}
		}
		for _, env := range saved {
			if env.present {
				_ = os.Setenv(env.name, env.value)
			}
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	// Load with non-existent file — should return defaults
	cfg, err := Load("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	defaults := Defaults()

	// The default listener must stay loopback-only so the built-in config is safe
	// without exposing the Docker API proxy on the network.
	if defaults.Listen.Address != "127.0.0.1:2375" {
		t.Errorf("Defaults().Listen.Address = %q, want %q", defaults.Listen.Address, "127.0.0.1:2375")
	}
	if defaults.Listen.Socket != "" {
		t.Errorf("Defaults().Listen.Socket = %q, want empty (opt-in only)", defaults.Listen.Socket)
	}

	if cfg.Listen.Socket != defaults.Listen.Socket {
		t.Errorf("Listen.Socket = %q, want %q", cfg.Listen.Socket, defaults.Listen.Socket)
	}
	if cfg.Listen.Address != defaults.Listen.Address {
		t.Errorf("Listen.Address = %q, want %q", cfg.Listen.Address, defaults.Listen.Address)
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

func TestLoadExplicitDefaultRulesDoNotTriggerCompat(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "default-rules.yaml")

	yaml := `
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: HEAD, path: "/_ping" }
    action: allow
  - match: { method: GET, path: "/version" }
    action: allow
  - match: { method: GET, path: "/events" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
    reason: no matching allow rule
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	t.Setenv("CONTAINERS", "1")

	if ApplyCompat(cfg, discardLogger) {
		t.Fatal("expected explicit rules from YAML to suppress compat mode")
	}

	if len(cfg.Rules) != len(Defaults().Rules) {
		t.Fatalf("got %d rules after compat check, want %d", len(cfg.Rules), len(Defaults().Rules))
	}

	for i, rule := range cfg.Rules {
		if rule != Defaults().Rules[i] {
			t.Fatalf("rule %d changed after compat check: got %+v want %+v", i, rule, Defaults().Rules[i])
		}
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("SOCKGUARD_LISTEN_ADDRESS", "0.0.0.0:1234")
	t.Setenv("SOCKGUARD_LISTEN_SOCKET", "/env/sockguard.sock")
	t.Setenv("SOCKGUARD_UPSTREAM_SOCKET", "/env/docker.sock")
	t.Setenv("SOCKGUARD_LOG_LEVEL", "warn")
	t.Setenv("SOCKGUARD_LOG_OUTPUT", "stdout")
	t.Setenv("SOCKGUARD_RESPONSE_DENY_VERBOSITY", "minimal")
	t.Setenv("SOCKGUARD_LISTEN_INSECURE_ALLOW_PLAIN_TCP", "true")
	t.Setenv("SOCKGUARD_LISTEN_TLS_CERT_FILE", "/env/server-cert.pem")
	t.Setenv("SOCKGUARD_LISTEN_TLS_KEY_FILE", "/env/server-key.pem")
	t.Setenv("SOCKGUARD_LISTEN_TLS_CLIENT_CA_FILE", "/env/ca.pem")
	t.Setenv("SOCKGUARD_INSECURE_ALLOW_BODY_BLIND_WRITES", "true")

	cfg, err := Load("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Upstream.Socket != "/env/docker.sock" {
		t.Errorf("Upstream.Socket = %q, want /env/docker.sock", cfg.Upstream.Socket)
	}
	if cfg.Listen.Address != "0.0.0.0:1234" {
		t.Errorf("Listen.Address = %q, want 0.0.0.0:1234", cfg.Listen.Address)
	}
	if cfg.Listen.Socket != "/env/sockguard.sock" {
		t.Errorf("Listen.Socket = %q, want /env/sockguard.sock", cfg.Listen.Socket)
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
	if !cfg.Listen.InsecureAllowPlainTCP {
		t.Errorf("Listen.InsecureAllowPlainTCP = %v, want true", cfg.Listen.InsecureAllowPlainTCP)
	}
	if cfg.Listen.TLS.CertFile != "/env/server-cert.pem" {
		t.Errorf("Listen.TLS.CertFile = %q, want /env/server-cert.pem", cfg.Listen.TLS.CertFile)
	}
	if cfg.Listen.TLS.KeyFile != "/env/server-key.pem" {
		t.Errorf("Listen.TLS.KeyFile = %q, want /env/server-key.pem", cfg.Listen.TLS.KeyFile)
	}
	if cfg.Listen.TLS.ClientCAFile != "/env/ca.pem" {
		t.Errorf("Listen.TLS.ClientCAFile = %q, want /env/ca.pem", cfg.Listen.TLS.ClientCAFile)
	}
	if !cfg.InsecureAllowBodyBlindWrites {
		t.Errorf("InsecureAllowBodyBlindWrites = %v, want true", cfg.InsecureAllowBodyBlindWrites)
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

func TestLoadReadConfigError(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error when config path is a directory")
	}
}

func TestLoadUnmarshalError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad-types.yaml")

	yaml := `
rules: definitely-not-a-list
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected unmarshal error for invalid rules type")
	}
}
