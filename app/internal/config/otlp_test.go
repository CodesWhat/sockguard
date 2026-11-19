package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func enabledOTLP() Config {
	cfg := Defaults()
	cfg.OTLP.Enabled = true
	cfg.OTLP.Endpoint = "https://collector.example:4318/v1/traces"
	return cfg
}

func TestOTLPDefaults(t *testing.T) {
	got := Defaults().OTLP
	want := OTLPConfig{
		Headers:       map[string]string{},
		Timeout:       "5s",
		QueueSize:     2048,
		BatchSize:     256,
		FlushInterval: "2s",
		SampleRatio:   1.0,
		ServiceName:   "sockguard",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OTLP defaults = %+v, want %+v", got, want)
	}
	cfg := Defaults()
	if err := Validate(&cfg); err != nil {
		t.Fatalf("default config (otlp disabled, empty endpoint) must validate: %v", err)
	}
}

func TestValidateOTLP(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string // substring; empty means valid
	}{
		{"valid https", func(c *Config) {}, ""},
		{"valid http", func(c *Config) { c.OTLP.Endpoint = "http://collector:4318/v1/traces" }, ""},
		{"valid ca file", func(c *Config) { c.OTLP.TLS.CAFile = caFile }, ""},
		{"valid headers", func(c *Config) { c.OTLP.Headers = map[string]string{"x-api-key": "k", "Authorization": "Bearer t"} }, ""},
		{"disabled skips checks", func(c *Config) { c.OTLP.Enabled = false; c.OTLP.Endpoint = "::bad"; c.OTLP.QueueSize = -1 }, ""},
		{"empty endpoint", func(c *Config) { c.OTLP.Endpoint = "" }, "otlp.endpoint must be an absolute http or https URL"},
		{"relative endpoint", func(c *Config) { c.OTLP.Endpoint = "/v1/traces" }, "otlp.endpoint must be an absolute"},
		{"wrong scheme", func(c *Config) { c.OTLP.Endpoint = "grpc://collector:4317" }, "otlp.endpoint must be an absolute"},
		{"no host", func(c *Config) { c.OTLP.Endpoint = "https:///v1/traces" }, "otlp.endpoint must be an absolute"},
		{"userinfo", func(c *Config) { c.OTLP.Endpoint = "https://user:pw@collector/v1/traces" }, "must not contain userinfo"},
		{"bad timeout", func(c *Config) { c.OTLP.Timeout = "soon" }, "otlp.timeout must be a positive duration"},
		{"zero timeout", func(c *Config) { c.OTLP.Timeout = "0s" }, "otlp.timeout must be a positive duration"},
		{"bad flush", func(c *Config) { c.OTLP.FlushInterval = "-1s" }, "otlp.flush_interval must be a positive duration"},
		{"queue zero", func(c *Config) { c.OTLP.QueueSize = 0 }, "otlp.queue_size must be between 1 and 65536"},
		{"queue too big", func(c *Config) { c.OTLP.QueueSize = 65537 }, "otlp.queue_size must be between 1 and 65536"},
		{"queue max ok", func(c *Config) { c.OTLP.QueueSize = 65536 }, ""},
		{"batch zero", func(c *Config) { c.OTLP.BatchSize = 0 }, "otlp.batch_size"},
		{"batch over queue", func(c *Config) { c.OTLP.QueueSize = 10; c.OTLP.BatchSize = 11 }, "otlp.batch_size"},
		{"ratio negative", func(c *Config) { c.OTLP.SampleRatio = -0.1 }, "otlp.sample_ratio must be between 0 and 1"},
		{"ratio over one", func(c *Config) { c.OTLP.SampleRatio = 1.5 }, "otlp.sample_ratio must be between 0 and 1"},
		{"ratio zero ok", func(c *Config) { c.OTLP.SampleRatio = 0 }, ""},
		{"header name space", func(c *Config) { c.OTLP.Headers = map[string]string{"bad name": "v"} }, "invalid header name"},
		{"header name empty", func(c *Config) { c.OTLP.Headers = map[string]string{"": "v"} }, "invalid header name"},
		{"header value LF", func(c *Config) { c.OTLP.Headers = map[string]string{"authorization": "Bearer t\n"} }, "has an invalid header value"},
		{"header value CR", func(c *Config) { c.OTLP.Headers = map[string]string{"authorization": "a\rb"} }, "has an invalid header value"},
		{"header value NUL", func(c *Config) { c.OTLP.Headers = map[string]string{"authorization": "a\x00b"} }, "has an invalid header value"},
		{"header value DEL", func(c *Config) { c.OTLP.Headers = map[string]string{"authorization": "a\x7fb"} }, "has an invalid header value"},
		{"header value tab ok", func(c *Config) { c.OTLP.Headers = map[string]string{"x-a": "a\tb"} }, ""},
		{"disabled skips header value", func(c *Config) { c.OTLP.Enabled = false; c.OTLP.Headers = map[string]string{"x-a": "a\nb"} }, ""},
		{"header name colon", func(c *Config) { c.OTLP.Headers = map[string]string{"a:b": "v"} }, "invalid header name"},
		{"missing ca file", func(c *Config) { c.OTLP.TLS.CAFile = "/nonexistent/secret-path/ca.pem" }, "otlp.tls.ca_file must be a readable file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := enabledOTLP()
			tt.mutate(&cfg)
			err := Validate(&cfg)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateOTLPErrorsNeverEchoSecrets(t *testing.T) {
	cfg := enabledOTLP()
	cfg.OTLP.Endpoint = "https://user:endpoint-secret@collector/v1/traces?key=query-secret"
	cfg.OTLP.Headers = map[string]string{"bad name": "header-value-secret", "x-key": "value-secret\n"}
	cfg.OTLP.QueueSize = 0
	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, secret := range []string{"endpoint-secret", "query-secret", "header-value-secret", "value-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("validation error leaks %q: %v", secret, err)
		}
	}
}

func TestOTLPEnvOverrides(t *testing.T) {
	t.Setenv("SOCKGUARD_OTLP_ENABLED", "true")
	t.Setenv("SOCKGUARD_OTLP_ENDPOINT", "https://env-collector:4318/v1/traces")
	t.Setenv("SOCKGUARD_OTLP_TIMEOUT", "9s")
	t.Setenv("SOCKGUARD_OTLP_QUEUE_SIZE", "512")
	t.Setenv("SOCKGUARD_OTLP_BATCH_SIZE", "32")
	t.Setenv("SOCKGUARD_OTLP_SAMPLE_RATIO", "0.25")
	t.Setenv("SOCKGUARD_OTLP_SERVICE_NAME", "edge-proxy")
	t.Setenv("SOCKGUARD_OTLP_TLS_INSECURE_SKIP_VERIFY", "true")
	cfg, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	o := cfg.OTLP
	if !o.Enabled || o.Endpoint != "https://env-collector:4318/v1/traces" || o.Timeout != "9s" ||
		o.QueueSize != 512 || o.BatchSize != 32 || o.SampleRatio != 0.25 || o.ServiceName != "edge-proxy" ||
		!o.TLS.InsecureSkipVerify {
		t.Fatalf("env overrides not applied: %+v", o)
	}
}

// Viper lower-cases map keys, so header names arrive lower-cased; HTTP header
// names are case-insensitive so this is harmless.
func TestOTLPYAMLHeadersLoad(t *testing.T) {
	cfg, err := LoadBytes([]byte("otlp:\n  enabled: true\n  endpoint: https://c/v1/traces\n  headers:\n    Authorization: Bearer abc\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.OTLP.Headers["authorization"] != "Bearer abc" || cfg.OTLP.ServiceName != "sockguard" {
		t.Fatalf("OTLP = %+v", cfg.OTLP)
	}
}

// Header values are secrets. Every surface that renders or reports config
// must keep them out: policy diff (paths and kinds only), validation errors,
// and the JSON a policy snapshot publishes.
func TestOTLPHeaderValuesNeverRendered(t *testing.T) {
	a, b := enabledOTLP(), enabledOTLP()
	a.OTLP.Headers = map[string]string{"x-tenant-key": "old-header-secret"}
	b.OTLP.Headers = map[string]string{"x-tenant-key": "new-header-secret"}
	changes := PolicyChanges(&a, &b)
	want := []PolicyChange{{"otlp.headers", "modified"}}
	if !reflect.DeepEqual(changes, want) {
		t.Fatalf("changes = %+v, want %+v", changes, want)
	}
	body, _ := json.Marshal(changes)
	for _, s := range []string{"x-tenant-key", "old-header-secret", "new-header-secret"} {
		if strings.Contains(string(body), s) {
			t.Errorf("policy diff exposes %q", s)
		}
	}
}

func TestValidateOTLPCAFileHonorsMode(t *testing.T) {
	cfg := enabledOTLP()
	cfg.OTLP.TLS.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if err := ValidateStructural(&cfg); err != nil {
		t.Fatalf("structural mode must not open ca_file: %v", err)
	}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "otlp.tls.ca_file") {
		t.Fatalf("full mode must reject a missing ca_file, got %v", err)
	}
}
