package config

import (
	"strings"
	"testing"
)

func TestValidateUpstreamFlavorAndFailoverTimings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"unknown flavor", func(c *Config) { c.Upstream.Flavor = "kubernetes" }, "upstream.flavor must be"},
		{"health interval not a duration", func(c *Config) { c.Upstream.Failover.HealthInterval = "soon" }, "health_interval must be a Go duration"},
		{"health interval zero", func(c *Config) { c.Upstream.Failover.HealthInterval = "0s" }, "health_interval must be non-zero"},
		{"health timeout not a duration", func(c *Config) { c.Upstream.Failover.HealthTimeout = "soon" }, "health_timeout must be a positive duration"},
		{"health timeout not positive", func(c *Config) { c.Upstream.Failover.HealthTimeout = "-1s" }, "health_timeout must be a positive duration"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			tc.mutate(&cfg)
			err := Validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}

	cfg := Defaults()
	cfg.Upstream.Failover.HealthInterval = "-1s"
	cfg.Upstream.Failover.HealthTimeout = "2s"
	if err := Validate(&cfg); err != nil && (strings.Contains(err.Error(), "health_interval") || strings.Contains(err.Error(), "health_timeout")) {
		t.Fatalf("a negative interval (disable) and a positive timeout must pass: %v", err)
	}
}

func TestNormalizeTCPBindTargetEdges(t *testing.T) {
	t.Parallel()
	if got := normalizeTCPBindTarget("not-a-hostport"); got != "not-a-hostport" {
		t.Fatalf("unsplittable address = %q, want it unchanged", got)
	}
	if got := normalizeTCPBindTarget("LocalHost:0080"); got != "localhost:80" {
		t.Fatalf("hostname = %q, want localhost:80", got)
	}
	if got := normalizeTCPBindTarget("127.0.0.1:2375"); got != "127.0.0.1:2375" {
		t.Fatalf("literal address = %q", got)
	}
}
