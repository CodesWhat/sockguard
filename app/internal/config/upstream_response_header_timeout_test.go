package config

import (
	"strings"
	"testing"
)

func TestDefaultsUpstreamResponseHeaderTimeout(t *testing.T) {
	cfg := Defaults()
	if cfg.Upstream.ResponseHeaderTimeout != "30s" {
		t.Fatalf("default = %q, want 30s", cfg.Upstream.ResponseHeaderTimeout)
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(Defaults()) = %v", err)
	}
}

func TestValidateUpstreamResponseHeaderTimeout(t *testing.T) {
	cases := []struct {
		value   string
		wantErr bool
	}{
		{"30s", false},
		{"2m", false},
		{"off", false},
		{"", true},
		{"OFF", true},
		{"0s", true},
		{"-5s", true},
		{"soon", true},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.ResponseHeaderTimeout = tc.value
			err := Validate(&cfg)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "upstream.response_header_timeout") {
					t.Fatalf("Validate(%q) = %v, want response_header_timeout error", tc.value, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q) = %v, want nil", tc.value, err)
			}
		})
	}
}
