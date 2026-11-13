package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

func TestDefaultMaxBufferedBodyMatchesFilterDefault(t *testing.T) {
	cfg := Defaults()
	if cfg.Response.MaxBufferedBody != DefaultMaxBufferedBody {
		t.Fatalf("default = %q, want %q", cfg.Response.MaxBufferedBody, DefaultMaxBufferedBody)
	}
	if got := cfg.Response.MaxBufferedBodyBytes(); got != filter.MaxResponseBodyBytes {
		t.Fatalf("default bytes = %d, want %d", got, filter.MaxResponseBodyBytes)
	}
}

func TestMaxBufferedBodyBytes(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"", filter.MaxResponseBodyBytes},
		{"garbage", filter.MaxResponseBodyBytes},
		{"32MiB", 32 << 20},
		{"2097152", 2 << 20},
	}
	for _, tc := range tests {
		if got := (ResponseConfig{MaxBufferedBody: tc.in}).MaxBufferedBodyBytes(); got != tc.want {
			t.Errorf("MaxBufferedBodyBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestValidateMaxBufferedBody(t *testing.T) {
	tests := []struct {
		in      string
		wantErr string
	}{
		{"", ""},
		{"8MiB", ""},
		{"1MiB", ""},
		{"256MiB", ""},
		{"268435456", ""},
		{"512KiB", "between 1MiB and 256MiB"},
		{"257MiB", "between 1MiB and 256MiB"},
		{"1GiB", "between 1MiB and 256MiB"},
		{"0", "must be positive"},
		{"-8MiB", "must be positive"},
		{"32MB", "response.max_buffered_body"},
		{"lots", "response.max_buffered_body"},
	}
	for _, tc := range tests {
		errs := validateMaxBufferedBody(tc.in)
		if tc.wantErr == "" {
			if len(errs) != 0 {
				t.Errorf("validateMaxBufferedBody(%q) = %v, want none", tc.in, errs)
			}
			continue
		}
		if len(errs) != 1 || !strings.Contains(errs[0], tc.wantErr) {
			t.Errorf("validateMaxBufferedBody(%q) = %v, want one error containing %q", tc.in, errs, tc.wantErr)
		}
	}
}

func TestLoadMaxBufferedBody(t *testing.T) {
	load := func(t *testing.T, yaml string) *Config {
		t.Helper()
		path := filepath.Join(t.TempDir(), "sockguard.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return cfg
	}
	if got := load(t, "response:\n  max_buffered_body: 32MiB\n").Response.MaxBufferedBodyBytes(); got != 32<<20 {
		t.Fatalf("size string: got %d, want 32MiB", got)
	}
	if got := load(t, "response:\n  max_buffered_body: 16777216\n").Response.MaxBufferedBodyBytes(); got != 16<<20 {
		t.Fatalf("integer bytes: got %d, want 16MiB", got)
	}
	if got := load(t, "response:\n  deny_verbosity: minimal\n").Response.MaxBufferedBodyBytes(); got != filter.MaxResponseBodyBytes {
		t.Fatalf("unset: got %d, want the 8MiB default", got)
	}

	t.Setenv("SOCKGUARD_RESPONSE_MAX_BUFFERED_BODY", "64MiB")
	if got := load(t, "response:\n  deny_verbosity: minimal\n").Response.MaxBufferedBodyBytes(); got != 64<<20 {
		t.Fatalf("env override: got %d, want 64MiB", got)
	}
}

func TestValidateRejectsBadMaxBufferedBody(t *testing.T) {
	cfg := Defaults()
	cfg.Response.MaxBufferedBody = "1GiB"
	errs := validateResponse(&cfg)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, "\n"), "max_buffered_body") {
		t.Fatalf("validateResponse() = %v, want a max_buffered_body error", errs)
	}
}
