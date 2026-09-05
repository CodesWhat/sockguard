package config

import (
	"strings"
	"testing"
	"time"
)

// TestDefaultsServerShutdownGrace pins the default: sockguard waits "30s"
// for in-flight requests to finish before force-closing every listener at
// shutdown, matching the value serve.go hardcoded before this field
// existed. The default value must still pass validation cleanly.
func TestDefaultsServerShutdownGrace(t *testing.T) {
	cfg := Defaults()
	if cfg.Server.ShutdownGrace != "30s" {
		t.Fatalf("Defaults().Server.ShutdownGrace = %q, want %q", cfg.Server.ShutdownGrace, "30s")
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(Defaults()) = %v, want no error", err)
	}
}

// TestValidateServerShutdownGrace exercises validateServer's
// server.shutdown_grace branch. Unlike upstream.hijack_inactivity_timeout,
// 0 is a valid value here — it means "close immediately" — so only a parse
// failure or a negative duration is rejected.
func TestValidateServerShutdownGrace(t *testing.T) {
	cases := []struct {
		name      string
		grace     string
		wantError bool
		wantMsg   string
	}{
		{
			name:      "invalid_with_extra_text",
			grace:     "5s extra",
			wantError: true,
			wantMsg:   "server.shutdown_grace must be a non-negative duration",
		},
		{
			name:      "negative_duration",
			grace:     "-1s",
			wantError: true,
			wantMsg:   "server.shutdown_grace must be a non-negative duration",
		},
		{
			name:      "empty_is_rejected",
			grace:     "",
			wantError: true,
			wantMsg:   "server.shutdown_grace must be a non-negative duration",
		},
		{
			name:      "zero_is_valid",
			grace:     "0s",
			wantError: false,
		},
		{
			name:      "valid_positive_duration",
			grace:     "30s",
			wantError: false,
		},
		{
			name:      "valid_positive_duration_milliseconds",
			grace:     "50ms",
			wantError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Server.ShutdownGrace = tc.grace
			err := Validate(&cfg)
			if tc.wantError {
				if err == nil {
					t.Fatalf("Validate() = nil, want error containing %q", tc.wantMsg)
				}
				if !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantMsg)
				}
			} else {
				if err != nil && strings.Contains(err.Error(), "server.shutdown_grace") {
					t.Fatalf("Validate() produced unexpected server.shutdown_grace error: %v", err)
				}
			}
		})
	}
}

func FuzzValidateServerShutdownGrace(f *testing.F) {
	for _, value := range []string{"", "0s", "-1s", "30s", "50ms", "5s extra"} {
		f.Add(value)
	}

	f.Fuzz(func(t *testing.T, value string) {
		cfg := Defaults()
		cfg.Server.ShutdownGrace = value
		err := Validate(&cfg)

		duration, parseErr := time.ParseDuration(value)
		if parseErr == nil && duration >= 0 {
			if err != nil {
				t.Fatalf("Validate() = %v for valid shutdown grace %q", err, value)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), "server.shutdown_grace") {
			t.Fatalf("Validate() = %v, want server shutdown grace error for %q", err, value)
		}
	})
}
