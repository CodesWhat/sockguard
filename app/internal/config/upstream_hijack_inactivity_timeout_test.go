package config

import (
	"strings"
	"testing"
)

// TestDefaultsUpstreamHijackInactivityTimeout pins the default: hijack
// connections (docker attach, exec start) get a "10m" inactivity timeout,
// matching the value hijack.go hardcoded before this field existed. The
// default value must still pass validation cleanly.
func TestDefaultsUpstreamHijackInactivityTimeout(t *testing.T) {
	cfg := Defaults()
	if cfg.Upstream.HijackInactivityTimeout != "10m" {
		t.Fatalf("Defaults().Upstream.HijackInactivityTimeout = %q, want %q", cfg.Upstream.HijackInactivityTimeout, "10m")
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(Defaults()) = %v, want no error", err)
	}
}

// TestValidateUpstreamHijackInactivityTimeout exercises validateUpstream's
// upstream.hijack_inactivity_timeout branch. Unlike upstream.request_timeout,
// there is no "off"/legacy-empty disable spelling — every value, including
// an explicit empty string, must parse as a positive Go duration.
func TestValidateUpstreamHijackInactivityTimeout(t *testing.T) {
	cases := []struct {
		name      string
		timeout   string
		wantError bool
		wantMsg   string
	}{
		{
			name:      "invalid_with_extra_text",
			timeout:   "5s extra",
			wantError: true,
			wantMsg:   "upstream.hijack_inactivity_timeout must be a positive duration",
		},
		{
			name:      "negative_duration",
			timeout:   "-1s",
			wantError: true,
			wantMsg:   "upstream.hijack_inactivity_timeout must be a positive duration",
		},
		{
			name:      "zero_duration",
			timeout:   "0s",
			wantError: true,
			wantMsg:   "upstream.hijack_inactivity_timeout must be a positive duration",
		},
		{
			name:      "empty_is_rejected",
			timeout:   "",
			wantError: true,
			wantMsg:   "upstream.hijack_inactivity_timeout must be a positive duration",
		},
		{
			name:      "off_is_not_a_recognized_disable_spelling",
			timeout:   "off",
			wantError: true,
			wantMsg:   "upstream.hijack_inactivity_timeout must be a positive duration",
		},
		{
			name:      "valid_positive_duration",
			timeout:   "30s",
			wantError: false,
		},
		{
			name:      "valid_positive_duration_minutes",
			timeout:   "10m",
			wantError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.HijackInactivityTimeout = tc.timeout
			err := Validate(&cfg)
			if tc.wantError {
				if err == nil {
					t.Fatalf("Validate() = nil, want error containing %q", tc.wantMsg)
				}
				if !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantMsg)
				}
			} else {
				if err != nil && strings.Contains(err.Error(), "upstream.hijack_inactivity_timeout") {
					t.Fatalf("Validate() produced unexpected upstream.hijack_inactivity_timeout error: %v", err)
				}
			}
		})
	}
}
