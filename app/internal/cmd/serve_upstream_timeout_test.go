package cmd

import (
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
)

// TestEffectiveUpstreamRequestTimeout exercises the config.Upstream.RequestTimeout
// -> time.Duration resolution used by newServeUpstreamHandler, including the
// degrade-to-disabled behavior for invalid values that request_timeout's
// config-load validation would normally reject before this ever runs.
func TestEffectiveUpstreamRequestTimeout(t *testing.T) {
	cases := []struct {
		name    string
		timeout string
		want    time.Duration
	}{
		{name: "empty_disabled", timeout: "", want: 0},
		{name: "off_disabled", timeout: "off", want: 0},
		{name: "valid_duration", timeout: "30s", want: 30 * time.Second},
		{name: "garbage_degrades_to_disabled", timeout: "garbage", want: 0},
		{name: "zero_degrades_to_disabled", timeout: "0s", want: 0},
		{name: "negative_degrades_to_disabled", timeout: "-1s", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Upstream.RequestTimeout = tc.timeout
			if got := effectiveUpstreamRequestTimeout(cfg); got != tc.want {
				t.Errorf("effectiveUpstreamRequestTimeout(%q) = %v, want %v", tc.timeout, got, tc.want)
			}
		})
	}
}

// TestUpstreamRequestTimeoutLogValue exercises the "sockguard started" log
// field renderer: "off" whenever the deadline is disabled (or degraded),
// otherwise the configured duration string verbatim.
func TestUpstreamRequestTimeoutLogValue(t *testing.T) {
	cases := []struct {
		name    string
		timeout string
		want    string
	}{
		{name: "empty_renders_off", timeout: "", want: "off"},
		{name: "off_renders_off", timeout: "off", want: "off"},
		{name: "valid_duration_renders_verbatim", timeout: "30s", want: "30s"},
		{name: "garbage_renders_off", timeout: "garbage", want: "off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Upstream.RequestTimeout = tc.timeout
			if got := upstreamRequestTimeoutLogValue(cfg); got != tc.want {
				t.Errorf("upstreamRequestTimeoutLogValue(%q) = %q, want %q", tc.timeout, got, tc.want)
			}
		})
	}
}
