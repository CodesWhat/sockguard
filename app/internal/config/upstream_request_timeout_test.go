package config

import "testing"

// TestDefaultsUpstreamRequestTimeout pins the v1.5 default: request_timeout
// now defaults to "60s" (previously unlimited), and the default value must
// still pass validation cleanly.
func TestDefaultsUpstreamRequestTimeout(t *testing.T) {
	cfg := Defaults()
	if cfg.Upstream.RequestTimeout != "60s" {
		t.Fatalf("Defaults().Upstream.RequestTimeout = %q, want %q", cfg.Upstream.RequestTimeout, "60s")
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(Defaults()) = %v, want no error", err)
	}
}

// TestUpstreamConfigRequestTimeoutDisabled exercises the centralized
// disabled-check that validate.go and cmd/serve.go both consult, so the two
// call sites can't drift on what "disabled" means.
func TestUpstreamConfigRequestTimeoutDisabled(t *testing.T) {
	cases := []struct {
		name    string
		timeout string
		want    bool
	}{
		{name: "empty_is_disabled", timeout: "", want: true},
		{name: "off_is_disabled", timeout: "off", want: true},
		{name: "OFF_uppercase_is_not_recognized", timeout: "OFF", want: false},
		{name: "positive_duration_is_not_disabled", timeout: "30s", want: false},
		{name: "zero_duration_is_not_disabled", timeout: "0s", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := UpstreamConfig{RequestTimeout: tc.timeout}
			if got := u.RequestTimeoutDisabled(); got != tc.want {
				t.Errorf("RequestTimeoutDisabled() with RequestTimeout=%q = %v, want %v", tc.timeout, got, tc.want)
			}
		})
	}
}
