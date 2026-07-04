package config

import (
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/upstream"
)

// TestEndpointSpecMapping exercises the endpointSpec function which adapts a
// config UpstreamEndpoint to an upstream.EndpointSpec.
func TestEndpointSpecMapping(t *testing.T) {
	ep := UpstreamEndpoint{
		Address: "tcp://daemon.example.com:2376",
		TLS: UpstreamTLSConfig{
			CAFile:     "/etc/certs/ca.pem",
			CertFile:   "/etc/certs/client.pem",
			KeyFile:    "/etc/certs/client-key.pem",
			ServerName: "daemon.example.com",
		},
		InsecureAllowPlainTCP: true,
		InsecureSkipTLSVerify: false,
	}

	got := endpointSpec(ep)

	want := upstream.EndpointSpec{
		Address:               "tcp://daemon.example.com:2376",
		CAFile:                "/etc/certs/ca.pem",
		CertFile:              "/etc/certs/client.pem",
		KeyFile:               "/etc/certs/client-key.pem",
		ServerName:            "daemon.example.com",
		InsecureAllowPlainTCP: true,
		InsecureSkipTLSVerify: false,
	}

	if got != want {
		t.Errorf("endpointSpec() = %+v, want %+v", got, want)
	}
}

// TestValidateUpstreamRequestTimeout exercises the validateUpstream branches
// for upstream.request_timeout that are not covered by existing tests.
func TestValidateUpstreamRequestTimeout(t *testing.T) {
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
			wantMsg:   "upstream.request_timeout must be a positive duration",
		},
		{
			name:      "negative_duration",
			timeout:   "-1s",
			wantError: true,
			wantMsg:   "upstream.request_timeout must be a positive duration",
		},
		{
			name:      "zero_duration",
			timeout:   "0s",
			wantError: true,
			wantMsg:   "upstream.request_timeout must be a positive duration",
		},
		{
			name:      "empty_is_skipped",
			timeout:   "",
			wantError: false,
		},
		{
			name:      "off_is_skipped",
			timeout:   "off",
			wantError: false,
		},
		{
			name:      "valid_positive_duration",
			timeout:   "30s",
			wantError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Upstream.RequestTimeout = tc.timeout
			err := Validate(&cfg)
			if tc.wantError {
				if err == nil {
					t.Fatalf("Validate() = nil, want error containing %q", tc.wantMsg)
				}
				if !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantMsg)
				}
			} else {
				// Only fail if the upstream.request_timeout field itself errors.
				if err != nil && strings.Contains(err.Error(), "upstream.request_timeout") {
					t.Fatalf("Validate() produced unexpected upstream.request_timeout error: %v", err)
				}
			}
		})
	}
}

// TestValidateContainerCreateAllowedDeviceRequests exercises the per-entry
// validation branches inside validateContainerCreateConfig for
// allowed_device_requests, which were previously unreachable from existing tests.
func TestValidateContainerCreateAllowedDeviceRequests(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	t.Run("empty_driver_rejected", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{Driver: "", AllowedCapabilities: [][]string{{"gpu"}}, MaxCount: nil},
		}
		err := Validate(&cfg)
		if err == nil {
			t.Fatal("Validate() = nil, want error for empty driver")
		}
		if !strings.Contains(err.Error(), "request_body.container_create.allowed_device_requests[0].driver is required") {
			t.Fatalf("Validate() = %v, want driver-required error", err)
		}
	})

	t.Run("whitespace_only_driver_rejected", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{Driver: "   ", AllowedCapabilities: [][]string{{"gpu"}}, MaxCount: nil},
		}
		err := Validate(&cfg)
		if err == nil {
			t.Fatal("Validate() = nil, want error for whitespace-only driver")
		}
		if !strings.Contains(err.Error(), "request_body.container_create.allowed_device_requests[0].driver is required") {
			t.Fatalf("Validate() = %v, want driver-required error", err)
		}
	})

	t.Run("empty_capability_set_rejected", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{
				Driver: "nvidia.com/gpu",
				// The outer slice has one entry; that entry is an empty capability set.
				AllowedCapabilities: [][]string{{}},
				MaxCount:            nil,
			},
		}
		err := Validate(&cfg)
		if err == nil {
			t.Fatal("Validate() = nil, want error for empty capability set")
		}
		if !strings.Contains(err.Error(), "request_body.container_create.allowed_device_requests[0].allowed_capabilities[0] must be a non-empty capability set") {
			t.Fatalf("Validate() = %v, want non-empty capability set error", err)
		}
	})

	t.Run("max_count_below_minus_one_rejected", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{Driver: "nvidia.com/gpu", AllowedCapabilities: [][]string{{"compute"}}, MaxCount: intPtr(-2)},
		}
		err := Validate(&cfg)
		if err == nil {
			t.Fatal("Validate() = nil, want error for max_count < -1")
		}
		if !strings.Contains(err.Error(), "request_body.container_create.allowed_device_requests[0].max_count must be -1 or a non-negative integer") {
			t.Fatalf("Validate() = %v, want max_count error", err)
		}
	})

	t.Run("valid_entry_max_count_minus_one", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{Driver: "nvidia.com/gpu", AllowedCapabilities: [][]string{{"compute", "utility"}}, MaxCount: intPtr(-1)},
		}
		err := Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "allowed_device_requests") {
			t.Fatalf("Validate() produced unexpected allowed_device_requests error: %v", err)
		}
	})

	t.Run("valid_entry_max_count_zero", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{Driver: "nvidia.com/gpu", AllowedCapabilities: [][]string{{"compute"}}, MaxCount: intPtr(0)},
		}
		err := Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "allowed_device_requests") {
			t.Fatalf("Validate() produced unexpected allowed_device_requests error: %v", err)
		}
	})

	t.Run("valid_entry_max_count_positive", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{Driver: "nvidia.com/gpu", AllowedCapabilities: [][]string{{"compute"}}, MaxCount: intPtr(4)},
		}
		err := Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "allowed_device_requests") {
			t.Fatalf("Validate() produced unexpected allowed_device_requests error: %v", err)
		}
	})

	t.Run("valid_entry_nil_max_count", func(t *testing.T) {
		cfg := Defaults()
		cfg.RequestBody.ContainerCreate.AllowedDeviceRequests = []AllowedDeviceRequest{
			{Driver: "nvidia.com/gpu", AllowedCapabilities: [][]string{{"compute", "utility"}, {"video"}}, MaxCount: nil},
		}
		err := Validate(&cfg)
		if err != nil && strings.Contains(err.Error(), "allowed_device_requests") {
			t.Fatalf("Validate() produced unexpected allowed_device_requests error: %v", err)
		}
	})
}
