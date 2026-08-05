package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLibpodNetworkInspectLibpodCreateAllowsDefaultBody(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})

	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"name":"my-net","driver":"bridge"}`))
	reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspectLibpodCreate() reason = %q, want empty", reason)
	}
}

func TestLibpodNetworkInspectLibpodCreateIgnoresNonMatchingPaths(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"docker networks create", http.MethodPost, "/networks/create"},
		{"wrong method", http.MethodGet, "/libpod/networks/create"},
		{"libpod network connect (no libpod inspector, deferred)", http.MethodPost, "/libpod/networks/my-net/connect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{"driver":"weird"}`))
			reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpodCreate() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("inspectLibpodCreate() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodNetworkInspectLibpodCreateDriverGate(t *testing.T) {
	tests := []struct {
		name    string
		opts    NetworkOptions
		body    string
		wantDen bool
	}{
		{"default denies custom driver", NetworkOptions{}, `{"driver":"weird"}`, true},
		{"bridge always allowed", NetworkOptions{}, `{"driver":"bridge"}`, false},
		{"macvlan always allowed", NetworkOptions{}, `{"driver":"macvlan"}`, false},
		{"custom driver allowed when configured", NetworkOptions{AllowCustomDrivers: true}, `{"driver":"weird"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newNetworkPolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(tt.body))
			reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpodCreate() error = %v", err)
			}
			if tt.wantDen && reason == "" {
				t.Fatal("inspectLibpodCreate() reason = empty, want driver denial")
			}
			if !tt.wantDen && reason != "" {
				t.Fatalf("inspectLibpodCreate() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodNetworkInspectLibpodCreateOptionsGate(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"options":{"mtu":"1400"}}`))
	reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason == "" {
		t.Fatal("inspectLibpodCreate() reason = empty, want driver-options denial")
	}

	policy = newNetworkPolicy(NetworkOptions{AllowDriverOptions: true})
	req = httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"options":{"mtu":"1400"}}`))
	reason, err = policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspectLibpodCreate() reason = %q, want empty", reason)
	}
}

func TestLibpodNetworkInspectLibpodCreateSubnetsGate(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"subnets":[{"subnet":"10.10.0.0/24"}]}`))
	reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason == "" {
		t.Fatal("inspectLibpodCreate() reason = empty, want subnet-config denial")
	}

	policy = newNetworkPolicy(NetworkOptions{AllowCustomIPAMConfig: true})
	reason, err = policy.inspectLibpodCreate(nil, httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"subnets":[{"subnet":"10.10.0.0/24"}]}`)), "/libpod/networks/create")
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspectLibpodCreate() reason = %q, want empty", reason)
	}
}

func TestLibpodNetworkInspectLibpodCreateIPAMOptionsGate(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"ipam_options":{"driver":"host-local"}}`))
	reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason == "" {
		t.Fatal("inspectLibpodCreate() reason = empty, want IPAM-options denial")
	}

	policy = newNetworkPolicy(NetworkOptions{AllowIPAMOptions: true})
	req = httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"ipam_options":{"driver":"host-local"}}`))
	reason, err = policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspectLibpodCreate() reason = %q, want empty", reason)
	}
}

// TestLibpodNetworkFieldsWithNoLibpodAnalogAreNeverConsulted documents (and
// pins) that NetworkOptions fields whose libpod Network type has no
// corresponding field — allow_swarm_scope, allow_ingress,
// allow_attachable, allow_config_only, allow_config_from,
// allow_custom_ipam_drivers, allow_disable_ipv4 — cannot deny a libpod
// network create no matter how the Docker-shaped JSON keys they gate are
// spelled in the request body, since libpodNetworkCreateRequest never
// decodes those keys at all.
func TestLibpodNetworkFieldsWithNoLibpodAnalogAreNeverConsulted(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	body := `{"Scope":"swarm","Ingress":true,"Attachable":true,"ConfigOnly":true,"ConfigFrom":{"Network":"other"},"EnableIPv4":false}`
	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(body))
	reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspectLibpodCreate() reason = %q, want empty (no libpod analog for these fields)", reason)
	}
}

func TestLibpodNetworkInspectLibpodCreateHandlesMalformedJSON(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", bytes.NewBufferString("{"))
	reason, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpodCreate() error = %v", err)
	}
	if reason != "libpod network create denied: request body could not be inspected" {
		t.Fatalf("inspectLibpodCreate() reason = %q, want malformed-body denial", reason)
	}
}

func TestLibpodNetworkInspectLibpodCreateBodyTooLarge(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{})
	oversized := strings.Repeat("a", int(maxLibpodNetworkBodyBytes)+1)
	body := `{"name":"` + oversized + `"}`

	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	_, err := policy.inspectLibpodCreate(nil, req, NormalizePath(req.URL.Path))
	if err == nil {
		t.Fatal("inspectLibpodCreate() error = nil, want request-too-large rejection")
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspectLibpodCreate() error = %v, want a request rejection error", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("rejection.status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
}
