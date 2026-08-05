package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLibpodVolumeInspectLibpodAllowsDefaultCreate(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})

	req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(`{"Name":"data"}`))
	reason, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpod() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
	}
}

func TestLibpodVolumeInspectLibpodIgnoresNonMatchingPaths(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"docker volumes create", http.MethodPost, "/volumes/create"},
		{"wrong method", http.MethodGet, "/libpod/volumes/create"},
		{"libpod volumes json", http.MethodPost, "/libpod/volumes/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{"Driver":"nfs"}`))
			reason, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodVolumeInspectLibpodDriverGate(t *testing.T) {
	tests := []struct {
		name    string
		opts    VolumeOptions
		body    string
		wantDen bool
	}{
		{"default denies custom driver", VolumeOptions{}, `{"Driver":"nfs"}`, true},
		{"local driver always allowed", VolumeOptions{}, `{"Driver":"local"}`, false},
		{"case-insensitive local allowed", VolumeOptions{}, `{"Driver":"Local"}`, false},
		{"empty driver allowed", VolumeOptions{}, `{}`, false},
		{"custom driver allowed when configured", VolumeOptions{AllowCustomDrivers: true}, `{"Driver":"nfs"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newVolumePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(tt.body))
			reason, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantDen && reason == "" {
				t.Fatal("inspectLibpod() reason = empty, want driver denial")
			}
			if !tt.wantDen && reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodVolumeInspectLibpodOptionsGate(t *testing.T) {
	tests := []struct {
		name    string
		opts    VolumeOptions
		body    string
		wantDen bool
	}{
		// "DriverOpts"/"Opts" are Docker's field names — libpod uses
		// "Options" (see libpodVolumeCreateRequest) — so sending Docker's
		// spelling must NOT trip the gate.
		{"docker-shaped DriverOpts ignored", VolumeOptions{}, `{"DriverOpts":{"o":"bind"}}`, false},
		{"default denies libpod Options", VolumeOptions{}, `{"Options":{"o":"bind"}}`, true},
		{"allowed permits libpod Options", VolumeOptions{AllowDriverOpts: true}, `{"Options":{"o":"bind"}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newVolumePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(tt.body))
			reason, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantDen && reason == "" {
				t.Fatal("inspectLibpod() reason = empty, want options denial")
			}
			if !tt.wantDen && reason != "" {
				t.Fatalf("inspectLibpod() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodVolumeInspectLibpodHandlesMalformedJSON(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", bytes.NewBufferString("{"))
	reason, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspectLibpod() error = %v", err)
	}
	if reason != "libpod volume create denied: request body could not be inspected" {
		t.Fatalf("inspectLibpod() reason = %q, want malformed-body denial", reason)
	}
}

func TestLibpodVolumeInspectLibpodBodyTooLarge(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	oversized := strings.Repeat("a", int(maxLibpodVolumeBodyBytes)+1)
	body := `{"Name":"` + oversized + `"}`

	req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	_, err := policy.inspectLibpod(nil, req, NormalizePath(req.URL.Path))
	if err == nil {
		t.Fatal("inspectLibpod() error = nil, want request-too-large rejection")
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspectLibpod() error = %v, want a request rejection error", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("rejection.status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
}
