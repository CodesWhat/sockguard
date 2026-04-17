package filter

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVolumeInspectAllowsDefaultCreate(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})

	req := httptest.NewRequest(http.MethodPost, "/v1.53/volumes/create", strings.NewReader(`{"Name":"cache"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestVolumeInspectDeniesUnsafeDrivers(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})

	req := httptest.NewRequest(http.MethodPost, "/volumes/create", strings.NewReader(`{"Driver":"nfs"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `volume create denied: driver "nfs" is not allowed` {
		t.Fatalf("inspect() reason = %q, want driver denial", reason)
	}

	req = httptest.NewRequest(http.MethodPost, "/volumes/create", strings.NewReader(`{"DriverOpts":{"device":"/srv/data"}}`))
	reason, err = policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "volume create denied: driver options are not allowed" {
		t.Fatalf("inspect() reason = %q, want driver options denial", reason)
	}
}

func TestVolumeInspectHandlesMalformedJSON(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", bytes.NewBufferString("{"))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}

	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if string(body) != "{" {
		t.Fatalf("reset body = %q, want %q", string(body), "{")
	}
}

func TestVolumeInspectCapsOversizedBody(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", bytes.NewReader(bytes.Repeat([]byte{'x'}, maxVolumeBodyBytes+1)))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspect() error = %v, want request rejection", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("rejection status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
	if !strings.HasPrefix(rejection.reason, "volume create denied: request body exceeds") {
		t.Fatalf("rejection reason = %q, want oversize denial", rejection.reason)
	}
}

type volumeCloseErrorReadCloser struct {
	io.Reader
	closeErr error
}

func (r *volumeCloseErrorReadCloser) Close() error { return r.closeErr }

func TestVolumeInspectReturnsCloseError(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := &http.Request{
		Method: http.MethodPost,
		Body: &volumeCloseErrorReadCloser{
			Reader:   strings.NewReader(`{"Name":"cache"}`),
			closeErr: errors.New("close failed"),
		},
	}

	reason, err := policy.inspect(nil, req, "/volumes/create")
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	if err == nil || err.Error() != "read body: close failed" {
		t.Fatalf("inspect() error = %v, want read body close failure", err)
	}
}
