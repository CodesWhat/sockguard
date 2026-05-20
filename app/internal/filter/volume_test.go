package filter

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
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
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "volume create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
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

func TestVolumeInspectNilRequestReturnsEmpty(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	reason, err := policy.inspect(nil, nil, "/volumes/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil) = (%q, %v), want empty", reason, err)
	}
}

func TestVolumeInspectNilBodyReturnsEmpty(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", nil)
	req.Body = nil
	reason, err := policy.inspect(nil, req, "/volumes/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil body) = (%q, %v), want empty", reason, err)
	}
}

func TestVolumeInspectEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", bytes.NewReader(nil))
	reason, err := policy.inspect(nil, req, "/volumes/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(empty body) = (%q, %v), want empty", reason, err)
	}
}

func TestVolumeInspectAllowsLocalDriverExplicitly(t *testing.T) {
	// Driver "local" should be allowed even when AllowCustomDrivers is false.
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", strings.NewReader(`{"Driver":"local"}`))
	reason, err := policy.inspect(nil, req, "/volumes/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect() = (%q, %v), want allow for local driver", reason, err)
	}
}

type volumeCloseErrorReadCloser struct {
	io.Reader
	closeErr error
}

func (r *volumeCloseErrorReadCloser) Close() error { return r.closeErr }

func TestVolumeInspectIgnoresBodyCloseErrorAfterRead(t *testing.T) {
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
	if err != nil {
		t.Fatalf("inspect() error = %v, want nil", err)
	}
}

func TestVolumeInspectWrapsBodyReadError(t *testing.T) {
	sentinel := errors.New("read failed")
	policy := newVolumePolicy(VolumeOptions{})
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}

	reason, err := policy.inspect(nil, req, "/volumes/create")
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), "read body") {
		t.Fatalf("inspect() error = %q, want read body context", err)
	}
}

func TestVolumeInspectMalformedJSONWithLogger(t *testing.T) {
	// Exercises the logger debug branch when JSON decode fails; must deny (fail-closed).
	policy := newVolumePolicy(VolumeOptions{})
	logs := &collectingHandler{}
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", strings.NewReader("{bad json}"))
	reason, err := policy.inspect(slog.New(logs), req, "/volumes/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	const wantReason = "volume create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if len(logs.snapshot()) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs.snapshot()))
	}
}
