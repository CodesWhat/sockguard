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

func TestReadBoundedBodyRestoresRequestBody(t *testing.T) {
	payload := []byte(`{"Name":"cache"}`)
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", bytes.NewReader(payload))

	body, err := readBoundedBody(req, int64(len(payload)))
	if err != nil {
		t.Fatalf("readBoundedBody() error = %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("readBoundedBody() body = %q, want %q", string(body), string(payload))
	}
	if req.ContentLength != int64(len(payload)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(payload))
	}

	resetBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(resetBody, payload) {
		t.Fatalf("reset body = %q, want %q", string(resetBody), string(payload))
	}
}

func TestReadBoundedBodyRejectsOversizedPayload(t *testing.T) {
	// Uses ContentLength=-1 so the actual LimitReader path runs (not the fast-path).
	const maxBodyBytes = 4
	payload := []byte("12345")
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewReader(payload))
	req.ContentLength = -1 // force actual read path, not ContentLength fast-path

	body, err := readBoundedBody(req, maxBodyBytes)
	if body != nil {
		t.Fatalf("readBoundedBody() body = %q, want nil", string(body))
	}
	if !isBodyTooLargeError(err) {
		t.Fatalf("readBoundedBody() error = %v, want body-too-large error", err)
	}
}

func TestReadBoundedBodyContentLengthFastPathCloseError(t *testing.T) {
	// ContentLength > max triggers the fast-path; if Body.Close() errors, the error propagates.
	sentinel := io.ErrClosedPipe
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", nil)
	req.Body = &erroringReadCloser{Reader: bytes.NewReader([]byte("12345")), closeErr: sentinel}
	req.ContentLength = 5

	_, err := readBoundedBody(req, 4)
	if err == nil {
		t.Fatal("expected error from Body.Close(), got nil")
	}
}

func TestReadBoundedBodyIgnoresCloseErrorAfterSuccessfulRead(t *testing.T) {
	payload := []byte(`{"Name":"cache"}`)
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", nil)
	req.Body = &erroringReadCloser{Reader: bytes.NewReader(payload), closeErr: io.ErrClosedPipe}

	body, err := readBoundedBody(req, int64(len(payload)))
	if err != nil {
		t.Fatalf("readBoundedBody() error = %v, want nil", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("readBoundedBody() body = %q, want %q", string(body), string(payload))
	}

	resetBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(resetBody, payload) {
		t.Fatalf("reset body = %q, want %q", string(resetBody), string(payload))
	}
}

func TestReadBoundedBodyRejectsWhenContentLengthExceedsMax(t *testing.T) {
	// Exercises the ContentLength fast-path branch (r.ContentLength > max).
	const maxBodyBytes = 4
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewReader([]byte("12345")))
	req.ContentLength = 5

	body, err := readBoundedBody(req, maxBodyBytes)
	if body != nil {
		t.Fatalf("readBoundedBody() body = %q, want nil", string(body))
	}
	if !isBodyTooLargeError(err) {
		t.Fatalf("readBoundedBody() error = %v, want body-too-large error", err)
	}
}

func TestInspectorsUseBoundedBodyContentLengthFastPath(t *testing.T) {
	readErr := errors.New("body read should not happen")

	tests := []struct {
		name       string
		path       string
		max        int64
		inspect    func(*http.Request) (string, error)
		wantPrefix string
		wantStatus int
	}{
		{
			name: "exec create",
			path: "/containers/abc/exec",
			max:  maxExecBodyBytes,
			inspect: func(req *http.Request) (string, error) {
				return newExecPolicy(ExecOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			},
			wantPrefix: "exec denied: request body exceeds",
		},
		{
			name: "container create",
			path: "/containers/create",
			max:  maxContainerCreateBodyBytes,
			inspect: func(req *http.Request) (string, error) {
				return newContainerCreatePolicy(ContainerCreateOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			},
			wantPrefix: "container create denied: request body exceeds",
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name: "plugin pull privileges",
			path: "/plugins/pull",
			max:  maxPluginBodyBytes,
			inspect: func(req *http.Request) (string, error) {
				return newPluginPolicy(PluginOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			},
			wantPrefix: "plugin pull denied: request body exceeds",
		},
		{
			name: "plugin set",
			path: "/plugins/acme/set",
			max:  maxPluginBodyBytes,
			inspect: func(req *http.Request) (string, error) {
				return newPluginPolicy(PluginOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			},
			wantPrefix: "plugin set denied: request body exceeds",
		},
		{
			name: "service create",
			path: "/services/create",
			max:  maxServiceBodyBytes,
			inspect: func(req *http.Request) (string, error) {
				return newServicePolicy(ServiceOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			},
			wantPrefix: "service denied: request body exceeds",
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name: "swarm join",
			path: "/swarm/join",
			max:  maxSwarmBodyBytes,
			inspect: func(req *http.Request) (string, error) {
				return newSwarmPolicy(SwarmOptions{}).inspect(nil, req, NormalizePath(req.URL.Path))
			},
			wantPrefix: "swarm join denied: request body exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req.Body = &readErrorReadCloser{readErr: readErr}
			req.ContentLength = tt.max + 1

			reason, err := tt.inspect(req)
			if tt.wantStatus != 0 {
				rejection, ok := requestRejectionFromError(err)
				if !ok {
					t.Fatalf("inspect() error = %v, want request rejection", err)
				}
				if rejection.status != tt.wantStatus {
					t.Fatalf("rejection status = %d, want %d", rejection.status, tt.wantStatus)
				}
				reason = rejection.reason
			} else if err != nil {
				t.Fatalf("inspect() error = %v, want nil", err)
			}

			if !strings.HasPrefix(reason, tt.wantPrefix) {
				t.Fatalf("reason = %q, want prefix %q", reason, tt.wantPrefix)
			}
		})
	}
}

func TestReadBoundedBodyNilRequest(t *testing.T) {
	body, err := readBoundedBody(nil, 1024)
	if body != nil || err != nil {
		t.Fatalf("readBoundedBody(nil) = %v, %v; want nil, nil", body, err)
	}
}

func TestReadBoundedBodyNilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", nil)
	req.Body = nil
	body, err := readBoundedBody(req, 1024)
	if body != nil || err != nil {
		t.Fatalf("readBoundedBody(req with nil body) = %v, %v; want nil, nil", body, err)
	}
}

func TestBodyTooLargeErrorMessage(t *testing.T) {
	err := &bodyTooLargeError{limit: 42}
	want := "request body exceeds 42 byte limit"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestRequestRejectionErrorMessage(t *testing.T) {
	err := newRequestRejectionError(http.StatusForbidden, "some denial reason")
	if got := err.Error(); got != "some denial reason" {
		t.Fatalf("Error() = %q, want %q", got, "some denial reason")
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatal("requestRejectionFromError() ok = false, want true")
	}
	if rejection.status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rejection.status, http.StatusForbidden)
	}
	if rejection.reason != "some denial reason" {
		t.Fatalf("reason = %q, want %q", rejection.reason, "some denial reason")
	}
}
