package filter

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type erroringReadCloser struct {
	io.Reader
	closeErr error
}

func (r *erroringReadCloser) Close() error {
	return r.closeErr
}

type readErrorReadCloser struct {
	readErr  error
	closeErr error
}

func (r *readErrorReadCloser) Read([]byte) (int, error) {
	return 0, r.readErr
}

func (r *readErrorReadCloser) Close() error {
	return r.closeErr
}

type trackingReadCloser struct {
	reader *bytes.Reader
	reads  int
	closed bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	r.reads++
	return r.reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestNewContainerCreatePolicyNormalizesAndDeduplicatesAllowedBindMounts(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts: []string{
			"",
			"relative",
			"/safe",
			"/safe/",
			"/safe/../safe",
			"/other/../allowed",
		},
	})

	want := []string{"/safe", "/allowed"}
	if len(policy.allowedBindMounts) != len(want) {
		t.Fatalf("allowedBindMounts length = %d, want %d (%v)", len(policy.allowedBindMounts), len(want), policy.allowedBindMounts)
	}
	for i, wantValue := range want {
		if policy.allowedBindMounts[i] != wantValue {
			t.Fatalf("allowedBindMounts[%d] = %q, want %q", i, policy.allowedBindMounts[i], wantValue)
		}
	}
}

func TestContainerCreatePolicyInspectSkipsBodyWhenPermissive(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowPrivileged:   true,
		AllowHostNetwork:  true,
		AllowedBindMounts: []string{"/"},
	})
	body := []byte(`{"HostConfig":{"Privileged":true,"NetworkMode":"host","Binds":["/var/run:/host/run"]}}`)
	tracker := &trackingReadCloser{reader: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req.Body = tracker

	reason, err := policy.inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	if tracker.reads != 0 {
		t.Fatalf("body reads = %d, want 0", tracker.reads)
	}
	if tracker.closed {
		t.Fatal("body was closed, want left open for downstream")
	}

	gotBody, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body after inspect = %q, want %q", string(gotBody), string(body))
	}
}

func TestContainerCreatePolicyInspectSkipsNonCreateRequests(t *testing.T) {
	policy := containerCreatePolicy{}

	tests := []struct {
		name           string
		request        *http.Request
		normalizedPath string
	}{
		{name: "nil request", request: nil, normalizedPath: "/containers/create"},
		{name: "wrong method", request: httptest.NewRequest(http.MethodGet, "/containers/create", bytes.NewReader([]byte(`{}`))), normalizedPath: "/containers/create"},
		{name: "wrong path", request: httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader([]byte(`{}`))), normalizedPath: "/containers/json"},
		{name: "nil body", request: &http.Request{Method: http.MethodPost}, normalizedPath: "/containers/create"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := policy.inspect(nil, tt.request, tt.normalizedPath)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

func TestContainerCreatePolicyInspectHandlesBodyEdgeCases(t *testing.T) {
	policy := containerCreatePolicy{}

	t.Run("empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", http.NoBody)

		reason, err := policy.inspect(nil, req, "/containers/create")
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason != "" {
			t.Fatalf("inspect() reason = %q, want empty", reason)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString("{"))

		reason, err := policy.inspect(nil, req, "/containers/create")
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
	})

	t.Run("close error after read is ignored", func(t *testing.T) {
		req := &http.Request{
			Method: http.MethodPost,
			Body: &erroringReadCloser{
				Reader:   bytes.NewReader([]byte(`{}`)),
				closeErr: errors.New("close failed"),
			},
		}

		reason, err := policy.inspect(nil, req, "/containers/create")
		if reason != "" {
			t.Fatalf("inspect() reason = %q, want empty", reason)
		}
		if err != nil {
			t.Fatalf("inspect() error = %v, want nil", err)
		}

		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Fatalf("ReadAll() error = %v", readErr)
		}
		if string(body) != "{}" {
			t.Fatalf("reset body = %q, want %q", string(body), "{}")
		}
	})
}

func TestContainerCreatePolicyDenyBindMountReasonRejectsBindMountSource(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts: []string{"/allowed"},
	})

	reason := policy.denyBindMountReason(containerCreateHostConfig{
		Binds: []string{"not-a-bind"},
		Mounts: []containerCreateMount{
			{Type: "volume", Source: "/denied"},
			{Type: "bind", Source: "relative"},
			{Type: "bind", Source: "/denied"},
		},
	})

	if reason != `container create denied: bind mount source "/denied" is not allowlisted` {
		t.Fatalf("denyBindMountReason() = %q", reason)
	}
}

func TestContainerCreateBindSource(t *testing.T) {
	tests := []struct {
		name   string
		bind   string
		want   string
		wantOK bool
	}{
		{name: "valid", bind: "/source:/target:ro", want: "/source", wantOK: true},
		{name: "missing separator", bind: "/source", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := containerCreateBindSource(tt.bind)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("source = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractAndValidateBindSource(t *testing.T) {
	tests := []struct {
		name   string
		bind   string
		mount  containerCreateMount
		want   string
		wantOK bool
	}{
		{
			name:   "bind string",
			bind:   "/source:/target:ro",
			want:   "/source",
			wantOK: true,
		},
		{
			name:   "bind string missing separator",
			bind:   "/source",
			wantOK: false,
		},
		{
			name:   "bind mount entry",
			mount:  containerCreateMount{Type: "bind", Source: "/safe/../allowed"},
			want:   "/allowed",
			wantOK: true,
		},
		{
			name:   "non-bind mount entry",
			mount:  containerCreateMount{Type: "volume", Source: "/allowed"},
			wantOK: false,
		},
		{
			name:   "bind mount with relative source",
			mount:  containerCreateMount{Type: "bind", Source: "relative"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractAndValidateBindSource(tt.bind, tt.mount)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("source = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeContainerCreateBindMount(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		want   string
		wantOK bool
	}{
		{name: "clean absolute path", value: "/safe/../allowed", want: "/allowed", wantOK: true},
		{name: "root", value: "/", want: "/", wantOK: true},
		{name: "relative path", value: "relative", wantOK: false},
		{name: "empty path", value: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeContainerCreateBindMount(tt.value)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("normalized = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBindPathAllowed(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		allowed []string
		want    bool
	}{
		{name: "root allows everything", source: "/etc", allowed: []string{"/"}, want: true},
		{name: "exact match allowed", source: "/srv/data", allowed: []string{"/srv/data"}, want: true},
		{name: "child path allowed", source: "/srv/data/cache", allowed: []string{"/srv/data"}, want: true},
		{name: "sibling prefix rejected", source: "/srv/database", allowed: []string{"/srv/data"}, want: false},
		{name: "parent path rejected", source: "/srv", allowed: []string{"/srv/data"}, want: false},
		{name: "empty allowlist rejected", source: "/srv/data", allowed: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindPathAllowed(tt.source, tt.allowed); got != tt.want {
				t.Fatalf("bindPathAllowed(%q, %v) = %v, want %v", tt.source, tt.allowed, got, tt.want)
			}
		})
	}
}

// TestContainerCreatePolicyInspectCapsOversizedBody locks in the OOM guard.
// A malicious client sending a body larger than maxContainerCreateBodyBytes
// must be rejected with 413 and must not cause the proxy to read unbounded
// memory. The LimitReader caps the read at maxBytes+1, so even a body of
// 100 MiB on the wire only costs ~1 MiB of proxy RAM for the check itself
// before the rejection is returned.
func TestContainerCreatePolicyInspectCapsOversizedBody(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})

	oversized := bytes.Repeat([]byte{'x'}, maxContainerCreateBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(oversized))

	reason, err := policy.inspect(nil, req, "/containers/create")
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
	wantPrefix := "container create denied: request body exceeds"
	if len(rejection.reason) < len(wantPrefix) || rejection.reason[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("rejection reason = %q, want prefix %q", rejection.reason, wantPrefix)
	}
}
