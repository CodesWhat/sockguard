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
			reason, err := policy.inspect(tt.request, tt.normalizedPath)
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

		reason, err := policy.inspect(req, "/containers/create")
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason != "" {
			t.Fatalf("inspect() reason = %q, want empty", reason)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString("{"))

		reason, err := policy.inspect(req, "/containers/create")
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

	t.Run("close error after read", func(t *testing.T) {
		req := &http.Request{
			Method: http.MethodPost,
			Body: &erroringReadCloser{
				Reader:   bytes.NewReader([]byte(`{}`)),
				closeErr: errors.New("close failed"),
			},
		}

		reason, err := policy.inspect(req, "/containers/create")
		if reason != "" {
			t.Fatalf("inspect() reason = %q, want empty", reason)
		}
		if err == nil || err.Error() != "read body: close failed" {
			t.Fatalf("inspect() error = %v, want read body close failure", err)
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

// TestContainerCreatePolicyInspectCapsOversizedBody locks in the OOM guard.
// A malicious client sending a body larger than maxContainerCreateBodyBytes
// must be rejected with a policy deny reason and must not cause the proxy
// to read unbounded memory. The LimitReader caps the read at maxBytes+1, so
// even a body of 100 MiB on the wire only costs ~1 MiB of proxy RAM for the
// check itself before the deny reason is returned.
func TestContainerCreatePolicyInspectCapsOversizedBody(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})

	oversized := bytes.Repeat([]byte{'x'}, maxContainerCreateBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(oversized))

	reason, err := policy.inspect(req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v, want nil", err)
	}
	wantPrefix := "container create denied: request body exceeds"
	if len(reason) < len(wantPrefix) || reason[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("inspect() reason = %q, want prefix %q", reason, wantPrefix)
	}
}
