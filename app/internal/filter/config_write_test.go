package filter

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigWriteInspectAllowsDefaultCreate(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{})

	req := httptest.NewRequest(http.MethodPost, "/configs/create", strings.NewReader(`{"Name":"app-config","Data":"Y29uZmln"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestConfigWriteInspectDeniesDriverSelections(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{})

	req := httptest.NewRequest(http.MethodPost, "/v1.53/configs/create", strings.NewReader(`{"Driver":"vault"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `config create denied: driver "vault" is not allowed` {
		t.Fatalf("inspect() reason = %q, want driver denial", reason)
	}

	req = httptest.NewRequest(http.MethodPost, "/configs/create", strings.NewReader(`{"TemplateDriver":"sprig"}`))
	reason, err = policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `config create denied: template driver "sprig" is not allowed` {
		t.Fatalf("inspect() reason = %q, want template-driver denial", reason)
	}
}

func TestConfigWriteInspectHandlesMalformedJSON(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{})
	req := httptest.NewRequest(http.MethodPost, "/configs/create", bytes.NewBufferString("{"))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "config create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
	}
}

func TestConfigWriteInspectCapsOversizedBody(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{})
	req := httptest.NewRequest(http.MethodPost, "/configs/create", bytes.NewReader(bytes.Repeat([]byte{'x'}, maxConfigWriteBodyBytes+1)))

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
	if !strings.HasPrefix(rejection.reason, "config create denied: request body exceeds") {
		t.Fatalf("rejection reason = %q, want oversize denial", rejection.reason)
	}
}

func TestConfigWriteInspectNilRequestReturnsEmpty(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{})
	reason, err := policy.inspect(nil, nil, "/configs/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil) = (%q, %v), want empty", reason, err)
	}
}

func TestConfigWriteInspectNilBodyReturnsEmpty(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{})
	req := httptest.NewRequest(http.MethodPost, "/configs/create", nil)
	req.Body = nil
	reason, err := policy.inspect(nil, req, "/configs/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil body) = (%q, %v), want empty", reason, err)
	}
}

func TestConfigWriteInspectEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{})
	req := httptest.NewRequest(http.MethodPost, "/configs/create", bytes.NewReader(nil))
	reason, err := policy.inspect(nil, req, "/configs/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(empty body) = (%q, %v), want empty", reason, err)
	}
}

func TestConfigWriteInspectAllowsTemplateDriverWhenConfigured(t *testing.T) {
	policy := newConfigPolicy(ConfigOptions{AllowTemplateDrivers: true})
	req := httptest.NewRequest(http.MethodPost, "/configs/create", strings.NewReader(`{"TemplateDriver":"sprig"}`))
	reason, err := policy.inspect(nil, req, "/configs/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestConfigWriteInspectBodyReadErrorPropagates(t *testing.T) {
	// Exercises the non-tooLarge error branch from readBoundedBody (line 48).
	policy := newConfigPolicy(ConfigOptions{})
	sentinel := io.ErrUnexpectedEOF
	req := httptest.NewRequest(http.MethodPost, "/configs/create", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}
	_, err := policy.inspect(nil, req, "/configs/create")
	if err == nil {
		t.Fatal("expected read error to propagate")
	}
}

func TestConfigWriteInspectMalformedJSONWithLogger(t *testing.T) {
	// Exercises the logger debug branch when JSON decode fails; must deny (fail-closed).
	policy := newConfigPolicy(ConfigOptions{})
	logs := &collectingHandler{}
	req := httptest.NewRequest(http.MethodPost, "/configs/create", strings.NewReader("{bad json}"))
	reason, err := policy.inspect(slog.New(logs), req, "/configs/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	const wantReason = "config create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if len(logs.snapshot()) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs.snapshot()))
	}
}
