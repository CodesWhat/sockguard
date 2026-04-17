package filter

import (
	"bytes"
	"io"
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
