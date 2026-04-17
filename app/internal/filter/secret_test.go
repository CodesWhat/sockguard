package filter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecretInspectAllowsDefaultCreate(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})

	req := httptest.NewRequest(http.MethodPost, "/secrets/create", strings.NewReader(`{"Name":"db-password","Data":"c2VjcmV0"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestSecretInspectDeniesDriverSelections(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})

	req := httptest.NewRequest(http.MethodPost, "/v1.53/secrets/create", strings.NewReader(`{"Driver":"s3"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `secret create denied: driver "s3" is not allowed` {
		t.Fatalf("inspect() reason = %q, want driver denial", reason)
	}

	req = httptest.NewRequest(http.MethodPost, "/secrets/create", strings.NewReader(`{"Templating":{"Name":"golang-template"}}`))
	reason, err = policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `secret create denied: template driver "golang-template" is not allowed` {
		t.Fatalf("inspect() reason = %q, want template-driver denial", reason)
	}
}

func TestSecretInspectHandlesMalformedJSON(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewBufferString("{"))

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

func TestSecretInspectCapsOversizedBody(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewReader(bytes.Repeat([]byte{'x'}, maxSecretBodyBytes+1)))

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
	if !strings.HasPrefix(rejection.reason, "secret create denied: request body exceeds") {
		t.Fatalf("rejection reason = %q, want oversize denial", rejection.reason)
	}
}
