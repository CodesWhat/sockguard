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

	req := httptest.NewRequest(http.MethodPost, "/v1.53/secrets/create", strings.NewReader(`{"Driver":{"Name":"s3"}}`))
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

// TestSecretInspectReadsTheDriverObject covers the Driver field as both
// engines decode it: an object of Name and Options (moby 28.5.1
// api/types/swarm/secret.go SecretSpec.Driver, a *swarm.Driver; Podman 5.8.6
// pkg/domain/entities/secrets.go SecretCreateRequest.Driver, a
// SecretDriverSpec). Read as a string, every body naming a driver failed to
// decode and was refused as uninspectable, allow_custom_drivers or not.
func TestSecretInspectReadsTheDriverObject(t *testing.T) {
	const uninspectable = "secret create denied: request body could not be inspected"
	tests := []struct {
		name       string
		allow      bool
		body       string
		wantReason string
	}{
		{name: "no driver", body: `{"Name":"s","Data":"c2VjcmV0"}`},
		{name: "null driver", body: `{"Name":"s","Driver":null}`},
		{name: "empty driver", body: `{"Name":"s","Driver":{}}`},
		{name: "empty driver name", body: `{"Name":"s","Driver":{"Name":""}}`},
		{
			name:       "named driver",
			body:       `{"Name":"s","Driver":{"Name":"vault"}}`,
			wantReason: `secret create denied: driver "vault" is not allowed`,
		},
		{
			// dockerd resolves every driver name as a secrets plugin, so
			// the compat route has no default to recognize by name.
			name:       "file driver",
			body:       `{"Name":"s","Driver":{"Name":"file"}}`,
			wantReason: `secret create denied: driver "file" is not allowed`,
		},
		{
			name:       "driver options without a driver",
			body:       `{"Name":"s","Driver":{"Options":{"path":"/etc/cron.d"}}}`,
			wantReason: "secret create denied: driver options are not allowed",
		},
		{
			name:       "driver lowercase key",
			body:       `{"Name":"s","driver":{"name":"vault"}}`,
			wantReason: `secret create denied: driver "vault" is not allowed`,
		},
		{name: "driver as a string", body: `{"Name":"s","Driver":"vault"}`, wantReason: uninspectable},
		{name: "named driver with options when allowed", allow: true, body: `{"Name":"s","Driver":{"Name":"vault","Options":{"addr":"https://vault:8200"}}}`},
		{name: "driver options when allowed", allow: true, body: `{"Name":"s","Driver":{"Options":{"addr":"https://vault:8200"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newSecretPolicy(SecretOptions{AllowCustomDrivers: tt.allow})
			req := httptest.NewRequest(http.MethodPost, "/v1.45/secrets/create", strings.NewReader(tt.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestSecretInspectHandlesMalformedJSON(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewBufferString("{"))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	// Malformed JSON must be denied (fail-closed).
	const wantReason = "secret create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
	}
}

func TestSecretInspectCapsOversizedBody(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewReader(bytes.Repeat([]byte{'x'}, driverCreateMaxBodyBytes+1)))

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

func TestSecretInspectNilRequestReturnsEmpty(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})
	reason, err := policy.inspect(nil, nil, "/secrets/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil) = (%q, %v), want empty", reason, err)
	}
}

func TestSecretInspectNilBodyReturnsEmpty(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", nil)
	req.Body = nil
	reason, err := policy.inspect(nil, req, "/secrets/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil body) = (%q, %v), want empty", reason, err)
	}
}

func TestSecretInspectEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewReader(nil))
	reason, err := policy.inspect(nil, req, "/secrets/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(empty body) = (%q, %v), want empty", reason, err)
	}
}

func TestSecretInspectAllowsTemplateDriverWhenConfigured(t *testing.T) {
	policy := newSecretPolicy(SecretOptions{AllowTemplateDrivers: true})
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", strings.NewReader(`{"TemplateDriver":"golang-template"}`))
	reason, err := policy.inspect(nil, req, "/secrets/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestSecretInspectBodyReadErrorPropagates(t *testing.T) {
	// Exercises the non-tooLarge error branch from readBoundedBody (line 48).
	policy := newSecretPolicy(SecretOptions{})
	sentinel := io.ErrUnexpectedEOF
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}
	_, err := policy.inspect(nil, req, "/secrets/create")
	if err == nil {
		t.Fatal("expected read error to propagate")
	}
}

func TestSecretInspectMalformedJSONWithLogger(t *testing.T) {
	// Exercises the logger debug branch when JSON decode fails; must deny (fail-closed).
	policy := newSecretPolicy(SecretOptions{})
	logs := &collectingHandler{}
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", strings.NewReader("{bad json}"))
	reason, err := policy.inspect(slog.New(logs), req, "/secrets/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	const wantReason = "secret create denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if len(logs.snapshot()) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs.snapshot()))
	}
}
