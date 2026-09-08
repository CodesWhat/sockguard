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

func TestSecretInspectDockerDriverShape(t *testing.T) {
	const driverDenied = `secret create denied: driver "vault" is not allowed`
	const malformed = "secret create denied: request body could not be inspected"
	for _, tt := range []struct {
		name, body string
		allow      bool
		want       string
	}{
		{"object denied", `{"Driver":{"Name":"vault","Options":{"address":"local"}}}`, false, driverDenied},
		{"object allowed", `{"Driver":{"Name":"vault","Options":{"address":"local"}}}`, true, ""},
		{"absent", `{}`, false, ""},
		{"null", `{"Driver":null}`, false, ""},
		{"empty", `{"Driver":{}}`, false, ""},
		{"boolean", `{"Driver":true}`, true, malformed},
		{"array", `{"Driver":[]}`, true, malformed},
		{"number", `{"Driver":1}`, true, malformed},
		{"invalid name", `{"Driver":{"Name":1}}`, true, malformed},
		{"merge empty", `{"Driver":{"Name":"vault"},"Driver":{}}`, false, driverDenied},
		{"merge null name", `{"Driver":{"Name":"vault"},"Driver":{"Name":null}}`, false, driverDenied},
		{"clear selection", `{"Driver":{"Name":"vault"},"Driver":null}`, false, ""},
		{"compatibility denied", `{"Driver":"vault"}`, false, driverDenied},
		{"compatibility allowed", `{"Driver":"vault"}`, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/secrets/create", strings.NewReader(tt.body))
			reason, err := newSecretPolicy(SecretOptions{AllowCustomDrivers: tt.allow}).inspect(nil, req, "/secrets/create")
			if err != nil || reason != tt.want {
				t.Fatalf("inspect() = (%q, %v), want (%q, nil)", reason, err, tt.want)
			}
		})
	}
}

func TestMiddlewareSecretDockerDriver(t *testing.T) {
	for _, path := range []string{"/secrets/create", "/v1.53/secrets/create"} {
		for _, tt := range []struct {
			name, body    string
			allow, denied bool
		}{
			{"denied", `{"Driver":{"Name":"vault","Options":{"address":"local"}}}`, false, true},
			{"allowed", `{"Driver":{"Name":"vault","Options":{"address":"local"}}}`, true, false},
			{"template still denied", `{"Driver":{"Name":"vault"},"TemplateDriver":"golang"}`, true, true},
			{"templating still denied", `{"Driver":{"Name":"vault"},"Templating":{"Name":"golang"}}`, true, true},
		} {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				assertFilterCreateRoundTrip(t, path, tt.body, PolicyConfig{Secret: SecretOptions{AllowCustomDrivers: tt.allow}}, tt.denied)
			})
		}
	}
}
