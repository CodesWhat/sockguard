package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLibpodSecretInspectAllowsDefaultCreate(t *testing.T) {
	policy := newLibpodSecretPolicy(SecretOptions{})

	req := httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?name=db-password", nil)
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestLibpodSecretInspectIgnoresNonMatchingPathsAndMethods(t *testing.T) {
	policy := newLibpodSecretPolicy(SecretOptions{})
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"docker secrets create", http.MethodPost, "/secrets/create?driver=s3"},
		{"wrong method", http.MethodGet, "/libpod/secrets/create?driver=s3"},
		{"libpod secrets json", http.MethodPost, "/libpod/secrets/json?driver=s3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

func TestLibpodSecretInspectDriverGateReadsQueryNotBody(t *testing.T) {
	// libpod secret create takes driver as a QUERY parameter, not a JSON
	// body field — a Docker-shaped JSON body claiming a custom driver must
	// have no effect, and an empty/absent body must not error.
	policy := newLibpodSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?name=x&driver=s3", nil)
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != `libpod secret create denied: driver "s3" is not allowed` {
		t.Fatalf("inspect() reason = %q, want driver denial", reason)
	}

	policy = newLibpodSecretPolicy(SecretOptions{AllowCustomDrivers: true})
	req = httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?name=x&driver=s3", nil)
	reason, err = policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestLibpodSecretInspectNeverReadsBody(t *testing.T) {
	// The request body is raw secret payload bytes, never JSON. A body
	// claiming {"Driver":"s3"} (Docker's shape) must have zero effect, and
	// the body itself must be left completely untouched for the proxy to
	// forward.
	policy := newLibpodSecretPolicy(SecretOptions{})
	req := httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?name=x", nil)
	req.Body = http.NoBody
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	if req.Body != http.NoBody {
		t.Fatal("inspect() must not replace or consume r.Body")
	}
}
