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

// TestLibpodSecretInspectDriverAndDriverOptions covers the two query
// parameters that pick where Podman stores a secret. podman-remote always
// sends `driver=file`, the containers.conf default, so that has to pass
// without allow_custom_drivers. `driveropts` reaches the driver whatever it
// is, including the default: the file driver's `path` option is the
// directory on the daemon host the secret data is written to, so any option
// needs the flag. Read from Podman 5.8.6 pkg/api/handlers/libpod/secrets.go,
// pkg/domain/infra/abi/secrets.go and go.podman.io/common v0.67.1
// pkg/secrets/secrets.go getDriver.
func TestLibpodSecretInspectDriverAndDriverOptions(t *testing.T) {
	const optionsDenied = "libpod secret create denied: driver options are not allowed"
	tests := []struct {
		name       string
		allow      bool
		target     string
		wantReason string
	}{
		{name: "podman-remote default create", target: "/libpod/secrets/create?driver=file&ignore=false&labels=%7B%7D&name=s&replace=false"},
		{name: "file driver", target: "/libpod/secrets/create?name=s&driver=file"},
		{name: "no driver", target: "/libpod/secrets/create?name=s"},
		{name: "empty driver options", target: "/libpod/secrets/create?name=s&driveropts="},
		{name: "empty driver options object", target: "/libpod/secrets/create?name=s&driver=file&driveropts=%7B%7D"},
		{name: "null driver options", target: "/libpod/secrets/create?name=s&driveropts=null"},
		{
			name:       "file driver path on the default driver",
			target:     "/libpod/secrets/create?name=s&driveropts=%7B%22path%22%3A%22%2Fetc%2Fcron.d%22%7D",
			wantReason: optionsDenied,
		},
		{
			name:       "file driver path on the file driver",
			target:     "/libpod/secrets/create?name=s&driver=file&driveropts=%7B%22path%22%3A%22%2Fetc%2Fcron.d%22%7D",
			wantReason: optionsDenied,
		},
		{
			// Podman's convertStringMap keeps the keys that decode, so the
			// path still lands even though another value has the wrong type.
			name:       "driver options with a value Podman cannot decode",
			target:     "/libpod/secrets/create?name=s&driveropts=%7B%22n%22%3A1%2C%22path%22%3A%22%2Fsrv%22%7D",
			wantReason: optionsDenied,
		},
		{
			name:       "driver options that are not a JSON object",
			target:     "/libpod/secrets/create?name=s&driveropts=path%3D%2Fsrv",
			wantReason: "libpod secret create denied: driver options could not be inspected",
		},
		{
			name:       "driver options in another spelling",
			target:     "/libpod/secrets/create?name=s&DriverOpts=%7B%22path%22%3A%22%2Fsrv%22%7D",
			wantReason: ambiguousQueryReason("libpod secret create", "driveropts"),
		},
		{
			name:       "driver options repeated behind an empty object",
			target:     "/libpod/secrets/create?name=s&driveropts=%7B%7D&driveropts=%7B%22path%22%3A%22%2Fsrv%22%7D",
			wantReason: ambiguousQueryReason("libpod secret create", "driveropts"),
		},
		{
			name:       "custom driver",
			target:     "/libpod/secrets/create?name=s&driver=shell",
			wantReason: `libpod secret create denied: driver "shell" is not allowed`,
		},
		{
			name:       "file in another letter case",
			target:     "/libpod/secrets/create?name=s&driver=FILE",
			wantReason: `libpod secret create denied: driver "FILE" is not allowed`,
		},
		{name: "driver options when allowed", allow: true, target: "/libpod/secrets/create?name=s&driveropts=%7B%22path%22%3A%22%2Fsrv%22%7D"},
		{name: "custom driver with options when allowed", allow: true, target: "/libpod/secrets/create?name=s&driver=shell&driveropts=%7B%22store%22%3A%22cat%22%7D"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newLibpodSecretPolicy(SecretOptions{AllowCustomDrivers: tt.allow})
			req := httptest.NewRequest(http.MethodPost, tt.target, nil)
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
