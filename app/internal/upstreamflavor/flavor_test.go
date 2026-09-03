package upstreamflavor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// clientFor returns an *http.Client whose transport dials addr no matter what
// host the request URL names. That is exactly how the production client
// behaves: Detect builds "http://docker/version" and the shared
// upstream.Resolver routes it to the configured endpoint, ignoring the
// placeholder host. Testing through the same shape means the fixed URL in
// Detect is exercised rather than bypassed.
func clientFor(addr string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}}
}

// podmanVersionBody is the shape pkg/api/handlers/compat/version.go builds at
// Podman v5.8.1: "Podman Engine" first, then Conmon and the OCI runtime.
const podmanVersionBody = `{
  "Platform": {"Name": "linux/arm64/fedora-41"},
  "Components": [
    {"Name": "Podman Engine", "Version": "5.8.1", "Details": {"APIVersion": "5.8.1"}},
    {"Name": "Conmon", "Version": "2.1.13"},
    {"Name": "OCI Runtime (crun)", "Version": "1.20"}
  ],
  "Version": "5.8.1",
  "ApiVersion": "1.41"
}`

// dockerVersionBody is the shape daemon/info.go's SystemVersion builds: a
// single "Engine" component.
const dockerVersionBody = `{
  "Platform": {"Name": "Docker Engine - Community"},
  "Components": [
    {"Name": "Engine", "Version": "28.6.0", "Details": {"ApiVersion": "1.52"}}
  ],
  "Version": "28.6.0",
  "ApiVersion": "1.52"
}`

func TestDetectClassifiesVersionResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      int
		body        string
		want        Flavor
		wantErr     bool
		wantErrIs   error
		wantErrPart string
	}{
		{
			name:   "podman engine",
			status: http.StatusOK,
			body:   podmanVersionBody,
			want:   Podman,
		},
		{
			name:   "docker engine",
			status: http.StatusOK,
			body:   dockerVersionBody,
			want:   Docker,
		},
		{
			name:      "ambiguous when both engines are named, engine first",
			status:    http.StatusOK,
			body:      `{"Components":[{"Name":"Engine"},{"Name":"Podman Engine"}]}`,
			wantErr:   true,
			wantErrIs: ErrAmbiguous,
		},
		{
			name:      "ambiguous when both engines are named, podman first",
			status:    http.StatusOK,
			body:      `{"Components":[{"Name":"Podman Engine"},{"Name":"Engine"}]}`,
			wantErr:   true,
			wantErrIs: ErrAmbiguous,
		},
		{
			name:      "unrecognized engine",
			status:    http.StatusOK,
			body:      `{"Components":[{"Name":"Containerd"},{"Name":"runc"}]}`,
			wantErr:   true,
			wantErrIs: ErrUnrecognized,
		},
		{
			name:      "no components at all",
			status:    http.StatusOK,
			body:      `{"Version":"28.6.0"}`,
			wantErr:   true,
			wantErrIs: ErrUnrecognized,
		},
		{
			name:        "malformed json",
			status:      http.StatusOK,
			body:        `{"Components":[{"Name":`,
			wantErr:     true,
			wantErrPart: "decode /version response",
		},
		{
			name:        "json that is not an object",
			status:      http.StatusOK,
			body:        `["Engine"]`,
			wantErr:     true,
			wantErrPart: "decode /version response",
		},
		{
			name:        "non-200 from a proxy that denies /version",
			status:      http.StatusForbidden,
			body:        `{"message":"denied"}`,
			wantErr:     true,
			wantErrPart: "returned HTTP 403",
		},
		{
			name:        "500 from the daemon",
			status:      http.StatusInternalServerError,
			body:        podmanVersionBody,
			wantErr:     true,
			wantErrPart: "returned HTTP 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			got, err := Detect(t.Context(), clientFor(srv.Listener.Addr().String()))

			if gotPath != "/version" {
				t.Fatalf("probed path = %q, want %q", gotPath, "/version")
			}
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Detect() = %q, want an error", got)
				}
				if got != "" {
					t.Fatalf("Detect() returned flavor %q alongside error %v, want an empty flavor", got, err)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("Detect() error = %v, want errors.Is %v", err, tt.wantErrIs)
				}
				if tt.wantErrPart != "" && !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Fatalf("Detect() error = %v, want it to mention %q", err, tt.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("Detect() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("Detect() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDetectFailsOnConnectionRefused covers the daemon that is not listening
// at all: the probe must report a transport error, never a flavor.
func TestDetectFailsOnConnectionRefused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.Listener.Addr().String()
	srv.Close()

	got, err := Detect(t.Context(), clientFor(addr))
	if err == nil {
		t.Fatalf("Detect() = %q, want a connection error", got)
	}
	if got != "" {
		t.Fatalf("Detect() = %q, want an empty flavor on a connection error", got)
	}
	if !strings.Contains(err.Error(), "GET /version") {
		t.Fatalf("Detect() error = %v, want it to name the failed call", err)
	}
}

// TestDetectFailsOnTimeout covers the daemon that accepts the connection and
// then never answers. The bound must come from the caller's context, so a
// hung upstream cannot hold the listener closed indefinitely.
func TestDetectFailsOnTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	got, err := Detect(ctx, clientFor(srv.Listener.Addr().String()))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Detect() = %q, want a timeout error", got)
	}
	if got != "" {
		t.Fatalf("Detect() = %q, want an empty flavor on timeout", got)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Detect() error = %v, want errors.Is context.DeadlineExceeded", err)
	}
	if elapsed >= DetectTimeout {
		t.Fatalf("Detect() took %v, want it bounded by the caller's context well under %v", elapsed, DetectTimeout)
	}
}

// TestDetectFailsOnOversizedBody covers an upstream that answers /version
// with an unbounded stream: the read is capped and the probe fails rather
// than allocating whatever the upstream feels like sending.
func TestDetectFailsOnOversizedBody(t *testing.T) {
	t.Parallel()
	chunk := strings.Repeat("a", 64*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for written := 0; written <= maxVersionBodyBytes; written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	got, err := Detect(t.Context(), clientFor(srv.Listener.Addr().String()))
	if err == nil {
		t.Fatalf("Detect() = %q, want a size-limit error", got)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Detect() error = %v, want a size-limit error", err)
	}
}

func TestDetectRejectsNilClient(t *testing.T) {
	t.Parallel()
	if got, err := Detect(t.Context(), nil); err == nil {
		t.Fatalf("Detect(nil) = %q, want an error", got)
	}
}

func TestConfigured(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  Flavor
		ok    bool
	}{
		{name: "auto", input: "auto", want: Auto, ok: true},
		{name: "docker", input: "docker", want: Docker, ok: true},
		{name: "podman", input: "podman", want: Podman, ok: true},
		{name: "surrounding whitespace", input: "  podman\n", want: Podman, ok: true},
		{name: "empty is not auto", input: ""},
		{name: "wrong case", input: "Podman"},
		{name: "unknown engine", input: "containerd"},
		{name: "abbreviation", input: "pod"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := Configured(tt.input)
			if ok != tt.ok {
				t.Fatalf("Configured(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("Configured(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestZeroFlavorIsNotAResolvedValue pins the contract the visibility package
// depends on: the zero Flavor is neither Docker nor Podman as a value, so a
// caller cannot accidentally get Podman semantics from an unset field, and
// Auto is never something a resolved flavor equals.
func TestZeroFlavorIsNotAResolvedValue(t *testing.T) {
	t.Parallel()
	var zero Flavor
	if zero == Docker || zero == Podman || zero == Auto {
		t.Fatalf("zero Flavor = %q, want it distinct from every named value", zero)
	}
}
