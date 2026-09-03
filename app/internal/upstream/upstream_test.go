package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/testcert"
)

// ── helpers ────────────────────────────────────────────────────────────────────

// tempSocketPath creates a unique path under /tmp safe for a unix socket
// (avoids the 104-byte sun_path limit that t.TempDir() can hit on macOS).
func tempSocketPath(t *testing.T, label string) string {
	t.Helper()
	f, err := os.CreateTemp("/tmp", "us-"+label+"-*.sock")
	if err != nil {
		t.Fatalf("create temp socket: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

// startUnixServer starts an HTTP server over a unix socket and returns the
// socket path. The server is shut down via t.Cleanup.
func startUnixServer(t *testing.T, label string, handler http.Handler) string {
	t.Helper()
	path := tempSocketPath(t, label)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return path
}

// probeAlways returns a probe func that always reports the given error.
func probeAlways(err error) func(context.Context, Endpoint) error {
	return func(_ context.Context, _ Endpoint) error { return err }
}

// ── parseAddress ──────────────────────────────────────────────────────────────

func TestParseAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		input       string
		wantNetwork string
		wantAddress string
		wantErr     bool
	}{
		// valid unix
		{name: "unix url", input: "unix:///var/run/docker.sock", wantNetwork: "unix", wantAddress: "/var/run/docker.sock"},
		{name: "bare absolute path", input: "/var/run/docker.sock", wantNetwork: "unix", wantAddress: "/var/run/docker.sock"},
		{name: "bare dot-relative path", input: "./docker.sock", wantNetwork: "unix", wantAddress: "./docker.sock"},
		{name: "bare dot-dot path", input: "../docker.sock", wantNetwork: "unix", wantAddress: "../docker.sock"},
		{name: "relative unix url", input: "unix://relative.sock/path", wantNetwork: "unix", wantAddress: "relative.sock/path"},
		{name: "unix encoded slash is literal", input: "unix:///tmp/docker%2Fsock", wantNetwork: "unix", wantAddress: "/tmp/docker%2Fsock"},
		{name: "unix encoded question is literal", input: "unix:///tmp/docker%3Fsock", wantNetwork: "unix", wantAddress: "/tmp/docker%3Fsock"},
		{name: "unix encoded hash is literal", input: "unix:///tmp/docker%23sock", wantNetwork: "unix", wantAddress: "/tmp/docker%23sock"},
		{name: "unix encoded percent is literal", input: "unix:///tmp/docker%25sock", wantNetwork: "unix", wantAddress: "/tmp/docker%25sock"},
		{name: "unix raw question and hash are literal", input: "unix:///tmp/docker?sock#one", wantNetwork: "unix", wantAddress: "/tmp/docker?sock#one"},
		{name: "relative unix raw URL punctuation is literal", input: "unix://relative.sock?one#two", wantNetwork: "unix", wantAddress: "relative.sock?one#two"},
		{name: "relative unix encoded percent is literal", input: "unix://relative%25sock", wantNetwork: "unix", wantAddress: "relative%25sock"},
		{name: "absolute unix escaped path and punctuation are literal", input: "unix:///tmp/relative%2Fsock?one#two", wantNetwork: "unix", wantAddress: "/tmp/relative%2Fsock?one#two"},
		// valid tcp-family
		{name: "tcp url", input: "tcp://host:2376", wantNetwork: "tcp", wantAddress: "host:2376"},
		{name: "http url", input: "http://host:2375", wantNetwork: "tcp", wantAddress: "host:2375"},
		{name: "https url", input: "https://host:2376", wantNetwork: "tcp", wantAddress: "host:2376"},
		// errors
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace only", input: "   ", wantErr: true},
		{name: "scheme-less non-path", input: "notapath", wantErr: true},
		{name: "unix missing path", input: "unix://", wantErr: true},
		{name: "tcp missing port", input: "tcp://myhost", wantErr: true},
		{name: "bad scheme", input: "ftp://host:21", wantErr: true},
		{name: "unix malformed escape", input: "unix:///tmp/docker%zzsock", wantErr: true},
		{name: "relative unix encoded slash is invalid host grammar", input: "unix://relative%2Fsock", wantErr: true},
		{name: "relative unix encoded question is invalid host grammar", input: "unix://relative%3Fsock", wantErr: true},
		{name: "relative unix encoded hash is invalid host grammar", input: "unix://relative%23sock", wantErr: true},
		{name: "unix nested scheme", input: "unix:///tmp/docker://sock", wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			net, addr, err := parseAddress(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAddress(%q) expected error, got network=%q addr=%q", tc.input, net, addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAddress(%q) unexpected error: %v", tc.input, err)
			}
			if net != tc.wantNetwork {
				t.Errorf("network = %q, want %q", net, tc.wantNetwork)
			}
			if addr != tc.wantAddress {
				t.Errorf("address = %q, want %q", addr, tc.wantAddress)
			}
		})
	}
}

// ── ValidateSpec ──────────────────────────────────────────────────────────────

func TestValidateSpec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		spec    EndpointSpec
		wantErr bool
	}{
		// unix — valid
		{
			name: "unix bare path ok",
			spec: EndpointSpec{Address: "/var/run/docker.sock"},
		},
		{
			name: "unix url ok",
			spec: EndpointSpec{Address: "unix:///var/run/docker.sock"},
		},
		// unix — rejects TLS fields
		{
			name:    "unix with CAFile",
			spec:    EndpointSpec{Address: "/run/docker.sock", CAFile: "/tmp/ca.pem"},
			wantErr: true,
		},
		{
			name:    "unix with CertFile",
			spec:    EndpointSpec{Address: "/run/docker.sock", CertFile: "/tmp/cert.pem"},
			wantErr: true,
		},
		{
			name:    "unix with KeyFile",
			spec:    EndpointSpec{Address: "/run/docker.sock", KeyFile: "/tmp/key.pem"},
			wantErr: true,
		},
		{
			name:    "unix with ServerName",
			spec:    EndpointSpec{Address: "/run/docker.sock", ServerName: "daemon.internal"},
			wantErr: true,
		},
		// tcp — valid TLS combos
		{
			name: "tcp with ca only",
			spec: EndpointSpec{Address: "tcp://host:2376", CAFile: "/tmp/ca.pem"},
		},
		{
			name: "tcp with cert+key",
			spec: EndpointSpec{Address: "tcp://host:2376", CertFile: "/tmp/cert.pem", KeyFile: "/tmp/key.pem"},
		},
		{
			name: "tcp insecure skip verify",
			spec: EndpointSpec{Address: "tcp://host:2376", InsecureSkipTLSVerify: true},
		},
		{
			name: "tcp plain insecure acknowledged",
			spec: EndpointSpec{Address: "tcp://host:2376", InsecureAllowPlainTCP: true},
		},
		// tcp — errors
		{
			name:    "tcp no tls no plain",
			spec:    EndpointSpec{Address: "tcp://host:2376"},
			wantErr: true,
		},
		{
			name:    "tcp cert without key",
			spec:    EndpointSpec{Address: "tcp://host:2376", CertFile: "/tmp/cert.pem"},
			wantErr: true,
		},
		{
			name:    "tcp key without cert",
			spec:    EndpointSpec{Address: "tcp://host:2376", KeyFile: "/tmp/key.pem"},
			wantErr: true,
		},
		// bad address
		{
			name:    "bad address",
			spec:    EndpointSpec{Address: ""},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSpec(tc.spec)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateSpec(%+v) expected error, got nil", tc.spec)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateSpec(%+v) unexpected error: %v", tc.spec, err)
			}
		})
	}
}

// ── BuildEndpoint ─────────────────────────────────────────────────────────────

func TestBuildEndpoint_Unix(t *testing.T) {
	t.Parallel()
	ep, err := BuildEndpoint(EndpointSpec{Address: "/var/run/docker.sock"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.Network != "unix" {
		t.Errorf("Network = %q, want %q", ep.Network, "unix")
	}
	if ep.Address != "/var/run/docker.sock" {
		t.Errorf("Address = %q, want %q", ep.Address, "/var/run/docker.sock")
	}
	if ep.IsTLS() {
		t.Error("unix endpoint must not be TLS")
	}
}

func TestBuildEndpoint_UnixWithTLS_Rejected(t *testing.T) {
	t.Parallel()
	_, err := BuildEndpoint(EndpointSpec{Address: "/run/docker.sock", CAFile: "/tmp/ca.pem"})
	if err == nil {
		t.Fatal("expected error for unix+TLS, got nil")
	}
}

func TestBuildEndpoint_UnixWithServerName_Rejected(t *testing.T) {
	t.Parallel()
	_, err := BuildEndpoint(EndpointSpec{Address: "/run/docker.sock", ServerName: "daemon.internal"})
	if err == nil {
		t.Fatal("expected error for unix+tls.server_name, got nil")
	}
}

func TestBuildEndpoint_PlainTCP(t *testing.T) {
	t.Parallel()
	ep, err := BuildEndpoint(EndpointSpec{Address: "tcp://host:2376", InsecureAllowPlainTCP: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.Network != "tcp" {
		t.Errorf("Network = %q, want %q", ep.Network, "tcp")
	}
	if ep.IsTLS() {
		t.Error("plain TCP endpoint must not be TLS")
	}
}

func TestBuildEndpoint_TCPBasePathMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		address     string
		wantDial    string
		wantPath    string
		wantRawPath string
		wantString  string
	}{
		{name: "none", address: "tcp://host:2375", wantDial: "host:2375", wantString: "tcp://host:2375"},
		{name: "root", address: "tcp://host:2375/", wantDial: "host:2375", wantPath: "/", wantString: "tcp://host:2375/"},
		{name: "plain trailing slash", address: "tcp://host:2375/gateway/docker/", wantDial: "host:2375", wantPath: "/gateway/docker/", wantString: "tcp://host:2375/gateway/docker/"},
		{name: "escaped", address: "tcp://host:2375/gateway%2Fdocker/%2e%2e", wantDial: "host:2375", wantPath: "/gateway/docker/..", wantRawPath: "/gateway%2Fdocker/%2e%2e", wantString: "tcp://host:2375/gateway%2Fdocker/%2e%2e"},
		{name: "IPv6", address: "tcp://[::1]:2375/gateway", wantDial: "[::1]:2375", wantPath: "/gateway", wantString: "tcp://[::1]:2375/gateway"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ep, err := BuildEndpoint(EndpointSpec{Address: tt.address, InsecureAllowPlainTCP: true})
			if err != nil {
				t.Fatalf("BuildEndpoint: %v", err)
			}
			if ep.Address != tt.wantDial || ep.BasePath != tt.wantPath || ep.RawBasePath != tt.wantRawPath {
				t.Fatalf("Endpoint = {Address:%q BasePath:%q RawBasePath:%q}, want {%q %q %q}", ep.Address, ep.BasePath, ep.RawBasePath, tt.wantDial, tt.wantPath, tt.wantRawPath)
			}
			if got := ep.String(); got != tt.wantString {
				t.Fatalf("String() = %q, want %q", got, tt.wantString)
			}
		})
	}
}

func TestBuildEndpoint_TLSInsecureSkip(t *testing.T) {
	t.Parallel()
	ep, err := BuildEndpoint(EndpointSpec{Address: "tcp://host:2376", InsecureSkipTLSVerify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ep.IsTLS() {
		t.Error("endpoint should be TLS when InsecureSkipTLSVerify is set")
	}
	if !ep.TLSConfig.InsecureSkipVerify {
		t.Error("TLSConfig.InsecureSkipVerify should be true")
	}
}

func TestBuildEndpoint_TLSWithCertFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("write test bundle: %v", err)
	}

	ep, err := BuildEndpoint(EndpointSpec{
		Address:  "tcp://127.0.0.1:2376",
		CAFile:   bundle.CAFile,
		CertFile: bundle.ClientCertFile,
		KeyFile:  bundle.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ep.IsTLS() {
		t.Error("endpoint should be TLS")
	}
	if len(ep.TLSConfig.Certificates) != 1 {
		t.Errorf("TLSConfig.Certificates len = %d, want 1", len(ep.TLSConfig.Certificates))
	}
	if ep.TLSConfig.RootCAs == nil {
		t.Error("TLSConfig.RootCAs should not be nil when CAFile is set")
	}
}

func TestBuildEndpoint_MissingCAFile(t *testing.T) {
	t.Parallel()
	_, err := BuildEndpoint(EndpointSpec{
		Address: "tcp://host:2376",
		CAFile:  "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing CAFile, got nil")
	}
}

func TestBuildEndpoint_MalformedCAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a valid PEM certificate"), 0o600); err != nil {
		t.Fatalf("write bad CA: %v", err)
	}
	_, err := BuildEndpoint(EndpointSpec{
		Address: "tcp://host:2376",
		CAFile:  caPath,
	})
	if err == nil {
		t.Fatal("expected error for malformed CA PEM, got nil")
	}
}

func TestBuildEndpoint_BadKeyPair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("write test bundle: %v", err)
	}
	// Pass mismatched files: cert from one bundle, key from another location.
	badKeyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badKeyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	_, err = BuildEndpoint(EndpointSpec{
		Address:  "tcp://host:2376",
		CertFile: bundle.ClientCertFile,
		KeyFile:  badKeyPath,
	})
	if err == nil {
		t.Fatal("expected error for bad keypair, got nil")
	}
}

func TestBuildEndpoint_CertWithoutKey(t *testing.T) {
	t.Parallel()
	_, err := BuildEndpoint(EndpointSpec{
		Address:  "tcp://host:2376",
		CertFile: "/tmp/cert.pem",
	})
	if err == nil {
		t.Fatal("expected error when CertFile set without KeyFile")
	}
}

func TestBuildEndpoint_KeyWithoutCert(t *testing.T) {
	t.Parallel()
	_, err := BuildEndpoint(EndpointSpec{
		Address: "tcp://host:2376",
		KeyFile: "/tmp/key.pem",
	})
	if err == nil {
		t.Fatal("expected error when KeyFile set without CertFile")
	}
}

func TestBuildEndpoint_ServerNameOverride(t *testing.T) {
	t.Parallel()
	ep, err := BuildEndpoint(EndpointSpec{
		Address:               "tcp://host:2376",
		InsecureSkipTLSVerify: true,
		ServerName:            "overridden.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.TLSConfig.ServerName != "overridden.example.com" {
		t.Errorf("ServerName = %q, want %q", ep.TLSConfig.ServerName, "overridden.example.com")
	}
}

func TestBuildEndpoint_SNIDerivedFromHost(t *testing.T) {
	t.Parallel()
	ep, err := BuildEndpoint(EndpointSpec{
		Address:               "tcp://daemon.example.com:2376",
		InsecureSkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.TLSConfig.ServerName != "daemon.example.com" {
		t.Errorf("ServerName = %q, want %q", ep.TLSConfig.ServerName, "daemon.example.com")
	}
}

func TestSplitHostPort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		hostport string
		wantHost string
		wantPort string
		wantOK   bool
	}{
		{name: "host and port", hostport: "example.com:2376", wantHost: "example.com", wantPort: "2376", wantOK: true},
		{name: "IPv6 literal", hostport: "[::1]:2376", wantHost: "::1", wantPort: "2376", wantOK: true},
		{name: "no colon at all", hostport: "example.com", wantHost: "example.com", wantPort: "", wantOK: false},
		// A colon at index 0 is still a colon that was found (i == 0, not < 0):
		// the empty host and the port after it must still be split out. This
		// pins the exact "not found" boundary at i < 0, not i <= 0.
		{name: "colon at index zero", hostport: ":2376", wantHost: "", wantPort: "2376", wantOK: true},
		{name: "trailing colon, no port", hostport: "example.com:", wantHost: "example.com", wantPort: "", wantOK: false},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			host, port, ok := splitHostPort(tt.hostport)
			if host != tt.wantHost || port != tt.wantPort || ok != tt.wantOK {
				t.Fatalf("splitHostPort(%q) = (%q, %q, %v), want (%q, %q, %v)", tt.hostport, host, port, ok, tt.wantHost, tt.wantPort, tt.wantOK)
			}
		})
	}
}

// ── Endpoint.String / IsTLS ───────────────────────────────────────────────────

func TestEndpoint_StringAndIsTLS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		ep        Endpoint
		wantStr   string
		wantIsTLS bool
	}{
		{
			name:      "unix socket",
			ep:        Endpoint{Name: "/run/docker.sock", Network: "unix", Address: "/run/docker.sock"},
			wantStr:   "unix:///run/docker.sock",
			wantIsTLS: false,
		},
		{
			name:      "plain tcp",
			ep:        Endpoint{Name: "host:2375", Network: "tcp", Address: "host:2375"},
			wantStr:   "tcp://host:2375",
			wantIsTLS: false,
		},
		{
			name:      "tcp with tls",
			ep:        Endpoint{Name: "host:2376", Network: "tcp", Address: "host:2376", TLSConfig: tlsMinConfig},
			wantStr:   "tcp+tls://host:2376",
			wantIsTLS: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.ep.String(); got != tc.wantStr {
				t.Errorf("String() = %q, want %q", got, tc.wantStr)
			}
			if got := tc.ep.IsTLS(); got != tc.wantIsTLS {
				t.Errorf("IsTLS() = %v, want %v", got, tc.wantIsTLS)
			}
		})
	}
}

// tlsMinConfig is a minimal non-nil *tls.Config used in tests that need to
// mark an endpoint as TLS without actually negotiating a handshake.
var tlsMinConfig = &tls.Config{MinVersion: tls.VersionTLS12}

// ── New / NewSingleSocket ─────────────────────────────────────────────────────

func TestNew_NoEndpoints(t *testing.T) {
	t.Parallel()
	_, err := New(nil, Options{})
	if !errors.Is(err, ErrNoEndpoints) {
		t.Fatalf("New(nil) error = %v, want ErrNoEndpoints", err)
	}
	_, err = New([]Endpoint{}, Options{})
	if !errors.Is(err, ErrNoEndpoints) {
		t.Fatalf("New(empty) error = %v, want ErrNoEndpoints", err)
	}
}

func TestNew_SingleEndpoint(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Name: "/tmp/test.sock", Network: "unix", Address: "/tmp/test.sock"}
	r, err := New([]Endpoint{ep}, Options{Probe: probeAlways(nil)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eps := r.Endpoints()
	if len(eps) != 1 {
		t.Fatalf("Endpoints() len = %d, want 1", len(eps))
	}
}

func TestNewSingleSocket(t *testing.T) {
	t.Parallel()
	r := NewSingleSocket("/var/run/docker.sock")
	if r == nil {
		t.Fatal("NewSingleSocket returned nil")
	}
	eps := r.Endpoints()
	if len(eps) != 1 || eps[0].Network != "unix" || eps[0].Address != "/var/run/docker.sock" {
		t.Errorf("unexpected endpoints: %+v", eps)
	}
	// NewSingleSocket passes Options{Interval: -1} specifically: negative (not
	// merely non-positive) is the sentinel loop() uses to skip the continuous
	// probe ticker entirely, leaving only the single startup probe.
	if r.interval != -1 {
		t.Errorf("interval = %v, want -1 (single startup probe only, no continuous loop)", r.interval)
	}
}

func TestNew_TimeoutBoundary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "zero uses default", timeout: 0, want: defaultProbeTimeout},
		{name: "negative uses default", timeout: -5 * time.Second, want: defaultProbeTimeout},
		{name: "positive is kept as-is", timeout: 3 * time.Second, want: 3 * time.Second},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ep := Endpoint{Name: "/tmp/timeout-boundary.sock", Network: "unix", Address: "/tmp/timeout-boundary.sock"}
			r, err := New([]Endpoint{ep}, Options{Probe: probeAlways(nil), Interval: -1, Timeout: tt.timeout})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if r.timeout != tt.want {
				t.Fatalf("timeout = %v, want %v", r.timeout, tt.want)
			}
		})
	}
}

// ── Resolver.Active and activeState precedence ────────────────────────────────

func TestResolver_Active_AllUnknown_ReturnsPrimary(t *testing.T) {
	t.Parallel()
	ep0 := Endpoint{Name: "ep0", Network: "unix", Address: "/tmp/ep0.sock"}
	ep1 := Endpoint{Name: "ep1", Network: "unix", Address: "/tmp/ep1.sock"}
	r, err := New([]Endpoint{ep0, ep1}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No probe has run yet, so all states are unknown.
	active := r.Active()
	// Should return the first unknown (ep0).
	if active.Name != "ep0" {
		t.Errorf("Active().Name = %q, want %q", active.Name, "ep0")
	}
}

func TestResolver_Active_KnownHealthyFirst(t *testing.T) {
	t.Parallel()
	ep0 := Endpoint{Name: "ep0", Network: "unix", Address: "/tmp/ep0.sock"}
	ep1 := Endpoint{Name: "ep1", Network: "unix", Address: "/tmp/ep1.sock"}

	// Probe: ep0 unhealthy, ep1 healthy. probeAll now invokes the probe
	// concurrently across endpoints, so the closure must hold no unsynchronized
	// shared state.
	probe := func(_ context.Context, ep Endpoint) error {
		if ep.Name == "ep0" {
			return errors.New("down")
		}
		return nil
	}
	r, err := New([]Endpoint{ep0, ep1}, Options{Probe: probe, Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	r.Start(ctx)
	// Wait for the startup probe (interval=-1 means one probe then stop).
	// Poll until both are known.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.states[0].known.Load() && r.states[1].known.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	active := r.Active()
	if active.Name != "ep1" {
		t.Errorf("Active().Name = %q, want %q after probe marks ep0 unhealthy and ep1 healthy", active.Name, "ep1")
	}
}

// ── Resolver routing (no real network — fake unix servers) ────────────────────

func TestResolver_RoutesToFirstEndpointWhenBothHealthy(t *testing.T) {
	t.Parallel()
	body0 := "response-from-ep0"
	body1 := "response-from-ep1"
	sock0 := startUnixServer(t, "ep0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body0)
	}))
	sock1 := startUnixServer(t, "ep1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body1)
	}))

	ep0 := Endpoint{Name: sock0, Network: "unix", Address: sock0}
	ep1 := Endpoint{Name: sock1, Network: "unix", Address: sock1}

	// Force both healthy via probe returning nil; mark them known immediately.
	r, err := New([]Endpoint{ep0, ep1}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Mark both known+healthy directly.
	r.setHealth(context.Background(), r.states[0], true)
	r.setHealth(context.Background(), r.states[1], true)

	got := doRoundTrip(t, r, sock0)
	if got != body0 {
		t.Errorf("body = %q, want %q (should route to ep0)", got, body0)
	}
}

func TestResolver_FailoverToSecondWhenFirstUnhealthy(t *testing.T) {
	t.Parallel()
	body1 := "response-from-ep1"
	sock1 := startUnixServer(t, "failover", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body1)
	}))

	// ep0 has a path that will never be listened on (already removed by tempSocketPath).
	sock0 := tempSocketPath(t, "dead")
	ep0 := Endpoint{Name: sock0, Network: "unix", Address: sock0}
	ep1 := Endpoint{Name: sock1, Network: "unix", Address: sock1}

	r, err := New([]Endpoint{ep0, ep1}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Mark ep0 known+unhealthy, ep1 known+healthy.
	r.setHealth(context.Background(), r.states[0], false)
	r.setHealth(context.Background(), r.states[1], true)

	got := doRoundTrip(t, r, sock1)
	if got != body1 {
		t.Errorf("body = %q, want %q (should route to ep1)", got, body1)
	}
}

func TestResolver_DialContext_UsesActiveEndpoint(t *testing.T) {
	t.Parallel()
	sock := startUnixServer(t, "dial", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "dial-ok")
	}))

	ep := Endpoint{Name: sock, Network: "unix", Address: sock}
	r, err := New([]Endpoint{ep}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.setHealth(context.Background(), r.states[0], true)

	ctx := context.Background()
	conn, err := r.DialContext(ctx, "ignored", "ignored")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
}

func TestResolver_DialContextConnectionFailureDemotesActiveEndpoint(t *testing.T) {
	t.Parallel()
	primary := tempSocketPath(t, "dialctx-primary-down") // nothing listens here
	secondary := startUnixServer(t, "dialctx-secondary", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "secondary")
	}))
	r, err := New([]Endpoint{
		{Name: "primary", Network: "unix", Address: primary},
		{Name: "secondary", Network: "unix", Address: secondary},
	}, Options{
		Interval: -1,
		// The re-probe (sync and any async follow-up) always reports primary
		// down, so the assertion below holds regardless of whether the
		// asynchronous re-probe goroutine has run yet.
		Probe: func(_ context.Context, ep Endpoint) error {
			if ep.Name == "primary" {
				return errors.New("primary remains unreachable")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.setHealth(context.Background(), r.states[0], true)
	r.setHealth(context.Background(), r.states[1], true)

	if _, err := r.DialContext(context.Background(), "ignored", "ignored"); err == nil {
		t.Fatal("DialContext error = nil, want a dial failure against the dead primary")
	}
	if r.states[0].healthy.Load() {
		t.Error("primary should be demoted (unhealthy) after DialContext dial failure")
	}
}

func TestResolver_DialContext_NoEndpoints(t *testing.T) {
	t.Parallel()
	// Build a valid resolver then empty the states to exercise the nil guard.
	ep := Endpoint{Name: "/tmp/x.sock", Network: "unix", Address: "/tmp/x.sock"}
	r, err := New([]Endpoint{ep}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.states = nil // white-box surgery
	_, err = r.DialContext(context.Background(), "", "")
	if !errors.Is(err, ErrNoEndpoints) {
		t.Fatalf("DialContext with no states: error = %v, want ErrNoEndpoints", err)
	}
}

func TestResolver_RoundTrip_NoEndpoints(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Name: "/tmp/x.sock", Network: "unix", Address: "/tmp/x.sock"}
	r, err := New([]Endpoint{ep}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.states = nil
	req, _ := http.NewRequest(http.MethodGet, "http://docker/containers/json", nil)
	_, err = r.RoundTrip(req)
	if !errors.Is(err, ErrNoEndpoints) {
		t.Fatalf("RoundTrip with no states: error = %v, want ErrNoEndpoints", err)
	}
}

// ── demote behavior ────────────────────────────────────────────────────────────

func TestResolver_Demote_TwoEndpoints_FlipsSelection(t *testing.T) {
	t.Parallel()
	body1 := "ep1-body"
	sock1 := startUnixServer(t, "demote-ep1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body1)
	}))
	sock0 := tempSocketPath(t, "demote-dead")
	ep0 := Endpoint{Name: sock0, Network: "unix", Address: sock0}
	ep1 := Endpoint{Name: sock1, Network: "unix", Address: sock1}

	// Probe says ep1 healthy so the re-probe after demote won't flip it back.
	probe := func(_ context.Context, ep Endpoint) error {
		if ep.Name == sock0 {
			return errors.New("still down")
		}
		return nil
	}
	r, err := New([]Endpoint{ep0, ep1}, Options{Probe: probe, Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Both known healthy to start so ep0 is active.
	r.setHealth(context.Background(), r.states[0], true)
	r.setHealth(context.Background(), r.states[1], true)

	if r.Active().Name != sock0 {
		t.Fatalf("expected ep0 active before demote, got %q", r.Active().Name)
	}

	// Demote ep0 directly.
	r.demote(r.states[0])

	// After demote ep0 should be unhealthy, ep1 healthy.
	// Poll briefly for the async re-probe goroutine (which will set ep0 to still-down).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if r.states[0].known.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	active := r.Active()
	if active.Name != sock1 {
		t.Errorf("after demote, Active().Name = %q, want %q", active.Name, sock1)
	}
}

func TestResolver_RoundTripConnectionFailureDemotesPrimary(t *testing.T) {
	t.Parallel()
	primary := tempSocketPath(t, "roundtrip-primary-down")
	secondary := startUnixServer(t, "roundtrip-secondary", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secondary")
	}))
	r, err := New([]Endpoint{
		{Name: "primary", Network: "unix", Address: primary},
		{Name: "secondary", Network: "unix", Address: secondary},
	}, Options{
		Interval: -1,
		Probe: func(_ context.Context, ep Endpoint) error {
			if ep.Name == "primary" {
				return errors.New("primary remains unreachable")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.setHealth(context.Background(), r.states[0], true)
	r.setHealth(context.Background(), r.states[1], true)

	req, err := http.NewRequest(http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		t.Fatalf("new primary request: %v", err)
	}
	if _, err := r.RoundTrip(req); err == nil {
		t.Fatal("primary RoundTrip error = nil, want connection failure")
	}
	if r.states[0].healthy.Load() {
		t.Fatal("primary remained healthy after RoundTrip connection failure")
	}
	if got := r.Active().Name; got != "secondary" {
		t.Fatalf("active endpoint = %q, want secondary", got)
	}

	resp, err := r.RoundTrip(req.Clone(context.Background()))
	if err != nil {
		t.Fatalf("secondary RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read secondary response: %v", err)
	}
	if got := string(body); got != "secondary" {
		t.Fatalf("secondary response = %q, want secondary", got)
	}
}

func TestResolver_Demote_SingleEndpoint_IsNoOp(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Name: "/tmp/sole.sock", Network: "unix", Address: "/tmp/sole.sock"}
	r, err := New([]Endpoint{ep}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.setHealth(context.Background(), r.states[0], true)

	// Demote should be a no-op: the single endpoint stays in whatever state it's in.
	r.demote(r.states[0])

	// In a single-endpoint resolver, demote returns early without changing health.
	if !r.states[0].healthy.Load() {
		t.Error("single-endpoint demote should be a no-op but flipped health to false")
	}
}

// waitForReprobe blocks until demote's asynchronous re-probe goroutine has
// finished (endpointState.reprobing is CAS-guarded and reset via a deferred
// Store after setHealth runs). The deadline is a safety net, not a timing
// assertion: a healthy reprobe finishes in microseconds, so 5s only guards
// against a future regression that deadlocks the goroutine and would
// otherwise hang the suite for the full go test default instead of failing
// fast.
func waitForReprobe(t *testing.T, s *endpointState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.reprobing.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("reprobe did not finish within 5s")
		}
		runtime.Gosched()
	}
}

func TestResolver_DemoteReprobeSetsHealthFromProbeResult(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		probeErr    error
		wantHealthy bool
	}{
		{name: "reprobe succeeds", probeErr: nil, wantHealthy: true},
		{name: "reprobe still fails", probeErr: errors.New("still down"), wantHealthy: false},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ep0 := Endpoint{Name: "ep0", Network: "unix", Address: "/tmp/reprobe-ep0.sock"}
			ep1 := Endpoint{Name: "ep1", Network: "unix", Address: "/tmp/reprobe-ep1.sock"}
			probe := func(_ context.Context, ep Endpoint) error {
				if ep.Name == "ep0" {
					return tt.probeErr
				}
				return nil
			}
			r, err := New([]Endpoint{ep0, ep1}, Options{Probe: probe, Interval: -1})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r.setHealth(context.Background(), r.states[0], true)
			r.setHealth(context.Background(), r.states[1], true)

			r.demote(r.states[0])
			waitForReprobe(t, r.states[0])

			if got := r.states[0].healthy.Load(); got != tt.wantHealthy {
				t.Fatalf("ep0 healthy after reprobe = %v, want %v", got, tt.wantHealthy)
			}
		})
	}
}

// ── activeState precedence ────────────────────────────────────────────────────

func TestActiveState_Precedence(t *testing.T) {
	t.Parallel()

	makeEp := func(name string) Endpoint {
		return Endpoint{Name: name, Network: "unix", Address: name}
	}

	t.Run("known healthy before unknown", func(t *testing.T) {
		t.Parallel()
		r, _ := New([]Endpoint{makeEp("a"), makeEp("b")}, Options{Probe: probeAlways(nil), Interval: -1})
		// a is unhealthy and known; b is unknown.
		r.states[0].healthy.Store(false)
		r.states[0].known.Store(true)
		// b remains unknown (zero value).
		// activeState should return the first unknown (b) rather than the known-unhealthy (a).
		s := r.activeState()
		if s.ep.Name != "b" {
			t.Errorf("activeState = %q, want %q", s.ep.Name, "b")
		}
	})

	t.Run("first unknown before all-known-unhealthy", func(t *testing.T) {
		t.Parallel()
		r, _ := New([]Endpoint{makeEp("a"), makeEp("b"), makeEp("c")}, Options{Probe: probeAlways(nil), Interval: -1})
		// a unhealthy+known; b unknown; c healthy+known.
		r.states[0].healthy.Store(false)
		r.states[0].known.Store(true)
		// b is zero = unknown.
		r.states[2].healthy.Store(true)
		r.states[2].known.Store(true)
		// c is healthy+known — should win.
		s := r.activeState()
		if s.ep.Name != "c" {
			t.Errorf("activeState = %q, want %q (known-healthy wins)", s.ep.Name, "c")
		}
	})

	t.Run("primary as last resort when all unhealthy", func(t *testing.T) {
		t.Parallel()
		r, _ := New([]Endpoint{makeEp("primary"), makeEp("secondary")}, Options{Probe: probeAlways(nil), Interval: -1})
		r.states[0].healthy.Store(false)
		r.states[0].known.Store(true)
		r.states[1].healthy.Store(false)
		r.states[1].known.Store(true)
		s := r.activeState()
		if s.ep.Name != "primary" {
			t.Errorf("activeState = %q, want primary as last resort", s.ep.Name)
		}
	})
}

// ── SpecsFromDockerEnv ────────────────────────────────────────────────────────

func TestSpecsFromDockerEnv(t *testing.T) {
	t.Parallel()
	mutualTLSDir := t.TempDir()
	installDockerCertificateFiles(t, mutualTLSDir, true, true, true)
	caOnlyDir := t.TempDir()
	installDockerCertificateFiles(t, caOnlyDir, true, false, false)
	cases := []struct {
		name     string
		env      map[string]string
		wantOK   bool
		wantErr  bool
		wantSpec EndpointSpec
	}{
		{
			name:   "DOCKER_HOST unset",
			env:    map[string]string{},
			wantOK: false,
		},
		{
			name: "DOCKER_HOST is unix socket regardless of TLS environment",
			env: map[string]string{
				"DOCKER_HOST":       "unix:///var/run/docker.sock",
				"DOCKER_TLS":        "1",
				"DOCKER_TLS_VERIFY": "1",
				"DOCKER_CERT_PATH":  "/certs",
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address: "unix:///var/run/docker.sock",
			},
		},
		{
			name:    "DOCKER_HOST whitespace only",
			env:     map[string]string{"DOCKER_HOST": "   "},
			wantErr: true,
		},
		{
			name:   "tcp plain no TLS verify no cert path",
			env:    map[string]string{"DOCKER_HOST": "tcp://host:2376"},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				InsecureAllowPlainTCP: true,
			},
		},
		{
			name: "empty TLS environment values leave TCP plaintext",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://host:2376",
				"DOCKER_TLS":        "",
				"DOCKER_TLS_VERIFY": "",
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				InsecureAllowPlainTCP: true,
			},
		},
		{
			name: "cert path alone does not enable TLS",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://host:2376",
				"DOCKER_CERT_PATH": "/certs",
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				InsecureAllowPlainTCP: true,
			},
		},
		{
			name: "DOCKER_TLS value zero enables unverified TLS",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://host:2376",
				"DOCKER_TLS":       "0",
				"DOCKER_CERT_PATH": caOnlyDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				CAFile:                filepath.Join(caOnlyDir, "ca.pem"),
				InsecureSkipTLSVerify: true,
			},
		},
		{
			name: "DOCKER_TLS value one enables unverified TLS",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://host:2376",
				"DOCKER_TLS":       "1",
				"DOCKER_CERT_PATH": caOnlyDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				CAFile:                filepath.Join(caOnlyDir, "ca.pem"),
				InsecureSkipTLSVerify: true,
			},
		},
		{
			name: "any other non-empty DOCKER_TLS value enables unverified TLS",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://host:2376",
				"DOCKER_TLS":       "false",
				"DOCKER_CERT_PATH": caOnlyDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				CAFile:                filepath.Join(caOnlyDir, "ca.pem"),
				InsecureSkipTLSVerify: true,
			},
		},
		{
			name: "DOCKER_TLS with cert path enables unverified mutual TLS",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://host:2376",
				"DOCKER_TLS":       "1",
				"DOCKER_CERT_PATH": mutualTLSDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				CAFile:                filepath.Join(mutualTLSDir, "ca.pem"),
				CertFile:              filepath.Join(mutualTLSDir, "cert.pem"),
				KeyFile:               filepath.Join(mutualTLSDir, "key.pem"),
				InsecureSkipTLSVerify: true,
			},
		},
		{
			name: "tcp with TLS_VERIFY and cert path",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://host:2376",
				"DOCKER_TLS_VERIFY": "1",
				"DOCKER_CERT_PATH":  mutualTLSDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:  "tcp://host:2376",
				CAFile:   filepath.Join(mutualTLSDir, "ca.pem"),
				CertFile: filepath.Join(mutualTLSDir, "cert.pem"),
				KeyFile:  filepath.Join(mutualTLSDir, "key.pem"),
			},
		},
		{
			name: "non-empty TLS_VERIFY takes precedence over DOCKER_TLS",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://host:2376",
				"DOCKER_TLS":        "1",
				"DOCKER_TLS_VERIFY": "false",
				"DOCKER_CERT_PATH":  mutualTLSDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:  "tcp://host:2376",
				CAFile:   filepath.Join(mutualTLSDir, "ca.pem"),
				CertFile: filepath.Join(mutualTLSDir, "cert.pem"),
				KeyFile:  filepath.Join(mutualTLSDir, "key.pem"),
			},
		},
		{
			name: "tcp with TLS_VERIFY and no cert path",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://host:2376",
				"DOCKER_TLS_VERIFY": "1",
				"DOCKER_CONFIG":     caOnlyDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address: "tcp://host:2376",
				CAFile:  filepath.Join(caOnlyDir, "ca.pem"),
			},
		},
		{
			name: "TLS_VERIFY value zero still enables verified TLS",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://host:2376",
				"DOCKER_TLS_VERIFY": "0",
				"DOCKER_CONFIG":     caOnlyDir,
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address: "tcp://host:2376",
				CAFile:  filepath.Join(caOnlyDir, "ca.pem"),
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lookupEnv := func(key string) (string, bool) {
				value, present := tc.env[key]
				return value, present
			}
			spec, ok, err := SpecsFromDockerEnv(lookupEnv)
			if tc.wantErr {
				if err == nil {
					t.Fatal("SpecsFromDockerEnv returned no error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SpecsFromDockerEnv: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if spec.Address != tc.wantSpec.Address {
				t.Errorf("Address = %q, want %q", spec.Address, tc.wantSpec.Address)
			}
			if spec.CAFile != tc.wantSpec.CAFile {
				t.Errorf("CAFile = %q, want %q", spec.CAFile, tc.wantSpec.CAFile)
			}
			if spec.CertFile != tc.wantSpec.CertFile {
				t.Errorf("CertFile = %q, want %q", spec.CertFile, tc.wantSpec.CertFile)
			}
			if spec.KeyFile != tc.wantSpec.KeyFile {
				t.Errorf("KeyFile = %q, want %q", spec.KeyFile, tc.wantSpec.KeyFile)
			}
			if spec.InsecureAllowPlainTCP != tc.wantSpec.InsecureAllowPlainTCP {
				t.Errorf("InsecureAllowPlainTCP = %v, want %v", spec.InsecureAllowPlainTCP, tc.wantSpec.InsecureAllowPlainTCP)
			}
			if spec.InsecureSkipTLSVerify != tc.wantSpec.InsecureSkipTLSVerify {
				t.Errorf("InsecureSkipTLSVerify = %v, want %v", spec.InsecureSkipTLSVerify, tc.wantSpec.InsecureSkipTLSVerify)
			}
		})
	}
}

func TestSpecsFromDockerEnv_DockerHostGrammar(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		host        string
		wantAddress string
		wantErr     bool
	}{
		{name: "bare host", host: "daemon.internal", wantAddress: "tcp://daemon.internal:2375"},
		{name: "bare host with port", host: "daemon.internal:4243", wantAddress: "tcp://daemon.internal:4243"},
		{name: "TCP host without port", host: "tcp://daemon.internal", wantAddress: "tcp://daemon.internal:2375"},
		{name: "TCP host with empty port", host: "tcp://daemon.internal:", wantAddress: "tcp://daemon.internal:2375"},
		{name: "TCP default host", host: "tcp://", wantAddress: "tcp://localhost:2375"},
		{name: "TCP default host with port", host: "tcp://:4243", wantAddress: "tcp://localhost:4243"},
		// Docker's address parser validates only that an explicit port is
		// numeric. Range errors are deferred until the connection attempt.
		{name: "TCP numeric zero port", host: "tcp://daemon.internal:0", wantAddress: "tcp://daemon.internal:0"},
		{name: "TCP numeric out-of-range port", host: "tcp://daemon.internal:99999", wantAddress: "tcp://daemon.internal:99999"},
		// A port long enough to overflow strconv.Atoi's int range still parses
		// as numeric (net/url only checks the digits, not the magnitude), so
		// the same "accepted here, rejected only at dial time" rule applies.
		{name: "TCP overflow numeric port", host: "tcp://daemon.internal:99999999999999999999", wantAddress: "tcp://daemon.internal:99999999999999999999"},
		{name: "IPv6 host without port", host: "[::1]:", wantAddress: "tcp://[::1]:2375"},
		{name: "IPv6 host without port and base path", host: "tcp://[::1]/gateway", wantAddress: "tcp://[::1]:2375/gateway"},
		{name: "absolute Unix socket", host: "unix:///tmp/docker.sock", wantAddress: "unix:///tmp/docker.sock"},
		{name: "relative Unix socket", host: "unix://relative.sock", wantAddress: "unix://relative.sock"},
		{name: "HTTP scheme", host: "http://daemon.internal:2375", wantErr: true},
		{name: "HTTPS scheme", host: "https://daemon.internal:2376", wantErr: true},
		{name: "unsupported SSH transport", host: "ssh://daemon.internal", wantErr: true},
		{name: "unsupported file descriptor transport", host: "fd://3", wantErr: true},
		{name: "unsupported named pipe transport", host: "npipe:////./pipe/docker_engine", wantErr: true},
		{name: "invalid port", host: "tcp://daemon.internal:not-a-port", wantErr: true},
		{name: "embedded spaces", host: "something with spaces", wantErr: true},
		{name: "TCP base path", host: "tcp://daemon.internal:2375/api", wantAddress: "tcp://daemon.internal:2375/api"},
		{name: "TCP escaped base path", host: "tcp://daemon.internal:2375/proxy/%2e%2e/docker%2Fapi/", wantAddress: "tcp://daemon.internal:2375/proxy/%2e%2e/docker%2Fapi/"},
		{name: "TCP query is not a base path", host: "tcp://daemon.internal:2375/api?tenant=one", wantErr: true},
		{name: "TCP fragment is not a base path", host: "tcp://daemon.internal:2375/api#one", wantErr: true},
		{name: "TCP malformed escape", host: "tcp://daemon.internal:2375/api%zz", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec, ok, err := SpecsFromDockerEnv(func(key string) (string, bool) {
				if key == "DOCKER_HOST" {
					return tt.host, true
				}
				return "", false
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SpecsFromDockerEnv(DOCKER_HOST=%q) returned no error", tt.host)
				}
				return
			}
			if err != nil {
				t.Fatalf("SpecsFromDockerEnv(DOCKER_HOST=%q): %v", tt.host, err)
			}
			if !ok {
				t.Fatalf("SpecsFromDockerEnv(DOCKER_HOST=%q) was inactive", tt.host)
			}
			if spec.Address != tt.wantAddress {
				t.Fatalf("Address = %q, want %q", spec.Address, tt.wantAddress)
			}
		})
	}
}

func TestSpecsFromDockerEnv_CustomUnixSocketBuilds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host        string
		wantAddress string
	}{
		{host: "unix:///tmp/custom-docker.sock", wantAddress: "/tmp/custom-docker.sock"},
		{host: "unix://relative.sock", wantAddress: "relative.sock"},
		{host: "unix:///tmp/docker%2Fsock", wantAddress: "/tmp/docker%2Fsock"},
		{host: "unix:///tmp/docker%3Fsock", wantAddress: "/tmp/docker%3Fsock"},
		{host: "unix:///tmp/docker%23sock", wantAddress: "/tmp/docker%23sock"},
		{host: "unix:///tmp/docker%25sock", wantAddress: "/tmp/docker%25sock"},
		{host: "unix:///tmp/docker?sock#one", wantAddress: "/tmp/docker?sock#one"},
		{host: "unix://relative.sock?one#two", wantAddress: "relative.sock?one#two"},
		{host: "unix://relative%25sock", wantAddress: "relative%25sock"},
		{host: "unix:///tmp/relative%2Fsock?one#two", wantAddress: "/tmp/relative%2Fsock?one#two"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.host, func(t *testing.T) {
			t.Parallel()
			spec, ok, err := SpecsFromDockerEnv(func(key string) (string, bool) {
				if key == "DOCKER_HOST" {
					return tt.host, true
				}
				return "", false
			})
			if err != nil {
				t.Fatalf("SpecsFromDockerEnv: %v", err)
			}
			if !ok {
				t.Fatal("custom Unix DOCKER_HOST was inactive")
			}
			endpoint, err := BuildEndpoint(spec)
			if err != nil {
				t.Fatalf("BuildEndpoint: %v", err)
			}
			if endpoint.Network != "unix" {
				t.Fatalf("Network = %q, want unix", endpoint.Network)
			}
			if endpoint.Address != tt.wantAddress {
				t.Fatalf("Address = %q, want %q", endpoint.Address, tt.wantAddress)
			}
		})
	}
}

func TestSpecsFromDockerEnv_RelativeUnixHostEscapesFailBuild(t *testing.T) {
	t.Parallel()
	for _, host := range []string{
		"unix://relative%2Fsock",
		"unix://relative%3Fsock",
		"unix://relative%23sock",
	} {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			spec, ok, err := SpecsFromDockerEnv(func(key string) (string, bool) {
				if key == "DOCKER_HOST" {
					return host, true
				}
				return "", false
			})
			if err != nil || !ok {
				t.Fatalf("SpecsFromDockerEnv = (%v, %v), want active spec deferred to endpoint validation", ok, err)
			}
			if _, err := BuildEndpoint(spec); err == nil {
				t.Fatal("BuildEndpoint accepted an escaped relative Unix host")
			}
		})
	}
}

func TestSpecsFromDockerEnv_MalformedUnixSocketFailsBuild(t *testing.T) {
	t.Parallel()
	spec, ok, err := SpecsFromDockerEnv(func(key string) (string, bool) {
		if key == "DOCKER_HOST" {
			return "unix:///tmp/docker%zzsock", true
		}
		return "", false
	})
	if err != nil || !ok {
		t.Fatalf("SpecsFromDockerEnv = (%v, %v), want active spec deferred to endpoint validation", ok, err)
	}
	if _, err := BuildEndpoint(spec); err == nil {
		t.Fatal("BuildEndpoint accepted malformed Unix percent escape")
	}
}

func TestBuildEndpointDialsLiteralUnixSocketName(t *testing.T) {
	t.Parallel()
	path := tempSocketPath(t, "literal") + "%2F?#"
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})

	ep, err := BuildEndpoint(EndpointSpec{Address: "unix://" + path})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	if ep.Address != path {
		t.Fatalf("Address = %q, want literal %q", ep.Address, path)
	}
	conn, err := ep.dial(context.Background())
	if err != nil {
		t.Fatalf("dial literal socket: %v", err)
	}
	_ = conn.Close()
}

func TestResolverRoundTripPrependsTCPBasePathWithoutCanonicalizing(t *testing.T) {
	t.Parallel()
	requestURI := make(chan string, 1)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI <- r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(daemon.Close)

	ep, err := BuildEndpoint(EndpointSpec{
		Address:               "tcp://" + strings.TrimPrefix(daemon.URL, "http://") + "/proxy/%2e%2e/docker%2Fapi/",
		InsecureAllowPlainTCP: true,
	})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	r, err := New([]Endpoint{ep}, Options{Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://docker/v1.47/containers/a%2Fb/json?all=1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	originalPath, originalRawPath := req.URL.Path, req.URL.RawPath
	resp, err := r.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if got := <-requestURI; got != "/proxy/%2e%2e/docker%2Fapi/v1.47/containers/a%2Fb/json?all=1" {
		t.Fatalf("daemon RequestURI = %q", got)
	}
	if req.URL.Path != originalPath || req.URL.RawPath != originalRawPath {
		t.Fatalf("RoundTrip mutated input URL: Path=%q RawPath=%q, want Path=%q RawPath=%q", req.URL.Path, req.URL.RawPath, originalPath, originalRawPath)
	}
}

func TestResolverRoundTripSetsResponseRequestToCallerOriginal(t *testing.T) {
	t.Parallel()
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(daemon.Close)

	// A non-empty base path forces requestWithBasePath to clone the request,
	// so the transport's own resp.Request (bound to that clone) differs by
	// pointer from the caller's original req unless RoundTrip explicitly
	// rebinds it back.
	ep, err := BuildEndpoint(EndpointSpec{
		Address:               "tcp://" + strings.TrimPrefix(daemon.URL, "http://") + "/proxy/",
		InsecureAllowPlainTCP: true,
	})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	r, err := New([]Endpoint{ep}, Options{Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := r.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.Request != req {
		t.Fatalf("resp.Request = %p, want the caller's original request %p", resp.Request, req)
	}
}

func TestRequestWithBasePath_ClonesWhenOnlyRawBasePathIsSet(t *testing.T) {
	t.Parallel()
	// BuildEndpoint never produces this exact combination (RawBasePath is
	// only populated alongside a non-empty BasePath), but the skip-clone
	// guard must still require BOTH fields empty before returning the
	// request untouched -- an empty BasePath paired with a non-empty
	// RawBasePath must still trigger a clone.
	ep := Endpoint{RawBasePath: "/v1"}
	req, err := http.NewRequest(http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if got := ep.requestWithBasePath(req); got == req {
		t.Fatal("requestWithBasePath returned the original request unmodified, want a clone because RawBasePath is non-empty")
	}
}

func TestResolverDialRequestBindsPrefixToDialedEndpoint(t *testing.T) {
	t.Parallel()
	primaryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen primary: %v", err)
	}
	t.Cleanup(func() { _ = primaryListener.Close() })
	standbyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen standby: %v", err)
	}
	t.Cleanup(func() { _ = standbyListener.Close() })

	primary, err := BuildEndpoint(EndpointSpec{
		Address:               "tcp://" + primaryListener.Addr().String() + "/primary/%2e%2e/api",
		InsecureAllowPlainTCP: true,
	})
	if err != nil {
		t.Fatalf("BuildEndpoint(primary): %v", err)
	}
	standby, err := BuildEndpoint(EndpointSpec{
		Address:               "tcp://" + standbyListener.Addr().String() + "/standby%2Fapi",
		InsecureAllowPlainTCP: true,
	})
	if err != nil {
		t.Fatalf("BuildEndpoint(standby): %v", err)
	}
	r, err := New([]Endpoint{primary, standby}, Options{Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.states[0].known.Store(true)
	r.states[0].healthy.Store(false)
	r.states[1].known.Store(true)
	r.states[1].healthy.Store(true)

	req, err := http.NewRequest(http.MethodPost, "http://docker/v1.47/containers/a%2Fb/attach?stream=1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	conn, upstreamReq, err := r.DialRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("DialRequest: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if conn.RemoteAddr().String() != standbyListener.Addr().String() {
		t.Fatalf("dialed %q, want standby %q", conn.RemoteAddr(), standbyListener.Addr())
	}

	// A health change after DialRequest returns must not swap in the primary's
	// prefix for the already-open standby connection.
	r.states[0].healthy.Store(true)
	r.states[1].healthy.Store(false)
	if got := upstreamReq.URL.EscapedPath(); got != "/standby%2Fapi/v1.47/containers/a%2Fb/attach" {
		t.Fatalf("prefixed path = %q, want standby prefix bound to dialed connection", got)
	}
	if req.URL.EscapedPath() != "/v1.47/containers/a%2Fb/attach" {
		t.Fatalf("DialRequest mutated input URL: %q", req.URL.EscapedPath())
	}
}

func TestResolverDialRequestCancellationDoesNotDemote(t *testing.T) {
	t.Parallel()
	r, err := New([]Endpoint{
		{Name: "primary", Network: "unix", Address: "/tmp/canceled-primary.sock"},
		{Name: "standby", Network: "unix", Address: "/tmp/canceled-standby.sock"},
	}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.CheckReachable(context.Background()); err != nil {
		t.Fatalf("CheckReachable: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequest(http.MethodPost, "http://docker/v1.53/containers/abc/attach", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, _, err := r.DialRequest(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialRequest error = %v, want context.Canceled", err)
	}
	if !r.states[0].healthy.Load() {
		t.Fatal("DialRequest demoted the active endpoint after request cancellation")
	}
}

func TestJoinURLPathUsesOneSlashBoundaryForDecodedAndEscapedForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		base        *url.URL
		request     *url.URL
		wantPath    string
		wantRawPath string
	}{
		{
			name:        "encoded trailing base slash and escaped client segment",
			base:        &url.URL{Path: "/api/", RawPath: "/api%2F"},
			request:     &url.URL{Path: "/v1/containers/a/b", RawPath: "/v1/containers/a%2Fb"},
			wantPath:    "/api/v1/containers/a/b",
			wantRawPath: "/api%2Fv1/containers/a%2Fb",
		},
		{
			name:        "plain base and escaped client segment",
			base:        &url.URL{Path: "/api"},
			request:     &url.URL{Path: "/containers/a/b", RawPath: "/containers/a%2Fb"},
			wantPath:    "/api/containers/a/b",
			wantRawPath: "/api/containers/a%2Fb",
		},
		{
			name:        "neither side has boundary slash",
			base:        &url.URL{Path: "api", RawPath: "api"},
			request:     &url.URL{Path: "v1/a/b", RawPath: "v1/a%2Fb"},
			wantPath:    "api/v1/a/b",
			wantRawPath: "api/v1/a%2Fb",
		},
		{
			// Neither side has an escaped form at all: joinURLPath must take
			// the fast joinPath path and report RawPath == "" (letting the
			// caller re-derive the escaped form from Path) rather than
			// falling through to the EscapedPath-based slow path.
			name:        "neither side has an escaped form",
			base:        &url.URL{Path: "/api/"},
			request:     &url.URL{Path: "/containers/json"},
			wantPath:    "/api/containers/json",
			wantRawPath: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotPath, gotRawPath := joinURLPath(tt.base, tt.request)
			if gotPath != tt.wantPath || gotRawPath != tt.wantRawPath {
				t.Fatalf("joinURLPath = (%q, %q), want (%q, %q)", gotPath, gotRawPath, tt.wantPath, tt.wantRawPath)
			}
			if tt.wantRawPath == "" {
				// An empty RawPath is the "no custom encoding" sentinel, not
				// an escaped form of Path, so the round-trip decode check
				// below does not apply.
				return
			}
			decoded, err := url.PathUnescape(gotRawPath)
			if err != nil {
				t.Fatalf("PathUnescape(%q): %v", gotRawPath, err)
			}
			if decoded != gotPath {
				t.Fatalf("RawPath %q decodes to %q, want Path %q", gotRawPath, decoded, gotPath)
			}
		})
	}
}

func TestResolverRoundTripKeepsEndpointAndPrefixTogetherDuringHealthFlaps(t *testing.T) {
	t.Parallel()
	errCh := make(chan string, 1)
	startDaemon := func(prefix string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.RequestURI, prefix) {
				select {
				case errCh <- fmt.Sprintf("daemon %s received %q", prefix, r.RequestURI):
				default:
				}
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	}
	primaryDaemon := startDaemon("/primary/")
	standbyDaemon := startDaemon("/standby%2F")
	t.Cleanup(primaryDaemon.Close)
	t.Cleanup(standbyDaemon.Close)
	build := func(rawURL, basePath string) Endpoint {
		t.Helper()
		ep, err := BuildEndpoint(EndpointSpec{
			Address:               "tcp://" + strings.TrimPrefix(rawURL, "http://") + basePath,
			InsecureAllowPlainTCP: true,
		})
		if err != nil {
			t.Fatalf("BuildEndpoint: %v", err)
		}
		return ep
	}
	r, err := New([]Endpoint{
		build(primaryDaemon.URL, "/primary"),
		build(standbyDaemon.URL, "/standby%2F"),
	}, Options{Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, state := range r.states {
		state.known.Store(true)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				r.states[0].healthy.Store(true)
				r.states[1].healthy.Store(false)
				r.states[0].healthy.Store(false)
				r.states[1].healthy.Store(true)
			}
		}
	}()
	for i := 0; i < 250; i++ {
		req, err := http.NewRequest(http.MethodGet, "http://docker/v1.52/containers/a%2Fb/json", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := r.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	close(stop)
	<-done
	select {
	case mismatch := <-errCh:
		t.Fatal(mismatch)
	default:
	}
}

// ── Resolver.Start health loop ────────────────────────────────────────────────

func TestResolverLoop_ZeroIntervalFallsThroughNegativeGuard(t *testing.T) {
	t.Parallel()
	// New() converts an Options.Interval of exactly zero to defaultProbeInterval,
	// so loop() never legitimately observes interval == 0 through the public
	// constructor -- this white-box literal bypasses that guard to pin the
	// exact boundary of "if r.interval < 0 { return }": only a *negative*
	// interval (the NewSingleSocket sentinel) skips the continuous-probe
	// ticker. Zero must fall through to the ticker construction, which panics
	// on a non-positive duration -- a synchronous, deterministic signal that
	// the guard did not fire, with no sleep or timeout guess involved.
	r := &Resolver{
		states:  []*endpointState{{ep: Endpoint{Name: "x", Network: "unix", Address: "/tmp/zero-interval.sock"}}},
		timeout: time.Second,
		probe:   probeAlways(nil),
	}
	defer func() {
		if recover() == nil {
			t.Fatal("loop() with interval == 0 returned without reaching ticker construction, want it to fall through the negative-interval guard")
		}
	}()
	r.loop(context.Background())
}

func TestResolver_Start_Idempotent(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	probe := func(_ context.Context, _ Endpoint) error {
		calls.Add(1)
		return nil
	}
	ep := Endpoint{Name: "/tmp/loop.sock", Network: "unix", Address: "/tmp/loop.sock"}
	r, err := New([]Endpoint{ep}, Options{Probe: probe, Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.Start(ctx)
	r.Start(ctx) // second call must be a no-op

	// Wait briefly for the single startup probe.
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Errorf("probe called %d times after two Start() calls with interval=-1, want 1", calls.Load())
	}
}

func TestResolver_Start_ContextCancel_StopsLoop(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	probe := func(_ context.Context, _ Endpoint) error {
		calls.Add(1)
		return nil
	}
	ep := Endpoint{Name: "/tmp/cancel.sock", Network: "unix", Address: "/tmp/cancel.sock"}
	r, err := New([]Endpoint{ep}, Options{
		Probe:    probe,
		Interval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// Let at least 2 probe ticks fire.
	time.Sleep(50 * time.Millisecond)
	cancel()

	snapshot := calls.Load()
	if snapshot < 2 {
		t.Errorf("expected at least 2 probe calls before cancel, got %d", snapshot)
	}

	// After cancel the count should not grow (allow a brief settle).
	time.Sleep(30 * time.Millisecond)
	after := calls.Load()
	if after > snapshot+1 {
		t.Errorf("probe still running after ctx cancel: before=%d after=%d", snapshot, after)
	}
}

func TestResolver_Start_OnChange_Fires(t *testing.T) {
	t.Parallel()

	type change struct {
		ep      Endpoint
		healthy bool
	}
	changes := make(chan change, 10)

	ep0 := Endpoint{Name: "ep0", Network: "unix", Address: "/tmp/onchange-ep0.sock"}
	ep1 := Endpoint{Name: "ep1", Network: "unix", Address: "/tmp/onchange-ep1.sock"}

	iteration := atomic.Int64{}
	probe := func(_ context.Context, ep Endpoint) error {
		// First round: ep0 healthy, ep1 unhealthy.
		// Second round: ep0 unhealthy, ep1 healthy.
		n := iteration.Load()
		if n == 0 {
			if ep.Name == "ep0" {
				return nil
			}
			return errors.New("down")
		}
		if ep.Name == "ep0" {
			return errors.New("down")
		}
		return nil
	}

	r, err := New([]Endpoint{ep0, ep1}, Options{
		Probe:    probe,
		Interval: 20 * time.Millisecond,
		OnChange: func(ep Endpoint, healthy bool) {
			changes <- change{ep: ep, healthy: healthy}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r.Start(ctx)

	// Collect the first two OnChange events (startup probe: ep0 up, ep1 down).
	deadline := time.Now().Add(500 * time.Millisecond)
	received := 0
	for time.Now().Before(deadline) && received < 2 {
		select {
		case <-changes:
			received++
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if received < 2 {
		t.Fatalf("expected 2 OnChange events from startup probe, got %d", received)
	}

	// Trigger a state flip in the next probe round.
	iteration.Add(1)

	// Collect the transition events (ep0 goes down, ep1 comes up).
	received = 0
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && received < 2 {
		select {
		case <-changes:
			received++
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if received < 2 {
		t.Fatalf("expected 2 OnChange events for state flip, got %d", received)
	}
}

func TestResolver_OnChange_NoFire_WhenSameState(t *testing.T) {
	t.Parallel()
	var count atomic.Int64
	ep := Endpoint{Name: "ep", Network: "unix", Address: "/tmp/nochange.sock"}
	r, err := New([]Endpoint{ep}, Options{
		Probe:    probeAlways(nil), // always healthy
		Interval: 10 * time.Millisecond,
		OnChange: func(_ Endpoint, _ bool) { count.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// Let several probe ticks run.
	time.Sleep(80 * time.Millisecond)
	cancel()

	// OnChange should fire exactly once: on the first known result.
	if count.Load() != 1 {
		t.Errorf("OnChange fired %d times, want 1 (only on first-known)", count.Load())
	}
}

// ── newTransport pool tunings ──────────────────────────────────────────────────

func TestEndpoint_NewTransport_PoolTunings(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Name: "ep", Network: "unix", Address: "/tmp/pool.sock"}
	tr := ep.newTransport()

	if got, want := tr.MaxIdleConns, defaultMaxIdleConns; got != want {
		t.Errorf("MaxIdleConns = %d, want %d", got, want)
	}
	if got, want := tr.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost; got != want {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", got, want)
	}
	if got, want := tr.IdleConnTimeout, defaultIdleConnTimeout; got != want {
		t.Errorf("IdleConnTimeout = %v, want %v", got, want)
	}
	if got, want := tr.ResponseHeaderTimeout, defaultResponseHeaderTimeout; got != want {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", got, want)
	}
	// TLS is handled inside dial, so the transport must not carry a TLS config.
	if tr.TLSClientConfig != nil {
		t.Error("TLSClientConfig is non-nil, want nil (TLS handled inside dial)")
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil, want the per-endpoint dialer")
	}
}

// ── CheckReachable ──────────────────────────────────────────────────────────────

func TestResolver_CheckReachable_AllReachable(t *testing.T) {
	t.Parallel()
	r, err := New([]Endpoint{
		{Name: "a", Network: "unix", Address: "/tmp/a.sock"},
		{Name: "b", Network: "unix", Address: "/tmp/b.sock"},
	}, Options{Probe: probeAlways(nil), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.CheckReachable(context.Background()); err != nil {
		t.Fatalf("CheckReachable: %v", err)
	}
	// Both endpoints should be seeded known-healthy.
	for _, s := range r.states {
		if !s.known.Load() || !s.healthy.Load() {
			t.Errorf("endpoint %s: known=%v healthy=%v, want both true", s.ep.Name, s.known.Load(), s.healthy.Load())
		}
	}
}

func TestResolver_CheckReachable_OneReachable_Succeeds(t *testing.T) {
	t.Parallel()
	// First endpoint down, second up: a failover set must still boot.
	probe := func(_ context.Context, ep Endpoint) error {
		if ep.Name == "down" {
			return errors.New("connection refused")
		}
		return nil
	}
	r, err := New([]Endpoint{
		{Name: "down", Network: "unix", Address: "/tmp/down.sock"},
		{Name: "up", Network: "unix", Address: "/tmp/up.sock"},
	}, Options{Probe: probe, Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.CheckReachable(context.Background()); err != nil {
		t.Fatalf("CheckReachable: %v (want success when one endpoint is up)", err)
	}
	if r.states[0].healthy.Load() {
		t.Error("down endpoint marked healthy, want unhealthy")
	}
	if !r.states[1].healthy.Load() {
		t.Error("up endpoint marked unhealthy, want healthy")
	}
}

func TestResolver_CheckReachable_AllDown_Errors(t *testing.T) {
	t.Parallel()
	r, err := New([]Endpoint{
		{Name: "a", Network: "unix", Address: "/tmp/a.sock"},
		{Name: "b", Network: "unix", Address: "/tmp/b.sock"},
	}, Options{Probe: probeAlways(errors.New("connection refused")), Interval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = r.CheckReachable(context.Background())
	if err == nil {
		t.Fatal("CheckReachable: nil error, want failure when all endpoints are down")
	}
	// Aggregated error should name both unreachable endpoints.
	for _, name := range []string{"a", "b"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not mention endpoint %q", err.Error(), name)
		}
	}
}

// ── demote: request-scoped errors must not flap a healthy endpoint ──────────────

func TestResolver_RoundTrip_RequestScopedError_NoDemote(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{
			name: "canceled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
		},
		{
			name: "deadline exceeded",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Unix(0, 0))
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Two endpoints, both seeded healthy. A request-scoped failure on the
			// active endpoint must NOT demote it (it says nothing about upstream
			// reachability) — otherwise every client cancel / request_timeout
			// would flap the primary.
			r, err := New([]Endpoint{
				{Name: "a", Network: "unix", Address: "/tmp/reqscoped-a.sock"},
				{Name: "b", Network: "unix", Address: "/tmp/reqscoped-b.sock"},
			}, Options{Probe: probeAlways(nil), Interval: -1})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := r.CheckReachable(context.Background()); err != nil {
				t.Fatalf("CheckReachable: %v", err)
			}

			ctx, cancel := tc.ctx()
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if _, rtErr := r.RoundTrip(req); rtErr == nil {
				t.Fatal("RoundTrip: nil error, want a context error")
			}
			if !r.states[0].healthy.Load() {
				t.Error("active endpoint was demoted on a request-scoped error, want still healthy")
			}
		})
	}
}

// ── doRoundTrip helper ────────────────────────────────────────────────────────

// doRoundTrip sends a GET to http://docker/containers/json through the resolver
// and returns the response body. The request Host is set to "docker" to
// satisfy the http.Transport requirement.
func doRoundTrip(t *testing.T, r *Resolver, _ string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := r.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}
