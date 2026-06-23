package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/testcert"
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
		// valid tcp-family
		{name: "tcp url", input: "tcp://host:2376", wantNetwork: "tcp", wantAddress: "host:2376"},
		{name: "http url", input: "http://host:2375", wantNetwork: "tcp", wantAddress: "host:2375"},
		{name: "https url", input: "https://host:2376", wantNetwork: "tcp", wantAddress: "host:2376"},
		// errors
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace only", input: "   ", wantErr: true},
		{name: "scheme-less non-path", input: "notapath", wantErr: true},
		{name: "unix with host", input: "unix://relative.sock/path", wantErr: true},
		{name: "unix missing path", input: "unix://", wantErr: true},
		{name: "tcp missing port", input: "tcp://myhost", wantErr: true},
		{name: "bad scheme", input: "ftp://host:21", wantErr: true},
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
	cases := []struct {
		name     string
		env      map[string]string
		wantOK   bool
		wantSpec EndpointSpec
	}{
		{
			name:   "DOCKER_HOST unset",
			env:    map[string]string{},
			wantOK: false,
		},
		{
			name:   "DOCKER_HOST is unix socket",
			env:    map[string]string{"DOCKER_HOST": "unix:///var/run/docker.sock"},
			wantOK: false,
		},
		{
			name:   "DOCKER_HOST whitespace only",
			env:    map[string]string{"DOCKER_HOST": "   "},
			wantOK: false,
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
			name: "tcp with TLS_VERIFY and cert path",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://host:2376",
				"DOCKER_TLS_VERIFY": "1",
				"DOCKER_CERT_PATH":  "/certs",
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:  "tcp://host:2376",
				CAFile:   "/certs/ca.pem",
				CertFile: "/certs/cert.pem",
				KeyFile:  "/certs/key.pem",
			},
		},
		{
			name: "tcp without TLS_VERIFY but with cert path — insecure skip",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://host:2376",
				"DOCKER_CERT_PATH": "/certs",
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address:               "tcp://host:2376",
				CAFile:                "/certs/ca.pem",
				CertFile:              "/certs/cert.pem",
				KeyFile:               "/certs/key.pem",
				InsecureSkipTLSVerify: true,
			},
		},
		{
			name: "tcp with TLS_VERIFY and no cert path",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://host:2376",
				"DOCKER_TLS_VERIFY": "1",
			},
			wantOK: true,
			wantSpec: EndpointSpec{
				Address: "tcp://host:2376",
				// no CA/cert/key — verify against the host's system root CAs.
				TLSSystemRoots: true,
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			getenv := func(key string) string { return tc.env[key] }
			spec, ok := SpecsFromDockerEnv(getenv)
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
			if spec.TLSSystemRoots != tc.wantSpec.TLSSystemRoots {
				t.Errorf("TLSSystemRoots = %v, want %v", spec.TLSSystemRoots, tc.wantSpec.TLSSystemRoots)
			}
		})
	}
}

// TestBuildEndpoint_TLSSystemRoots covers the DOCKER_TLS_VERIFY-without-cert-path
// path end to end: a spec carrying only TLSSystemRoots must build a valid TLS
// endpoint that verifies against the host's system roots (RootCAs nil) and
// presents no client certificate, rather than being rejected as plain TCP.
func TestBuildEndpoint_TLSSystemRoots(t *testing.T) {
	t.Parallel()
	ep, err := BuildEndpoint(EndpointSpec{Address: "tcp://dockerd.internal:2376", TLSSystemRoots: true})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	if !ep.IsTLS() {
		t.Fatal("endpoint is not TLS, want TLS with system roots")
	}
	if ep.TLSConfig.RootCAs != nil {
		t.Error("RootCAs is non-nil, want nil (use system roots)")
	}
	if len(ep.TLSConfig.Certificates) != 0 {
		t.Error("client certificate present, want none (server-auth only)")
	}
	if ep.TLSConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is true, want false (system roots must verify)")
	}
	if ep.TLSConfig.ServerName != "dockerd.internal" {
		t.Errorf("ServerName = %q, want %q", ep.TLSConfig.ServerName, "dockerd.internal")
	}
}

// TestValidateSpec_TLSSystemRoots confirms the file-free validator accepts the
// system-roots spec (so admin/validate does not reject a DOCKER_TLS_VERIFY env
// drop-in on a host without cert files).
func TestValidateSpec_TLSSystemRoots(t *testing.T) {
	t.Parallel()
	if err := ValidateSpec(EndpointSpec{Address: "tcp://dockerd.internal:2376", TLSSystemRoots: true}); err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
}

// ── Resolver.Start health loop ────────────────────────────────────────────────

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
