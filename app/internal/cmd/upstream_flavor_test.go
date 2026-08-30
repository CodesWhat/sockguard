package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/testcert"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// countingRoundTripper fails the test if it is ever used. It is how the
// explicit-flavor cases prove "no probe runs" rather than merely "the right
// value is returned": a stubbed detect function could be skipped while the
// client was still built and used, and only a transport that refuses to be
// called rules that out.
type countingRoundTripper struct {
	t     *testing.T
	calls int
}

func (rt *countingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.t.Helper()
	rt.calls++
	rt.t.Fatalf("unexpected upstream request to %s; an explicit upstream.flavor must never probe", r.URL)
	return nil, errors.New("unreachable")
}

// flavorTransportTo dials addr no matter what host the request URL names,
// which is how the shared upstream.Resolver behaves in production: Detect
// builds the fixed "http://docker/version" URL and the transport routes it to
// the configured endpoint.
func flavorTransportTo(addr string) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}
}

func flavorTestConfig(flavor string) *config.Config {
	cfg := config.Defaults()
	cfg.Upstream.Flavor = flavor
	return &cfg
}

func flavorTestLogger() (*slog.Logger, *testhelp.CollectingHandler) {
	collector := &testhelp.CollectingHandler{}
	return collector.Logger(), collector
}

// TestResolveUpstreamFlavorExplicitWinsWithoutProbing is constraint (2): an
// explicit docker or podman is taken as given, and nothing on the network can
// move it. The assertion is on HTTP requests, not on the returned value.
func TestResolveUpstreamFlavorExplicitWinsWithoutProbing(t *testing.T) {
	t.Parallel()
	for _, want := range []upstreamflavor.Flavor{upstreamflavor.Docker, upstreamflavor.Podman} {
		t.Run(string(want), func(t *testing.T) {
			t.Parallel()
			rt := &countingRoundTripper{t: t}
			deps := newServeDeps()
			deps.detectUpstreamFlavor = func(context.Context, *http.Client) (upstreamflavor.Flavor, error) {
				t.Fatal("detectUpstreamFlavor called for an explicit flavor")
				return "", nil
			}
			logger, collector := flavorTestLogger()

			got, err := resolveUpstreamFlavor(t.Context(), deps, flavorTestConfig(string(want)), rt, logger)
			if err != nil {
				t.Fatalf("resolveUpstreamFlavor() error = %v", err)
			}
			if got != want {
				t.Fatalf("resolveUpstreamFlavor() = %q, want %q", got, want)
			}
			if rt.calls != 0 {
				t.Fatalf("upstream round trips = %d, want 0", rt.calls)
			}
			if !collector.HasMessage("upstream flavor resolved") {
				t.Fatalf("no resolution log line; records: %#v", collector.Records())
			}
		})
	}
}

// TestResolveUpstreamFlavorAutoProbes covers the "auto" happy path against a
// real /version response for each engine, routed through the real
// upstreamflavor.Detect so the probe itself is exercised end to end rather
// than stubbed.
func TestResolveUpstreamFlavorAutoProbes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want upstreamflavor.Flavor
	}{
		{
			name: "podman",
			body: `{"Components":[{"Name":"Podman Engine","Version":"5.8.1"},{"Name":"Conmon"}],"Version":"5.8.1"}`,
			want: upstreamflavor.Podman,
		},
		{
			name: "docker",
			body: `{"Components":[{"Name":"Engine","Version":"28.6.0"}],"Version":"28.6.0"}`,
			want: upstreamflavor.Docker,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var probedPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				probedPath = r.URL.Path
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			deps := newServeDeps()
			logger, collector := flavorTestLogger()

			got, err := resolveUpstreamFlavor(t.Context(), deps, flavorTestConfig("auto"), flavorTransportTo(srv.Listener.Addr().String()), logger)
			if err != nil {
				t.Fatalf("resolveUpstreamFlavor() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("resolveUpstreamFlavor() = %q, want %q", got, tt.want)
			}
			if probedPath != "/version" {
				t.Fatalf("probed path = %q, want %q", probedPath, "/version")
			}
			if !collector.HasMessage("upstream flavor resolved") {
				t.Fatalf("no resolution log line; records: %#v", collector.Records())
			}
		})
	}
}

func TestResolveUpstreamFlavorAutoUsesMutualTLSAndBasePath(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("write mutual TLS bundle: %v", err)
	}
	serverCert, err := tls.LoadX509KeyPair(bundle.ServerCertFile, bundle.ServerKeyFile)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	caPEM, err := os.ReadFile(bundle.CAFile)
	if err != nil {
		t.Fatalf("read CA file: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA file contains no PEM certificates")
	}

	var probedPath string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probedPath = r.URL.EscapedPath()
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("flavor probe reached daemon without a verified client certificate")
		}
		_, _ = io.WriteString(w, `{"Components":[{"Name":"Podman Engine","Version":"5.8.1"}],"Version":"5.8.1"}`)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	cfg := config.Defaults()
	cfg.Upstream.Flavor = string(upstreamflavor.Auto)
	cfg.Upstream.Endpoints = []config.UpstreamEndpoint{{
		Address: "tcp://" + strings.TrimPrefix(srv.URL, "https://") + "/engine%2Fgateway",
		TLS: config.UpstreamTLSConfig{
			CAFile:     bundle.CAFile,
			CertFile:   bundle.ClientCertFile,
			KeyFile:    bundle.ClientKeyFile,
			ServerName: "127.0.0.1",
		},
	}}
	cfg.Upstream.Failover.HealthInterval = "-1s"

	resolver, legacy, err := buildUpstreamResolver(&cfg, nil, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("buildUpstreamResolver: %v", err)
	}
	if legacy {
		t.Fatal("buildUpstreamResolver used the legacy socket, want configured endpoint")
	}
	logger, _ := flavorTestLogger()
	got, err := resolveUpstreamFlavor(t.Context(), newServeDeps(), &cfg, resolver, logger)
	if err != nil {
		t.Fatalf("resolveUpstreamFlavor: %v", err)
	}
	if got != upstreamflavor.Podman {
		t.Fatalf("resolved flavor = %q, want %q", got, upstreamflavor.Podman)
	}
	if probedPath != "/engine%2Fgateway/version" {
		t.Fatalf("probed path = %q, want %q", probedPath, "/engine%2Fgateway/version")
	}
}

// TestResolveUpstreamFlavorFailsClosedOnAmbiguousProbe is constraint (1).
//
// Every way an "auto" probe can come back without an answer must fail, and
// the error must name the field the operator has to set. Neither fallback is
// available: "docker" silently reopens the Podman /events disclosure and
// "podman" silently refuses /events on a Docker deployment, and the probe
// result is cached for the process lifetime, so a single transient failure
// would carry the wrong answer until the next restart.
func TestResolveUpstreamFlavorFailsClosedOnAmbiguousProbe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		detectErr error
		flavor    upstreamflavor.Flavor
	}{
		{name: "transport failure", detectErr: errors.New("dial unix: connection refused")},
		{name: "deadline exceeded", detectErr: context.DeadlineExceeded},
		{name: "unrecognized engine", detectErr: upstreamflavor.ErrUnrecognized},
		// A detect implementation that returned a flavor alongside an error
		// must still be treated as a failure by the caller.
		{name: "flavor returned with an error", detectErr: errors.New("boom"), flavor: upstreamflavor.Docker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deps := newServeDeps()
			deps.detectUpstreamFlavor = func(context.Context, *http.Client) (upstreamflavor.Flavor, error) {
				return tt.flavor, tt.detectErr
			}
			logger, collector := flavorTestLogger()

			got, err := resolveUpstreamFlavor(t.Context(), deps, flavorTestConfig("auto"), http.DefaultTransport, logger)
			if err == nil {
				t.Fatalf("resolveUpstreamFlavor() = %q, want an error", got)
			}
			if got != "" {
				t.Fatalf("resolveUpstreamFlavor() = %q, want no flavor on failure", got)
			}
			if !strings.Contains(err.Error(), "upstream.flavor") {
				t.Fatalf("error = %v, want it to name upstream.flavor as the remedy", err)
			}
			for _, want := range []string{`"docker"`, `"podman"`} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %v, want it to name %s as a value to set", err, want)
				}
			}
			if !collector.HasMessage("upstream flavor probe failed") {
				t.Fatalf("no probe-failure log line; records: %#v", collector.Records())
			}
		})
	}
}

// TestResolveUpstreamFlavorRejectsUnknownConfiguredValue covers the
// belt-and-braces path: config validation already rejects a bad value, so a
// caller that skipped it must still fail rather than probe.
func TestResolveUpstreamFlavorRejectsUnknownConfiguredValue(t *testing.T) {
	t.Parallel()
	rt := &countingRoundTripper{t: t}
	deps := newServeDeps()
	deps.detectUpstreamFlavor = func(context.Context, *http.Client) (upstreamflavor.Flavor, error) {
		t.Fatal("detectUpstreamFlavor called for an invalid flavor")
		return "", nil
	}
	logger, _ := flavorTestLogger()

	if got, err := resolveUpstreamFlavor(t.Context(), deps, flavorTestConfig("containerd"), rt, logger); err == nil {
		t.Fatalf("resolveUpstreamFlavor() = %q, want an error", got)
	}
	if rt.calls != 0 {
		t.Fatalf("upstream round trips = %d, want 0", rt.calls)
	}
}

// TestServeDepsBindTheRealUpstreamFlavorProbe stops the shared test-deps stub
// from hiding a production regression: newServeDeps must bind the real probe,
// not a placeholder.
func TestServeDepsBindTheRealUpstreamFlavorProbe(t *testing.T) {
	t.Parallel()
	got := runtime.FuncForPC(reflect.ValueOf(newServeDeps().detectUpstreamFlavor).Pointer()).Name()
	if !strings.HasSuffix(got, "upstreamflavor.Detect") {
		t.Fatalf("newServeDeps().detectUpstreamFlavor = %s, want upstreamflavor.Detect", got)
	}
}

// TestRuntimeUpstreamFlavorDefaultsToDocker pins the reader's fallback. It is
// a test-only path (resolveUpstreamFlavorForRuntime fails startup rather than
// leaving the field empty), and it must report the pre-detection semantics so
// a bare serveRuntime cannot silently acquire Podman's refusals.
func TestRuntimeUpstreamFlavorDefaultsToDocker(t *testing.T) {
	t.Parallel()
	if got := runtimeUpstreamFlavor(nil); got != upstreamflavor.Docker {
		t.Fatalf("runtimeUpstreamFlavor(nil) = %q, want %q", got, upstreamflavor.Docker)
	}
	if got := runtimeUpstreamFlavor(&serveRuntime{}); got != upstreamflavor.Docker {
		t.Fatalf("runtimeUpstreamFlavor(zero runtime) = %q, want %q", got, upstreamflavor.Docker)
	}
	if got := runtimeUpstreamFlavor(&serveRuntime{upstreamFlavor: upstreamflavor.Podman}); got != upstreamflavor.Podman {
		t.Fatalf("runtimeUpstreamFlavor(podman) = %q, want %q", got, upstreamflavor.Podman)
	}
}

// TestResolveUpstreamFlavorForRuntimeRecordsResult covers the runtime-facing
// wrapper: a successful resolution lands on the runtime, and a failure leaves
// it untouched so no chain is ever built from a guessed flavor.
func TestResolveUpstreamFlavorForRuntimeRecordsResult(t *testing.T) {
	t.Parallel()
	cfg := flavorTestConfig("podman")
	deps := newServeDeps()
	deps.detectUpstreamFlavor = func(context.Context, *http.Client) (upstreamflavor.Flavor, error) {
		t.Fatal("detectUpstreamFlavor called for an explicit flavor")
		return "", nil
	}
	logger, _ := flavorTestLogger()

	rt := &serveRuntime{}
	if err := resolveUpstreamFlavorForRuntime(t.Context(), deps, rt, cfg, logger); err != nil {
		t.Fatalf("resolveUpstreamFlavorForRuntime() error = %v", err)
	}
	if rt.upstreamFlavor != upstreamflavor.Podman {
		t.Fatalf("runtime.upstreamFlavor = %q, want %q", rt.upstreamFlavor, upstreamflavor.Podman)
	}

	failing := newServeDeps()
	failing.detectUpstreamFlavor = func(context.Context, *http.Client) (upstreamflavor.Flavor, error) {
		return "", errors.New("probe failed")
	}
	unresolved := &serveRuntime{}
	if err := resolveUpstreamFlavorForRuntime(t.Context(), failing, unresolved, flavorTestConfig("auto"), logger); err == nil {
		t.Fatal("resolveUpstreamFlavorForRuntime() error = nil, want a failure")
	}
	if unresolved.upstreamFlavor != "" {
		t.Fatalf("runtime.upstreamFlavor = %q, want it untouched after a failed probe", unresolved.upstreamFlavor)
	}
}

// TestServeChainPassesResolvedFlavorToVisibility is the wiring proof the
// visibility package's Options doc comment points at. The zero Flavor means
// Docker, so a chain builder that dropped the field would leave the Podman
// /events hole open with every unit test still green. Driving the real
// withVisibility layer that buildServeHandlerLayersWithRuntime produced —
// rather than a hand-built visibility.Options — is what makes it a wiring
// test.
func TestServeChainPassesResolvedFlavorToVisibility(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		flavor     upstreamflavor.Flavor
		wantStatus int
	}{
		{name: "podman refuses a multi-selector events stream", flavor: upstreamflavor.Podman, wantStatus: http.StatusForbidden},
		{name: "docker is unchanged", flavor: upstreamflavor.Docker, wantStatus: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Response.VisibleResourceLabels = []string{"com.sockguard.visible=true", "com.sockguard.client=watchtower"}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			deps := newServeTestDeps()

			serveRT, err := newServeRuntime(&cfg, logger, deps)
			if err != nil {
				t.Fatalf("newServeRuntime: %v", err)
			}
			serveRT.upstreamFlavor = tt.flavor

			layers, teardown, _ := buildServeHandlerLayersWithRuntime(serveHandlerBuild{
				Cfg:    &cfg,
				Logger: logger,
				Rules:  []*filter.CompiledRule{},
				Deps:   deps,
				// Runtime carries the resolved flavor; this is the value under
				// test.
				Runtime: serveRT,
			})
			t.Cleanup(teardown)

			var visibilityLayer func(http.Handler) http.Handler
			for _, layer := range layers {
				if layer.name == "withVisibility" {
					visibilityLayer = layer.with
				}
			}
			if visibilityLayer == nil {
				t.Fatal("no withVisibility layer in the built chain")
			}

			handler := visibilityLayer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/events", nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("GET /events status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestValidateDoesNotRequireAReachableDaemon is constraint (3). `sockguard
// validate` must be a pure config operation: it runs on a build box, in CI,
// and in a pre-flight container with no daemon anywhere. The config here
// leaves upstream.flavor at its "auto" default and points upstream.socket at
// a path that does not exist, so a validate path that probed would fail.
func TestValidateDoesNotRequireAReachableDaemon(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
listen:
  socket: ` + filepath.Join(dir, "sockguard.sock") + `
upstream:
  socket: ` + filepath.Join(dir, "definitely-absent-docker.sock") + `
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if loaded.Upstream.Flavor != string(upstreamflavor.Auto) {
		t.Fatalf("upstream.flavor = %q, want the %q default so this test exercises the probing path", loaded.Upstream.Flavor, upstreamflavor.Auto)
	}

	var out, errOut bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)
	command.SetErr(&errOut)

	if err := runValidate(command, nil); err != nil {
		t.Fatalf("runValidate() error = %v; validate must not need a daemon, stderr:\n%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "validation passed") {
		t.Fatalf("stdout = %s, want a passing validation", out.String())
	}
}

// TestValidateRejectsAnUnknownFlavor pins the config-time guard, so a typo is
// caught by `sockguard validate` rather than at the next restart.
func TestValidateRejectsAnUnknownFlavor(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"containerd", "Podman", "", "auto "} {
		cfg := config.Defaults()
		cfg.Upstream.Flavor = value
		err := config.Validate(&cfg)
		if value == "auto " {
			// Surrounding whitespace is tolerated, matching Configured.
			if err != nil {
				t.Fatalf("Validate(flavor=%q) error = %v, want nil", value, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("Validate(flavor=%q) error = nil, want a rejection", value)
		}
		if !strings.Contains(err.Error(), "upstream.flavor") {
			t.Fatalf("Validate(flavor=%q) error = %v, want it to name upstream.flavor", value, err)
		}
	}
}

// TestRunServeFailsWhenTheFlavorProbeIsAmbiguous is the startup-sequence half
// of constraint (1): resolveUpstreamFlavor failing closed is only useful if
// `sockguard serve` actually calls it, and calls it BEFORE it binds a
// listener. A chain built on a guessed flavor is the failure this prevents,
// so the assertion is that no listener was ever created.
func TestRunServeFailsWhenTheFlavorProbeIsAmbiguous(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) { return testServeConfig(), nil }
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return stubCompiledRules(), nil }
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) { return &serveTestConn{}, nil }
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil
	}
	// Override the shared stub: this test is specifically about the probe
	// failing.
	deps.detectUpstreamFlavor = func(context.Context, *http.Client) (upstreamflavor.Flavor, error) {
		return "", upstreamflavor.ErrUnrecognized
	}
	listenerCreated := false
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		listenerCreated = true
		return &serveTestListener{}, nil
	}
	deps.notifySignals = func(chan<- os.Signal, ...os.Signal) {}

	err := runServeWithDeps(newServeCommand(), nil, deps)
	if err == nil {
		t.Fatal("runServeWithDeps() error = nil, want startup to fail on an ambiguous flavor probe")
	}
	if !strings.Contains(err.Error(), "upstream.flavor") {
		t.Fatalf("error = %v, want it to name upstream.flavor", err)
	}
	if listenerCreated {
		t.Fatal("a listener was bound before the flavor was known")
	}
}

// TestRunServeSucceedsWithAnExplicitFlavorAndNoProbe is the companion: an
// operator who declares the flavor gets a normal startup, and the probe seam
// is never entered.
func TestRunServeSucceedsWithAnExplicitFlavorAndNoProbe(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Upstream.Flavor = string(upstreamflavor.Podman)
		return cfg, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return stubCompiledRules(), nil }
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) { return &serveTestConn{}, nil }
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil
	}
	deps.detectUpstreamFlavor = func(context.Context, *http.Client) (upstreamflavor.Flavor, error) {
		t.Fatal("the flavor probe ran despite an explicit upstream.flavor")
		return "", nil
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) { return &serveTestListener{}, nil }
	deps.startServing = func(_ *http.Server, _ net.Listener, errCh chan<- error) { errCh <- http.ErrServerClosed }
	deps.notifySignals = func(chan<- os.Signal, ...os.Signal) {}
	deps.shutdownServer = func(*http.Server, context.Context) error { return nil }

	// The premature-Serve return is this suite's standard way to end a
	// runServeWithDeps test; what matters here is that startup got past the
	// flavor step and reached serving at all, and that the probe stub (which
	// fails the test if entered) was never called.
	err := runServeWithDeps(newServeCommand(), nil, deps)
	if err == nil || !strings.Contains(err.Error(), "server error") {
		t.Fatalf("runServeWithDeps() error = %v, want startup to have reached serving", err)
	}
	if strings.Contains(err.Error(), "upstream.flavor") {
		t.Fatalf("runServeWithDeps() error = %v, want no flavor failure for an explicit flavor", err)
	}
}
