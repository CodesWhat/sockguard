package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/admin"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

// TestBuildServeHandlerSkipsAdminLayerWhenDedicatedListenerConfigured proves
// the gate in buildServeHandlerLayersWithRuntime: when admin.listen is set,
// the main chain must NOT mount the admin endpoints — otherwise the same
// path resolves on both listeners and operators lose the isolation they
// asked for.
func TestBuildServeHandlerSkipsAdminLayerWhenDedicatedListenerConfigured(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-skip-up")
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	rules := adminTestRules(t)
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodPost, cfg.Admin.Path, strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// With the admin layer skipped on the main chain, the request falls
	// through to the Docker-API filter, which has no allow rule for
	// /admin/validate and denies it. A 200 here would mean the admin
	// interceptor leaked onto the main listener — the bug we're guarding
	// against.
	if rec.Code == http.StatusOK {
		t.Fatalf("admin validate served on main chain (status %d) — admin.listen isolation broken", rec.Code)
	}
}

// TestBuildAdminHandlerChainServesValidate exercises the dedicated admin
// handler's POST /admin/validate path. The chain composed by
// buildAdminHandlerChain is the same one bound to the dedicated listener,
// so verifying it in isolation is the cheapest way to prove the endpoint
// works without spinning up two real TCP servers.
func TestBuildAdminHandlerChainServesValidate(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-only-svc")
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	versioner := admin.NewPolicyVersioner()
	versioner.Update(admin.PolicySnapshot{Rules: 1, Source: "startup"})

	handler := buildAdminHandlerChain(&cfg, newDiscardLogger(), nil, versioner)

	body := strings.NewReader("rules:\n  - match: { method: GET, path: /_ping }\n    action: allow\n")
	req := httptest.NewRequest(http.MethodPost, cfg.Admin.Path, body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("validate status = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var resp admin.ValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if !resp.OK {
		t.Fatalf("ok=false errors=%v", resp.Errors)
	}
}

// TestBuildAdminHandlerChainServesPolicyVersion exercises the dedicated
// admin handler's GET /admin/policy/version path and verifies the
// generation counter wired through the same versioner pointer that
// runServeWithDeps publishes into.
func TestBuildAdminHandlerChainServesPolicyVersion(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-pv")
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	versioner := admin.NewPolicyVersioner()
	versioner.Update(admin.PolicySnapshot{Rules: 3, Source: "startup"})

	handler := buildAdminHandlerChain(&cfg, newDiscardLogger(), nil, versioner)

	req := httptest.NewRequest(http.MethodGet, cfg.Admin.PolicyVersionPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("policy version status = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var snap admin.PolicySnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if snap.Version != 1 {
		t.Fatalf("Version = %d, want 1", snap.Version)
	}
	if snap.Rules != 3 {
		t.Fatalf("Rules = %d, want 3", snap.Rules)
	}
}

// TestBuildAdminHandlerChainReturns404ForUnknownPath confirms the admin
// listener's terminator: any non-admin path returns 404, never 200 and
// never silently 502s through to a non-existent upstream.
func TestBuildAdminHandlerChainReturns404ForUnknownPath(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	versioner := admin.NewPolicyVersioner()
	versioner.Update(admin.PolicySnapshot{Source: "startup"})

	handler := buildAdminHandlerChain(&cfg, newDiscardLogger(), nil, versioner)

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown admin path", rec.Code)
	}
}

// TestStartAdminServerNoopWhenAdminDisabled proves the early-return guard:
// admin off OR admin.listen unconfigured must NOT bind a listener and must
// return a stop func that is safe to defer.
func TestStartAdminServerNoopWhenAdminDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = false

	deps := newServeTestDeps()
	listenerCalls := 0
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		listenerCalls++
		return nil, errors.New("should not be called")
	}

	server, errCh, stop, err := startAdminServer(&cfg, newDiscardLogger(), nil, nil, deps)
	if err != nil {
		t.Fatalf("startAdminServer() error = %v, want nil", err)
	}
	if server != nil {
		t.Fatalf("server = %v, want nil", server)
	}
	if listenerCalls != 0 {
		t.Fatalf("createAdminListener called %d times, want 0", listenerCalls)
	}
	if errCh == nil {
		t.Fatal("errCh = nil, want non-nil blocking channel")
	}
	stop() // must not panic
}

// TestStartAdminServerNoopWhenListenerNotConfigured covers the second half
// of the gate: Enabled=true but Listen empty must still no-op.
func TestStartAdminServerNoopWhenListenerNotConfigured(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	// Listen sub-block is zero-valued → not configured.

	deps := newServeTestDeps()
	listenerCalls := 0
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		listenerCalls++
		return nil, errors.New("should not be called")
	}

	server, _, stop, err := startAdminServer(&cfg, newDiscardLogger(), nil, nil, deps)
	if err != nil {
		t.Fatalf("startAdminServer() error = %v, want nil", err)
	}
	if server != nil {
		t.Fatalf("server = %v, want nil", server)
	}
	if listenerCalls != 0 {
		t.Fatalf("createAdminListener called %d times, want 0", listenerCalls)
	}
	stop()
}

// TestStartAdminServerPropagatesListenerError surfaces createAdminListener
// failure as a wrapped error so the operator sees the cause at startup
// rather than a generic "server error".
func TestStartAdminServerPropagatesListenerError(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	deps := newServeTestDeps()
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		return nil, errors.New("bind boom")
	}

	_, _, stop, err := startAdminServer(&cfg, newDiscardLogger(), nil, nil, deps)
	if err == nil || !strings.Contains(err.Error(), "admin listener: bind boom") {
		t.Fatalf("error = %v, want admin listener: bind boom", err)
	}
	if stop == nil {
		t.Fatal("stop = nil, want non-nil even on error")
	}
	stop() // must not panic with a no-op stop on the error path
}

// TestStartAdminServerStartsServing brings up the dedicated admin server on
// an injected listener and confirms the startServing dep is invoked exactly
// once with the right binding. This is the wiring proof — actual HTTP I/O
// is exercised by the chain-level tests above.
func TestStartAdminServerStartsServing(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	deps := newServeTestDeps()
	injected := &serveTestListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}}
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		return injected, nil
	}

	var mu sync.Mutex
	var serveCalls int
	var sawListener net.Listener
	deps.startServing = func(_ *http.Server, ln net.Listener, errCh chan<- error) {
		mu.Lock()
		serveCalls++
		sawListener = ln
		mu.Unlock()
		errCh <- http.ErrServerClosed
	}

	server, errCh, stop, err := startAdminServer(&cfg, newDiscardLogger(), nil, admin.NewPolicyVersioner(), deps)
	if err != nil {
		t.Fatalf("startAdminServer() error = %v", err)
	}
	if server == nil {
		t.Fatal("server = nil, want non-nil")
	}
	defer stop()

	select {
	case got := <-errCh:
		if !errors.Is(got, http.ErrServerClosed) {
			t.Fatalf("errCh = %v, want http.ErrServerClosed", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startServing did not signal in time")
	}

	mu.Lock()
	defer mu.Unlock()
	if serveCalls != 1 {
		t.Fatalf("serveCalls = %d, want 1", serveCalls)
	}
	if sawListener != injected {
		t.Fatalf("startServing got listener %v, want injected %v", sawListener, injected)
	}
}

// TestRunServeWithDedicatedAdminListenerShutsDownBothServers is the
// end-to-end wiring test: build a config that turns on admin + a dedicated
// listener, drive runServeWithDeps with injected listeners, and confirm
// both Serve goroutines were started and both Shutdown calls fire on
// SIGTERM.
func TestRunServeWithDedicatedAdminListenerShutsDownBothServers(t *testing.T) {
	deps := newServeTestDeps()
	cfg := testServeConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	deps.loadConfig = func(string) (*config.Config, error) { return cfg, nil }
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}

	mainListener := &serveTestListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2375}}
	adminListener := &serveTestListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}}
	deps.createServeListener = func(*config.Config) (net.Listener, error) { return mainListener, nil }
	deps.createAdminListener = func(*config.Config) (net.Listener, error) { return adminListener, nil }

	var serveMu sync.Mutex
	var serveCalls int
	// startServing records that the goroutine launched and then blocks
	// forever (well, until the test exits) — we drive the shutdown path
	// via SIGTERM, so the serve goroutines never need to return.
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	deps.startServing = func(*http.Server, net.Listener, chan<- error) {
		serveMu.Lock()
		serveCalls++
		serveMu.Unlock()
		<-block
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
		// Sending the signal is deferred to a goroutine so the select in
		// runServeWithDeps is already armed by the time we trigger it,
		// and so notifySignals returns promptly without blocking on the
		// channel send.
		go func() { c <- syscall.SIGTERM }()
	}

	var shutdownMu sync.Mutex
	var shutdownCalls int
	deps.shutdownServer = func(*http.Server, context.Context) error {
		shutdownMu.Lock()
		shutdownCalls++
		shutdownMu.Unlock()
		return nil
	}

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v, want nil", err)
	}

	// runServeWithDeps does not synchronously wait on the serve goroutines
	// after Shutdown, but the test's deps.startServing increments under a
	// lock before blocking, so by the time runServeWithDeps reaches the
	// select both increments have happened or one is about to.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		serveMu.Lock()
		ok := serveCalls == 2
		serveMu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	serveMu.Lock()
	gotServeCalls := serveCalls
	serveMu.Unlock()
	if gotServeCalls != 2 {
		t.Fatalf("startServing calls = %d, want 2 (main + admin)", gotServeCalls)
	}

	shutdownMu.Lock()
	gotShutdownCalls := shutdownCalls
	shutdownMu.Unlock()
	if gotShutdownCalls != 2 {
		t.Fatalf("shutdownServer calls = %d, want 2 (admin + main)", gotShutdownCalls)
	}
}

// TestRunServeAdminListenerErrorIsFatal proves the admin Serve error
// branch in the select: an admin Serve return that is not ErrServerClosed
// must propagate as an error from runServeWithDeps, not be silently
// swallowed.
//
// main and admin share the same startServing dep but are distinguished by
// listener identity — admin's createAdminListener returns a tagged
// listener that startServing recognizes.
func TestRunServeAdminListenerErrorIsFatal(t *testing.T) {
	deps := newServeTestDeps()
	cfg := testServeConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	deps.loadConfig = func(string) (*config.Config, error) { return cfg, nil }
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}

	mainListener := &serveTestListener{}
	adminListener := &serveTestListener{}
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return mainListener, nil
	}
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		return adminListener, nil
	}

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	deps.startServing = func(_ *http.Server, ln net.Listener, errCh chan<- error) {
		if ln == adminListener {
			errCh <- errors.New("admin accept boom")
			return
		}
		// Main server — block until the test exits so its err channel
		// stays silent and runServeWithDeps must select on adminErrCh.
		<-block
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {} // no signal — only admin error
	deps.shutdownServer = func(*http.Server, context.Context) error { return nil }

	err := runServeWithDeps(newServeCommand(), nil, deps)
	if err == nil || !strings.Contains(err.Error(), "admin server error") {
		t.Fatalf("error = %v, want admin server error wrap", err)
	}
}
