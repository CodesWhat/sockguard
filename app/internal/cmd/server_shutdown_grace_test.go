package cmd

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/health"
	"github.com/codeswhat/sockguard/app/internal/inbound"
	"github.com/codeswhat/sockguard/app/internal/metrics"
)

// TestShutdownServersConfiguredGracePeriodBoundsInFlightRequests proves that
// server.shutdown_grace — not just the pre-existing hardcoded 30s — is what
// actually bounds how long shutdownServers waits for in-flight requests on
// the real net/http shutdown path (defaultServeShutdown), at a scaled-down
// value: a handler that outlives the configured grace period is cut off mid
// response, while one that finishes inside it completes normally.
func TestShutdownServersConfiguredGracePeriodBoundsInFlightRequests(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	entered := make(chan string, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- r.URL.Path
		switch r.URL.Path {
		case "/slow":
			// Outlives the 50ms grace period configured below; only released
			// after the test has already asserted the connection was cut off.
			<-release
		case "/fast":
			// Well inside the 50ms grace period.
			time.Sleep(10 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	identity := inbound.Identity{Name: "default", Role: inbound.RoleMain, Network: inbound.NetworkTCP}
	server := newHTTPServerForIdentity(handler, identity)
	go func() { _ = server.Serve(ln) }()

	addr := ln.Addr().String()

	fastDone := make(chan error, 1)
	go func() {
		resp, getErr := http.Get("http://" + addr + "/fast")
		if getErr == nil {
			resp.Body.Close()
		}
		fastDone <- getErr
	}()

	slowDone := make(chan error, 1)
	go func() {
		resp, getErr := http.Get("http://" + addr + "/slow")
		if getErr == nil {
			resp.Body.Close()
		}
		slowDone <- getErr
	}()

	// Wait for both handlers to actually start before draining begins, so
	// both requests are genuinely in-flight when shutdownServers runs —
	// not still racing to connect.
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/2 handlers entered before timeout", i)
		}
	}

	cfg := testServeConfig()
	cfg.Server.ShutdownGrace = "50ms"

	deps := newServeTestDeps()
	deps.shutdownGracePeriod = effectiveShutdownGracePeriod(cfg)
	deps.shutdownServer = defaultServeShutdown
	deps.removePath = func(string) error { return nil }

	board := newListenerStatusBoard()
	board.register(identity, health.ListenerStateServing)
	member := &listenerMember{identity: identity, listener: ln, server: server}

	shutdownServers(context.Background(), deps, cfg, []*listenerMember{member}, nil, metrics.NewRegistry(), board, newDiscardLogger())
	close(release)

	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("fast request (finishes inside the grace period) failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fast request never returned")
	}

	select {
	case err := <-slowDone:
		if err == nil {
			t.Fatal("slow request (outlives the grace period) unexpectedly succeeded; want the connection cut off")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow request never returned")
	}
}

// TestShutdownServersDefaultGracePeriodIsUnchanged pins that
// server.shutdown_grace's default ("30s") still resolves to the same 30s
// deadline shutdownServers used before this field existed, so a config that
// never sets server.shutdown_grace keeps today's shutdown behavior
// byte-for-byte.
func TestShutdownServersDefaultGracePeriodIsUnchanged(t *testing.T) {
	t.Parallel()

	cfg := testServeConfig()
	if cfg.Server.ShutdownGrace != "30s" {
		t.Fatalf("testServeConfig().Server.ShutdownGrace = %q, want %q", cfg.Server.ShutdownGrace, "30s")
	}
	if got, want := effectiveShutdownGracePeriod(cfg), 30*time.Second; got != want {
		t.Fatalf("effectiveShutdownGracePeriod(default cfg) = %v, want %v", got, want)
	}
}
