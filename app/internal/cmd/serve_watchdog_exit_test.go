package cmd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/health"
)

func newWatchdogExitDeps(upstreamSocket string) *serveDeps {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Socket = "/tmp/sockguard-test.sock"
		cfg.Listen.Address = ""
		cfg.Upstream.Socket = upstreamSocket
		cfg.Health.Enabled = true
		cfg.Health.Watchdog.Enabled = true
		cfg.Health.Watchdog.Interval = "10ms"
		cfg.Health.Watchdog.ExitAfter = "60ms"
		return cfg, nil
	}
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{}, nil
	}
	deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {}
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error { return nil }
	deps.removePath = func(string) error { return nil }
	return deps
}

func TestRunServeExitsNonZeroWhenWatchdogUpstreamStaysDown(t *testing.T) {
	deps := newWatchdogExitDeps(shortSocketPath(t, "wd-exit-down"))
	deps.notifySignals = func(chan<- os.Signal, ...os.Signal) {}

	done := make(chan error, 1)
	go func() { done <- runServeWithDeps(newServeCommand(), nil, deps) }()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "watchdog: upstream unreachable") {
			t.Fatalf("runServe() error = %v, want watchdog exit error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not exit after the upstream stayed down past exit_after")
	}
}

func TestRunServeHealthyUpstreamStaysUpAndShutsDownCleanly(t *testing.T) {
	sock := shortSocketPath(t, "wd-exit-up")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	deps := newWatchdogExitDeps(sock)
	sigReady := make(chan chan<- os.Signal, 1)
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) { sigReady <- c }

	done := make(chan error, 1)
	go func() { done <- runServeWithDeps(newServeCommand(), nil, deps) }()

	sigCh := <-sigReady
	// Several multiples of exit_after: a healthy upstream must not trip it.
	select {
	case err := <-done:
		t.Fatalf("serve exited while the upstream was healthy: %v", err)
	case <-time.After(400 * time.Millisecond):
	}

	sigCh <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down on SIGTERM")
	}
}

func TestStartWatchdogExitAfterDisabledNeverSignals(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "wd-exit-off")
	cfg.Health.Watchdog.Enabled = true
	cfg.Health.Watchdog.Interval = "10ms"

	rt := &serveRuntime{watchdogExit: make(chan error, 1)}
	rt.health = health.NewMonitor(cfg.Upstream.Socket, time.Now(), newDiscardLogger())
	stop := rt.startWatchdog(context.Background(), &cfg)
	t.Cleanup(stop)

	select {
	case err := <-rt.watchdogExit:
		t.Fatalf("exit_after=0s signaled: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}
