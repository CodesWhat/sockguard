package cmd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/admin"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/ratelimit"
	"github.com/codeswhat/sockguard/internal/reload"
	"github.com/codeswhat/sockguard/internal/testhelp"
)

// TestWarnAssignedProfilesWithoutLimitsEmitsWarning seeds the four
// assignment channels (default, source-IP, certificate, unix-peer) with a
// profile that has no entry in limitedProfiles, and verifies a warning is
// emitted for each unique assigned profile.
func TestWarnAssignedProfilesWithoutLimitsEmitsWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := &config.Config{}
	cfg.Clients.DefaultProfile = "default"
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{{Profile: "ip"}}
	cfg.Clients.ClientCertificateProfiles = []config.ClientCertificateProfileAssignmentConfig{{Profile: "cert"}}
	cfg.Clients.UnixPeerProfiles = []config.ClientUnixPeerProfileAssignmentConfig{{Profile: "peer"}}

	warnAssignedProfilesWithoutLimits(cfg, map[string]ratelimit.ProfileOptions{}, logger)

	out := buf.String()
	for _, want := range []string{"default", "ip", "cert", "peer"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning output missing profile %q\nfull output:\n%s", want, out)
		}
	}
}

// TestWarnAssignedProfilesWithoutLimitsSilentWhenLimited verifies that
// profiles which DO have a limits entry are not flagged.
func TestWarnAssignedProfilesWithoutLimitsSilentWhenLimited(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := &config.Config{}
	cfg.Clients.DefaultProfile = "default"

	limited := map[string]ratelimit.ProfileOptions{
		"default": {Concurrency: &ratelimit.ConcurrencyOptions{MaxInflight: 1}},
	}
	warnAssignedProfilesWithoutLimits(cfg, limited, logger)

	if got := buf.String(); got != "" {
		t.Fatalf("warning unexpectedly emitted: %q", got)
	}
}

// TestBuildRateLimitMiddlewareReturnsNilWhenNoLimitsConfigured covers the
// happy default: no profile has limits, no global concurrency, so the
// middleware factory returns (nil, nil) and the chain skips this layer.
func TestBuildRateLimitMiddlewareReturnsNilWhenNoLimitsConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "p1"}, // empty LimitsConfig
	}

	rt := &serveRuntime{}
	mw, stop := buildRateLimitMiddleware(cfg, newDiscardLogger(), rt)
	if mw != nil {
		t.Errorf("mw = non-nil, want nil")
	}
	if stop != nil {
		t.Errorf("stop = non-nil, want nil")
	}
}

// TestBuildRateLimitMiddlewareBuildsWhenGlobalConcurrencyConfigured covers
// the branch where only the global-concurrency block is set: middleware
// must be non-nil and stop must release goroutines without blocking.
func TestBuildRateLimitMiddlewareBuildsWhenGlobalConcurrencyConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Clients.GlobalConcurrency = &config.GlobalConcurrencyConfig{MaxInflight: 4}

	rt := &serveRuntime{}
	mw, stop := buildRateLimitMiddleware(cfg, newDiscardLogger(), rt)
	if mw == nil {
		t.Fatal("mw = nil, want non-nil when global concurrency configured")
	}
	if stop == nil {
		t.Fatal("stop = nil, want non-nil")
	}
	defer stop()
}

// TestBuildRateLimitMiddlewareGlobalConcurrencyZeroSkipped pins the
// CONDITIONALS_BOUNDARY mutant at serve.go:533 (`MaxInflight > 0` → `>= 0`).
// When the global-concurrency block is present but MaxInflight is zero, the
// middleware must NOT activate (otherwise the proxy installs a zero-cap
// concurrency limiter that blocks every request). With no profile limits,
// returning the no-op (nil, nil) is the correct behaviour.
func TestBuildRateLimitMiddlewareGlobalConcurrencyZeroSkipped(t *testing.T) {
	cfg := &config.Config{}
	cfg.Clients.GlobalConcurrency = &config.GlobalConcurrencyConfig{MaxInflight: 0}

	rt := &serveRuntime{}
	mw, stop := buildRateLimitMiddleware(cfg, newDiscardLogger(), rt)
	if mw != nil {
		t.Fatal("mw = non-nil, want nil when MaxInflight is 0 (the boundary)")
	}
	if stop != nil {
		t.Fatal("stop = non-nil, want nil when MaxInflight is 0")
	}
}

// TestBuildRateLimitMiddlewareBuildsWhenProfileLimitsConfigured covers the
// branch where a profile has concurrency limits — middleware must be
// non-nil so the limiter layer is installed.
func TestBuildRateLimitMiddlewareBuildsWhenProfileLimitsConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "p1",
			Limits: config.LimitsConfig{
				Concurrency: &config.ConcurrencyConfig{MaxInflight: 2},
			},
		},
	}

	rt := &serveRuntime{}
	mw, stop := buildRateLimitMiddleware(cfg, newDiscardLogger(), rt)
	if mw == nil {
		t.Fatal("mw = nil, want non-nil when profile limits configured")
	}
	if stop == nil {
		t.Fatal("stop = nil, want non-nil")
	}
	defer stop()
}

// TestStartReloaderRejectsEmptyCfgFile exercises the early-return guard.
func TestStartReloaderRejectsEmptyCfgFile(t *testing.T) {
	_, err := startReloader(context.Background(), "", 0, 0, nil, newDiscardLogger())
	if err == nil {
		t.Fatal("startReloader(\"\") err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "cfgFile is required") {
		t.Errorf("err = %v, want cfgFile is required", err)
	}
}

// TestStartReloaderStartsAndStops drives a happy-path lifecycle: point at
// a real temp config file, start the reloader, then call stop and confirm
// it returns. A stop that doesn't return within a second indicates the
// goroutine is leaking.
func TestStartReloaderStartsAndStops(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte("listen:\n  socket: /tmp/x.sock\n"), 0o600); err != nil {
		t.Fatalf("write cfgFile: %v", err)
	}

	coordinator := &reloadCoordinator{
		chainTeardown: func() {},
		swappable:     reload.NewSwappableHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
	}
	stop, err := startReloader(context.Background(), cfgFile, 10*time.Millisecond, 50*time.Millisecond, coordinator, newDiscardLogger())
	if err != nil {
		t.Fatalf("startReloader err = %v", err)
	}

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not return within 2 seconds — reloader goroutine leak")
	}
}

// TestStartReloaderLogsNonCanceledRunError pins the CONDITIONALS_NEGATION
// mutant at serve_reload.go:286 (`runErr != nil` → `==`). The reloader
// goroutine logs a warning only when Run returns a non-Canceled error;
// the mutant inverts the nil check, so a clean exit would log spuriously
// AND a real error would be silently swallowed. We point the reloader at
// a path under a non-existent parent so fsnotify.Add fails immediately
// (a "reload: watch ..." error from reload.Run), then assert the warn
// record is present.
func TestStartReloaderLogsNonCanceledRunError(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "nonexistent-child", "config.yaml")

	collector := &testhelp.CollectingHandler{}

	coordinator := &reloadCoordinator{
		chainTeardown: func() {},
		swappable:     reload.NewSwappableHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
	}

	stop, err := startReloader(context.Background(), cfgFile, 10*time.Millisecond, 0, coordinator, collector.Logger())
	if err != nil {
		t.Fatalf("startReloader err = %v", err)
	}
	// stop() waits for the goroutine to exit, which is the moment after
	// the Warn line is emitted.
	stop()

	if !collector.HasMessage("config reloader stopped with error") {
		t.Fatalf("expected reloader error log; records: %#v", collector.Records())
	}
}

// TestCreateAdminListenerImplRejectsUnconfiguredListener covers the
// guard: callers must check Configured() before invoking; calling here
// with an empty Listen block returns an explicit error rather than
// silently binding 0.0.0.0.
func TestCreateAdminListenerImplRejectsUnconfiguredListener(t *testing.T) {
	cfg := &config.Config{}
	deps := newServeTestDeps()

	_, err := deps.createAdminListenerImpl(cfg)
	if err == nil {
		t.Fatal("createAdminListenerImpl(unconfigured) err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "admin listener not configured") {
		t.Errorf("err = %v, want admin listener not configured", err)
	}
}

// TestCreateAdminListenerImplCreatesUnixSocket covers the unix-socket
// branch: with admin.listen.socket and the hardened socket_mode set, the
// listener must be returned and accept a connection.
//
// Uses os.MkdirTemp("/tmp", ...) directly rather than t.TempDir() because
// macOS' default $TMPDIR ($USER/var/folders/...) routinely exceeds the
// 104-char sun_path limit when combined with a long test name.
func TestCreateAdminListenerImplCreatesUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sg-adm-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "admin.sock")

	cfg := &config.Config{}
	cfg.Admin.Listen.Socket = socketPath
	cfg.Admin.Listen.SocketMode = config.HardenedListenSocketMode

	deps := newServeTestDeps()
	ln, err := deps.createAdminListenerImpl(cfg)
	if err != nil {
		t.Fatalf("createAdminListenerImpl err = %v", err)
	}
	if ln == nil {
		t.Fatal("ln = nil, want non-nil")
	}
	defer ln.Close()

	if _, ok := ln.(*net.UnixListener); !ok {
		t.Errorf("ln type = %T, want *net.UnixListener", ln)
	}
}

// Unused-import suppression. The tests above don't reference these
// indirectly-imported helpers, but keeping the imports anchored avoids
// drift when future tests in this file are added.
var (
	_ = admin.PolicyVersioner{}
	_ = logging.AuditLogger{}
	_ = sync.Mutex{}
	_ error
	_ = errors.New
)
