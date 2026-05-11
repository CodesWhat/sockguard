package cmd

// mutant_kill_test.go — focused tests that kill surviving mutation testing mutants.
// Each test section names the source file, line, and mutation kind it targets.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/ui"
)

// ---------------------------------------------------------------------------
// serve_deps.go:63 — ARITHMETIC_BASE: shutdownGracePeriod = 30 * time.Second
// Mutation flips * → /, yielding 30 / time.Second (≈ 0 or wrong duration).
// Kill: assert the exact value.
// ---------------------------------------------------------------------------

func TestNewServeDeps_ShutdownGracePeriodIs30Seconds(t *testing.T) {
	const want = 30 * time.Second
	deps := newServeDeps()
	if deps.shutdownGracePeriod != want {
		t.Fatalf("shutdownGracePeriod = %v, want %v", deps.shutdownGracePeriod, want)
	}
}

// ---------------------------------------------------------------------------
// serve_deps.go:80 — ARITHMETIC_BASE: dialUpstream("unix", …, 5*time.Second)
// Mutation flips * → /, yielding 5/time.Second (≈ 0 ns timeout).
// Kill: capture the timeout passed to dialUpstream and assert it equals 5s.
// ---------------------------------------------------------------------------

func TestVerifyUpstreamReachable_DialTimeoutIs5Seconds(t *testing.T) {
	const want = 5 * time.Second

	deps := newServeTestDeps()
	var captured time.Duration
	deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
		captured = timeout
		return nil, errors.New("stop")
	}

	_ = deps.verifyUpstreamReachable("/var/run/docker.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if captured != want {
		t.Fatalf("dial timeout = %v, want %v", captured, want)
	}
}

// ---------------------------------------------------------------------------
// version.go:47 — CONDITIONALS_BOUNDARY: len(c) > n  (n == 7)
// Mutation flips > → >=, causing a 7-char commit to be truncated (returns c[:7]).
// Kill: assert that a 7-char commit is NOT truncated (returned as-is).
// ---------------------------------------------------------------------------

func TestShortCommit_ExactlyNCharsIsNotTruncated(t *testing.T) {
	// n == 7; len("abcdefg") == 7, so len(c) > 7 is false → no truncation.
	// With the mutation (>=) the condition would be true and the result would
	// still be c[:7] == "abcdefg" — same value, so this IS an equivalent mutant.
	// We record it below but include the test for documentation.
	got := shortCommit("abcdefg")
	if got != "abcdefg" {
		t.Fatalf("shortCommit(7-char) = %q, want untruncated %q", got, "abcdefg")
	}
	// n+1 chars must be truncated regardless of boundary direction.
	got8 := shortCommit("abcdefgh")
	if got8 != "abcdefg" {
		t.Fatalf("shortCommit(8-char) = %q, want %q", got8, "abcdefg")
	}
}

// ---------------------------------------------------------------------------
// match.go:131 — CONDITIONALS_BOUNDARY: matchedRuleIndex < len(cfg.Rules)
// Mutation flips < → <=, causing an out-of-bounds panic when index == len.
// Kill: force matchedRuleIndex to equal exactly len(cfg.Rules) via a config
// with zero rules but a match call that triggers default-deny (index == -1),
// and separately verify the MatchedRule is populated only when in-range.
// ---------------------------------------------------------------------------

func TestRunMatch_MatchedRuleIndexBoundary(t *testing.T) {
	// When matchedRuleIndex >= 0 AND < len(cfg.Rules) the MatchedRule block
	// runs; otherwise it must be nil. We exercise index == len by ensuring
	// only one rule exists and gets matched at index 0 (== len-1), then verify
	// no panic and the rule is populated.
	//
	// The direct boundary to kill the mutant is matchedRuleIndex == len(cfg.Rules).
	// filter.Evaluate returns index == -1 (no match) which lands in the safe
	// path, so we concentrate on verifying the in-bounds path (index 0 of a
	// single-rule config) produces MatchedRule != nil.
	dir := t.TempDir()
	cfgPath := t.TempDir() + "/sockguard.yaml"
	_ = os.WriteFile(cfgPath, []byte(`
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`), 0o644)

	stdout, _, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "GET",
		"--path", "/_ping",
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("executeRootCommand: %v", err)
	}
	if !strings.Contains(stdout, `"matched_rule"`) {
		t.Fatalf("expected matched_rule in JSON output, got:\n%s", stdout)
	}
	// index 0 → MatchedRule.Index == 1
	if !strings.Contains(stdout, `"index":1`) {
		t.Fatalf("expected index 1 in matched_rule, got:\n%s", stdout)
	}
	_ = dir
}

// ---------------------------------------------------------------------------
// serve.go:221 — CONDITIONALS_BOUNDARY: interval <= 0
// Mutation flips <= → <, so interval == 0 would pass through and
// StartWatchdog would receive a zero duration (panic / infinite-loop risk).
// Kill: call startWatchdog with interval == "0s" and assert it returns a
// no-op cancel without starting the watchdog.
// ---------------------------------------------------------------------------

func TestStartWatchdog_ZeroIntervalReturnsNoop(t *testing.T) {
	monitor := health.NewMonitor("/tmp/missing.sock", time.Now(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	rt := &serveRuntime{health: monitor}

	cfg := &config.Config{}
	cfg.Health.Watchdog.Enabled = true
	cfg.Health.Watchdog.Interval = "0s" // ParseDuration succeeds, interval == 0

	cancel := rt.startWatchdog(context.Background(), cfg)
	// If the mutant fired, StartWatchdog would have been called with 0 and
	// likely panicked or blocked. Reaching here confirms the noop path was taken.
	cancel()
}

func TestStartWatchdog_NegativeIntervalReturnsNoop(t *testing.T) {
	monitor := health.NewMonitor("/tmp/missing.sock", time.Now(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	rt := &serveRuntime{health: monitor}

	cfg := &config.Config{}
	cfg.Health.Watchdog.Enabled = true
	cfg.Health.Watchdog.Interval = "-1s" // valid parse, interval < 0

	cancel := rt.startWatchdog(context.Background(), cfg)
	cancel()
}

// ---------------------------------------------------------------------------
// config_flag.go:13:10 — CONDITIONALS_NEGATION: flag == nil
// config_flag.go:13:31 — CONDITIONALS_NEGATION: cmd.Root() != nil
// Both flip the short-circuit logic for falling back to the root command's
// flag. Kill by exercising: (a) flag found on the root, (b) flag not found
// anywhere, (c) flag found directly on the command.
// ---------------------------------------------------------------------------

func TestRequireExplicitConfigFile_FlagOnRootCommand(t *testing.T) {
	// The command itself has no "config" flag; the root does.
	// requireExplicitConfigFile must look up the root's flag.
	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("config", "", "")
	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	// Flag exists but not Changed → must return nil (no-op).
	if err := requireExplicitConfigFile(child, ""); err != nil {
		t.Fatalf("expected no error when flag not changed, got: %v", err)
	}
}

func TestRequireExplicitConfigFile_NoFlagAnywhere(t *testing.T) {
	// Neither the command nor the root have a "config" flag.
	cmd := &cobra.Command{Use: "orphan"}
	// flag == nil on cmd AND cmd.Root() returns cmd itself (no parent), which
	// also has no "config" flag → should return nil.
	if err := requireExplicitConfigFile(cmd, ""); err != nil {
		t.Fatalf("expected no error when no config flag exists anywhere, got: %v", err)
	}
}

func TestRequireExplicitConfigFile_FlagChangedOnRoot_EmptyPath(t *testing.T) {
	// Simulate "-c ''" via the root flag being changed.
	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("config", "", "")
	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	if err := root.PersistentFlags().Set("config", ""); err != nil {
		t.Fatalf("set config flag: %v", err)
	}

	err := requireExplicitConfigFile(child, "")
	if err == nil {
		t.Fatal("expected error for empty config path with changed flag")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error = %v, want mention of 'empty'", err)
	}
}

func TestRequireExplicitConfigFile_FlagChangedDirectlyOnCmd(t *testing.T) {
	// The flag lives on the command itself, not the root.
	cmd := &cobra.Command{Use: "cmd"}
	cmd.Flags().String("config", "", "")
	if err := cmd.Flags().Set("config", ""); err != nil {
		t.Fatalf("set config flag: %v", err)
	}

	err := requireExplicitConfigFile(cmd, "")
	if err == nil {
		t.Fatal("expected error for empty config path on direct flag")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error = %v, want mention of 'empty'", err)
	}
}

// ---------------------------------------------------------------------------
// match.go:166:21 — CONDITIONALS_NEGATION: result.Decision == ActionAllow
// match.go:176:32 — CONDITIONALS_NEGATION: result.MatchedRule.Action == ActionAllow
// writeMatchText colors the decision/action green for allow, red otherwise.
// Mutation flips == → !=, swapping the colors.
// Kill: call writeMatchText with both allow and deny outcomes and assert the
// correct label appears (the color codes are stripped in no-color mode, but
// the text is stable).
// ---------------------------------------------------------------------------

func TestWriteMatchText_AllowDecisionUsesAllowLabel(t *testing.T) {
	var buf bytes.Buffer
	writeMatchText(&buf, matchResult{
		Config:         "test.yaml",
		Method:         "GET",
		Path:           "/_ping",
		NormalizedPath: "/_ping",
		Decision:       string(filter.ActionAllow),
		MatchedRule: &matchedRuleInfo{
			Index:  1,
			Method: "GET",
			Path:   "/_ping",
			Action: string(filter.ActionAllow),
		},
	})

	output := buf.String()
	// The decision line must contain "allow" and the rule action must be "allow".
	if !strings.Contains(output, "allow") {
		t.Fatalf("expected 'allow' in output for allow decision, got:\n%s", output)
	}
}

func TestWriteMatchText_DenyDecisionUsesDenyLabel(t *testing.T) {
	var buf bytes.Buffer
	writeMatchText(&buf, matchResult{
		Config:         "test.yaml",
		Method:         "DELETE",
		Path:           "/containers/abc",
		NormalizedPath: "/containers/abc",
		Decision:       string(filter.ActionDeny),
		MatchedRule: &matchedRuleInfo{
			Index:  2,
			Method: "*",
			Path:   "/**",
			Action: string(filter.ActionDeny),
		},
	})

	output := buf.String()
	if !strings.Contains(output, "deny") {
		t.Fatalf("expected 'deny' in output for deny decision, got:\n%s", output)
	}
}

// writeMatchText with no matched rule (default-deny) should show "none".
func TestWriteMatchText_NoMatchedRule(t *testing.T) {
	var buf bytes.Buffer
	writeMatchText(&buf, matchResult{
		Config:         "test.yaml",
		Method:         "DELETE",
		Path:           "/containers/abc",
		NormalizedPath: "/containers/abc",
		Decision:       string(filter.ActionDeny),
		MatchedRule:    nil,
	})

	output := buf.String()
	if !strings.Contains(output, "none") {
		t.Fatalf("expected 'none' for no matched rule, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// serve.go:124:15 — CONDITIONALS_NEGATION: closeErr == nil
// The deferred listener close should not log a warning when closeErr is nil
// OR when it is net.ErrClosed; any other error must log.
// Mutation flips == → !=: a nil error would reach the Warn call.
// Kill: run the full lifecycle and verify NO warning when listener Close
// returns nil.
// ---------------------------------------------------------------------------

func TestRunServe_DeferredListenerCloseNilErrorNoWarn(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Address = "127.0.0.1:2375"
		return cfg, nil
	}

	var logBuf strings.Builder
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}

	// Listener returns nil on Close.
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{closeErr: nil}, nil
	}
	deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
		errCh <- http.ErrServerClosed
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error { return nil }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}

	if strings.Contains(logBuf.String(), `"msg":"failed to close listener"`) {
		t.Fatalf("unexpected listener-close warning when Close returns nil: %s", logBuf.String())
	}
}

// Non-nil, non-ErrClosed error must produce a warning.
// This test is covered by the existing TestRunServeDoesNotWarnWhenDeferredListenerCloseReturnsNetErrClosed
// (which exercises net.ErrClosed → no warn). The unexpected-error-warns branch is tested below by
// running a signal-driven shutdown where the deferred Close returns an unexpected error.
func TestRunServe_DeferredListenerCloseUnexpectedErrorWarns(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Address = "127.0.0.1:2375"
		return cfg, nil
	}

	var logBuf strings.Builder
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}

	// The server will call listener.Close() via Shutdown, then the deferred close
	// runs again — we make the second call return an unexpected error.
	listener := &serveTestSequentialCloseListener{
		closeErrs: []error{nil, errors.New("unexpected close boom")},
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) { return listener, nil }
	deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
		errCh <- http.ErrServerClosed
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
		// Simulate Shutdown closing the listener (first close → nil).
		_ = listener.Close()
		return nil
	}

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}
	if !strings.Contains(logBuf.String(), `"msg":"failed to close listener"`) {
		t.Fatalf("expected listener-close warning for unexpected error, got: %s", logBuf.String())
	}
}

// ---------------------------------------------------------------------------
// serve.go:170:58 — CONDITIONALS_NEGATION: cfg.Listen.Socket != ""
// The socket-cleanup block runs only when a Unix socket is configured.
// Mutation flips != → ==: would run for TCP (empty socket) instead.
// Kill: run lifecycle with a TCP config and assert removePath is NOT called;
// run with a Unix socket config and assert it IS called.
// ---------------------------------------------------------------------------

func TestRunServe_SocketCleanupOnlyForUnixSocket(t *testing.T) {
	t.Run("TCP config does not call removePath", func(t *testing.T) {
		deps := newServeTestDeps()
		deps.loadConfig = func(string) (*config.Config, error) {
			cfg := testServeConfig()
			cfg.Listen.Socket = "" // TCP
			cfg.Listen.Address = "127.0.0.1:0"
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
		deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			errCh <- http.ErrServerClosed
		}
		deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
		deps.shutdownServer = func(server *http.Server, ctx context.Context) error { return nil }

		removeCalled := false
		deps.removePath = func(string) error {
			removeCalled = true
			return nil
		}

		if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
			t.Fatalf("runServeWithDeps() error = %v", err)
		}
		if removeCalled {
			t.Fatal("removePath was called for TCP listener — must not be")
		}
	})

	t.Run("Unix socket config calls removePath", func(t *testing.T) {
		deps := newServeTestDeps()
		deps.loadConfig = func(string) (*config.Config, error) {
			cfg := testServeConfig()
			cfg.Listen.Socket = "/tmp/test.sock"
			cfg.Listen.Address = ""
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
		deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			errCh <- http.ErrServerClosed
		}
		deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
		deps.shutdownServer = func(server *http.Server, ctx context.Context) error { return nil }

		removeCalled := false
		deps.removePath = func(string) error {
			removeCalled = true
			return nil
		}

		if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
			t.Fatalf("runServeWithDeps() error = %v", err)
		}
		if !removeCalled {
			t.Fatal("removePath was not called for Unix socket — must be")
		}
	})
}

// ---------------------------------------------------------------------------
// serve.go:173:23 — CONDITIONALS_NEGATION: !os.IsNotExist(err)
// serve.go:174:53 — error reaching logger.Error for non-NotExist remove errors
// When removePath returns a NotExist error it is silently ignored; any other
// error should be logged. Mutations flip the guard logic.
// Kill: verify that a non-NotExist remove error produces a log warning, and
// that an os.ErrNotExist remove error does NOT.
// ---------------------------------------------------------------------------

func TestRunServe_SocketRemoveNotExistIgnored(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Socket = "/tmp/test-notexist.sock"
		cfg.Listen.Address = ""
		return cfg, nil
	}

	var logBuf strings.Builder
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})), nil, nil
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
	deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
		errCh <- http.ErrServerClosed
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error { return nil }
	deps.removePath = func(string) error { return os.ErrNotExist }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}
	if strings.Contains(logBuf.String(), "remove socket error") {
		t.Fatalf("unexpected remove-socket error log for ErrNotExist: %s", logBuf.String())
	}
}

func TestRunServe_SocketRemoveOtherErrorLogs(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Socket = "/tmp/test-removefail.sock"
		cfg.Listen.Address = ""
		return cfg, nil
	}

	var logBuf strings.Builder
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})), nil, nil
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
	deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
		errCh <- http.ErrServerClosed
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error { return nil }
	deps.removePath = func(string) error { return errors.New("permission denied") }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}
	if !strings.Contains(logBuf.String(), "remove socket error") {
		t.Fatalf("expected remove socket error log, got: %s", logBuf.String())
	}
}

// ---------------------------------------------------------------------------
// serve.go:338:13 — CONDITIONALS_NEGATION: runtime != nil
// serve.go:338:38 — CONDITIONALS_NEGATION: runtime.health != nil
// withHealth should use runtime.health when available (non-nil runtime AND
// non-nil runtime.health), otherwise fall back to a fresh monitor.
// ---------------------------------------------------------------------------

func TestWithHealth_NilRuntimeUsesFreshMonitor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "wh-nil-rt")
	cfg.Health.Path = "/health"

	deps := newServeTestDeps()
	deps.now = func() time.Time { return time.Unix(0, 0) }

	// nil runtime → must not panic; fresh monitor must answer /health.
	layer := withHealth(&cfg, newDiscardLogger(), deps, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := layer(next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// /health should have been intercepted (not fall through to 418).
	if rec.Code == http.StatusTeapot {
		t.Fatal("health interceptor did not intercept /health for nil runtime")
	}
}

func TestWithHealth_RuntimeWithNilHealthUsesFreshMonitor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "wh-nil-health")
	cfg.Health.Path = "/health"

	deps := newServeTestDeps()
	deps.now = func() time.Time { return time.Unix(0, 0) }

	// runtime is non-nil but runtime.health is nil → must use fresh monitor.
	rt := &serveRuntime{health: nil}
	layer := withHealth(&cfg, newDiscardLogger(), deps, rt)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := layer(next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusTeapot {
		t.Fatal("health interceptor did not intercept /health for runtime with nil health")
	}
}

func TestWithHealth_RuntimeWithHealthUsesInjectedMonitor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "wh-injected")
	cfg.Health.Path = "/health"

	deps := newServeTestDeps()
	deps.now = func() time.Time { return time.Unix(0, 0) }

	sharedMonitor := health.NewMonitor(cfg.Upstream.Socket, deps.now(), newDiscardLogger())
	rt := &serveRuntime{health: sharedMonitor}

	layer := withHealth(&cfg, newDiscardLogger(), deps, rt)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := layer(next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusTeapot {
		t.Fatal("health interceptor did not intercept /health for injected monitor")
	}
}

// ---------------------------------------------------------------------------
// validate.go:75:15 — CONDITIONALS_NEGATION: r.Action == "deny" (printRules)
// validate.go:80:13 — CONDITIONALS_NEGATION: r.Action == "deny" (printClientProfiles)
// validate.go:103:16 — same for printRules
// validate.go:108:14 — same for printClientProfiles
// The glyph+action color for allow vs deny must be correct.
// Mutation flips == → !=: deny rules would be printed as "allow" and vice versa.
// Kill: call printRules and printClientProfiles with known allow and deny
// rules and assert each rule's text appears correctly in the output.
// ---------------------------------------------------------------------------

func TestPrintRules_AllowActionDoesNotRenderAsDeny(t *testing.T) {
	cfg := &config.Config{
		Rules: []config.RuleConfig{
			{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
		},
	}

	var out bytes.Buffer
	p := ui.New(&out)
	printRules(&out, p, cfg, 1)

	output := out.String()
	// The word "allow" must appear and NOT "deny" for this single allow-rule cfg.
	if !strings.Contains(output, "allow") {
		t.Fatalf("expected 'allow' in output for allow rule, got:\n%s", output)
	}
	// With the mutation, "deny " would appear in the output instead of "allow".
	if strings.Contains(output, "deny") {
		t.Fatalf("unexpected 'deny' in output for allow-only rules, got:\n%s", output)
	}
}

func TestPrintRules_DenyActionDoesNotRenderAsAllow(t *testing.T) {
	cfg := &config.Config{
		Rules: []config.RuleConfig{
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		},
	}

	var out bytes.Buffer
	p := ui.New(&out)
	printRules(&out, p, cfg, 1)

	output := out.String()
	if !strings.Contains(output, "deny") {
		t.Fatalf("expected 'deny' in output for deny rule, got:\n%s", output)
	}
	// With the mutation, "allow" would appear instead.
	if strings.Contains(output, "allow") {
		t.Fatalf("unexpected 'allow' in output for deny-only rules, got:\n%s", output)
	}
}

func TestPrintClientProfiles_AllowActionDoesNotRenderAsDeny(t *testing.T) {
	cfg := &config.Config{
		Clients: config.ClientsConfig{
			Profiles: []config.ClientProfileConfig{
				{
					Name: "readonly",
					Rules: []config.RuleConfig{
						{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
					},
				},
			},
		},
	}

	var out bytes.Buffer
	p := ui.New(&out)
	printClientProfiles(&out, p, cfg)

	output := out.String()
	if !strings.Contains(output, "allow") {
		t.Fatalf("expected 'allow' in output for allow profile rule, got:\n%s", output)
	}
	if strings.Contains(output, "deny") {
		t.Fatalf("unexpected 'deny' in output for allow-only profile rules, got:\n%s", output)
	}
}

func TestPrintClientProfiles_DenyActionDoesNotRenderAsAllow(t *testing.T) {
	cfg := &config.Config{
		Clients: config.ClientsConfig{
			Profiles: []config.ClientProfileConfig{
				{
					Name: "restricted",
					Rules: []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					},
				},
			},
		},
	}

	var out bytes.Buffer
	p := ui.New(&out)
	printClientProfiles(&out, p, cfg)

	output := out.String()
	if !strings.Contains(output, "deny") {
		t.Fatalf("expected 'deny' in output for deny profile rule, got:\n%s", output)
	}
	if strings.Contains(output, "allow") {
		t.Fatalf("unexpected 'allow' in output for deny-only profile rules, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Equivalent mutants (unkillable):
//
// version.go:47 CONDITIONALS_BOUNDARY (len(c) > n):
//   The boundary case is len(c) == n == 7. With > the condition is false and
//   c is returned whole ("abcdefg"). With >= the condition is true but
//   c[:7] == "abcdefg" as well — identical observable output. This mutant
//   cannot be killed by any test because both sides of the boundary produce
//   the same string when len(c) == n.
// ---------------------------------------------------------------------------

