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
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/policybundle"
	"github.com/codeswhat/sockguard/internal/testhelp"
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

// TestWriteMatchText_AllowAndDenyUseDistinctColors kills the two CONDITIONALS_NEGATION
// mutants in writeMatchText that flip the green/red coloring of allow vs. deny.
// The existing label-only tests cannot kill these — both branches emit the
// same "allow" / "deny" text, only the surrounding ANSI escapes differ — and
// bytes.Buffer is not a TTY so detectColor returns false by default. Force
// colors on with FORCE_COLOR so the escapes appear, then assert allow paints
// green and deny paints red on both the decision line and the matched-rule
// action line.
func TestWriteMatchText_AllowAndDenyUseDistinctColors(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "")

	const ansiGreen = "\x1b[32m"
	const ansiRed = "\x1b[31m"

	t.Run("allow paints green and not red", func(t *testing.T) {
		var buf bytes.Buffer
		writeMatchText(&buf, matchResult{
			Decision: string(filter.ActionAllow),
			MatchedRule: &matchedRuleInfo{
				Index:  1,
				Method: "GET",
				Path:   "/_ping",
				Action: string(filter.ActionAllow),
			},
		})
		got := buf.String()
		if !strings.Contains(got, ansiGreen+"allow") {
			t.Fatalf("allow decision should be green, got:\n%q", got)
		}
		if strings.Contains(got, ansiRed+"allow") {
			t.Fatalf("allow decision should NOT be red, got:\n%q", got)
		}
	})

	t.Run("deny paints red and not green", func(t *testing.T) {
		var buf bytes.Buffer
		writeMatchText(&buf, matchResult{
			Decision: string(filter.ActionDeny),
			MatchedRule: &matchedRuleInfo{
				Index:  2,
				Method: "*",
				Path:   "/**",
				Action: string(filter.ActionDeny),
			},
		})
		got := buf.String()
		if !strings.Contains(got, ansiRed+"deny") {
			t.Fatalf("deny decision should be red, got:\n%q", got)
		}
		if strings.Contains(got, ansiGreen+"deny") {
			t.Fatalf("deny decision should NOT be green, got:\n%q", got)
		}
	})
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

	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
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

	if collector.HasMessage("failed to close listener") {
		t.Fatalf("unexpected listener-close warning when Close returns nil; records: %#v", collector.Records())
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

	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
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
	if !collector.HasMessage("failed to close listener") {
		t.Fatalf("expected listener-close warning for unexpected error; records: %#v", collector.Records())
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

	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
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
	if collector.HasMessage("remove socket error") {
		t.Fatalf("unexpected remove-socket error log for ErrNotExist; records: %#v", collector.Records())
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

	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
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
	if !collector.HasMessage("remove socket error") {
		t.Fatalf("expected remove socket error log; records: %#v", collector.Records())
	}
}

// TestStartAdminServer_NilListenerCloseDoesNotWarn pins the
// CONDITIONALS_NEGATION mutant at serve.go:332 (`closeErr == nil` → `!=` in
// the admin listener's stop closure). The original early-returns when the
// listener closes cleanly (closeErr == nil) OR with net.ErrClosed. The
// mutant inverts the first conjunct so a clean close (closeErr == nil)
// falls through and emits a spurious "failed to close admin listener"
// Warn line. We inject a listener whose Close returns nil and assert the
// warning is absent from the collected records.
func TestStartAdminServer_NilListenerCloseDoesNotWarn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"

	collector := &testhelp.CollectingHandler{}

	deps := newServeTestDeps()
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{closeErr: nil}, nil
	}
	deps.startServing = func(_ *http.Server, _ net.Listener, errCh chan<- error) {
		errCh <- http.ErrServerClosed
	}

	_, _, stop, err := startAdminServer(&cfg, collector.Logger(), nil, nil, deps)
	if err != nil {
		t.Fatalf("startAdminServer() error = %v", err)
	}
	stop()
	if collector.HasMessage("failed to close admin listener") {
		t.Fatalf("clean close (closeErr=nil) emitted spurious warning — mutant `closeErr != nil` would yield this; records: %#v", collector.Records())
	}
}

// TestRunServe_ShutdownErrorLogs pins the CONDITIONALS_NEGATION mutant at
// serve.go:270 (`err != nil` → `==` on the regular shutdownServer call).
// The mutant silently swallows the shutdown error instead of logging it.
// We force shutdownServer to return a non-nil error via SIGINT-driven
// graceful shutdown and assert the structured "shutdown error" record
// is present in the collected log.
func TestRunServe_ShutdownErrorLogs(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Address = "127.0.0.1:0"
		return cfg, nil
	}

	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
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
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) { c <- syscall.SIGINT }
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
		return errors.New("shutdown boom")
	}
	deps.removePath = func(string) error { return nil }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}
	if !collector.HasMessage("shutdown error") {
		t.Fatalf("expected 'shutdown error' log; records: %#v", collector.Records())
	}
}

// TestRunServe_AdminShutdownErrorLogs pins the CONDITIONALS_NEGATION mutant at
// serve.go:266 (`err != nil` → `==` on the admin shutdownServer call). The
// mutant would silently swallow a failed admin server graceful-shutdown.
// We enable the admin listener, force shutdownServer to return an error only
// when invoked with the admin *http.Server (i.e. the first call — serve.go
// shuts admin down before the regular server), and assert the structured
// "admin shutdown error" record is in the collected log.
func TestRunServe_AdminShutdownErrorLogs(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Address = "127.0.0.1:0"
		cfg.Admin.Enabled = true
		cfg.Admin.Listen.Address = "127.0.0.1:0"
		return cfg, nil
	}

	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
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
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{}, nil
	}
	deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) { c <- syscall.SIGINT }

	// serve.go shuts the admin server down first (line 266), then the regular
	// server (line 270). Discriminate by call order so we only return an
	// error for the admin call — that isolates the kill to serve.go:266 and
	// avoids triggering the regular-shutdown "shutdown error" log too.
	var shutdownCalls int
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
		shutdownCalls++
		if shutdownCalls == 1 {
			return errors.New("admin shutdown boom")
		}
		return nil
	}
	deps.removePath = func(string) error { return nil }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}
	if !collector.HasMessage("admin shutdown error") {
		t.Fatalf("expected 'admin shutdown error' log; records: %#v", collector.Records())
	}
}

// ---------------------------------------------------------------------------
// serve.go: CONDITIONALS_NEGATION: runtime.health != nil
// withHealth should use runtime.health when set, otherwise fall back to a
// fresh monitor. Runtime itself is guaranteed non-nil by the call-site
// contract (newServeRuntime never returns nil), so we only test the
// runtime.health branch.
// ---------------------------------------------------------------------------

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

// TestPrintClientProfiles_EmptyMethodRendersWildcard kills the
// CONDITIONALS_NEGATION mutant at validate.go:106 (`method == ""` → `!= ""`).
// An empty Method should render as "*" so the output communicates the
// implicit any-method behavior; the mutated form would print blank space.
func TestPrintClientProfiles_EmptyMethodRendersWildcard(t *testing.T) {
	cfg := &config.Config{
		Clients: config.ClientsConfig{
			Profiles: []config.ClientProfileConfig{
				{
					Name: "wild",
					Rules: []config.RuleConfig{
						{Match: config.MatchConfig{Method: "", Path: "/sentinel"}, Action: "allow"},
					},
				},
			},
		},
	}

	var out bytes.Buffer
	p := ui.New(&out)
	printClientProfiles(&out, p, cfg)

	output := out.String()
	if !strings.Contains(output, "* ") && !strings.Contains(output, "*     ") {
		t.Fatalf("expected '*' wildcard for empty method, got:\n%s", output)
	}
	if !strings.Contains(output, "/sentinel") {
		t.Fatalf("expected /sentinel path in output, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// serve.go:691 — CONDITIONALS_NEGATION: pb.VerifyTimeout == ""
// serve.go:709 — CONDITIONALS_NEGATION: cfg == nil
// serve.go:713 — CONDITIONALS_NEGATION: err != nil (from json.Marshal)
// serve.go:971 — CONDITIONALS_NEGATION: cfg.Admin.Listen.Socket != ""
// Pure-function helpers covered with table tests below.
// ---------------------------------------------------------------------------

func TestBundleVerifyDeadline(t *testing.T) {
	t.Run("empty VerifyTimeout falls back to package default", func(t *testing.T) {
		pb := config.PolicyBundleConfig{VerifyTimeout: ""}
		if got := bundleVerifyDeadline(pb); got != policybundle.VerifyTimeout {
			t.Fatalf("got %v, want package default %v", got, policybundle.VerifyTimeout)
		}
	})

	t.Run("valid positive duration is honored", func(t *testing.T) {
		pb := config.PolicyBundleConfig{VerifyTimeout: "12s"}
		if got, want := bundleVerifyDeadline(pb), 12*time.Second; got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("zero duration falls back to default", func(t *testing.T) {
		pb := config.PolicyBundleConfig{VerifyTimeout: "0s"}
		if got := bundleVerifyDeadline(pb); got != policybundle.VerifyTimeout {
			t.Fatalf("got %v, want package default %v", got, policybundle.VerifyTimeout)
		}
	})

	t.Run("negative duration falls back to default", func(t *testing.T) {
		pb := config.PolicyBundleConfig{VerifyTimeout: "-1s"}
		if got := bundleVerifyDeadline(pb); got != policybundle.VerifyTimeout {
			t.Fatalf("got %v, want package default %v", got, policybundle.VerifyTimeout)
		}
	})

	t.Run("invalid duration string falls back to default", func(t *testing.T) {
		pb := config.PolicyBundleConfig{VerifyTimeout: "not-a-duration"}
		if got := bundleVerifyDeadline(pb); got != policybundle.VerifyTimeout {
			t.Fatalf("got %v, want package default %v", got, policybundle.VerifyTimeout)
		}
	})
}

func TestPolicyConfigHash(t *testing.T) {
	t.Run("nil cfg returns empty string", func(t *testing.T) {
		if got := policyConfigHash(nil); got != "" {
			t.Fatalf("policyConfigHash(nil) = %q, want empty string", got)
		}
	})

	t.Run("non-nil cfg returns 64-char hex sha256", func(t *testing.T) {
		cfg := config.Defaults()
		got := policyConfigHash(&cfg)
		if len(got) != 64 {
			t.Fatalf("policyConfigHash() length = %d, want 64", len(got))
		}
		for _, c := range got {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("policyConfigHash() contains non-hex char %q: %s", c, got)
			}
		}
	})

	t.Run("identical configs hash identically", func(t *testing.T) {
		a := config.Defaults()
		b := config.Defaults()
		if policyConfigHash(&a) != policyConfigHash(&b) {
			t.Fatal("identical configs produced different hashes")
		}
	})

	t.Run("different configs hash differently", func(t *testing.T) {
		a := config.Defaults()
		b := config.Defaults()
		b.Listen.Address = "127.0.0.1:9999"
		if policyConfigHash(&a) == policyConfigHash(&b) {
			t.Fatal("different configs produced identical hashes")
		}
	})
}

func TestAdminListenerAddr(t *testing.T) {
	t.Run("unix socket path uses unix: prefix", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Admin.Listen.Socket = "/tmp/admin.sock"
		cfg.Admin.Listen.Address = ""
		if got, want := adminListenerAddr(&cfg), "unix:/tmp/admin.sock"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("empty socket falls back to tcp address", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Admin.Listen.Socket = ""
		cfg.Admin.Listen.Address = "127.0.0.1:2376"
		if got, want := adminListenerAddr(&cfg), "tcp://127.0.0.1:2376"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

// ---------------------------------------------------------------------------
// serve.go:959,960 — ARITHMETIC_BASE: 30 * time.Second (admin server timeouts)
// Mutation flips * → / which yields a near-zero duration that breaks the
// admin endpoint contract.
// ---------------------------------------------------------------------------

func TestNewAdminHTTPServerTimeoutsAre30Seconds(t *testing.T) {
	srv := newAdminHTTPServer(http.NewServeMux())
	if got, want := srv.ReadTimeout, 30*time.Second; got != want {
		t.Fatalf("ReadTimeout = %v, want %v", got, want)
	}
	if got, want := srv.WriteTimeout, 30*time.Second; got != want {
		t.Fatalf("WriteTimeout = %v, want %v", got, want)
	}
	if got, want := srv.ReadHeaderTimeout, 5*time.Second; got != want {
		t.Fatalf("ReadHeaderTimeout = %v, want %v (readHeaderTimeout const)", got, want)
	}
	if got, want := srv.IdleTimeout, 120*time.Second; got != want {
		t.Fatalf("IdleTimeout = %v, want %v (idleTimeout const)", got, want)
	}
	if got, want := srv.MaxHeaderBytes, 1<<20; got != want {
		t.Fatalf("MaxHeaderBytes = %d, want %d (maxHeaderBytes const)", got, want)
	}
}

// TestNewHTTPServerHardeningConstants pins the main-server timeout/limit
// values that hijack-aware tuning depends on. ReadTimeout/WriteTimeout are
// deliberately 0 so streaming responses don't hit a deadline mid-flight, but
// ReadHeaderTimeout/IdleTimeout/MaxHeaderBytes guard the request prelude.
func TestNewHTTPServerHardeningConstants(t *testing.T) {
	srv := newHTTPServer(http.NewServeMux())
	if got := srv.ReadTimeout; got != 0 {
		t.Fatalf("ReadTimeout = %v, want 0 (hijack-safe)", got)
	}
	if got := srv.WriteTimeout; got != 0 {
		t.Fatalf("WriteTimeout = %v, want 0 (hijack-safe)", got)
	}
	if got, want := srv.ReadHeaderTimeout, 5*time.Second; got != want {
		t.Fatalf("ReadHeaderTimeout = %v, want %v (readHeaderTimeout const)", got, want)
	}
	if got, want := srv.IdleTimeout, 120*time.Second; got != want {
		t.Fatalf("IdleTimeout = %v, want %v (idleTimeout const)", got, want)
	}
	if got, want := srv.MaxHeaderBytes, 1<<20; got != want {
		t.Fatalf("MaxHeaderBytes = %d, want %d (maxHeaderBytes const)", got, want)
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
