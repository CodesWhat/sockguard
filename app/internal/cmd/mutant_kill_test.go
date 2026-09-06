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
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/health"
	"github.com/codeswhat/sockguard/app/internal/policybundle"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
	"github.com/codeswhat/sockguard/app/internal/ui"
	"github.com/codeswhat/sockguard/app/internal/upstream"
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
	//
	// match.go:129:47 CONDITIONALS_BOUNDARY (matchedRuleIndex < len(cfg.Rules)):
	// this mutant (< vs <=) is equivalent, not merely untested. filter.Evaluate
	// delegates to evaluateNormalized (rules.go:336-348), which returns
	// rule.Index either as -1 (no match) or as an index into the compiled
	// rule slice, i.e. strictly in the range 0..len(compiled)-1. Since compiled
	// is built one-to-one from cfg.Rules, matchedRuleIndex can never equal
	// len(cfg.Rules) at match.go:129. The < vs <= distinction is therefore
	// unreachable, the same category as the already-documented version.go:47
	// case above.
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

// TestRequireExplicitConfigFile_FlagOnRootLocalChanged actually exercises the
// "look up the flag on the root" fallback. Earlier tests used PersistentFlags
// which cobra propagates via persistentFlag inheritance — so cmd.Flag("config")
// returns non-nil and the if-branch is dead code. By installing the flag as a
// LOCAL flag on root (not persistent), child.Flag("config") returns nil and
// the fallback path is the only way to surface the Changed flag. This is what
// kills config_flag.go:13:10 (`flag == nil` → `!=`) and 13:31
// (`cmd.Root() != nil` → `==`).
func TestRequireExplicitConfigFile_FlagOnRootLocalChanged(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	root.Flags().String("config", "", "") // local, NOT persistent
	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	if err := root.Flags().Set("config", ""); err != nil {
		t.Fatalf("set config flag: %v", err)
	}

	err := requireExplicitConfigFile(child, "")
	if err == nil {
		t.Fatal("expected error for empty config path when fallback to root's local flag is required")
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

	if err := runServeWithDeps(newServeCommand(), nil, deps); err == nil || !strings.Contains(err.Error(), "server error") {
		t.Fatalf("runServeWithDeps() error = %v, want premature Serve error", err)
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

	if err := runServeWithDeps(newServeCommand(), nil, deps); err == nil || !strings.Contains(err.Error(), "server error") {
		t.Fatalf("runServeWithDeps() error = %v, want premature Serve error", err)
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
		deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(1), nil }

		removeCalled := false
		deps.removePath = func(string) error {
			removeCalled = true
			return nil
		}

		if err := runServeWithDeps(newServeCommand(), nil, deps); err == nil || !strings.Contains(err.Error(), "server error") {
			t.Fatalf("runServeWithDeps() error = %v, want premature Serve error", err)
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
		deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(1), nil }

		removeCalled := false
		deps.removePath = func(string) error {
			removeCalled = true
			return nil
		}

		if err := runServeWithDeps(newServeCommand(), nil, deps); err == nil || !strings.Contains(err.Error(), "server error") {
			t.Fatalf("runServeWithDeps() error = %v, want premature Serve error", err)
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
	deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(1), nil }
	deps.removePath = func(string) error { return os.ErrNotExist }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err == nil || !strings.Contains(err.Error(), "server error") {
		t.Fatalf("runServeWithDeps() error = %v, want premature Serve error", err)
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
	deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(1), nil }
	deps.removePath = func(string) error { return errors.New("permission denied") }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err == nil || !strings.Contains(err.Error(), "server error") {
		t.Fatalf("runServeWithDeps() error = %v, want premature Serve error", err)
	}
	if !collector.HasMessage("remove socket error") {
		t.Fatalf("expected remove socket error log; records: %#v", collector.Records())
	}
}

// The old dedicated admin listener's stop-closure mutant coverage
// (`closeErr == nil` → `!=`) was folded into the unified bind-barrier close
// loop when the admin listener moved inside the two-phase bind barrier
// (#149) — see TestRunServe_DeferredListenerCloseNilErrorNoWarn above,
// which exercises the same shared loop that now closes every member,
// admin included, in reverse bind order.

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

// TestRunServe_AdminShutdownErrorLogs pins the CONDITIONALS_NEGATION mutant
// on the admin shutdownServer call's `err != nil` check in shutdownServers.
// The mutant would silently swallow a failed admin server graceful-shutdown.
// We enable the admin listener and force every shutdownServer call to
// return an error. Main-listener and admin shutdown now run concurrently
// (#149 — shutdownServers no longer shuts admin down before the regular
// server), so the mock can no longer discriminate by call order; instead we
// assert both the "admin shutdown error" and "shutdown error" records are
// present, which still fails if either conditional's mutant swallows its
// error.
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

	// Main and admin shutdown run concurrently, so every call gets the same
	// error rather than discriminating by call order.
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
		return errors.New("shutdown boom")
	}
	deps.removePath = func(string) error { return nil }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}
	if !collector.HasMessage("admin shutdown error") {
		t.Fatalf("expected 'admin shutdown error' log; records: %#v", collector.Records())
	}
	if !collector.HasMessage("shutdown error") {
		t.Fatalf("expected 'shutdown error' log; records: %#v", collector.Records())
	}
}

// TestRunServe_AdminSocketRemovedWhenSocketPathSet pins the
// CONDITIONALS_NEGATION mutant at serve.go:278 (`Socket != ""` → `==`) in
// the admin-socket cleanup branch. With the mutation, the admin socket
// path is only cleaned up when the socket string is empty (calling
// removePath("")), and a real configured path is skipped — leaking the
// admin socket file. We assert removePath is invoked with the admin
// socket path exactly when that path is non-empty.
func TestRunServe_AdminSocketRemovedWhenSocketPathSet(t *testing.T) {
	const adminSock = "/tmp/sockguard-admin-shutdown-test.sock"

	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Address = "127.0.0.1:0"
		cfg.Admin.Enabled = true
		cfg.Admin.Listen.Address = ""
		cfg.Admin.Listen.Socket = adminSock
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
	deps.startServing = func(_ *http.Server, _ net.Listener, errCh chan<- error) {}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) { c <- syscall.SIGINT }
	deps.shutdownServer = func(_ *http.Server, _ context.Context) error { return nil }
	deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(1), nil }

	var removed []string
	deps.removePath = func(p string) error {
		removed = append(removed, p)
		return nil
	}

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}

	foundAdmin := false
	for _, p := range removed {
		if p == adminSock {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Fatalf("expected removePath(%q) call (admin socket cleanup); calls: %#v", adminSock, removed)
	}

	// Also pin serve.go:279 CONDITIONALS_NEGATION (`err != nil` → `==`): the
	// mutant logs "remove admin socket error" whenever removePath returns nil,
	// even though that's the happy path. removePath above returns nil for both
	// the listen socket and the admin socket, so no such log line should fire.
	if collector.HasMessage("remove admin socket error") {
		t.Fatalf("removePath returned nil but admin-socket error log fired (mutant `err == nil` would do this); records: %#v", collector.Records())
	}
}

// TestDefaultBuildBundleVerifier_PropagatesBuildConfigError pins the
// CONDITIONALS_NEGATION mutant at serve_deps.go:104 (`err != nil` → `==` on
// the policybundle.BuildConfig return). With the mutation, BuildConfig's
// error is silently swallowed and the function falls through to
// policybundle.New with whatever zero Config came back — masking a
// misconfiguration the operator must see at startup.
// Enabled=true with no allowed_signing_keys and no allowed_keyless triggers
// BuildConfig's "no entries" error.
func TestDefaultBuildBundleVerifier_PropagatesBuildConfigError(t *testing.T) {
	pb := config.PolicyBundleConfig{Enabled: true}

	verifier, err := defaultBuildBundleVerifier(pb)
	if err == nil {
		t.Fatalf("expected error for enabled=true with no signing keys; got verifier=%v err=nil", verifier)
	}
	if !strings.Contains(err.Error(), "no allowed_signing_keys") {
		t.Fatalf("error = %q, want substring %q", err.Error(), "no allowed_signing_keys")
	}
}

// TestRunServe_ReloadEnabledStartsWatcherWhenCfgFileSet pins the
// CONDITIONALS_NEGATION mutant at serve.go:216 (`cfgFile != ""` → `==`).
// With the mutation the reload branch fires only when cfgFile is empty —
// where startReloader returns "cfgFile is required" — so a real configured
// reload setup silently fails to start the watcher. We point cfgFile at a
// real temp file with Reload.Enabled=true and assert the reload package's
// "config hot-reload enabled" Info line fires (it is emitted from inside
// rl.Run after the fsnotify watch is attached).
func TestRunServe_ReloadEnabledStartsWatcherWhenCfgFileSet(t *testing.T) {
	tmpDir := t.TempDir()
	tmpCfg := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(tmpCfg, []byte("listen:\n  socket: /tmp/x.sock\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	originalCfgFile := cfgFile
	cfgFile = tmpCfg
	t.Cleanup(func() { cfgFile = originalCfgFile })

	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Address = "127.0.0.1:0"
		cfg.Reload.Enabled = true
		// Non-default Debounce + PollInterval so we can assert they flow
		// through to the reload package. The mutants at serve.go:218, 219,
		// and 224 would all collapse one of these to the DefaultDebounce
		// (250ms) / zero PollInterval default.
		cfg.Reload.Debounce = "10ms"
		cfg.Reload.PollInterval = "200ms"
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
	deps.startServing = func(_ *http.Server, _ net.Listener, errCh chan<- error) {}
	// Wait until the reloader has logged "config hot-reload enabled" before
	// sending SIGINT — otherwise shutdown can race the watcher startup and
	// the log never appears.
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
		go func() {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if collector.HasMessage("config hot-reload enabled") {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			c <- syscall.SIGINT
		}()
	}
	deps.shutdownServer = func(_ *http.Server, _ context.Context) error { return nil }
	deps.removePath = func(string) error { return nil }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}
	enabledRecs := collector.FindMessage("config hot-reload enabled")
	if len(enabledRecs) == 0 {
		t.Fatalf("expected 'config hot-reload enabled' log when Reload.Enabled and cfgFile set; records: %#v", collector.Records())
	}
	// Pin serve.go:218 (`Debounce != ""` → `==`) and 219 (`err == nil` → `!=`):
	// both would collapse our configured "10ms" debounce back to the
	// DefaultDebounce (250ms). The reload-package log carries the value as
	// a duration string.
	if got := enabledRecs[0].Attrs["debounce"]; got != "10ms" {
		t.Fatalf("debounce attr = %v, want \"10ms\" (mutant at serve.go:218 or :219 collapses to DefaultDebounce)", got)
	}
	// Pin serve.go:224 (`PollInterval != ""` → `==`): mutant collapses to
	// the zero default (formatted "0s").
	if got := enabledRecs[0].Attrs["poll_interval"]; got != "200ms" {
		t.Fatalf("poll_interval attr = %v, want \"200ms\" (mutant at serve.go:224 collapses to 0s)", got)
	}
	// Pin serve.go:231 (`startErr != nil` → `==`): when startReloader
	// succeeds (startErr == nil), the mutant takes the "disabled" branch and
	// emits the error log AND replaces stopReload with a noop. The "enabled"
	// log still fires from the goroutine, so existence alone isn't enough —
	// we must assert the "disabled" log is ABSENT.
	if collector.HasMessage("config hot-reload disabled: failed to start watcher") {
		t.Fatalf("'config hot-reload disabled' fired despite startReloader success (mutant `startErr == nil`); records: %#v", collector.Records())
	}
}

// withHealth must intercept /health via the runtime monitor. The function's
// precondition is that newServeRuntime has allocated runtime.health, so the
// "nil-fallback" branch was removed; this test pins the only remaining path.

func TestWithHealth_UsesRuntimeMonitor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "wh-runtime")
	cfg.Health.Path = "/health"

	deps := newServeTestDeps()
	deps.now = func() time.Time { return time.Unix(0, 0) }

	sharedMonitor := health.NewMonitor(cfg.Upstream.Socket, deps.now(), newDiscardLogger())
	rt := &serveRuntime{health: sharedMonitor}

	layer := withHealth(&cfg, rt)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := layer(next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusTeapot {
		t.Fatal("health interceptor did not intercept /health")
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
// serve.go:296 — CONDITIONALS_NEGATION: `if adminMember != nil` guarding the
// banner's "admin <addr>" line. Mutation flips != to ==, so the admin line
// would render only when there is NO admin listener (never, in practice) and
// never render when one is actually configured.
// Kill: run a full serve startup with and without a dedicated admin
// listener and assert the rendered banner contains the admin line exactly
// when adminMember is non-nil.
// ---------------------------------------------------------------------------

// unsetEnvForTest clears an environment variable for the duration of the
// test, restoring its original value (set or unset) on cleanup. t.Setenv is
// called first so testing's cleanup captures/restores the original value;
// os.Unsetenv then actually clears it for the test body. t.Setenv alone
// would leave the variable set to "" — which upstream_tls_config_test.go
// documents as an explicit-but-invalid DOCKER_HOST, not an unset one — so
// the Unsetenv step is required, not cosmetic.
func unsetEnvForTest(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "") // registers automatic restore of the original value on test cleanup
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unsetenv %s: %v", name, err)
	}
}

func runServeAndCaptureBanner(t *testing.T, adminEnabled bool) string {
	t.Helper()
	unsetEnvForTest(t, "DOCKER_HOST")

	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Admin.Enabled = adminEnabled
		if adminEnabled {
			cfg.Admin.Listen.Address = "127.0.0.1:0"
		}
		return cfg, nil
	}
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{}, nil
	}
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{}, nil
	}

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	deps.startServing = func(*http.Server, net.Listener, chan<- error) {
		<-block
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
		go func() { c <- syscall.SIGTERM }()
	}
	deps.shutdownServer = func(*http.Server, context.Context) error { return nil }
	deps.removePath = func(string) error { return nil }

	cmd := newServeCommand()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := runServeWithDeps(cmd, nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v, want nil", err)
	}
	return stderr.String()
}

func TestRunServe_BannerAdminLineOnlyWhenAdminMemberPresent(t *testing.T) {
	t.Run("no admin listener", func(t *testing.T) {
		out := runServeAndCaptureBanner(t, false)
		if strings.Contains(out, "admin ") {
			t.Fatalf("banner contains an admin line without a configured admin listener:\n%s", out)
		}
	})

	t.Run("with admin listener", func(t *testing.T) {
		out := runServeAndCaptureBanner(t, true)
		if !strings.Contains(out, "admin ") {
			t.Fatalf("banner missing admin line with a configured admin listener:\n%s", out)
		}
	})
}

// ---------------------------------------------------------------------------
// serve.go:421 — CONDITIONALS_NEGATION: `if shutdownCtx.Err() != nil` inside
// shutdownServers' admin-shutdown goroutine. Mutation flips != to ==, so the
// force-close of the admin server/listener would fire only when the shutdown
// deadline has NOT been exceeded — i.e. never on the real timeout path.
// Kill: force deps.shutdownGracePeriod down to ~0 and have deps.shutdownServer
// sleep past it before returning an error, so shutdownCtx is guaranteed to
// have expired by the time the branch is evaluated. Assert the admin
// listener's Close() was invoked by the force-close branch, in addition to
// the unconditional cleanup Close() every listener gets on the way out
// (so the count must be 2, not 1).
// ---------------------------------------------------------------------------

func TestRunServe_AdminShutdownTimeoutForcesListenerClose(t *testing.T) {
	unsetEnvForTest(t, "DOCKER_HOST")

	deps := newServeTestDeps()

	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Admin.Enabled = true
		cfg.Admin.Listen.Address = "127.0.0.1:0"
		// server.shutdown_grace drives deps.shutdownGracePeriod once
		// runServeWithDeps validates cfg (see effectiveShutdownGracePeriod);
		// setting it here, not on deps directly, is what now reaches the
		// real shutdownCtx deadline this test depends on.
		cfg.Server.ShutdownGrace = "1ms"
		return cfg, nil
	}
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{}, nil
	}
	adminListener := &serveTestListener{}
	deps.createAdminListener = func(*config.Config) (net.Listener, error) { return adminListener, nil }

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	deps.startServing = func(*http.Server, net.Listener, chan<- error) {
		<-block
	}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
		go func() { c <- syscall.SIGTERM }()
	}
	deps.shutdownServer = func(_ *http.Server, ctx context.Context) error {
		// Synchronize with the real shutdownCtx deadline (server.shutdown_grace,
		// set above to 1ms) instead of sleeping past it on a wall-clock
		// margin: wait for ctx.Done() so this returns exactly once the
		// deadline has actually expired, which is what the force-close
		// branch under test depends on. The time.After is only a safety net
		// so the test cannot hang forever if ctx is never canceled.
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			// deps.shutdownServer runs in a background goroutine (see
			// shutdownServers in serve.go), where t.Fatal is unsafe to call
			// (it must run on the test's own goroutine); t.Errorf is safe
			// from any goroutine and still fails the test.
			t.Errorf("shutdownServer: shutdownCtx was never canceled")
		}
		return errors.New("shutdown boom")
	}
	deps.removePath = func(string) error { return nil }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v, want nil", err)
	}

	if adminListener.closeCalls < 2 {
		t.Fatalf("admin listener Close() calls = %d, want >= 2 (force-close branch + deferred cleanup)", adminListener.closeCalls)
	}
}

// ---------------------------------------------------------------------------
// serve.go:592 — CONDITIONALS_NEGATION (x2): `if r == nil || r.resolver == nil`
// guarding serveRuntime.startResolver. Mutating either == to != makes the
// guard true whenever r is non-nil (the common case), so Resolver.Start is
// never actually invoked in production.
// Kill: build a real *upstream.Resolver with an OnChange hook and confirm
// startResolver actually starts it (OnChange fires) when both r and
// r.resolver are non-nil; also confirm the nil-guard paths don't panic.
// ---------------------------------------------------------------------------

func TestStartResolver_NilGuardsAndRealStart(t *testing.T) {
	t.Run("nil runtime is a noop", func(t *testing.T) {
		var rt *serveRuntime
		stop := rt.startResolver(context.Background())
		stop()
	})

	t.Run("nil resolver is a noop", func(t *testing.T) {
		rt := &serveRuntime{}
		stop := rt.startResolver(context.Background())
		stop()
	})

	t.Run("real resolver is actually started", func(t *testing.T) {
		changed := make(chan struct{}, 1)
		resolver, err := upstream.New([]upstream.Endpoint{
			{Name: "e", Network: "unix", Address: "/nonexistent/sockguard-start-resolver-test.sock"},
		}, upstream.Options{
			Interval: -1, // single startup probe only, loop exits after
			OnChange: func(upstream.Endpoint, bool) {
				select {
				case changed <- struct{}{}:
				default:
				}
			},
		})
		if err != nil {
			t.Fatalf("upstream.New() error = %v", err)
		}
		rt := &serveRuntime{resolver: resolver}
		stop := rt.startResolver(context.Background())
		defer stop()

		select {
		case <-changed:
		case <-time.After(2 * time.Second):
			t.Fatal("resolver.Start() was never invoked (OnChange never fired)")
		}
	})
}

// ---------------------------------------------------------------------------
// serve.go:621 — CONDITIONALS_NEGATION (x2): `if r == nil || r.readiness == nil`
// guarding serveRuntime.startReadiness. Same failure mode as startResolver
// above: mutating either == to != makes the guard true whenever r is
// non-nil, so the readiness watchdog is never actually started.
// Kill: build a real *health.Monitor and confirm StartWatchdog actually ran
// by polling Monitor.State() for hasState becoming true.
// ---------------------------------------------------------------------------

func TestStartReadiness_NilGuardsAndRealStart(t *testing.T) {
	t.Run("nil runtime is a noop", func(t *testing.T) {
		var rt *serveRuntime
		cfg := &config.Config{}
		cfg.Health.Readiness.Enabled = true
		cfg.Health.Readiness.Interval = "1ms"
		stop := rt.startReadiness(context.Background(), cfg)
		stop()
	})

	t.Run("nil readiness monitor is a noop", func(t *testing.T) {
		rt := &serveRuntime{}
		cfg := &config.Config{}
		cfg.Health.Readiness.Enabled = true
		cfg.Health.Readiness.Interval = "1ms"
		stop := rt.startReadiness(context.Background(), cfg)
		stop()
	})

	t.Run("real monitor is actually started", func(t *testing.T) {
		monitor := health.NewMonitor("/nonexistent/sockguard-start-readiness-test.sock", time.Now(), newDiscardLogger())
		rt := &serveRuntime{readiness: monitor}
		cfg := &config.Config{}
		cfg.Health.Readiness.Enabled = true
		cfg.Health.Readiness.Interval = "1ms"

		stop := rt.startReadiness(context.Background(), cfg)
		defer stop()

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := monitor.State(); ok {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("readiness monitor never recorded a state (StartWatchdog was never invoked)")
	})
}

// ---------------------------------------------------------------------------
// serve.go:910 — CONDITIONALS_NEGATION + CONDITIONALS_BOUNDARY on
// `if err != nil || d <= 0` inside effectiveHijackInactivityTimeout.
// Unlike effectiveUpstreamRequestTimeout (serve.go:710, an equivalent
// boundary — see below), this function's disabled/degraded value (10m) is
// NOT the same as returning d==0, so the boundary is genuinely observable
// here: d==0 must degrade to the 10m default, and a valid positive duration
// must be returned verbatim (killing both the err!=nil negation and the
// d<=0 negation/boundary at once).
// ---------------------------------------------------------------------------

func TestEffectiveHijackInactivityTimeout(t *testing.T) {
	const wantDefault = 10 * time.Minute
	cases := []struct {
		name    string
		timeout string
		want    time.Duration
	}{
		{name: "invalid_degrades_to_default", timeout: "garbage", want: wantDefault},
		{name: "zero_degrades_to_default", timeout: "0s", want: wantDefault},
		{name: "negative_degrades_to_default", timeout: "-1s", want: wantDefault},
		{name: "valid_positive_returned_verbatim", timeout: "5m", want: 5 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Upstream.HijackInactivityTimeout = tc.timeout
			if got := effectiveHijackInactivityTimeout(cfg); got != tc.want {
				t.Errorf("effectiveHijackInactivityTimeout(%q) = %v, want %v", tc.timeout, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// serve.go:1355 — CONDITIONALS_NEGATION: `if parent == nil { parent =
// context.Background() }` inside verifyPolicyBundleAtStartup. Mutation flips
// == to !=, so a nil parent is left as-is and context.WithTimeout(nil, ...)
// panics.
// Kill: run the full success path with an explicit nil parent context and
// assert no panic.
// ---------------------------------------------------------------------------

func TestVerifyPolicyBundleAtStartup_NilParentDoesNotPanic(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()
	deps.readConfigBytes = func(string) ([]byte, error) {
		return []byte("policy_bundle:\n  signature_path: /tmp/sig.bundle.json\nrules: []\n"), nil
	}
	deps.loadBundleEntity = func(string) (verify.SignedEntity, error) { return &stubEntity{}, nil }
	want := policybundle.VerifyResult{Signer: "keyed:1234"}
	verifier := &stubBundleVerifier{res: want}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("verifyPolicyBundleAtStartup panicked with a nil parent context: %v", r)
		}
	}()

	//nolint:staticcheck // intentionally passing nil to exercise the nil-parent guard
	got, _, err := verifyPolicyBundleAtStartup(nil, cfg, "/tmp/cfg.yaml", deps, verifier, newDiscardLogger())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got == nil || got.Signer != want.Signer {
		t.Fatalf("got = %+v, want Signer %q", got, want.Signer)
	}
}

// ---------------------------------------------------------------------------
// serve.go:1402 — CONDITIONALS_NEGATION (x2): `if candidateErr == nil &&
// trustErr == nil && candidateAbs == trustAbs` inside samePolicyConfigFile.
// filepath.Abs practically never errors, so negating either err==nil check
// makes the fast abs-equality path dead code in normal operation — it
// always falls through to the statPath fallback. That's unobservable when
// the fallback is also wired up (both agree for a genuinely identical
// file), so the kill disables the fallback (deps.statPath = nil) and
// relies purely on the abs-equality fast path: a mutant that never takes
// it now returns false where the original returns true.
// ---------------------------------------------------------------------------

func TestSamePolicyConfigFile_AbsEqualityFastPathAloneIsSufficient(t *testing.T) {
	deps := newServeTestDeps()
	deps.statPath = nil // disable the fallback entirely

	path := filepath.Join(t.TempDir(), "policy.yaml")
	alias := filepath.Join(filepath.Dir(path), ".", filepath.Base(path))

	if !samePolicyConfigFile(deps, path, alias) {
		t.Fatal("samePolicyConfigFile() = false for paths resolving to the same absolute path, with no statPath fallback available")
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
