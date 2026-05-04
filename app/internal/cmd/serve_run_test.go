package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

type serveTestConn struct {
	closeErr error
}

func (c *serveTestConn) Read(b []byte) (int, error)       { return 0, io.EOF }
func (c *serveTestConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *serveTestConn) Close() error                     { return c.closeErr }
func (c *serveTestConn) LocalAddr() net.Addr              { return &net.UnixAddr{Name: "local", Net: "unix"} }
func (c *serveTestConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "remote", Net: "unix"} }
func (c *serveTestConn) SetDeadline(time.Time) error      { return nil }
func (c *serveTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *serveTestConn) SetWriteDeadline(time.Time) error { return nil }

type serveTestListener struct {
	addr       net.Addr
	acceptErr  error
	closeErr   error
	closeCalls int
}

func (l *serveTestListener) Accept() (net.Conn, error) {
	if l.acceptErr == nil {
		l.acceptErr = errors.New("accept failed")
	}
	return nil, l.acceptErr
}

func (l *serveTestListener) Close() error {
	l.closeCalls++
	return l.closeErr
}

func (l *serveTestListener) Addr() net.Addr {
	if l.addr == nil {
		l.addr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	return l.addr
}

type serveTestSequentialCloseListener struct {
	serveTestListener
	closeErrs []error
}

func (l *serveTestSequentialCloseListener) Close() error {
	l.closeCalls++
	if len(l.closeErrs) == 0 {
		return nil
	}
	idx := l.closeCalls - 1
	if idx >= len(l.closeErrs) {
		return l.closeErrs[len(l.closeErrs)-1]
	}
	return l.closeErrs[idx]
}

type serveTestCloser struct {
	err error
}

func (c *serveTestCloser) Close() error {
	return c.err
}

type serveTestAuditCloser struct {
	logger *logging.AuditLogger
	err    error
}

func (c *serveTestAuditCloser) Close() error {
	if c.logger != nil {
		_ = c.logger.Close()
	}
	return c.err
}

type serveTestFileInfo struct {
	mode os.FileMode
}

func (i serveTestFileInfo) Name() string       { return "sock" }
func (i serveTestFileInfo) Size() int64        { return 0 }
func (i serveTestFileInfo) Mode() os.FileMode  { return i.mode }
func (i serveTestFileInfo) ModTime() time.Time { return time.Time{} }
func (i serveTestFileInfo) IsDir() bool        { return false }
func (i serveTestFileInfo) Sys() any           { return nil }

func newServeTestDeps() *serveDeps {
	deps := newServeDeps()
	deps.umaskMu = &sync.Mutex{}
	return deps
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newServeCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().String("listen-socket", "", "")
	cmd.Flags().String("upstream-socket", "", "")
	cmd.Flags().String("log-level", "", "")
	cmd.Flags().String("log-format", "", "")
	cmd.Flags().String("deny-response-verbosity", "", "")
	return cmd
}

func TestRunServeWithDepsUsesInjectedLoadConfig(t *testing.T) {
	t.Parallel()

	deps := newServeDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		return nil, errors.New("boom")
	}

	err := runServeWithDeps(newServeCommand(), nil, deps)
	if err == nil || !strings.Contains(err.Error(), "config load: boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunServeWrapperPropagatesConfigLoadError(t *testing.T) {
	originalCfgFile := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(cfgFile, []byte("rules: [:"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() {
		cfgFile = originalCfgFile
	})

	err := runServe(newServeCommand(), nil)
	if err == nil || !strings.Contains(err.Error(), "config load:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunServeWithDepsRejectsMissingExplicitConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	originalCfgFile := cfgFile
	cfgFile = missing
	t.Cleanup(func() {
		cfgFile = originalCfgFile
	})

	cmd := newServeCommand()
	cmd.Flags().String("config", "", "")
	if err := cmd.Flags().Set("config", missing); err != nil {
		t.Fatalf("set config flag: %v", err)
	}

	loadCalled := false
	deps := newServeDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		loadCalled = true
		return nil, errors.New("load should not be called")
	}

	err := runServeWithDeps(cmd, nil, deps)
	if err == nil {
		t.Fatal("expected runServeWithDeps() to fail when explicit config file is missing")
	}
	if !strings.Contains(err.Error(), "config preflight:") {
		t.Fatalf("expected config preflight error, got: %v", err)
	}
	if strings.Contains(err.Error(), "config load:") {
		t.Fatalf("expected preflight error not to be reported as config load, got: %v", err)
	}
	if loadCalled {
		t.Fatal("expected explicit config preflight to fail before loading config")
	}
}

func captureMergedServeConfig(t *testing.T, deps *serveDeps, cmd *cobra.Command, configPath string) *config.Config {
	t.Helper()

	originalCfgFile := cfgFile
	cfgFile = configPath
	t.Cleanup(func() {
		cfgFile = originalCfgFile
	})

	deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}

	stopErr := errors.New("stop after merged config capture")
	var captured *config.Config
	deps.validateRules = func(cfg *config.Config) ([]*filter.CompiledRule, error) {
		clone := *cfg
		clone.Rules = append([]config.RuleConfig(nil), cfg.Rules...)
		captured = &clone
		return nil, stopErr
	}

	err := runServeWithDeps(cmd, nil, deps)
	if !errors.Is(err, stopErr) {
		t.Fatalf("runServe() error = %v, want wrapped %v", err, stopErr)
	}
	if captured == nil {
		t.Fatal("expected merged config to be captured before validation failure")
	}

	return captured
}

func testServeConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Listen.Socket = ""
	cfg.Listen.Address = "127.0.0.1:0"
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	return &cfg
}

func stubCompiledRules() []*filter.CompiledRule {
	return []*filter.CompiledRule{}
}

func TestApplyFlagOverridesErrorBranches(t *testing.T) {
	tests := []string{
		"listen-socket",
		"upstream-socket",
		"log-format",
		"deny-response-verbosity",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := config.Defaults()
			cmd := &cobra.Command{Use: "serve"}
			cmd.Flags().Int(name, 0, "")
			if err := cmd.Flags().Set(name, "1"); err != nil {
				t.Fatalf("set %s: %v", name, err)
			}

			err := applyFlagOverrides(cmd, &cfg)
			if err == nil {
				t.Fatal("expected applyFlagOverrides() to fail")
			}
			if !strings.Contains(err.Error(), "get "+name+" flag") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCreateListenerAndListenUnixSocketErrorPaths(t *testing.T) {
	addrInUseErr := fmt.Errorf("listen unix: %w", syscall.EADDRINUSE)

	t.Run("create listener returns unix listen error", func(t *testing.T) {
		deps := newServeTestDeps()
		deps.listenNetwork = func(network, address string) (net.Listener, error) {
			return nil, errors.New("boom")
		}

		_, err := deps.createListener(&config.Config{
			Listen: config.ListenConfig{
				Socket:     "/tmp/test.sock",
				SocketMode: "0600",
			},
		})
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected unix listen error, got: %v", err)
		}
	})

	t.Run("listen unix socket returns non address-in-use error", func(t *testing.T) {
		deps := newServeTestDeps()
		deps.listenNetwork = func(network, address string) (net.Listener, error) {
			return nil, errors.New("boom")
		}

		_, err := deps.listenUnixSocket("/tmp/test.sock")
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected direct listen error, got: %v", err)
		}
	})

	t.Run("listen unix socket returns stat error", func(t *testing.T) {
		deps := newServeTestDeps()
		listenNetworkCalls := 0
		deps.isAddrInUse = func(error) bool { return true }
		deps.listenNetwork = func(network, address string) (net.Listener, error) {
			listenNetworkCalls++
			return nil, addrInUseErr
		}
		deps.lstatPath = func(string) (os.FileInfo, error) {
			return nil, errors.New("stat failed")
		}

		_, err := deps.listenUnixSocket("/tmp/test.sock")
		if err == nil || !strings.Contains(err.Error(), "could not inspect") {
			t.Fatalf("expected stat error, got: %v", err)
		}
		if listenNetworkCalls != 1 {
			t.Fatalf("listen calls = %d, want 1", listenNetworkCalls)
		}
	})

	t.Run("listen unix socket returns remove error", func(t *testing.T) {
		deps := newServeTestDeps()
		deps.isAddrInUse = func(error) bool { return true }
		deps.listenNetwork = func(network, address string) (net.Listener, error) {
			return nil, addrInUseErr
		}
		deps.lstatPath = func(string) (os.FileInfo, error) {
			return serveTestFileInfo{mode: os.ModeSocket | 0o600}, nil
		}
		deps.removePath = func(string) error {
			return errors.New("remove failed")
		}

		_, err := deps.listenUnixSocket("/tmp/test.sock")
		if err == nil {
			t.Fatal("expected listenUnixSocket() to fail")
		}
		if !strings.Contains(err.Error(), "remove stale socket") && !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("listen unix socket ignores not exist on remove", func(t *testing.T) {
		deps := newServeTestDeps()
		listenCalls := 0
		deps.isAddrInUse = func(error) bool { return true }
		deps.listenNetwork = func(network, address string) (net.Listener, error) {
			listenCalls++
			if listenCalls == 1 {
				return nil, addrInUseErr
			}
			return &serveTestListener{}, nil
		}
		deps.lstatPath = func(string) (os.FileInfo, error) {
			return serveTestFileInfo{mode: os.ModeSocket | 0o600}, nil
		}
		deps.removePath = func(string) error {
			return os.ErrNotExist
		}

		ln, err := deps.listenUnixSocket("/tmp/test.sock")
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		_ = ln.Close()
		if listenCalls != 2 {
			t.Fatalf("listen calls = %d, want 2", listenCalls)
		}
	})

	t.Run("listen unix socket returns second listen error", func(t *testing.T) {
		deps := newServeTestDeps()
		listenCalls := 0
		deps.isAddrInUse = func(error) bool { return true }
		deps.listenNetwork = func(network, address string) (net.Listener, error) {
			listenCalls++
			if listenCalls == 1 {
				return nil, addrInUseErr
			}
			return nil, errors.New("second boom")
		}
		deps.lstatPath = func(string) (os.FileInfo, error) {
			return serveTestFileInfo{mode: os.ModeSocket | 0o600}, nil
		}
		deps.removePath = func(string) error {
			return nil
		}

		_, err := deps.listenUnixSocket("/tmp/test.sock")
		if err == nil || !strings.Contains(err.Error(), "second boom") {
			t.Fatalf("expected second listen error, got: %v", err)
		}
	})
}

func TestRunServeErrorPaths(t *testing.T) {
	newRunServeDeps := func() *serveDeps {
		deps := newServeTestDeps()
		deps.loadConfig = func(string) (*config.Config, error) {
			return testServeConfig(), nil
		}
		deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return newDiscardLogger(), nil, nil
		}
		deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
			return stubCompiledRules(), nil
		}
		return deps
	}

	t.Run("load config", func(t *testing.T) {
		deps := newRunServeDeps()
		deps.loadConfig = func(string) (*config.Config, error) {
			return nil, errors.New("boom")
		}

		err := runServeWithDeps(newServeCommand(), nil, deps)
		if err == nil || !strings.Contains(err.Error(), "config load: boom") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("flag overrides", func(t *testing.T) {
		deps := newRunServeDeps()
		cmd := &cobra.Command{Use: "serve"}
		cmd.Flags().Int("listen-socket", 0, "")
		if err := cmd.Flags().Set("listen-socket", "1"); err != nil {
			t.Fatalf("set listen-socket: %v", err)
		}

		err := runServeWithDeps(cmd, nil, deps)
		if err == nil || !strings.Contains(err.Error(), "apply flag overrides") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("logger", func(t *testing.T) {
		deps := newRunServeDeps()
		deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return nil, nil, errors.New("boom")
		}

		err := runServeWithDeps(newServeCommand(), nil, deps)
		if err == nil || !strings.Contains(err.Error(), "logger: boom") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("audit logger", func(t *testing.T) {
		deps := newRunServeDeps()
		cfg := testServeConfig()
		cfg.Log.Audit.Enabled = true
		deps.loadConfig = func(string) (*config.Config, error) {
			return cfg, nil
		}
		deps.newAuditLogger = func(format, output string) (*logging.AuditLogger, io.Closer, error) {
			return nil, nil, errors.New("audit boom")
		}

		err := runServeWithDeps(newServeCommand(), nil, deps)
		if err == nil || !strings.Contains(err.Error(), "audit logger: audit boom") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("validate and close log output", func(t *testing.T) {
		deps := newRunServeDeps()
		var errOut strings.Builder
		cmd := newServeCommand()
		cmd.SetErr(&errOut)

		deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return newDiscardLogger(), &serveTestCloser{err: errors.New("close boom")}, nil
		}
		deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
			return nil, errors.New("validation boom")
		}

		err := runServeWithDeps(cmd, nil, deps)
		if err == nil || !strings.Contains(err.Error(), "config validation: validation boom") {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(errOut.String(), "failed to close log output: close boom") {
			t.Fatalf("expected log output close warning, got: %q", errOut.String())
		}
	})

	t.Run("close audit log output", func(t *testing.T) {
		deps := newRunServeDeps()
		cfg := testServeConfig()
		cfg.Log.Audit.Enabled = true
		deps.loadConfig = func(string) (*config.Config, error) {
			return cfg, nil
		}

		var errOut strings.Builder
		cmd := newServeCommand()
		cmd.SetErr(&errOut)

		deps.newAuditLogger = func(format, output string) (*logging.AuditLogger, io.Closer, error) {
			auditLogger := logging.NewAuditLogger(io.Discard)
			return auditLogger, &serveTestAuditCloser{logger: auditLogger, err: errors.New("audit close boom")}, nil
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
		deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
			return nil
		}

		if err := runServeWithDeps(cmd, nil, deps); err != nil {
			t.Fatalf("runServeWithDeps() error = %v, want nil", err)
		}
		if !strings.Contains(errOut.String(), "failed to close audit log output: audit close boom") {
			t.Fatalf("expected audit log output close warning, got: %q", errOut.String())
		}
	})

	t.Run("audit log pipeline", func(t *testing.T) {
		deps := newRunServeDeps()
		cfg := testServeConfig()
		cfg.Log.Audit.Enabled = true
		deps.loadConfig = func(string) (*config.Config, error) {
			return cfg, nil
		}

		var auditBuf bytes.Buffer
		deps.newAuditLogger = func(format, output string) (*logging.AuditLogger, io.Closer, error) {
			auditLogger := logging.NewAuditLogger(&auditBuf)
			return auditLogger, auditLogger, nil
		}
		deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
			return &serveTestConn{}, nil
		}
		deps.createServeListener = func(*config.Config) (net.Listener, error) {
			return &serveTestListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2375}}, nil
		}
		deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			req := httptest.NewRequest(http.MethodGet, "/v1.45/denied", nil)
			req.RemoteAddr = "198.51.100.10:4444"
			req.Header.Set("X-Request-ID", "client-123")
			rec := httptest.NewRecorder()
			server.Handler.ServeHTTP(rec, req)
			errCh <- http.ErrServerClosed
		}

		if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
			t.Fatalf("runServeWithDeps() error = %v, want nil", err)
		}

		var event map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
			t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, auditBuf.String())
		}
		if got := event["decision"]; got != "deny" {
			t.Fatalf("decision = %#v, want %q", got, "deny")
		}
		if got := event["normalized_path"]; got != "/denied" {
			t.Fatalf("normalized_path = %#v, want %q", got, "/denied")
		}
		if got := event["reason_code"]; got != "no_matching_allow_rule" {
			t.Fatalf("reason_code = %#v, want %q", got, "no_matching_allow_rule")
		}
		if got := event["client_request_id"]; got != "client-123" {
			t.Fatalf("client_request_id = %#v, want %q", got, "client-123")
		}
	})

	t.Run("upstream dial variants", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
			want string
		}{
			{name: "not found", err: os.ErrNotExist, want: "upstream socket not found"},
			{name: "permission", err: os.ErrPermission, want: "permission denied on upstream socket"},
			{name: "unreachable", err: errors.New("boom"), want: "upstream socket unreachable"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				deps := newRunServeDeps()
				deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
					return nil, tt.err
				}

				err := runServeWithDeps(newServeCommand(), nil, deps)
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("listener", func(t *testing.T) {
		deps := newRunServeDeps()
		deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
			return &serveTestConn{}, nil
		}
		deps.createServeListener = func(*config.Config) (net.Listener, error) {
			return nil, errors.New("listen boom")
		}

		err := runServeWithDeps(newServeCommand(), nil, deps)
		if err == nil || !strings.Contains(err.Error(), "listener: listen boom") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRunServeConfigSourcePrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")

	yaml := `
listen:
  socket: /file/sockguard.sock
upstream:
  socket: /file/docker.sock
log:
  level: error
  format: text
  output: file.log
response:
  deny_verbosity: minimal
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("SOCKGUARD_LISTEN_SOCKET", "/env/sockguard.sock")
	t.Setenv("SOCKGUARD_UPSTREAM_SOCKET", "/env/docker.sock")
	t.Setenv("SOCKGUARD_LOG_LEVEL", "warn")
	t.Setenv("SOCKGUARD_LOG_FORMAT", "json")
	t.Setenv("SOCKGUARD_LOG_OUTPUT", "stdout")
	t.Setenv("SOCKGUARD_RESPONSE_DENY_VERBOSITY", "verbose")

	cmd := newServeCommand()
	if err := cmd.Flags().Set("listen-socket", "/flag/sockguard.sock"); err != nil {
		t.Fatalf("set listen-socket: %v", err)
	}
	if err := cmd.Flags().Set("upstream-socket", "/flag/docker.sock"); err != nil {
		t.Fatalf("set upstream-socket: %v", err)
	}
	if err := cmd.Flags().Set("log-level", "debug"); err != nil {
		t.Fatalf("set log-level: %v", err)
	}
	if err := cmd.Flags().Set("log-format", "console"); err != nil {
		t.Fatalf("set log-format: %v", err)
	}
	if err := cmd.Flags().Set("deny-response-verbosity", "minimal"); err != nil {
		t.Fatalf("set deny-response-verbosity: %v", err)
	}

	cfg := captureMergedServeConfig(t, newServeTestDeps(), cmd, cfgPath)

	tests := []struct {
		name string
		got  func(*config.Config) string
		want string
	}{
		{
			name: "listen socket uses flag over env, file, and default",
			got:  func(cfg *config.Config) string { return cfg.Listen.Socket },
			want: "/flag/sockguard.sock",
		},
		{
			name: "upstream socket uses flag over env, file, and default",
			got:  func(cfg *config.Config) string { return cfg.Upstream.Socket },
			want: "/flag/docker.sock",
		},
		{
			name: "log level uses flag over env, file, and default",
			got:  func(cfg *config.Config) string { return cfg.Log.Level },
			want: "debug",
		},
		{
			name: "log format uses flag over env, file, and default",
			got:  func(cfg *config.Config) string { return cfg.Log.Format },
			want: "console",
		},
		{
			name: "deny verbosity uses flag over env, file, and default",
			got:  func(cfg *config.Config) string { return cfg.Response.DenyVerbosity },
			want: "minimal",
		},
		{
			name: "log output uses env over file and default when no flag exists",
			got:  func(cfg *config.Config) string { return cfg.Log.Output },
			want: "stdout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got(cfg); got != tt.want {
				t.Fatalf("value = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunServeLifecyclePaths(t *testing.T) {
	newLifecycleDeps := func() *serveDeps {
		deps := newServeTestDeps()
		deps.loadConfig = func(string) (*config.Config, error) {
			cfg := testServeConfig()
			cfg.Listen.Socket = "/tmp/sockguard-test.sock"
			cfg.Listen.Address = ""
			cfg.Health.Enabled = true
			cfg.Log.AccessLog = true
			return cfg, nil
		}
		deps.newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return newDiscardLogger(), nil, nil
		}
		deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
			return stubCompiledRules(), nil
		}
		deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
			return &serveTestConn{closeErr: errors.New("close boom")}, nil
		}
		deps.createServeListener = func(*config.Config) (net.Listener, error) {
			return &serveTestListener{closeErr: errors.New("listener close boom")}, nil
		}
		return deps
	}

	t.Run("server error", func(t *testing.T) {
		deps := newLifecycleDeps()
		shutdownCalled := false
		removeCalled := false
		deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			errCh <- errors.New("serve boom")
		}
		deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
		deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
			shutdownCalled = true
			return nil
		}
		deps.removePath = func(string) error {
			removeCalled = true
			return nil
		}

		err := runServeWithDeps(newServeCommand(), nil, deps)
		if err == nil || !strings.Contains(err.Error(), "server error: serve boom") {
			t.Fatalf("unexpected error: %v", err)
		}
		if shutdownCalled {
			t.Fatal("expected shutdownServer to be skipped on serve error")
		}
		if removeCalled {
			t.Fatal("expected socket cleanup to be skipped on serve error")
		}
	})

	t.Run("server closed", func(t *testing.T) {
		deps := newLifecycleDeps()
		deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			errCh <- http.ErrServerClosed
		}
		deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
		deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
			return nil
		}
		deps.removePath = func(string) error { return nil }

		if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
			t.Fatalf("runServe() error = %v", err)
		}
	})

	t.Run("signal shutdown with cleanup errors", func(t *testing.T) {
		deps := newLifecycleDeps()
		deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {}
		deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
			c <- syscall.SIGINT
		}
		deps.shutdownGracePeriod = -time.Second
		deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
			if ctx.Err() == nil {
				t.Fatal("expected expired shutdown context")
			}
			return errors.New("shutdown boom")
		}
		deps.removePath = func(string) error { return errors.New("remove boom") }
		deps.now = func() time.Time { return time.Unix(0, 0) }

		if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
			t.Fatalf("runServe() error = %v", err)
		}
	})
}

func TestVerifyUpstreamReachable(t *testing.T) {
	t.Run("error mapping", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
			want string
		}{
			{name: "not found", err: os.ErrNotExist, want: "upstream socket not found"},
			{name: "permission", err: os.ErrPermission, want: "permission denied on upstream socket"},
			{name: "unreachable", err: errors.New("boom"), want: "upstream socket unreachable"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				deps := newServeTestDeps()
				deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
					return nil, tt.err
				}

				err := deps.verifyUpstreamReachable("/var/run/docker.sock", newDiscardLogger())
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("close failure is debug logged", func(t *testing.T) {
		deps := newServeTestDeps()
		var logBuf strings.Builder
		logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

		deps.dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
			return &serveTestConn{closeErr: errors.New("close boom")}, nil
		}

		if err := deps.verifyUpstreamReachable("/var/run/docker.sock", logger); err != nil {
			t.Fatalf("verifyUpstreamReachable() error = %v", err)
		}
		if !strings.Contains(logBuf.String(), `"msg":"failed to close upstream check connection"`) {
			t.Fatalf("expected debug close log, got: %s", logBuf.String())
		}
	})
}

func TestVerifyUpstreamReachableMissingSocket(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := newServeDeps().verifyUpstreamReachable(shortSocketPath(t, "missing-upstream"), logger)
	if err == nil || !strings.Contains(err.Error(), "upstream socket not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithUmaskReturnsCallbackResult(t *testing.T) {
	t.Parallel()

	ln := &serveTestListener{}
	got, err := newServeDeps().withUmask(0o177, func() (net.Listener, error) {
		return ln, nil
	})
	if err != nil {
		t.Fatalf("withUmask() error = %v", err)
	}
	if got != ln {
		t.Fatalf("listener = %v, want %v", got, ln)
	}
}

func TestRunServeWarnsOnWildcardTCPBind(t *testing.T) {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Address = ":2375"
		cfg.Listen.InsecureAllowPlainTCP = true
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
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
		return nil
	}

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServe() error = %v", err)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"msg":"plaintext TCP listener is exposed beyond loopback"`) {
		t.Fatalf("expected insecure remote tcp warning, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"recommendation":"configure listen.tls for mTLS, bind 127.0.0.1:<port>, or use listen.socket"`) {
		t.Fatalf("expected mTLS/loopback/socket recommendation, got: %s", logOutput)
	}
}

func TestRunServeDoesNotWarnWhenDeferredListenerCloseReturnsNetErrClosed(t *testing.T) {
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

	listener := &serveTestSequentialCloseListener{
		closeErrs: []error{nil, net.ErrClosed},
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return listener, nil
	}
	deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {}
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
		c <- syscall.SIGINT
	}
	deps.shutdownServer = func(server *http.Server, ctx context.Context) error {
		return listener.Close()
	}

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServe() error = %v", err)
	}

	if listener.closeCalls != 2 {
		t.Fatalf("listener close calls = %d, want 2", listener.closeCalls)
	}
	if strings.Contains(logBuf.String(), `"msg":"failed to close listener"`) {
		t.Fatalf("unexpected listener-close warning for net.ErrClosed: %s", logBuf.String())
	}
}

func TestServeHelperDefaults(t *testing.T) {
	deps := newServeDeps()
	errCh := make(chan error, 1)
	server := newHTTPServer(http.NotFoundHandler())
	listener := &serveTestListener{acceptErr: errors.New("accept boom")}

	deps.startServing(server, listener, errCh)

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "accept boom") {
		t.Fatalf("unexpected serve error: %v", err)
	}

	if err := deps.shutdownServer(newHTTPServer(http.NotFoundHandler()), context.Background()); err != nil {
		t.Fatalf("shutdownServer() error = %v", err)
	}
}
