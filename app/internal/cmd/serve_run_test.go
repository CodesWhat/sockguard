package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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

type serveTestCloser struct {
	err error
}

func (c *serveTestCloser) Close() error {
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

		_, err := deps.listenUnixSocket("/tmp/test.sock", 0o600)
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

		_, err := deps.listenUnixSocket("/tmp/test.sock", 0o600)
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

		_, err := deps.listenUnixSocket("/tmp/test.sock", 0o600)
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

		ln, err := deps.listenUnixSocket("/tmp/test.sock", 0o600)
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

		_, err := deps.listenUnixSocket("/tmp/test.sock", 0o600)
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
		deps.startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			errCh <- errors.New("serve boom")
		}
		deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}

		err := runServeWithDeps(newServeCommand(), nil, deps)
		if err == nil || !strings.Contains(err.Error(), "server error: serve boom") {
			t.Fatalf("unexpected error: %v", err)
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

func TestVerifyUpstreamReachableWrapperMissingSocket(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := verifyUpstreamReachable(shortSocketPath(t, "missing-upstream"), logger)
	if err == nil || !strings.Contains(err.Error(), "upstream socket not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithUmaskWrapperReturnsCallbackResult(t *testing.T) {
	t.Parallel()

	ln := &serveTestListener{}
	got, err := withUmask(0o177, func() (net.Listener, error) {
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
