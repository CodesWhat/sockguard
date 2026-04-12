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
	"strings"
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
	addr      net.Addr
	acceptErr error
	closeErr  error
}

func (l *serveTestListener) Accept() (net.Conn, error) {
	if l.acceptErr == nil {
		l.acceptErr = errors.New("accept failed")
	}
	return nil, l.acceptErr
}

func (l *serveTestListener) Close() error {
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

func useServeDeps(t *testing.T) {
	t.Helper()

	originalLoadConfig := loadConfig
	originalNewLogger := newLogger
	originalValidateRules := validateRules
	originalDialUpstream := dialUpstream
	originalListenNetwork := listenNetwork
	originalLstatPath := lstatPath
	originalIsAddrInUseFn := isAddrInUseFn
	originalCreateServeListener := createServeListener
	originalNotifySignals := notifySignals
	originalStartServing := startServing
	originalShutdownServer := shutdownServer
	originalRemovePath := removePath
	originalNow := now
	originalShutdownGracePeriod := shutdownGracePeriod

	t.Cleanup(func() {
		loadConfig = originalLoadConfig
		newLogger = originalNewLogger
		validateRules = originalValidateRules
		dialUpstream = originalDialUpstream
		listenNetwork = originalListenNetwork
		lstatPath = originalLstatPath
		isAddrInUseFn = originalIsAddrInUseFn
		createServeListener = originalCreateServeListener
		notifySignals = originalNotifySignals
		startServing = originalStartServing
		shutdownServer = originalShutdownServer
		removePath = originalRemovePath
		now = originalNow
		shutdownGracePeriod = originalShutdownGracePeriod
	})
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
	useServeDeps(t)

	addrInUseErr := fmt.Errorf("listen unix: %w", syscall.EADDRINUSE)

	t.Run("create listener returns unix listen error", func(t *testing.T) {
		listenNetwork = func(network, address string) (net.Listener, error) {
			return nil, errors.New("boom")
		}

		_, err := createListener(&config.Config{
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
		listenNetwork = func(network, address string) (net.Listener, error) {
			return nil, errors.New("boom")
		}

		_, err := listenUnixSocket("/tmp/test.sock", 0o600)
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected direct listen error, got: %v", err)
		}
	})

	t.Run("listen unix socket returns stat error", func(t *testing.T) {
		listenNetworkCalls := 0
		isAddrInUseFn = func(error) bool { return true }
		listenNetwork = func(network, address string) (net.Listener, error) {
			listenNetworkCalls++
			return nil, addrInUseErr
		}
		lstatPath = func(string) (os.FileInfo, error) {
			return nil, errors.New("stat failed")
		}

		_, err := listenUnixSocket("/tmp/test.sock", 0o600)
		if err == nil || !strings.Contains(err.Error(), "could not inspect") {
			t.Fatalf("expected stat error, got: %v", err)
		}
		if listenNetworkCalls != 1 {
			t.Fatalf("listen calls = %d, want 1", listenNetworkCalls)
		}
	})

	t.Run("listen unix socket returns remove error", func(t *testing.T) {
		isAddrInUseFn = func(error) bool { return true }
		listenNetwork = func(network, address string) (net.Listener, error) {
			return nil, addrInUseErr
		}
		lstatPath = func(string) (os.FileInfo, error) {
			return serveTestFileInfo{mode: os.ModeSocket | 0o600}, nil
		}
		removePath = func(string) error {
			return errors.New("remove failed")
		}

		_, err := listenUnixSocket("/tmp/test.sock", 0o600)
		if err == nil {
			t.Fatal("expected listenUnixSocket() to fail")
		}
		if !strings.Contains(err.Error(), "remove stale socket") && !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("listen unix socket ignores not exist on remove", func(t *testing.T) {
		listenCalls := 0
		isAddrInUseFn = func(error) bool { return true }
		listenNetwork = func(network, address string) (net.Listener, error) {
			listenCalls++
			if listenCalls == 1 {
				return nil, addrInUseErr
			}
			return &serveTestListener{}, nil
		}
		lstatPath = func(string) (os.FileInfo, error) {
			return serveTestFileInfo{mode: os.ModeSocket | 0o600}, nil
		}
		removePath = func(string) error {
			return os.ErrNotExist
		}

		ln, err := listenUnixSocket("/tmp/test.sock", 0o600)
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		_ = ln.Close()
		if listenCalls != 2 {
			t.Fatalf("listen calls = %d, want 2", listenCalls)
		}
	})

	t.Run("listen unix socket returns second listen error", func(t *testing.T) {
		listenCalls := 0
		isAddrInUseFn = func(error) bool { return true }
		listenNetwork = func(network, address string) (net.Listener, error) {
			listenCalls++
			if listenCalls == 1 {
				return nil, addrInUseErr
			}
			return nil, errors.New("second boom")
		}
		lstatPath = func(string) (os.FileInfo, error) {
			return serveTestFileInfo{mode: os.ModeSocket | 0o600}, nil
		}
		removePath = func(string) error {
			return nil
		}

		_, err := listenUnixSocket("/tmp/test.sock", 0o600)
		if err == nil || !strings.Contains(err.Error(), "second boom") {
			t.Fatalf("expected second listen error, got: %v", err)
		}
	})
}

func TestRunServeErrorPaths(t *testing.T) {
	useServeDeps(t)

	loadConfig = func(string) (*config.Config, error) {
		return testServeConfig(), nil
	}
	newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}

	t.Run("load config", func(t *testing.T) {
		loadConfig = func(string) (*config.Config, error) {
			return nil, errors.New("boom")
		}

		err := runServe(newServeCommand(), nil)
		if err == nil || !strings.Contains(err.Error(), "config load: boom") {
			t.Fatalf("unexpected error: %v", err)
		}

		loadConfig = func(string) (*config.Config, error) { return testServeConfig(), nil }
	})

	t.Run("flag overrides", func(t *testing.T) {
		cmd := &cobra.Command{Use: "serve"}
		cmd.Flags().Int("listen-socket", 0, "")
		if err := cmd.Flags().Set("listen-socket", "1"); err != nil {
			t.Fatalf("set listen-socket: %v", err)
		}

		err := runServe(cmd, nil)
		if err == nil || !strings.Contains(err.Error(), "apply flag overrides") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("logger", func(t *testing.T) {
		newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return nil, nil, errors.New("boom")
		}

		err := runServe(newServeCommand(), nil)
		if err == nil || !strings.Contains(err.Error(), "logger: boom") {
			t.Fatalf("unexpected error: %v", err)
		}

		newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return newDiscardLogger(), nil, nil
		}
	})

	t.Run("validate and close log output", func(t *testing.T) {
		var errOut strings.Builder
		cmd := newServeCommand()
		cmd.SetErr(&errOut)

		newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return newDiscardLogger(), &serveTestCloser{err: errors.New("close boom")}, nil
		}
		validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
			return nil, errors.New("validation boom")
		}

		err := runServe(cmd, nil)
		if err == nil || !strings.Contains(err.Error(), "config validation: validation boom") {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(errOut.String(), "failed to close log output: close boom") {
			t.Fatalf("expected log output close warning, got: %q", errOut.String())
		}

		newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
			return newDiscardLogger(), nil, nil
		}
		validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
			return stubCompiledRules(), nil
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
				dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
					return nil, tt.err
				}

				err := runServe(newServeCommand(), nil)
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("listener", func(t *testing.T) {
		dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
			return &serveTestConn{}, nil
		}
		createServeListener = func(*config.Config) (net.Listener, error) {
			return nil, errors.New("listen boom")
		}

		err := runServe(newServeCommand(), nil)
		if err == nil || !strings.Contains(err.Error(), "listener: listen boom") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRunServeLifecyclePaths(t *testing.T) {
	useServeDeps(t)

	loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Listen.Socket = "/tmp/sockguard-test.sock"
		cfg.Listen.Address = ""
		cfg.Health.Enabled = true
		cfg.Log.AccessLog = true
		return cfg, nil
	}
	newLogger = func(level, format, output string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	dialUpstream = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &serveTestConn{closeErr: errors.New("close boom")}, nil
	}
	createServeListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{closeErr: errors.New("listener close boom")}, nil
	}

	t.Run("server error", func(t *testing.T) {
		startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			errCh <- errors.New("serve boom")
		}
		notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}

		err := runServe(newServeCommand(), nil)
		if err == nil || !strings.Contains(err.Error(), "server error: serve boom") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("server closed", func(t *testing.T) {
		startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {
			errCh <- http.ErrServerClosed
		}
		notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {}
		shutdownServer = func(server *http.Server, ctx context.Context) error {
			return nil
		}
		removePath = func(string) error { return nil }

		if err := runServe(newServeCommand(), nil); err != nil {
			t.Fatalf("runServe() error = %v", err)
		}
	})

	t.Run("signal shutdown with cleanup errors", func(t *testing.T) {
		startServing = func(server *http.Server, ln net.Listener, errCh chan<- error) {}
		notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
			c <- syscall.SIGINT
		}
		shutdownGracePeriod = -time.Second
		shutdownServer = func(server *http.Server, ctx context.Context) error {
			if ctx.Err() == nil {
				t.Fatal("expected expired shutdown context")
			}
			return errors.New("shutdown boom")
		}
		removePath = func(string) error { return errors.New("remove boom") }
		now = func() time.Time { return time.Unix(0, 0) }

		if err := runServe(newServeCommand(), nil); err != nil {
			t.Fatalf("runServe() error = %v", err)
		}
	})
}

func TestServeHelperDefaults(t *testing.T) {
	errCh := make(chan error, 1)
	server := newHTTPServer(http.NotFoundHandler())
	listener := &serveTestListener{acceptErr: errors.New("accept boom")}

	startServing(server, listener, errCh)

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "accept boom") {
		t.Fatalf("unexpected serve error: %v", err)
	}

	if err := shutdownServer(newHTTPServer(http.NotFoundHandler()), context.Background()); err != nil {
		t.Fatalf("shutdownServer() error = %v", err)
	}
}
