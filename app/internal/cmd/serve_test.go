package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/testcert"
)

// shortSocketPath returns a unique short /tmp socket path that fits within
// macOS's 104-byte sun_path limit (t.TempDir() paths are too long on macOS).
// os.CreateTemp guarantees uniqueness across -count=N and crashed prior runs.
func shortSocketPath(t *testing.T, label string) string {
	t.Helper()
	f, err := os.CreateTemp("/tmp", "dp-"+label+"-*.sock")
	if err != nil {
		t.Fatalf("create temp socket: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func closeAuditLoggerForTest(t *testing.T, logger *logging.AuditLogger) {
	t.Helper()
	if err := logger.Close(); err != nil {
		t.Fatalf("audit logger close: %v", err)
	}
}

func TestIsAddrInUse(t *testing.T) {
	if !isAddrInUse(syscall.EADDRINUSE) {
		t.Fatal("expected EADDRINUSE to be detected")
	}
	if isAddrInUse(errors.New("other")) {
		t.Fatal("did not expect non-EADDRINUSE error to be detected")
	}
}

func TestServeUsesConfigValidate(t *testing.T) {
	got := runtime.FuncForPC(reflect.ValueOf(newServeDeps().validateRules).Pointer()).Name()
	want := runtime.FuncForPC(reflect.ValueOf(validateAndCompileRules).Pointer()).Name()

	if got != want {
		t.Fatalf("serve validation entry point = %s, want %s", got, want)
	}
}

func TestRuleCompilationUsesConfigValidate(t *testing.T) {
	got := runtime.FuncForPC(reflect.ValueOf(validateConfig).Pointer()).Name()
	want := runtime.FuncForPC(reflect.ValueOf(config.Validate).Pointer()).Name()

	if got != want {
		t.Fatalf("config validation entry point = %s, want %s", got, want)
	}
}

func TestServePolicyConfigAddsRuntimeFilterOptions(t *testing.T) {
	cfg := config.Defaults()
	cfg.Response.DenyVerbosity = "verbose"
	cfg.Upstream.Socket = "/tmp/docker.sock"
	cfg.RequestBody.ContainerCreate.AllowPrivileged = true
	cfg.RequestBody.Exec.AllowRootUser = true
	cfg.RequestBody.Exec.AllowedCommands = [][]string{{"/usr/bin/id"}}

	got := servePolicyConfig(&cfg)

	if got.DenyResponseVerbosity != filter.DenyResponseVerbosityVerbose {
		t.Fatalf("DenyResponseVerbosity = %q, want %q", got.DenyResponseVerbosity, filter.DenyResponseVerbosityVerbose)
	}
	if !got.ContainerCreate.AllowPrivileged {
		t.Fatal("ContainerCreate.AllowPrivileged = false, want true")
	}
	if !got.Exec.AllowRootUser {
		t.Fatal("Exec.AllowRootUser = false, want true")
	}
	if !reflect.DeepEqual(got.Exec.AllowedCommands, [][]string{{"/usr/bin/id"}}) {
		t.Fatalf("Exec.AllowedCommands = %#v, want [[/usr/bin/id]]", got.Exec.AllowedCommands)
	}
	if got.Exec.InspectStart == nil {
		t.Fatal("Exec.InspectStart is nil, want runtime inspector")
	}
}

func TestListenUnixSocketCreatesNewSocket(t *testing.T) {
	path := shortSocketPath(t, "new")

	ln, err := newServeDeps().listenUnixSocket(path)
	if err != nil {
		t.Fatalf("listenUnixSocket() error = %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket path: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected socket file at %q, mode=%v", path, info.Mode())
	}
}

func TestListenUnixSocketReplacesStaleSocket(t *testing.T) {
	path := shortSocketPath(t, "stale")

	original, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("create initial socket: %v", err)
	}
	original.Close()

	ln, err := newServeDeps().listenUnixSocket(path)
	if err != nil {
		t.Fatalf("listenUnixSocket() with stale socket error = %v", err)
	}
	defer ln.Close()
}

func TestListenUnixSocketRejectsNonSocketPath(t *testing.T) {
	path := shortSocketPath(t, "nonsock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write non-socket path: %v", err)
	}

	_, err := newServeDeps().listenUnixSocket(path)
	if err == nil {
		t.Fatal("expected error for non-socket path")
	}
	if !strings.Contains(err.Error(), "is not a socket") {
		t.Fatalf("expected non-socket path error, got: %v", err)
	}
}

func TestCreateListenerUnixSocket(t *testing.T) {
	socketPath := shortSocketPath(t, "create")
	cfg := &config.Config{
		Listen: config.ListenConfig{
			Socket:     socketPath,
			SocketMode: "0600",
		},
	}

	ln, err := newServeDeps().createListener(cfg)
	if err != nil {
		t.Fatalf("createListener() error = %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket path: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected socket file at %q, mode=%v", socketPath, info.Mode())
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCreateListenerUnixSocketSetsTemporaryUmask(t *testing.T) {
	socketPath := shortSocketPath(t, "umask")
	cfg := &config.Config{
		Listen: config.ListenConfig{
			Socket:     socketPath,
			SocketMode: "0600",
		},
	}

	deps := newServeTestDeps()
	currentMask := 0o022
	var calls []int
	deps.umask = func(mask int) int {
		previous := currentMask
		currentMask = mask
		calls = append(calls, mask)
		return previous
	}

	ln, err := deps.createListener(cfg)
	if err != nil {
		t.Fatalf("createListener() error = %v", err)
	}
	defer ln.Close()

	if len(calls) != 2 {
		t.Fatalf("umask call count = %d, want 2", len(calls))
	}
	if calls[0] != 0o177 {
		t.Fatalf("temporary umask = %03o, want 177", calls[0])
	}
	if calls[1] != 0o022 {
		t.Fatalf("restored umask = %03o, want 022", calls[1])
	}
}

func TestWithUmaskConcurrency(t *testing.T) {
	deps := newServeTestDeps()
	var mu sync.Mutex
	currentMask := 0o022
	deps.umask = func(mask int) int {
		mu.Lock()
		defer mu.Unlock()
		previous := currentMask
		currentMask = mask
		return previous
	}

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			socketPath := shortSocketPath(t, fmt.Sprintf("conc%d", id))
			_, err := deps.withUmask(0o177, func() (net.Listener, error) {
				return net.Listen("unix", socketPath)
			})
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", id, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	mu.Lock()
	finalMask := currentMask
	mu.Unlock()
	if finalMask != 0o022 {
		t.Fatalf("final umask = %03o, want 022 (umask was corrupted by concurrent calls)", finalMask)
	}
}

func TestCreateListenerTCP(t *testing.T) {
	cfg := &config.Config{
		Listen: config.ListenConfig{
			Address: "127.0.0.1:0",
		},
	}

	ln, err := newServeDeps().createListener(cfg)
	if err != nil {
		t.Fatalf("createListener() error = %v", err)
	}
	defer ln.Close()

	if ln.Addr().Network() != "tcp" {
		t.Fatalf("listener network = %q, want tcp", ln.Addr().Network())
	}
}

func TestCreateListenerTCPReturnsListenError(t *testing.T) {
	deps := newServeTestDeps()
	deps.listenNetwork = func(network, address string) (net.Listener, error) {
		return nil, errors.New("listen boom")
	}

	_, err := deps.createListener(&config.Config{
		Listen: config.ListenConfig{
			Address: "127.0.0.1:0",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "listen boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateListenerTCPWithMutualTLS(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cfg := &config.Config{
		Listen: config.ListenConfig{
			Address: "127.0.0.1:0",
			TLS: config.ListenTLSConfig{
				CertFile:           bundle.ServerCertFile,
				KeyFile:            bundle.ServerKeyFile,
				ClientCAFile:       bundle.CAFile,
				AllowedCommonNames: []string{"sockguard-test-client"},
			},
		},
	}

	ln, err := newServeDeps().createListener(cfg)
	if err != nil {
		t.Fatalf("createListener() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				errCh <- err
				return
			}
		}
		_ = conn.Close()
		errCh <- nil
	}()

	clientTLS, err := testcert.ClientTLSConfig(bundle, "127.0.0.1")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	clientConn, err := tls.Dial(ln.Addr().Network(), ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial() error = %v", err)
	}
	_ = clientConn.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("listener accept error = %v", err)
	}
}

func TestCreateListenerTCPWithMutualTLSRejectsMissingClientCertificate(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cfg := &config.Config{
		Listen: config.ListenConfig{
			Address: "127.0.0.1:0",
			TLS: config.ListenTLSConfig{
				CertFile:     bundle.ServerCertFile,
				KeyFile:      bundle.ServerKeyFile,
				ClientCAFile: bundle.CAFile,
			},
		},
	}

	ln, err := newServeDeps().createListener(cfg)
	if err != nil {
		t.Fatalf("createListener() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			err = tlsConn.Handshake()
		}
		_ = conn.Close()
		errCh <- err
	}()

	clientTLS, err := testcert.ClientTLSConfig(bundle, "127.0.0.1")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	clientTLS.Certificates = nil

	clientConn, err := tls.Dial(ln.Addr().Network(), ln.Addr().String(), clientTLS)
	if err == nil {
		_ = clientConn.Close()
	}

	if err := <-errCh; err == nil {
		t.Fatal("expected listener handshake to fail without client certificate")
	}
}

func TestCreateListenerTCPWithMutualTLSRejectsDisallowedClientCertificateIdentity(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cfg := &config.Config{
		Listen: config.ListenConfig{
			Address: "127.0.0.1:0",
			TLS: config.ListenTLSConfig{
				CertFile:           bundle.ServerCertFile,
				KeyFile:            bundle.ServerKeyFile,
				ClientCAFile:       bundle.CAFile,
				AllowedCommonNames: []string{"different-client"},
			},
		},
	}

	ln, err := newServeDeps().createListener(cfg)
	if err != nil {
		t.Fatalf("createListener() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			err = tlsConn.Handshake()
		}
		_ = conn.Close()
		errCh <- err
	}()

	clientTLS, err := testcert.ClientTLSConfig(bundle, "127.0.0.1")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	clientConn, err := tls.Dial(ln.Addr().Network(), ln.Addr().String(), clientTLS)
	if err == nil {
		_ = clientConn.Close()
	}

	if err := <-errCh; err == nil {
		t.Fatal("expected listener handshake to fail for disallowed client certificate identity")
	}
}

func TestCreateListenerTCPWithMutualTLSClosesBaseListenerOnTLSConfigError(t *testing.T) {
	deps := newServeTestDeps()
	baseListener := &serveTestListener{}
	deps.listenNetwork = func(network, address string) (net.Listener, error) {
		return baseListener, nil
	}

	cfg := &config.Config{
		Listen: config.ListenConfig{
			Address: "127.0.0.1:0",
			TLS: config.ListenTLSConfig{
				CertFile:     "/nonexistent/server-cert.pem",
				KeyFile:      "/nonexistent/server-key.pem",
				ClientCAFile: "/nonexistent/ca.pem",
			},
		},
	}

	ln, err := deps.createListener(cfg)
	if err == nil {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatal("expected createListener() to fail")
	}
	if baseListener.closeCalls != 1 {
		t.Fatalf("base listener close calls = %d, want 1", baseListener.closeCalls)
	}
}

func TestCreateListenerInvalidSocketMode(t *testing.T) {
	socketPath := shortSocketPath(t, "badmode")
	cfg := &config.Config{
		Listen: config.ListenConfig{
			Socket:     socketPath,
			SocketMode: "not-octal",
		},
	}

	ln, err := newServeDeps().createListener(cfg)
	if err == nil {
		ln.Close()
		t.Fatal("expected createListener() to fail for invalid socket_mode")
	}
	if !strings.Contains(err.Error(), "listen.socket_mode") {
		t.Fatalf("expected listen.socket_mode error, got: %v", err)
	}
}

func TestCreateListenerRejectsSocketModeOtherThan0600(t *testing.T) {
	socketPath := shortSocketPath(t, "badperm")
	cfg := &config.Config{
		Listen: config.ListenConfig{
			Socket:     socketPath,
			SocketMode: "0660",
		},
	}

	ln, err := newServeDeps().createListener(cfg)
	if err == nil {
		ln.Close()
		t.Fatal("expected createListener() to fail for unsupported socket_mode")
	}
	if !strings.Contains(err.Error(), "listen.socket_mode") {
		t.Fatalf("expected listen.socket_mode error, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"0600"`) {
		t.Fatalf("expected hardened mode hint, got: %v", err)
	}
}

func TestApplyFlagOverrides(t *testing.T) {
	cfg := config.Defaults()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("listen-socket", "", "")
	cmd.Flags().String("upstream-socket", "", "")
	cmd.Flags().String("log-level", "", "")
	cmd.Flags().String("log-format", "", "")
	cmd.Flags().String("deny-response-verbosity", "", "")

	if err := cmd.Flags().Set("listen-socket", "/tmp/sockguard.sock"); err != nil {
		t.Fatalf("set listen-socket: %v", err)
	}
	if err := cmd.Flags().Set("upstream-socket", "/tmp/docker.sock"); err != nil {
		t.Fatalf("set upstream-socket: %v", err)
	}
	if err := cmd.Flags().Set("log-level", "debug"); err != nil {
		t.Fatalf("set log-level: %v", err)
	}
	if err := cmd.Flags().Set("log-format", "text"); err != nil {
		t.Fatalf("set log-format: %v", err)
	}
	if err := cmd.Flags().Set("deny-response-verbosity", "minimal"); err != nil {
		t.Fatalf("set deny-response-verbosity: %v", err)
	}

	if err := applyFlagOverrides(cmd, &cfg); err != nil {
		t.Fatalf("applyFlagOverrides() error = %v", err)
	}
	if cfg.Listen.Socket != "/tmp/sockguard.sock" {
		t.Fatalf("listen socket = %q, want %q", cfg.Listen.Socket, "/tmp/sockguard.sock")
	}
	if cfg.Upstream.Socket != "/tmp/docker.sock" {
		t.Fatalf("upstream socket = %q, want %q", cfg.Upstream.Socket, "/tmp/docker.sock")
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("log level = %q, want %q", cfg.Log.Level, "debug")
	}
	if cfg.Log.Format != "text" {
		t.Fatalf("log format = %q, want %q", cfg.Log.Format, "text")
	}
	if cfg.Response.DenyVerbosity != "minimal" {
		t.Fatalf("deny response verbosity = %q, want %q", cfg.Response.DenyVerbosity, "minimal")
	}
}

func TestApplyFlagOverridesGetStringError(t *testing.T) {
	cfg := config.Defaults()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("log-level", 0, "")
	if err := cmd.Flags().Set("log-level", "1"); err != nil {
		t.Fatalf("set log-level: %v", err)
	}

	err := applyFlagOverrides(cmd, &cfg)
	if err == nil {
		t.Fatal("expected applyFlagOverrides to fail when log-level is not a string flag")
	}
	if !strings.Contains(err.Error(), "get log-level flag") {
		t.Fatalf("expected get log-level error, got: %v", err)
	}
}

func TestApplyStringFlagOverride(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("log-level", "", "")
	if err := cmd.Flags().Set("log-level", "debug"); err != nil {
		t.Fatalf("set log-level: %v", err)
	}

	got := "info"
	if err := applyStringFlagOverride(cmd, "log-level", func(v string) {
		got = v
	}); err != nil {
		t.Fatalf("applyStringFlagOverride() error = %v", err)
	}
	if got != "debug" {
		t.Fatalf("applied value = %q, want %q", got, "debug")
	}
}

func TestApplyStringFlagOverrides(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("log-level", "", "")
	cmd.Flags().String("log-format", "", "")
	if err := cmd.Flags().Set("log-level", "debug"); err != nil {
		t.Fatalf("set log-level: %v", err)
	}
	if err := cmd.Flags().Set("log-format", "text"); err != nil {
		t.Fatalf("set log-format: %v", err)
	}

	gotLevel := "info"
	gotFormat := "json"
	err := applyStringFlagOverrides(cmd, []stringFlagOverride{
		{
			name: "log-level",
			set: func(v string) {
				gotLevel = v
			},
		},
		{
			name: "log-format",
			set: func(v string) {
				gotFormat = v
			},
		},
	})
	if err != nil {
		t.Fatalf("applyStringFlagOverrides() error = %v", err)
	}
	if gotLevel != "debug" {
		t.Fatalf("log level = %q, want %q", gotLevel, "debug")
	}
	if gotFormat != "text" {
		t.Fatalf("log format = %q, want %q", gotFormat, "text")
	}
}

func TestApplyStringFlagOverridesReturnsFirstError(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("log-level", 0, "")
	cmd.Flags().String("log-format", "", "")
	if err := cmd.Flags().Set("log-level", "1"); err != nil {
		t.Fatalf("set log-level: %v", err)
	}
	if err := cmd.Flags().Set("log-format", "text"); err != nil {
		t.Fatalf("set log-format: %v", err)
	}

	called := false
	err := applyStringFlagOverrides(cmd, []stringFlagOverride{
		{
			name: "log-level",
			set: func(string) {
				t.Fatal("setter should not be called when GetString fails")
			},
		},
		{
			name: "log-format",
			set: func(string) {
				called = true
			},
		},
	})
	if err == nil {
		t.Fatal("expected applyStringFlagOverrides to fail when the first flag is not a string")
	}
	if !strings.Contains(err.Error(), "get log-level flag") {
		t.Fatalf("expected get log-level error, got: %v", err)
	}
	if called {
		t.Fatal("expected overrides after the first error to be skipped")
	}
}

func TestApplyStringFlagOverrideUnchangedNoOp(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("log-level", "", "")

	called := false
	if err := applyStringFlagOverride(cmd, "log-level", func(string) {
		called = true
	}); err != nil {
		t.Fatalf("applyStringFlagOverride() error = %v", err)
	}
	if called {
		t.Fatal("expected unchanged flag to be ignored")
	}
}

func TestApplyStringFlagOverrideGetStringError(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("log-level", 0, "")
	if err := cmd.Flags().Set("log-level", "1"); err != nil {
		t.Fatalf("set log-level: %v", err)
	}

	err := applyStringFlagOverride(cmd, "log-level", func(string) {})
	if err == nil {
		t.Fatal("expected applyStringFlagOverride to fail when flag is not a string")
	}
	if !strings.Contains(err.Error(), "get log-level flag") {
		t.Fatalf("expected get log-level error, got: %v", err)
	}
}

func TestHealthInterceptor(t *testing.T) {
	healthReached := false
	nextReached := false

	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthReached = true
		w.WriteHeader(http.StatusNoContent)
	})
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextReached = true
		w.WriteHeader(http.StatusTeapot)
	})

	handler := healthInterceptor("/health", healthHandler, nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !healthReached {
		t.Fatal("expected health handler to be reached")
	}
	if nextReached {
		t.Fatal("did not expect next handler to be reached")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHealthInterceptorFallsThrough(t *testing.T) {
	healthReached := false
	nextReached := false

	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthReached = true
		w.WriteHeader(http.StatusNoContent)
	})
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextReached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := healthInterceptor("/health", healthHandler, nextHandler)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if healthReached {
		t.Fatal("did not expect health handler to be reached")
	}
	if !nextReached {
		t.Fatal("expected next handler to be reached")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMetricsInterceptor(t *testing.T) {
	metricsReached := false
	nextReached := false

	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metricsReached = true
		w.WriteHeader(http.StatusNoContent)
	})
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextReached = true
		w.WriteHeader(http.StatusTeapot)
	})

	handler := metricsInterceptor("/metrics", metricsHandler, nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !metricsReached {
		t.Fatal("expected metrics handler to be reached")
	}
	if nextReached {
		t.Fatal("did not expect next handler to be reached")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMetricsInterceptorFallsThrough(t *testing.T) {
	metricsReached := false
	nextReached := false

	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metricsReached = true
		w.WriteHeader(http.StatusNoContent)
	})
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextReached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := metricsInterceptor("/metrics", metricsHandler, nextHandler)

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if metricsReached {
		t.Fatal("did not expect metrics handler to be reached")
	}
	if !nextReached {
		t.Fatal("expected next handler to be reached")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBuildServeHandlerFiltersHijackEndpointsBeforeHijackHandler(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "missing-hijack-upstream")
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/abc/attach?stream=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "request denied by sockguard policy") {
		t.Fatalf("expected denial body, got: %s", rec.Body.String())
	}
}

func TestBuildServeHandlerClientACLWrapsHealthInterceptor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "missing-health-upstream")
	cfg.Log.AccessLog = false
	cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "client IP not allowed") {
		t.Fatalf("expected client ACL denial body, got: %s", rec.Body.String())
	}
}

func TestBuildServeHandlerMetricsEndpointBypassesDockerRules(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "missing-metrics-upstream")
	cfg.Metrics.Enabled = true
	cfg.Log.AccessLog = false

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "sockguard_http_requests_total") {
		t.Fatalf("expected Prometheus metrics body, got: %s", rec.Body.String())
	}
}

func TestBuildServeHandlerClientACLWrapsMetricsInterceptor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "missing-metrics-acl-upstream")
	cfg.Metrics.Enabled = true
	cfg.Log.AccessLog = false
	cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "client IP not allowed") {
		t.Fatalf("expected client ACL denial body, got: %s", rec.Body.String())
	}
}

func TestBuildServeHandlerRedactsProtectedResponsesByDefault(t *testing.T) {
	socketPath := shortSocketPath(t, "response-redaction")
	_ = os.Remove(socketPath)

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{
			"Config":{"Env":["SECRET_TOKEN=shh","PATH=/usr/bin"]},
			"HostConfig":{"Binds":["/srv/secrets:/run/secrets:ro","named-cache:/cache"]},
			"Mounts":[
				{"Type":"bind","Source":"/srv/secrets","Destination":"/run/secrets"},
				{"Type":"volume","Source":"/var/lib/docker/volumes/cache/_data","Destination":"/cache"}
			]
		}`)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc123/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody: %s", err, rec.Body.String())
	}

	configBody, _ := body["Config"].(map[string]any)
	if env, _ := configBody["Env"].([]any); len(env) != 0 {
		t.Fatalf("Config.Env = %#v, want empty redacted array", configBody["Env"])
	}

	hostConfig, _ := body["HostConfig"].(map[string]any)
	binds, _ := hostConfig["Binds"].([]any)
	if gotBind, _ := binds[0].(string); gotBind != "<redacted>:/run/secrets:ro" {
		t.Fatalf("HostConfig.Binds[0] = %q, want %q", gotBind, "<redacted>:/run/secrets:ro")
	}
	if gotBind, _ := binds[1].(string); gotBind != "named-cache:/cache" {
		t.Fatalf("HostConfig.Binds[1] = %q, want named volume bind unchanged", gotBind)
	}

	mounts, _ := body["Mounts"].([]any)
	for i, mountValue := range mounts {
		mount, _ := mountValue.(map[string]any)
		if gotSource, _ := mount["Source"].(string); gotSource != "<redacted>" {
			t.Fatalf("Mounts[%d].Source = %q, want %q", i, gotSource, "<redacted>")
		}
	}
}

func TestBuildServeHandlerAppliesAssignedClientProfile(t *testing.T) {
	socketPath := shortSocketPath(t, "profile-upstream")
	_ = os.Remove(socketPath)

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			t.Fatalf("path = %q, want /_ping", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "readonly",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "profile deny"},
			},
		},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "readonly", CIDRs: []string{"192.0.2.0/24"}},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != "OK" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "OK")
	}
}

func TestBuildServeHandlerAppliesAssignedClientVisibilityProfile(t *testing.T) {
	socketPath := shortSocketPath(t, "visibility-upstream")
	_ = os.Remove(socketPath)

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Fatalf("path = %q, want /containers/json", r.URL.Path)
		}
		filters := r.URL.Query().Get("filters")
		if !strings.Contains(filters, "com.sockguard.visible=true") {
			t.Fatalf("filters = %q, want default visibility label", filters)
		}
		if !strings.Contains(filters, "com.sockguard.client=watchtower") {
			t.Fatalf("filters = %q, want profile visibility label", filters)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[]`)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Response.VisibleResourceLabels = []string{"com.sockguard.visible=true"}
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "watchtower",
			Response: config.ClientProfileResponseConfig{
				VisibleResourceLabels: []string{"com.sockguard.client=watchtower"},
			},
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/json"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "profile deny"},
			},
		},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "watchtower", CIDRs: []string{"192.0.2.0/24"}},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != "[]" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "[]")
	}
}

func TestBuildServeHandlerGeneratesTrustedRequestIDWithoutAccessLog(t *testing.T) {
	socketPath := shortSocketPath(t, "request-id-upstream")
	_ = os.Remove(socketPath)

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"request_id":"`+r.Header.Get("X-Request-ID")+`"}`)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/info"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header.Set("X-Request-ID", "client-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody: %s", err, rec.Body.String())
	}

	generatedID := body["request_id"]
	if generatedID == "" {
		t.Fatal("expected generated request id upstream, got empty string")
	}
	if generatedID == "client-123" {
		t.Fatalf("expected generated request id to replace caller header, got %q", generatedID)
	}
	if got := rec.Header().Get("X-Request-Id"); got != generatedID {
		t.Fatalf("response X-Request-Id = %q, want %q", got, generatedID)
	}
}

func TestBuildServeHandlerEmitsAuditEventWhenEnabled(t *testing.T) {
	socketPath := shortSocketPath(t, "audit-upstream")
	_ = os.Remove(socketPath)

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Log.Audit.Enabled = true
	cfg.Ownership.Owner = "ci-job-123"

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/info"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	var auditBuf bytes.Buffer
	auditLogger := logging.NewAuditLogger(&auditBuf)

	handler := buildServeHandler(&cfg, newDiscardLogger(), auditLogger, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/v1.45/info", nil)
	req.RemoteAddr = "198.51.100.10:4444"
	req.Header.Set("X-Request-ID", "client-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	closeAuditLoggerForTest(t, auditLogger)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, auditBuf.String())
	}
	if got := event["decision"]; got != "allow" {
		t.Fatalf("decision = %#v, want %q", got, "allow")
	}
	if got := event["normalized_path"]; got != "/info" {
		t.Fatalf("normalized_path = %#v, want %q", got, "/info")
	}
	if got := event["status"]; got != float64(http.StatusOK) {
		t.Fatalf("status = %#v, want %d", got, http.StatusOK)
	}
	if got := event["client_request_id"]; got != "client-123" {
		t.Fatalf("client_request_id = %#v, want %q", got, "client-123")
	}
	if got := event["transport_listener"]; got != "tcp" {
		t.Fatalf("transport_listener = %#v, want %q", got, "tcp")
	}
	requestID, _ := event["request_id"].(string)
	if requestID == "" || requestID == "client-123" {
		t.Fatalf("request_id = %#v, want generated canonical id", event["request_id"])
	}
	ownership, ok := event["ownership"].(map[string]any)
	if !ok {
		t.Fatalf("ownership = %#v, want object", event["ownership"])
	}
	if got := ownership["owner"]; got != "ci-job-123" {
		t.Fatalf("ownership.owner = %#v, want %q", got, "ci-job-123")
	}
}

func TestWithAuditLogUsesConfiguredUnixListener(t *testing.T) {
	cfg := config.Defaults()
	cfg.Listen.Socket = "/var/run/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Log.Audit.Enabled = true

	var auditBuf bytes.Buffer
	auditLogger := logging.NewAuditLogger(&auditBuf)
	handler := withAuditLog(auditLogger, &cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = "198.51.100.10:4444"
	handler.ServeHTTP(httptest.NewRecorder(), req)
	closeAuditLoggerForTest(t, auditLogger)

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, auditBuf.String())
	}
	if got := event["transport_listener"]; got != "unix" {
		t.Fatalf("transport_listener = %#v, want %q", got, "unix")
	}
}

func TestBuildServeHandlerAuditEventIncludesSelectedProfile(t *testing.T) {
	socketPath := shortSocketPath(t, "audit-profile-upstream")
	_ = os.Remove(socketPath)

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			t.Fatalf("path = %q, want /_ping", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Log.Audit.Enabled = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "readonly",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "profile deny"},
			},
		},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "readonly", CIDRs: []string{"192.0.2.0/24"}},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	var auditBuf bytes.Buffer
	auditLogger := logging.NewAuditLogger(&auditBuf)
	handler := buildServeHandler(&cfg, newDiscardLogger(), auditLogger, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	closeAuditLoggerForTest(t, auditLogger)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, auditBuf.String())
	}
	if got := event["selected_profile"]; got != "readonly" {
		t.Fatalf("selected_profile = %#v, want %q", got, "readonly")
	}
	if got := event["reason_code"]; got != "matched_allow_rule" {
		t.Fatalf("reason_code = %#v, want %q", got, "matched_allow_rule")
	}
	if got := event["status"]; got != float64(http.StatusOK) {
		t.Fatalf("status = %#v, want %d", got, http.StatusOK)
	}
}

func TestBuildServeHandlerAuditEventCapturesMalformedOwnershipRequest(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "audit-malformed-upstream")
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Log.Audit.Enabled = true
	cfg.Ownership.Owner = "ci-job-123"

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	var auditBuf bytes.Buffer
	auditLogger := logging.NewAuditLogger(&auditBuf)
	handler := buildServeHandler(&cfg, newDiscardLogger(), auditLogger, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/create", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	closeAuditLoggerForTest(t, auditLogger)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, auditBuf.String())
	}
	if got := event["decision"]; got != "deny" {
		t.Fatalf("decision = %#v, want %q", got, "deny")
	}
	if got := event["reason_code"]; got != "owner_request_invalid" {
		t.Fatalf("reason_code = %#v, want %q", got, "owner_request_invalid")
	}
	if got := event["status"]; got != float64(http.StatusBadRequest) {
		t.Fatalf("status = %#v, want %d", got, http.StatusBadRequest)
	}
}

func TestBuildServeHandlerAuditEventCapturesUpstreamFailure(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "audit-upstream-missing")
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Log.Audit.Enabled = true

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	var auditBuf bytes.Buffer
	auditLogger := logging.NewAuditLogger(&auditBuf)
	handler := buildServeHandler(&cfg, newDiscardLogger(), auditLogger, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	closeAuditLoggerForTest(t, auditLogger)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, auditBuf.String())
	}
	if got := event["decision"]; got != "allow" {
		t.Fatalf("decision = %#v, want %q", got, "allow")
	}
	if got := event["reason_code"]; got != "upstream_socket_unreachable" {
		t.Fatalf("reason_code = %#v, want %q", got, "upstream_socket_unreachable")
	}
	if got := event["status"]; got != float64(http.StatusBadGateway) {
		t.Fatalf("status = %#v, want %d", got, http.StatusBadGateway)
	}
}

func TestBuildServeHandlerLayers(t *testing.T) {
	cfg := config.Defaults()
	cfg.Health.Enabled = true
	cfg.Metrics.Enabled = true
	cfg.Log.AccessLog = true
	cfg.Log.Audit.Enabled = true

	auditLogger := logging.NewAuditLogger(io.Discard)
	t.Cleanup(func() { _ = auditLogger.Close() })

	got := serveHandlerLayerNames(buildServeHandlerLayers(&cfg, newDiscardLogger(), auditLogger, nil, newServeTestDeps(), nil))
	want := []string{
		"withHijack",
		"withOwnership",
		"withVisibility",
		"withFilter",
		"withHealth",
		"withMetricsEndpoint",
		"withClientACL",
		"withMetrics",
		"withRequestID",
		"withAuditLog",
		"withAccessLog",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("layer names = %#v, want %#v", got, want)
	}

	cfg.Health.Enabled = false
	cfg.Metrics.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Log.Audit.Enabled = false

	got = serveHandlerLayerNames(buildServeHandlerLayers(&cfg, newDiscardLogger(), nil, nil, newServeTestDeps(), nil))
	want = []string{
		"withHijack",
		"withOwnership",
		"withVisibility",
		"withFilter",
		"withClientACL",
		"withRequestID",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("layer names without optional middleware = %#v, want %#v", got, want)
	}
}

func TestListenerAddr(t *testing.T) {
	withSocket := &config.Config{
		Listen: config.ListenConfig{
			Socket:  "/var/run/sockguard.sock",
			Address: "127.0.0.1:2375",
		},
	}
	if got := listenerAddr(withSocket); got != "unix:/var/run/sockguard.sock" {
		t.Fatalf("listenerAddr(withSocket) = %q, want %q", got, "unix:/var/run/sockguard.sock")
	}

	withTCP := &config.Config{
		Listen: config.ListenConfig{
			Address: "127.0.0.1:2375",
		},
	}
	if got := listenerAddr(withTCP); got != "tcp://127.0.0.1:2375" {
		t.Fatalf("listenerAddr(withTCP) = %q, want %q", got, "tcp://127.0.0.1:2375")
	}
}

func serveHandlerLayerNames(layers []serveHandlerLayer) []string {
	names := make([]string, 0, len(layers))
	for _, layer := range layers {
		names = append(names, layer.name)
	}
	return names
}

func TestFullMiddlewareChainIntegration(t *testing.T) {
	allowPing, err := filter.CompileRule(filter.Rule{
		Methods: []string{http.MethodGet},
		Pattern: "/_ping",
		Action:  filter.ActionAllow,
		Index:   0,
	})
	if err != nil {
		t.Fatalf("compile allowPing rule: %v", err)
	}
	denyAll, err := filter.CompileRule(filter.Rule{
		Methods: []string{"*"},
		Pattern: "/**",
		Action:  filter.ActionDeny,
		Reason:  "deny all",
		Index:   1,
	})
	if err != nil {
		t.Fatalf("compile denyAll rule: %v", err)
	}
	rules := []*filter.CompiledRule{allowPing, denyAll}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	upstreamHits := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	})

	healthHits := 0
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthHits++
		w.WriteHeader(http.StatusNoContent)
	})

	var handler http.Handler = upstream
	handler = filter.Middleware(rules, logger)(handler)
	handler = healthInterceptor("/health", healthHandler, handler)
	handler = logging.RequestIDMiddleware()(handler)
	handler = logging.AccessLogMiddleware(logger)(handler)

	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusNoContent {
		t.Fatalf("health status = %d, want %d", healthRec.Code, http.StatusNoContent)
	}
	if healthHits != 1 {
		t.Fatalf("health hits = %d, want 1", healthHits)
	}
	if upstreamHits != 0 {
		t.Fatalf("upstream hits after health = %d, want 0", upstreamHits)
	}

	allowReq := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	allowRec := httptest.NewRecorder()
	handler.ServeHTTP(allowRec, allowReq)
	if allowRec.Code != http.StatusOK {
		t.Fatalf("allow status = %d, want %d", allowRec.Code, http.StatusOK)
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits after allow = %d, want 1", upstreamHits)
	}

	denyReq := httptest.NewRequest(http.MethodPost, "/v1.45/containers/create", nil)
	denyRec := httptest.NewRecorder()
	handler.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("deny status = %d, want %d", denyRec.Code, http.StatusForbidden)
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits after deny = %d, want 1", upstreamHits)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"msg":"request"`) {
		t.Fatalf("expected request log event, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"msg":"request_denied"`) {
		t.Fatalf("expected request_denied log event, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"normalized_path":"/containers/create"`) {
		t.Fatalf("expected normalized path in denied log, got: %s", logOutput)
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	server := newHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	if server.ReadTimeout != 0 {
		t.Fatalf("ReadTimeout = %v, want 0", server.ReadTimeout)
	}
	if server.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %v, want 0", server.WriteTimeout)
	}
	if server.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %v, want > 0", server.ReadHeaderTimeout)
	}
	if server.ReadHeaderTimeout != readHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", server.ReadHeaderTimeout, readHeaderTimeout)
	}
	if server.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout = %v, want > 0", server.IdleTimeout)
	}
	if server.IdleTimeout != idleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", server.IdleTimeout, idleTimeout)
	}
	if server.MaxHeaderBytes != maxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, maxHeaderBytes)
	}
	if server.ConnContext == nil {
		t.Fatal("ConnContext is nil, want client identity capture hook")
	}
}

func TestIsWildcardTCPBind(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{address: ":2375", want: true},
		{address: "0.0.0.0:2375", want: true},
		{address: "[::]:2375", want: true},
		{address: "127.0.0.1:2375", want: false},
		{address: "localhost:2375", want: false},
		{address: "[::1]:2375", want: false},
		{address: "192.168.1.10:2375", want: false},
		{address: "invalid", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := isWildcardTCPBind(tt.address); got != tt.want {
				t.Fatalf("isWildcardTCPBind(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

// isWildcardTCPBind is a test-only helper that classifies an address as a
// wildcard TCP bind (empty host, 0.0.0.0, or ::). Production code never calls
// it — the guardrail that cares about wildcard binds lives elsewhere — but
// the classification logic is useful enough for test coverage that we keep
// it defined here rather than inlined per test case. Move back into
// production code only if a real caller appears.
func isWildcardTCPBind(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
