package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

// shortSocketPath returns a short /tmp socket path that fits within macOS's
// 104-byte sun_path limit (t.TempDir() paths are too long on macOS).
func shortSocketPath(t *testing.T, label string) string {
	t.Helper()
	path := fmt.Sprintf("/tmp/dp-%s-%d.sock", label, os.Getpid())
	t.Cleanup(func() { os.Remove(path) })
	return path
}

func TestIsAddrInUse(t *testing.T) {
	if !isAddrInUse(syscall.EADDRINUSE) {
		t.Fatal("expected EADDRINUSE to be detected")
	}
	if isAddrInUse(errors.New("other")) {
		t.Fatal("did not expect non-EADDRINUSE error to be detected")
	}
}

func TestListenUnixSocketCreatesNewSocket(t *testing.T) {
	path := shortSocketPath(t, "new")

	ln, err := listenUnixSocket(path, 0o600)
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

	ln, err := listenUnixSocket(path, 0o600)
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

	_, err := listenUnixSocket(path, 0o600)
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

	ln, err := createListener(cfg)
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

	originalUmask := syscallUmask
	currentMask := 0o022
	var calls []int
	syscallUmask = func(mask int) int {
		previous := currentMask
		currentMask = mask
		calls = append(calls, mask)
		return previous
	}
	t.Cleanup(func() {
		syscallUmask = originalUmask
	})

	ln, err := createListener(cfg)
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
	originalUmask := syscallUmask
	var mu sync.Mutex
	currentMask := 0o022
	syscallUmask = func(mask int) int {
		mu.Lock()
		defer mu.Unlock()
		previous := currentMask
		currentMask = mask
		return previous
	}
	t.Cleanup(func() {
		syscallUmask = originalUmask
	})

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			socketPath := shortSocketPath(t, fmt.Sprintf("conc%d", id))
			_, err := withUmask(0o177, func() (net.Listener, error) {
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

	ln, err := createListener(cfg)
	if err != nil {
		t.Fatalf("createListener() error = %v", err)
	}
	defer ln.Close()

	if ln.Addr().Network() != "tcp" {
		t.Fatalf("listener network = %q, want tcp", ln.Addr().Network())
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

	ln, err := createListener(cfg)
	if err == nil {
		ln.Close()
		t.Fatal("expected createListener() to fail for invalid socket_mode")
	}
	if !strings.Contains(err.Error(), "invalid socket_mode") {
		t.Fatalf("expected invalid socket_mode error, got: %v", err)
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
	if got := listenerAddr(withTCP); got != "tcp:127.0.0.1:2375" {
		t.Fatalf("listenerAddr(withTCP) = %q, want %q", got, "tcp:127.0.0.1:2375")
	}
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

func TestNewHTTPServerSetsReadHeaderTimeout(t *testing.T) {
	server := newHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	if server.ReadTimeout != 0 {
		t.Fatalf("ReadTimeout = %v, want 0", server.ReadTimeout)
	}
	if server.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %v, want > 0", server.ReadHeaderTimeout)
	}
	if server.ReadHeaderTimeout != readHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", server.ReadHeaderTimeout, readHeaderTimeout)
	}
}
