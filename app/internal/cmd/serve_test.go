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

	ln, err := listenUnixSocket(path)
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

	ln, err := listenUnixSocket(path)
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

	_, err := listenUnixSocket(path)
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
