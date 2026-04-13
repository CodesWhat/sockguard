package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

// newMockDockerSocket starts an HTTP server on a temporary unix socket that
// serves trivial responses for /containers/json and /containers/*/exec.
// The returned cleanup should be deferred.
func newMockDockerSocket(tb testing.TB) (string, func()) {
	tb.Helper()
	dir, err := os.MkdirTemp("", "sockguard-bench-*")
	if err != nil {
		tb.Fatalf("mktmp: %v", err)
	}
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		tb.Fatalf("listen unix: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Id":"abc","State":"running"}]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// catch-all for POST /containers/{id}/exec etc.
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"exec-abc"}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	return sock, func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.RemoveAll(dir)
	}
}

// buildChain replicates the production middleware stack from buildServeHandler,
// minus health (not exercised in these benches).
func buildChain(tb testing.TB, sock string) http.Handler {
	tb.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	rules := []filter.Rule{
		{Methods: []string{"GET"}, Pattern: "/_ping", Action: filter.ActionAllow, Index: 0},
		{Methods: []string{"GET"}, Pattern: "/containers/json", Action: filter.ActionAllow, Index: 1},
		{Methods: []string{"GET"}, Pattern: "/containers/*/json", Action: filter.ActionAllow, Index: 2},
		{Methods: []string{"GET"}, Pattern: "/networks/**", Action: filter.ActionAllow, Index: 3},
		{Methods: []string{"POST"}, Pattern: "/containers/*/exec", Action: filter.ActionAllow, Index: 4},
		{Methods: []string{"POST"}, Pattern: "/containers/*/start", Action: filter.ActionAllow, Index: 5},
		{Methods: []string{"*"}, Pattern: "/**", Action: filter.ActionDeny, Index: 6, Reason: "default deny"},
	}
	compiled := make([]*filter.CompiledRule, len(rules))
	for i, r := range rules {
		cr, err := filter.CompileRule(r)
		if err != nil {
			tb.Fatalf("compile rule %d: %v", i, err)
		}
		compiled[i] = cr
	}

	var handler http.Handler = New(sock, logger)
	handler = HijackHandler(sock, logger, handler)
	handler = filter.Middleware(compiled, logger)(handler)
	handler = logging.AccessLogMiddleware(logger)(handler)
	return handler
}

// nopResponseWriter is a cheap http.ResponseWriter that also satisfies
// http.Flusher / http.Hijacker via the embedded httptest.ResponseRecorder...
// but we actually need a flusher because ReverseProxy uses it. Use a recorder.
func BenchmarkChainGetContainersJSON(b *testing.B) {
	sock, cleanup := newMockDockerSocket(b)
	defer cleanup()

	handler := buildChain(b, sock)
	req := httptest.NewRequest("GET", "/v1.45/containers/json", nil)
	req.RemoteAddr = "unix"

	// Warmup one request so idle conns are established.
	{
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("warmup status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkChainPostContainerExec(b *testing.B) {
	sock, cleanup := newMockDockerSocket(b)
	defer cleanup()

	handler := buildChain(b, sock)
	body := []byte(`{"AttachStdin":false,"Cmd":["echo","hi"]}`)

	// Warmup.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1.45/containers/abc123/exec", bytes.NewReader(body))
		req.RemoteAddr = "unix"
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("warmup status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1.45/containers/abc123/exec", bytes.NewReader(body))
		req.RemoteAddr = "unix"
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkChainDenied measures the fast-path deny at the filter layer
// (no upstream dial).
func BenchmarkChainDenied(b *testing.B) {
	sock, cleanup := newMockDockerSocket(b)
	defer cleanup()

	handler := buildChain(b, sock)
	req := httptest.NewRequest("DELETE", "/containers/abc123", nil)
	req.RemoteAddr = "unix"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
