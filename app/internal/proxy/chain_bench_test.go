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

// permissivePolicyConfig returns a PolicyConfig wide enough that bench chains
// can exercise allowed POST endpoints without the inspector denying.
func permissivePolicyConfig() filter.PolicyConfig {
	return filter.PolicyConfig{
		ContainerCreate: filter.ContainerCreateOptions{
			AllowPrivileged:        true,
			AllowHostNetwork:       true,
			AllowHostPID:           true,
			AllowHostIPC:           true,
			AllowHostUserNS:        true,
			AllowedBindMounts:      []string{"/"},
			AllowAllDevices:        true,
			AllowDeviceRequests:    true,
			AllowDeviceCgroupRules: true,
			AllowAllCapabilities:   true,
			AllowSysctls:           true,
		},
		Exec: filter.ExecOptions{
			AllowPrivileged: true,
			AllowRootUser:   true,
			AllowedCommands: [][]string{{"echo", "hi"}},
		},
	}
}

// buildChain replicates the production middleware stack from buildServeHandler,
// minus health (not exercised in these benches). Inspect policies are wired
// permissively so POST endpoints reach the upstream instead of being denied.
func buildChain(tb testing.TB, sock string) http.Handler {
	tb.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	rules := []filter.Rule{
		{Methods: []string{"GET"}, Pattern: "/_ping", Action: filter.ActionAllow, Index: 0},
		{Methods: []string{"GET"}, Pattern: "/containers/json", Action: filter.ActionAllow, Index: 1},
		{Methods: []string{"GET"}, Pattern: "/containers/*/json", Action: filter.ActionAllow, Index: 2},
		{Methods: []string{"GET"}, Pattern: "/networks/**", Action: filter.ActionAllow, Index: 3},
		{Methods: []string{"POST"}, Pattern: "/containers/create", Action: filter.ActionAllow, Index: 4},
		{Methods: []string{"POST"}, Pattern: "/containers/*/exec", Action: filter.ActionAllow, Index: 5},
		{Methods: []string{"POST"}, Pattern: "/containers/*/start", Action: filter.ActionAllow, Index: 6},
		{Methods: []string{"*"}, Pattern: "/**", Action: filter.ActionDeny, Index: 7, Reason: "default deny"},
	}
	compiled := make([]*filter.CompiledRule, len(rules))
	for i, r := range rules {
		cr, err := filter.CompileRule(r)
		if err != nil {
			tb.Fatalf("compile rule %d: %v", i, err)
		}
		compiled[i] = cr
	}

	opts := filter.Options{PolicyConfig: permissivePolicyConfig()}

	var handler http.Handler = New(sock, logger)
	handler = HijackHandler(sock, logger, handler)
	handler = filter.MiddlewareWithOptions(compiled, logger, opts)(handler)
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

// BenchmarkChainPostContainerCreate exercises the full chain including the
// containers/create body inspector. The body is a realistic spec that the
// permissive policy in buildChain accepts.
func BenchmarkChainPostContainerCreate(b *testing.B) {
	sock, cleanup := newMockDockerSocket(b)
	defer cleanup()

	handler := buildChain(b, sock)
	body := []byte(`{
		"Image":"alpine:3.19",
		"Cmd":["sh","-c","echo hi"],
		"Labels":{"app":"web"},
		"HostConfig":{
			"Memory":67108864,
			"NetworkMode":"bridge",
			"RestartPolicy":{"Name":"unless-stopped"},
			"PortBindings":{"80/tcp":[{"HostPort":"8080"}]},
			"Binds":["/srv/data:/data:ro"]
		}
	}`)

	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1.45/containers/create?name=web", bytes.NewReader(body))
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
		req := httptest.NewRequest("POST", "/v1.45/containers/create?name=web", bytes.NewReader(body))
		req.RemoteAddr = "unix"
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkChainParallelGet exercises concurrent GET throughput through the
// full chain — surfaces lock contention introduced (or fixed) by recent
// lock-free perf work.
func BenchmarkChainParallelGet(b *testing.B) {
	sock, cleanup := newMockDockerSocket(b)
	defer cleanup()

	handler := buildChain(b, sock)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest("GET", "/v1.45/containers/json", nil)
		req.RemoteAddr = "unix"
		for pb.Next() {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}
	})
}

// BenchmarkChainParallelDenied measures concurrent deny throughput. Deny is
// the cheapest path through the middleware (no upstream dial); lock
// contention shows up as a flat ceiling here.
func BenchmarkChainParallelDenied(b *testing.B) {
	sock, cleanup := newMockDockerSocket(b)
	defer cleanup()

	handler := buildChain(b, sock)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest("DELETE", "/containers/abc123", nil)
		req.RemoteAddr = "unix"
		for pb.Next() {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}
	})
}
