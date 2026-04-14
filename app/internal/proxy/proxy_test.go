package proxy

import (
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/responsefilter"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tempSocketPath returns a unique /tmp unix-socket path for a test. Uses
// os.CreateTemp so parallel tests and interrupted prior runs never collide,
// and /tmp (not t.TempDir()) to keep the path under macOS's 104-byte
// sun_path limit. t.Cleanup removes the path after the test.
func tempSocketPath(t *testing.T, label string) string {
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

func TestNew_ErrorHandler(t *testing.T) {
	// Point at a socket that does not exist so the error handler fires.
	socketPath := "/tmp/dp-nonexistent-socket.sock"
	rp := New(socketPath, testLogger())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var body httpjson.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body.Message != "upstream Docker socket unreachable" {
		t.Errorf("unexpected message: %s", body.Message)
	}
	if strings.Contains(rec.Body.String(), socketPath) {
		t.Fatalf("response leaked upstream socket path: %q", rec.Body.String())
	}
}

func TestNew_ErrorHandlerEncodeFailure(t *testing.T) {
	rp := New("/tmp/does-not-matter.sock", testLogger())
	writer := &erroringResponseWriter{}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	rp.ErrorHandler(writer, req, errors.New("boom"))

	if writer.status != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusBadGateway)
	}
}

func TestNew_ErrorHandlerLogsRequestCorrelation(t *testing.T) {
	var logBuf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rp := New("/tmp/does-not-matter.sock", logger)

	meta := &logging.RequestMeta{
		Decision: "allow",
		Rule:     1,
		NormPath: "/info",
	}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/info", nil)
	req.Header.Set("X-Request-ID", "req-123")
	req = req.WithContext(logging.WithMeta(req.Context(), meta))

	rec := httptest.NewRecorder()
	rp.ErrorHandler(rec, req, errors.New("dial boom"))

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"msg":"upstream request failed"`) {
		t.Fatalf("expected upstream failure log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"request_id":"req-123"`) {
		t.Fatalf("expected request_id in proxy error log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"normalized_path":"/info"`) {
		t.Fatalf("expected normalized_path in proxy error log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"decision":"allow"`) {
		t.Fatalf("expected decision in proxy error log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"rule":1`) {
		t.Fatalf("expected rule in proxy error log, got: %s", logOutput)
	}
}

// startMockDocker creates a Unix socket with an HTTP server that echoes
// the request method and path as JSON. Returns the socket path; the
// server is shut down via t.Cleanup.
func startMockDocker(t *testing.T) string {
	t.Helper()
	socketPath := tempSocketPath(t, "proxy")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"method":%q,"path":%q}`, r.Method, r.URL.Path)
		}),
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return socketPath
}

func TestNew_ForwardsRequests(t *testing.T) {
	socketPath := startMockDocker(t)
	rp := New(socketPath, testLogger())

	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/containers/json"},
		{"GET", "/v1.45/info"},
		{"POST", "/containers/create"},
		{"DELETE", "/containers/abc123"},
		{"HEAD", "/_ping"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
			}

			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("expected Content-Type application/json, got %s", ct)
			}

			// HEAD responses have no body
			if tt.method == "HEAD" {
				return
			}

			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("invalid JSON: %v — body: %s", err, rec.Body.String())
			}
			if body["method"] != tt.method {
				t.Errorf("upstream saw method %q, want %q", body["method"], tt.method)
			}
			if body["path"] != tt.path {
				t.Errorf("upstream saw path %q, want %q", body["path"], tt.path)
			}
		})
	}
}

func TestNew_PreservesResponseBody(t *testing.T) {
	socketPath := startMockDocker(t)
	rp := New(socketPath, testLogger())

	req := httptest.NewRequest("GET", "/version", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected non-empty response body")
	}
	if !strings.Contains(string(body), "/version") {
		t.Errorf("expected body to contain path, got: %s", string(body))
	}
}

func TestNewWithOptions_RedactsProtectedResponses(t *testing.T) {
	socketPath := tempSocketPath(t, "response-filter")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}),
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	rp := NewWithOptions(socketPath, testLogger(), Options{
		ModifyResponse: responsefilter.New(responsefilter.Options{
			RedactContainerEnv: true,
			RedactMountPaths:   true,
		}).ModifyResponse,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc123/json", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody: %s", err, rec.Body.String())
	}

	config, _ := body["Config"].(map[string]any)
	if env, _ := config["Env"].([]any); len(env) != 0 {
		t.Fatalf("Config.Env = %#v, want empty redacted array", config["Env"])
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

func TestNewWithOptions_RejectsProtectedResponsesThatCannotBeSanitized(t *testing.T) {
	socketPath := tempSocketPath(t, "response-reject")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"Config":`)
		}),
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	rp := NewWithOptions(socketPath, testLogger(), Options{
		ModifyResponse: responsefilter.New(responsefilter.Options{
			RedactContainerEnv: true,
		}).ModifyResponse,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc123/json", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}

	var body httpjson.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody: %s", err, rec.Body.String())
	}
	if body.Message != "upstream Docker response rejected by sockguard policy" {
		t.Fatalf("message = %q, want %q", body.Message, "upstream Docker response rejected by sockguard policy")
	}
}

func TestNew_UpstreamDown(t *testing.T) {
	// Point at a socket that does not exist.
	socketPath := "/tmp/dp-nonexistent-socket.sock"
	rp := New(socketPath, testLogger())

	req := httptest.NewRequest("GET", "/info", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}

	var body httpjson.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body.Message != "upstream Docker socket unreachable" {
		t.Errorf("unexpected message: %s", body.Message)
	}
	if strings.Contains(rec.Body.String(), socketPath) {
		t.Fatalf("response leaked upstream socket path: %q", rec.Body.String())
	}
}

func TestNew_UpstreamGoesAway(t *testing.T) {
	// Start a real upstream, then shut it down before the request.
	socketPath := tempSocketPath(t, "goaway")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go srv.Serve(ln)

	// Shut it down immediately — socket file remains but nothing is listening.
	srv.Close()
	ln.Close()
	os.Remove(socketPath)

	rp := New(socketPath, testLogger())
	req := httptest.NewRequest("GET", "/info", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestNew_ConcurrentRequestsRemainIsolated(t *testing.T) {
	socketPath := tempSocketPath(t, "proxy-concurrent")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(
				w,
				`{"method":%q,"path":%q,"request_id":%q}`,
				r.Method,
				r.URL.Path,
				r.Header.Get("X-Request-ID"),
			)
		}),
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	rp := New(socketPath, testLogger())

	const requestCount = 32

	type result struct {
		method string
		path   string
		id     string
		err    error
	}

	results := make(chan result, requestCount)
	var wg sync.WaitGroup

	for i := 0; i < requestCount; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			method := http.MethodGet
			if i%2 == 1 {
				method = http.MethodPost
			}
			path := fmt.Sprintf("/containers/%d/json", i)
			id := strconv.Itoa(i)

			req := httptest.NewRequest(method, path, nil)
			req.Header.Set("X-Request-ID", id)
			rec := httptest.NewRecorder()

			rp.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				results <- result{err: fmt.Errorf("request %d status = %d, want 200; body: %s", i, rec.Code, rec.Body.String())}
				return
			}

			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				results <- result{err: fmt.Errorf("request %d invalid JSON: %w", i, err)}
				return
			}

			results <- result{
				method: body["method"],
				path:   body["path"],
				id:     body["request_id"],
			}
		}(i)
	}

	wg.Wait()
	close(results)

	seenIDs := make(map[string]bool, requestCount)
	for res := range results {
		if res.err != nil {
			t.Fatal(res.err)
		}
		if seenIDs[res.id] {
			t.Fatalf("duplicate request_id observed in upstream responses: %q", res.id)
		}
		seenIDs[res.id] = true

		expectedMethod := http.MethodGet
		if idNum, err := strconv.Atoi(res.id); err == nil && idNum%2 == 1 {
			expectedMethod = http.MethodPost
		}
		expectedPath := fmt.Sprintf("/containers/%s/json", res.id)

		if res.method != expectedMethod {
			t.Fatalf("response method for request_id %q = %q, want %q", res.id, res.method, expectedMethod)
		}
		if res.path != expectedPath {
			t.Fatalf("response path for request_id %q = %q, want %q", res.id, res.path, expectedPath)
		}
	}

	if len(seenIDs) != requestCount {
		t.Fatalf("observed %d request ids, want %d", len(seenIDs), requestCount)
	}
}

// TestNew_ClientCancelMidResponsePropagates verifies that when a client
// disconnects while the reverse proxy is mid-stream, the cancellation
// propagates to the upstream handler (via req.Context().Done()) and the
// server releases its goroutines instead of leaking them.
func TestNew_ClientCancelMidResponsePropagates(t *testing.T) {
	socketPath := tempSocketPath(t, "cancel-mid-stream")

	upstreamCtx := make(chan struct{}, 1)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	upstream := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("upstream ResponseWriter is not a Flusher")
				return
			}
			flusher.Flush()

			// Write small chunks until the caller's context cancels. If the
			// proxy correctly forwards client disconnects, r.Context().Done()
			// fires and we stop.
			chunk := []byte("tick\n")
			deadline := time.After(5 * time.Second)
			for {
				select {
				case <-r.Context().Done():
					upstreamCtx <- struct{}{}
					return
				case <-deadline:
					t.Error("upstream never saw client context cancel")
					return
				default:
				}
				if _, err := w.Write(chunk); err != nil {
					upstreamCtx <- struct{}{}
					return
				}
				flusher.Flush()
				time.Sleep(5 * time.Millisecond)
			}
		}),
	}
	go func() { _ = upstream.Serve(ln) }()
	t.Cleanup(func() { _ = upstream.Close() })

	rp := New(socketPath, testLogger())
	proxySrv := httptest.NewServer(rp)
	t.Cleanup(proxySrv.Close)

	ctx, cancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxySrv.URL+"/containers/abc/logs?stdout=1&follow=1", nil)
	if err != nil {
		cancel()
		t.Fatalf("new request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("client Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Read one chunk so we know the body is actively streaming, then cancel.
	buf := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		_ = resp.Body.Close()
		cancel()
		t.Fatalf("read first chunk: %v", err)
	}

	cancel()
	_ = resp.Body.Close()

	select {
	case <-upstreamCtx:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream handler did not observe client cancellation within 3s")
	}
}
