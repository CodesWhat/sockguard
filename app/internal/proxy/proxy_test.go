package proxy

import (
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

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
	socketPath := fmt.Sprintf("/tmp/dp-test-proxy-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-goaway-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-proxy-concurrent-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
