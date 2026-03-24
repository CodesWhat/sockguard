package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNew_ErrorHandler(t *testing.T) {
	// Point at a socket that does not exist so the error handler fires.
	rp := New("/tmp/dp-nonexistent-socket.sock", testLogger())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["message"] != "upstream Docker socket unreachable" {
		t.Errorf("unexpected message: %s", body["message"])
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
	rp := New("/tmp/dp-nonexistent-socket.sock", testLogger())

	req := httptest.NewRequest("GET", "/info", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["message"] != "upstream Docker socket unreachable" {
		t.Errorf("unexpected message: %s", body["message"])
	}
	if body["error"] == "" {
		t.Error("expected non-empty error field")
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
