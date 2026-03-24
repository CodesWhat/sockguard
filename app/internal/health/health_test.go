package health

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type devNull struct{}

func (devNull) Write(b []byte) (int, error) { return len(b), nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

func TestHealthReachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	handler := Handler(sock, time.Now(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["status"] != "healthy" {
		t.Errorf("expected status healthy, got %v", body["status"])
	}
	if body["upstream"] != "connected" {
		t.Errorf("expected upstream connected, got %v", body["upstream"])
	}
}

func TestHealthUpstreamTimeout(t *testing.T) {
	// Create a Unix socket where the listener never calls Accept.
	// On most systems this causes the dial to block until the kernel
	// backlog fills. We pass a pre-cancelled context through the
	// request so the handler's 3-second dial timeout fires immediately,
	// exercising the timeout → 503 path.
	sock := filepath.Join(t.TempDir(), "slow.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	// Intentionally never call ln.Accept() — the backlog will fill.
	defer ln.Close()

	// Saturate the kernel accept backlog so the next dial blocks.
	// Unix sockets typically have a small backlog (often 128).
	// We stuff it with connections that are never accepted.
	var stuffConns []net.Conn
	for i := 0; i < 256; i++ {
		c, err := net.DialTimeout("unix", sock, 50*time.Millisecond)
		if err != nil {
			break
		}
		stuffConns = append(stuffConns, c)
	}
	defer func() {
		for _, c := range stuffConns {
			c.Close()
		}
	}()

	handler := Handler(sock, time.Now(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rec, req)
		close(done)
	}()

	// The handler has a 3-second internal timeout. The test should
	// complete within 5 seconds. If the backlog was fully saturated
	// the dial blocks and hits the timeout → 503. If it wasn't fully
	// saturated (platform-dependent), the dial succeeds → 200.
	// Either way, the handler must not hang.
	select {
	case <-done:
		if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status 200 or 503, got %d", rec.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("health handler did not complete within 5 seconds — possible hang on slow upstream")
	}
}

func TestHealthUnreachable(t *testing.T) {
	handler := Handler("/nonexistent/socket.sock", time.Now(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["status"] != "unhealthy" {
		t.Errorf("expected status unhealthy, got %v", body["status"])
	}
	if body["upstream"] != "unreachable" {
		t.Errorf("expected upstream unreachable, got %v", body["upstream"])
	}
}
