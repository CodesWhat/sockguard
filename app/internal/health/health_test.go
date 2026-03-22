package health

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthReachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	handler := Handler(sock, time.Now())

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

func TestHealthUnreachable(t *testing.T) {
	handler := Handler("/nonexistent/socket.sock", time.Now())

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
