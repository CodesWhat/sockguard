package logging

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLogAllowed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate filter middleware writing to the shared meta
		if m := Meta(r.Context()); m != nil {
			m.Decision = "allow"
			m.Rule = 0
			m.NormPath = "/_ping"
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := AccessLogMiddleware(logger)(inner)

	req := httptest.NewRequest("GET", "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, `"msg":"request"`) {
		t.Errorf("expected msg=request in log output, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"method":"GET"`) {
		t.Errorf("expected method=GET in log output, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"decision":"allow"`) {
		t.Errorf("expected decision=allow in log output, got: %s", logOutput)
	}
}

func TestAccessLogDenied(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := Meta(r.Context()); m != nil {
			m.Decision = "deny"
			m.Rule = 2
			m.Reason = "default deny"
			m.NormPath = "/containers/create"
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"denied"}`))
	})

	handler := AccessLogMiddleware(logger)(inner)

	req := httptest.NewRequest("POST", "/containers/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, `"msg":"request_denied"`) {
		t.Errorf("expected msg=request_denied in log output, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"reason":"default deny"`) {
		t.Errorf("expected reason in log output, got: %s", logOutput)
	}
}

func TestResponseCaptureTracksStatusAndBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	rc := &responseCapture{ResponseWriter: rec, status: http.StatusOK}

	rc.WriteHeader(http.StatusCreated)
	n, err := rc.Write([]byte("hello world"))

	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if rc.status != http.StatusCreated {
		t.Errorf("status = %d, want %d", rc.status, http.StatusCreated)
	}
	if rc.bytes != n {
		t.Errorf("bytes = %d, want %d", rc.bytes, n)
	}
	if rc.bytes != 11 {
		t.Errorf("bytes = %d, want 11", rc.bytes)
	}
}

func TestResponseCaptureFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	rc := &responseCapture{ResponseWriter: rec, status: http.StatusOK}

	rc.Flush()
	if !rec.Flushed {
		t.Error("expected Flush() to delegate to underlying writer")
	}
}

func TestResponseCaptureWriteWithoutWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	rc := &responseCapture{ResponseWriter: rec, status: http.StatusOK}

	n, err := rc.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if rc.status != http.StatusOK {
		t.Errorf("status = %d, want %d", rc.status, http.StatusOK)
	}
	if rc.bytes != n {
		t.Errorf("bytes = %d, want %d", rc.bytes, n)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("recorder status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMetaRoundTrip(t *testing.T) {
	meta := &RequestMeta{Decision: "allow", Rule: 1, Reason: "test", NormPath: "/test"}
	ctx := WithMeta(context.Background(), meta)

	got := Meta(ctx)
	if got == nil {
		t.Fatal("Meta() returned nil")
	}
	if got.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", got.Decision)
	}
	if got.Rule != 1 {
		t.Errorf("Rule = %d, want 1", got.Rule)
	}
	if got.Reason != "test" {
		t.Errorf("Reason = %q, want test", got.Reason)
	}
	if got.NormPath != "/test" {
		t.Errorf("NormPath = %q, want /test", got.NormPath)
	}
}

func TestMetaNilContext(t *testing.T) {
	got := Meta(context.Background())
	if got != nil {
		t.Errorf("Meta() = %v, want nil for empty context", got)
	}
}
