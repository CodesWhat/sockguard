package httpjson

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()

	err := Write(rec, http.StatusBadGateway, map[string]string{"message": "upstream unreachable"})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["message"] != "upstream unreachable" {
		t.Fatalf("message = %q, want upstream unreachable", body["message"])
	}
}

type trackingWriter struct {
	header http.Header
	status int
	body   []byte
}

func (w *trackingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *trackingWriter) WriteHeader(status int) {
	w.status = status
}

func (w *trackingWriter) Write(p []byte) (int, error) {
	w.body = append(w.body, p...)
	return len(p), nil
}

func TestWriteDoesNotCommitOnEncodeError(t *testing.T) {
	err := Write(&trackingWriter{}, http.StatusForbidden, map[string]any{
		"broken": func() {},
	})
	if err == nil {
		t.Fatal("expected encode error")
	}
	var unsupported *json.UnsupportedTypeError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want UnsupportedTypeError", err)
	}

	w := &trackingWriter{}
	err = Write(w, http.StatusForbidden, map[string]any{
		"broken": func() {},
	})
	if err == nil {
		t.Fatal("expected encode error")
	}
	if w.status != 0 {
		t.Fatalf("status = %d, want 0", w.status)
	}
	if got := w.Header().Get("Content-Type"); got != "" {
		t.Fatalf("Content-Type = %q, want empty", got)
	}
	if len(w.body) != 0 {
		t.Fatalf("body length = %d, want 0", len(w.body))
	}
}
