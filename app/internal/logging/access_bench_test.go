package logging

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

type benchRW struct {
	header http.Header
	status int
}

func newBenchRW() *benchRW { return &benchRW{header: make(http.Header)} }

func (w *benchRW) Header() http.Header    { return w.header }
func (w *benchRW) WriteHeader(status int) { w.status = status }
func (w *benchRW) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(p), nil
}
func (w *benchRW) reset() {
	clear(w.header)
	w.status = 0
}

// BenchmarkAccessLogAllowed measures the overhead of the access log middleware
// for a simple allow-decision request against a no-op handler.
func BenchmarkAccessLogAllowed(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := Meta(r.Context()); m != nil {
			m.Decision = "allow"
			m.Rule = 4
			m.NormPath = "/containers/json"
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	handler := AccessLogMiddleware(logger)(next)

	req := httptest.NewRequest("GET", "/v1.45/containers/json", nil)
	w := newBenchRW()
	b.ReportAllocs()
	for b.Loop() {
		w.reset()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkAccessLogDenied measures warn-level deny path.
func BenchmarkAccessLogDenied(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := Meta(r.Context()); m != nil {
			m.Decision = "deny"
			m.Rule = -1
			m.Reason = "default deny"
			m.NormPath = "/secrets/foo"
		}
		w.WriteHeader(http.StatusForbidden)
	})
	handler := AccessLogMiddleware(logger)(next)

	req := httptest.NewRequest("DELETE", "/secrets/foo", nil)
	w := newBenchRW()
	b.ReportAllocs()
	for b.Loop() {
		w.reset()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkAccessLogDiscard measures the case where the logger level suppresses output.
// Useful for showing the floor cost of context injection + pooling.
func BenchmarkAccessLogDiscard(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := Meta(r.Context()); m != nil {
			m.Decision = "allow"
			m.Rule = 0
		}
	})
	handler := AccessLogMiddleware(logger)(next)

	req := httptest.NewRequest("GET", "/_ping", nil)
	w := newBenchRW()
	b.ReportAllocs()
	for b.Loop() {
		w.reset()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkAppendCorrelationAttrs measures the attribute construction hotspot.
func BenchmarkAppendCorrelationAttrs(b *testing.B) {
	meta := &RequestMeta{
		Decision: "allow",
		Rule:     4,
		NormPath: "/containers/json",
	}
	req := httptest.NewRequest("GET", "/v1.45/containers/json", nil).WithContext(WithMeta(
		httptest.NewRequest("GET", "/", nil).Context(), meta,
	))
	req.Header.Set("X-Request-Id", "req-abc-123")
	buf := make([]slog.Attr, 0, 11)
	b.ReportAllocs()
	for b.Loop() {
		buf = AppendCorrelationAttrs(buf[:0], req)
	}
	_ = buf
}
