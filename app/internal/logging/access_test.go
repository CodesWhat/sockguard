package logging

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestGetRequestMetaReturnsUsableMeta(t *testing.T) {
	meta := getRequestMeta()
	if meta == nil {
		t.Fatal("getRequestMeta() returned nil")
	}
	putRequestMeta(meta)
}

func TestPutRequestMetaResetsFields(t *testing.T) {
	meta := &RequestMeta{
		Decision: "deny",
		Rule:     7,
		Reason:   "default deny",
		NormPath: "/containers/create",
	}

	putRequestMeta(meta)

	if *meta != (RequestMeta{}) {
		t.Fatalf("meta after put = %#v, want zero value", *meta)
	}
}

func TestRequestMetaPoolFallbackAndNilPut(t *testing.T) {
	originalPool := requestMetaPool
	requestMetaPool = sync.Pool{New: func() any { return nil }}
	t.Cleanup(func() {
		requestMetaPool = originalPool
	})

	meta := getRequestMeta()
	if meta == nil {
		t.Fatal("getRequestMeta() returned nil")
	}
	putRequestMeta(nil)
}

func TestAccessLogAttrPoolFallbackAndNilPut(t *testing.T) {
	originalPool := accessLogAttrPool
	accessLogAttrPool = sync.Pool{New: func() any { return nil }}
	t.Cleanup(func() {
		accessLogAttrPool = originalPool
	})

	attrs := getAccessLogAttrs()
	if attrs == nil {
		t.Fatal("getAccessLogAttrs() returned nil")
	}
	putAccessLogAttrs(nil)
}

func TestResponseCapturePoolFallbackAndNilPut(t *testing.T) {
	originalPool := responseCapturePool
	responseCapturePool = sync.Pool{New: func() any { return nil }}
	t.Cleanup(func() {
		responseCapturePool = originalPool
	})

	rc := getResponseCapture(httptest.NewRecorder())
	if rc == nil {
		t.Fatal("getResponseCapture() returned nil")
	}
	putResponseCapture(nil)
}

type stubHijacker struct {
	http.ResponseWriter
	conn net.Conn
	rw   *bufio.ReadWriter
	err  error
}

func (h stubHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, h.err
}

func TestResponseCaptureHijack(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})

	wantErr := errors.New("boom")
	rc := &responseCapture{
		ResponseWriter: stubHijacker{
			ResponseWriter: httptest.NewRecorder(),
			conn:           serverConn,
			rw:             bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
			err:            wantErr,
		},
		status: http.StatusOK,
	}

	conn, rw, err := rc.Hijack()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Hijack() error = %v, want %v", err, wantErr)
	}
	if conn != serverConn {
		t.Fatalf("conn = %v, want %v", conn, serverConn)
	}
	if rw == nil {
		t.Fatal("readwriter = nil, want non-nil")
	}
}

func TestResponseCaptureHijackNotSupported(t *testing.T) {
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}

	conn, rw, err := rc.Hijack()
	if !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack() error = %v, want %v", err, http.ErrNotSupported)
	}
	if conn != nil || rw != nil {
		t.Fatalf("Hijack() = (%v, %v), want nils", conn, rw)
	}
}

func TestAccessLogDefaultClientAddress(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	handler := AccessLogMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = ""
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.Contains(buf.String(), `"client":"unix"`) {
		t.Fatalf("expected unix client in log output, got: %s", buf.String())
	}
}

type benchmarkResponseWriter struct {
	header http.Header
	status int
}

func newBenchmarkResponseWriter() *benchmarkResponseWriter {
	return &benchmarkResponseWriter{
		header: make(http.Header),
	}
}

func (w *benchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (w *benchmarkResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *benchmarkResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(p), nil
}

func (w *benchmarkResponseWriter) Reset() {
	clear(w.header)
	w.status = 0
}

func TestAccessLogMiddlewareAllocationBudget(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := Meta(r.Context()); m != nil {
			m.Decision = "allow"
			m.Rule = 0
			m.NormPath = "/_ping"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(inner)
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	w := newBenchmarkResponseWriter()

	allocs := testing.AllocsPerRun(1000, func() {
		w.Reset()
		handler.ServeHTTP(w, req)
	})

	// Race detector instruments sync.Pool, adding ~2 extra allocs.
	limit := 3.0
	if raceEnabled {
		limit = 6.0
	}
	if allocs > limit {
		t.Fatalf("AccessLogMiddleware allocated %.0f times, want <= %.0f", allocs, limit)
	}
}

func BenchmarkAccessLogMiddleware(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := Meta(r.Context()); m != nil {
			m.Decision = "allow"
			m.Rule = 0
			m.NormPath = "/_ping"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(inner)
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	w := newBenchmarkResponseWriter()

	b.ReportAllocs()
	for b.Loop() {
		w.Reset()
		handler.ServeHTTP(w, req)
	}
}
