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
	"testing"
)

func TestAccessLogAllowed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate filter middleware writing to the shared meta
		if Meta(r.Context()) != nil {
			t.Fatal("expected request context to remain untouched by access log middleware")
		}
		m := MetaFromResponseWriter(w)
		if m == nil {
			t.Fatal("expected meta on wrapped response writer")
		}
		m.Decision = "allow"
		m.Rule = 0
		m.NormPath = "/_ping"
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
		if m := MetaFromResponseWriter(w); m != nil {
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

func TestAccessLogIncludesRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := MetaFromResponseWriter(w); m != nil {
			m.Decision = "allow"
			m.NormPath = "/info"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header.Set("X-Request-ID", "req-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, `"request_id":"req-123"`) {
		t.Fatalf("expected request_id in access log, got: %s", logOutput)
	}
}

func TestAccessLogEscapesCRLFInRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := MetaFromResponseWriter(w); m != nil {
			m.Decision = "allow"
			m.NormPath = "/info"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	// httptest lets us set values containing CRLF that a real HTTP parser
	// would reject. The log sink is the next line of defense — slog must
	// escape control characters so an attacker can't forge a new log record.
	req.Header.Set("X-Request-ID", "legit\r\nmsg=\"spoofed\"")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	// Every log record emitted by this middleware ends in exactly one LF. If
	// the CRLF in the header made it through unescaped, there would be an
	// extra \n inside the line, so we'd see more than one newline total.
	if got := strings.Count(logOutput, "\n"); got != 1 {
		t.Fatalf("log output contains %d newlines, want 1 — CRLF may have leaked: %q", got, logOutput)
	}
	if strings.Contains(logOutput, "\r") {
		t.Fatalf("log output contains raw CR: %q", logOutput)
	}
	// slog's JSON encoder escapes CR/LF as \r and \n within the string value.
	if !strings.Contains(logOutput, `"request_id":"legit\r\nmsg=\"spoofed\""`) {
		t.Fatalf("expected CRLF-escaped request_id in log, got: %s", logOutput)
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
	originalNew := requestMetaPool.New
	requestMetaPool.New = func() any { return nil }
	t.Cleanup(func() {
		requestMetaPool.New = originalNew
	})

	meta := getRequestMeta()
	if meta == nil {
		t.Fatal("getRequestMeta() returned nil")
	}
	putRequestMeta(nil)
}

func TestRequestMetaPoolFallbackWhenPoolReturnsWrongType(t *testing.T) {
	wrong := new(int)
	originalNew := requestMetaPool.New
	requestMetaPool.New = func() any { return wrong }
	t.Cleanup(func() {
		requestMetaPool.New = originalNew
	})

	requestMetaPool.Put(wrong)

	meta := getRequestMeta()
	if meta == nil {
		t.Fatal("getRequestMeta() returned nil")
	}
}

func TestAccessLogAttrPoolFallbackAndNilPut(t *testing.T) {
	originalNew := accessLogAttrPool.New
	accessLogAttrPool.New = func() any { return nil }
	t.Cleanup(func() {
		accessLogAttrPool.New = originalNew
	})

	attrs := getAccessLogAttrs()
	if attrs == nil {
		t.Fatal("getAccessLogAttrs() returned nil")
	}
	putAccessLogAttrs(nil)
}

func TestAccessLogAttrPoolFallbackWhenPoolReturnsWrongType(t *testing.T) {
	wrong := new(int)
	originalNew := accessLogAttrPool.New
	accessLogAttrPool.New = func() any { return wrong }
	t.Cleanup(func() {
		accessLogAttrPool.New = originalNew
	})

	accessLogAttrPool.Put(wrong)

	attrs := getAccessLogAttrs()
	if attrs == nil {
		t.Fatal("getAccessLogAttrs() returned nil")
	}
}

func TestAccessLogAttrPoolHasHeadroomForFutureFields(t *testing.T) {
	attrs := getAccessLogAttrs()
	if attrs == nil {
		t.Fatal("getAccessLogAttrs() returned nil")
	}
	defer putAccessLogAttrs(attrs)

	if got, want := len(*attrs), 16; got != want {
		t.Fatalf("pooled access log attr capacity = %d, want %d", got, want)
	}
}

func TestResponseCapturePoolFallbackAndNilPut(t *testing.T) {
	originalNew := responseCapturePool.New
	responseCapturePool.New = func() any { return nil }
	t.Cleanup(func() {
		responseCapturePool.New = originalNew
	})

	rc := getResponseCapture(httptest.NewRecorder())
	if rc == nil {
		t.Fatal("getResponseCapture() returned nil")
	}
	putResponseCapture(nil)
}

func TestResponseCapturePoolFallbackWhenPoolReturnsWrongType(t *testing.T) {
	wrong := new(int)
	originalNew := responseCapturePool.New
	responseCapturePool.New = func() any { return wrong }
	t.Cleanup(func() {
		responseCapturePool.New = originalNew
	})

	responseCapturePool.Put(wrong)

	rc := getResponseCapture(httptest.NewRecorder())
	if rc == nil {
		t.Fatal("getResponseCapture() returned nil")
	}
}

func TestMetaFromResponseWriter(t *testing.T) {
	meta := &RequestMeta{Decision: "allow"}
	rc := &responseCapture{meta: meta}

	got := MetaFromResponseWriter(rc)
	if got != meta {
		t.Fatalf("MetaFromResponseWriter() = %p, want %p", got, meta)
	}
	if MetaFromResponseWriter(httptest.NewRecorder()) != nil {
		t.Fatal("expected nil meta for non-capturing writer")
	}
}

func TestMetaForRequest(t *testing.T) {
	responseMeta := &RequestMeta{Decision: "allow"}
	ctxMeta := &RequestMeta{Decision: "deny"}

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req = req.WithContext(WithMeta(req.Context(), ctxMeta))

	if got := MetaForRequest(&responseCapture{meta: responseMeta}, req); got != responseMeta {
		t.Fatalf("MetaForRequest() = %p, want response-writer meta %p", got, responseMeta)
	}
	if got := MetaForRequest(httptest.NewRecorder(), req); got != ctxMeta {
		t.Fatalf("MetaForRequest() = %p, want context meta %p", got, ctxMeta)
	}
	if got := MetaForRequest(httptest.NewRecorder(), nil); got != nil {
		t.Fatalf("MetaForRequest() = %v, want nil", got)
	}
}

func TestAppendCorrelationAttrsForResponseWriter(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req.Header.Set(requestIDHeader, "req-123")
	req = req.WithContext(WithMeta(req.Context(), &RequestMeta{
		Decision: "deny",
		Rule:     4,
		Reason:   "context reason",
		NormPath: "/context/path",
	}))

	attrs := AppendCorrelationAttrsForResponseWriter(nil, req, &responseCapture{meta: &RequestMeta{
		Decision: "allow",
		Rule:     2,
		Reason:   "writer reason",
		NormPath: "/writer/path",
	}})

	got := make(map[string]any, len(attrs))
	for _, attr := range attrs {
		got[attr.Key] = attr.Value.Any()
	}

	if got["request_id"] != "req-123" {
		t.Fatalf("request_id = %#v, want req-123", got["request_id"])
	}
	if got["normalized_path"] != "/writer/path" {
		t.Fatalf("normalized_path = %#v, want /writer/path", got["normalized_path"])
	}
	if got["decision"] != "allow" {
		t.Fatalf("decision = %#v, want allow", got["decision"])
	}
	if got["rule"] != int64(2) && got["rule"] != 2 {
		t.Fatalf("rule = %#v, want 2", got["rule"])
	}
	if got["reason"] != "writer reason" {
		t.Fatalf("reason = %#v, want writer reason", got["reason"])
	}
}

func TestAppendCorrelationAttrsNilRequest(t *testing.T) {
	attrs := []slog.Attr{slog.String("existing", "value")}
	got := AppendCorrelationAttrs(attrs, nil)
	if len(got) != 1 {
		t.Fatalf("attrs length = %d, want 1", len(got))
	}
	if got[0].Key != "existing" {
		t.Fatalf("first attr key = %q, want existing", got[0].Key)
	}
}

func TestAppendCorrelationAttrsOmitsEmptyRequestIDAndReason(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.Header[requestIDHeader] = []string{""}
	req = req.WithContext(WithMeta(req.Context(), &RequestMeta{
		Decision: "allow",
		Rule:     3,
		NormPath: "/containers/json",
	}))

	attrs := AppendCorrelationAttrs(nil, req)
	for _, attr := range attrs {
		if attr.Key == "request_id" {
			t.Fatalf("unexpected request_id attr: %#v", attr)
		}
		if attr.Key == "reason" {
			t.Fatalf("unexpected reason attr: %#v", attr)
		}
	}
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
		if m := MetaFromResponseWriter(w); m != nil {
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
	limit := 2.0
	if raceEnabled {
		limit = 5.0
	}
	if allocs > limit {
		t.Fatalf("AccessLogMiddleware allocated %.0f times, want <= %.0f", allocs, limit)
	}
}

func BenchmarkAccessLogMiddleware(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := MetaFromResponseWriter(w); m != nil {
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
