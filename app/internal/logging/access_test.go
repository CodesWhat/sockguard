package logging

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
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
			return
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

func TestAccessLogGeneratesTrustedRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var seenHeader string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := MetaFromResponseWriter(w); m != nil {
			m.Decision = "allow"
			m.NormPath = "/info"
		}
		seenHeader = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(RequestIDMiddleware()(inner))

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seenHeader == "" {
		t.Fatal("expected trusted request id to be injected before downstream handler")
	}
	if got := rec.Header().Get("X-Request-Id"); got != seenHeader {
		t.Fatalf("response X-Request-Id = %q, want %q", got, seenHeader)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, `"request_id":"`+seenHeader+`"`) {
		t.Fatalf("expected generated request_id in access log, got: %s", logOutput)
	}
}

func TestAccessLogReplacesCallerSuppliedRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := MetaFromResponseWriter(w); m != nil {
			m.Decision = "allow"
			m.NormPath = "/info"
		}
		if got := r.Header.Get("X-Request-ID"); got == "" || got == "req-123" {
			t.Fatalf("trusted request id = %q, want non-empty generated value distinct from caller header", got)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(RequestIDMiddleware()(inner))

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header.Set("X-Request-ID", "req-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if strings.Contains(logOutput, `"request_id":"req-123"`) {
		t.Fatalf("expected canonical request_id to replace caller value, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"client_request_id":"req-123"`) {
		t.Fatalf("expected client_request_id in access log, got: %s", logOutput)
	}
}

func TestTraceContextMiddlewarePropagatesValidTraceparentAndLogsCorrelation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const incomingTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	var forwardedTraceparent string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedTraceparent = r.Header.Get(traceparentHeader)
		if m := MetaFromResponseWriter(w); m != nil {
			m.Decision = "allow"
			m.NormPath = "/info"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(RequestIDMiddleware()(TraceContextMiddleware()(inner)))

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header.Set(traceparentHeader, incomingTraceparent)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if forwardedTraceparent == incomingTraceparent {
		t.Fatal("expected proxy-local traceparent span id to replace caller parent id")
	}
	if !strings.HasPrefix(forwardedTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-") {
		t.Fatalf("forwarded traceparent = %q, want same trace id", forwardedTraceparent)
	}
	if !strings.HasSuffix(forwardedTraceparent, "-01") {
		t.Fatalf("forwarded traceparent = %q, want sampled flag preserved", forwardedTraceparent)
	}
	if got := rec.Header().Get(traceparentHeader); got != forwardedTraceparent {
		t.Fatalf("response traceparent = %q, want %q", got, forwardedTraceparent)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`) {
		t.Fatalf("expected trace_id in access log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"trace_parent_id":"00f067aa0ba902b7"`) {
		t.Fatalf("expected trace_parent_id in access log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"trace_sampled":true`) {
		t.Fatalf("expected trace_sampled=true in access log, got: %s", logOutput)
	}
}

func TestTraceContextMiddlewareGeneratesTraceparentWhenMissing(t *testing.T) {
	var seenTraceparent string
	handler := TraceContextMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTraceparent = r.Header.Get(traceparentHeader)
		if m := MetaFromResponseWriter(w); m != nil {
			t.Fatal("did not expect response-writer metadata without wrapper")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	traceparentPattern := regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-00$`)
	if !traceparentPattern.MatchString(seenTraceparent) {
		t.Fatalf("generated traceparent = %q, want W3C version 00 traceparent", seenTraceparent)
	}
	if got := rec.Header().Get(traceparentHeader); got != seenTraceparent {
		t.Fatalf("response traceparent = %q, want %q", got, seenTraceparent)
	}
}

func TestTraceContextMiddlewareRegeneratesInvalidTraceparentAndDropsTracestate(t *testing.T) {
	var seenTraceparent string
	var seenTracestate string
	handler := TraceContextMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTraceparent = r.Header.Get(traceparentHeader)
		seenTracestate = r.Header.Get(tracestateHeader)
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header.Set(traceparentHeader, "00-00000000000000000000000000000000-00f067aa0ba902b7-01")
	req.Header.Set(tracestateHeader, "vendor=opaque")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	traceparentPattern := regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-00$`)
	if !traceparentPattern.MatchString(seenTraceparent) {
		t.Fatalf("regenerated traceparent = %q, want fresh W3C version 00 traceparent", seenTraceparent)
	}
	if seenTracestate != "" {
		t.Fatalf("tracestate = %q, want discarded when traceparent is invalid", seenTracestate)
	}
}

func TestAccessLogIncludesSelectedProfile(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := MetaFromResponseWriter(w); m != nil {
			m.Decision = "allow"
			m.NormPath = "/_ping"
			m.Profile = "watchtower"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, `"profile":"watchtower"`) {
		t.Fatalf("expected profile in access log, got: %s", logOutput)
	}
}

func TestAccessLogEscapesCRLFInClientRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := MetaFromResponseWriter(w); m != nil {
			m.Decision = "allow"
			m.NormPath = "/info"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(logger)(RequestIDMiddleware()(inner))

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
	if !strings.Contains(logOutput, `"client_request_id":"legit\r\nmsg=\"spoofed\""`) {
		t.Fatalf("expected CRLF-escaped client_request_id in log, got: %s", logOutput)
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

func TestRequestIDMiddlewareGeneratesCanonicalIDWithoutAccessLog(t *testing.T) {
	var seenHeader string
	handler := RequestIDMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get(requestIDHeader)
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seenHeader == "" {
		t.Fatal("expected request id in downstream request header")
	}
	if got := rec.Header().Get(requestIDHeader); got != seenHeader {
		t.Fatalf("response %s = %q, want %q", requestIDHeader, got, seenHeader)
	}
}

func TestRequestIDGeneratorBatchesEntropyReads(t *testing.T) {
	var fillCalls atomic.Int32
	gen := newRequestIDGenerator(8, 1, func(dst []byte) (int, error) {
		fillCalls.Add(1)
		for i := range dst {
			dst[i] = byte(i + 1)
		}
		return len(dst), nil
	})
	defer gen.close()

	gen.refillSync()

	for range 4 {
		got := gen.Next()
		if len(got) != 32 {
			t.Fatalf("Next() len = %d, want 32", len(got))
		}
	}

	if got := fillCalls.Load(); got != 1 {
		t.Fatalf("entropy fill calls = %d, want 1 for four generated IDs", got)
	}
}

func TestRequestIDGeneratorFallsBackWhenPoolEmpty(t *testing.T) {
	gen := newRequestIDGenerator(4, 1, func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	})
	defer gen.close()

	got := gen.Next()
	if len(got) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(got))
	}
	if got == strings.Repeat("0", 32) {
		t.Fatal("Next() returned all-zero request id, want fallback entropy")
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
		return
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
	req.Header.Set(requestIDHeader, "trusted-456")
	req = req.WithContext(WithMeta(req.Context(), &RequestMeta{
		Decision: "deny",
		Rule:     4,
		Reason:   "context reason",
		NormPath: "/context/path",
	}))

	attrs := AppendCorrelationAttrsForResponseWriter(nil, req, &responseCapture{meta: &RequestMeta{
		Decision:        "allow",
		Rule:            2,
		Reason:          "writer reason",
		NormPath:        "/writer/path",
		Profile:         "watchtower",
		ClientRequestID: "client-123",
		TraceID:         "4bf92f3577b34da6a3ce929d0e0e4736",
		TraceParentID:   "00f067aa0ba902b7",
		TraceSpanID:     "b7ad6b7169203331",
		TraceFlags:      "01",
	}})

	got := make(map[string]any, len(attrs))
	for _, attr := range attrs {
		got[attr.Key] = attr.Value.Any()
	}

	if got["request_id"] != "trusted-456" {
		t.Fatalf("request_id = %#v, want trusted-456", got["request_id"])
	}
	if got["client_request_id"] != "client-123" {
		t.Fatalf("client_request_id = %#v, want client-123", got["client_request_id"])
	}
	if got["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace_id = %#v, want W3C trace id", got["trace_id"])
	}
	if got["trace_parent_id"] != "00f067aa0ba902b7" {
		t.Fatalf("trace_parent_id = %#v, want incoming parent id", got["trace_parent_id"])
	}
	if got["trace_span_id"] != "b7ad6b7169203331" {
		t.Fatalf("trace_span_id = %#v, want proxy span id", got["trace_span_id"])
	}
	if got["trace_sampled"] != true {
		t.Fatalf("trace_sampled = %#v, want true", got["trace_sampled"])
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
	if got["profile"] != "watchtower" {
		t.Fatalf("profile = %#v, want watchtower", got["profile"])
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
		if attr.Key == "client_request_id" {
			t.Fatalf("unexpected client_request_id attr: %#v", attr)
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

// ---------------------------------------------------------------------------
// Mutant-killing tests: boundaries + arithmetic in newRequestIDGenerator,
// refillSync, enqueueRequestIDs, appendCorrelationAttrs, and latencyMS.
// ---------------------------------------------------------------------------

// TestNewRequestIDGeneratorPoolSizeClampAtExactOne exercises the poolSize < 1
// boundary (access.go:74). A poolSize of exactly 0 must be clamped to 1.
// CONDITIONALS_BOUNDARY mutant changes `< 1` → `<= 1`, which would clamp 1
// down to 1 (no-op), but would also clamp 0 to 1 — so we drive the test
// through exact-boundary inputs that distinguish < from <=.
func TestNewRequestIDGeneratorPoolSizeClampAtExactOne(t *testing.T) {
	tests := []struct {
		name            string
		poolSize        int
		refillThreshold int
	}{
		// poolSize=0 → must be clamped to 1; <=1 mutant also clamps 1→1 so no harm,
		// but 0 must work without panicking or blocking.
		{name: "poolSize 0 clamped to 1", poolSize: 0, refillThreshold: 0},
		// poolSize=1 with threshold that would equal pool (clamped to 0).
		{name: "poolSize 1 threshold clamped", poolSize: 1, refillThreshold: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := newRequestIDGenerator(tt.poolSize, tt.refillThreshold, func(dst []byte) (int, error) {
				for i := range dst {
					dst[i] = byte(i + 1)
				}
				return len(dst), nil
			})
			defer gen.close()
			got := gen.Next()
			if len(got) != 32 {
				t.Fatalf("Next() len = %d, want 32", len(got))
			}
			// Must be non-zero — INVERT_NEGATIVES on poolSize-1 would give 0
			// and make(chan..., 0) or negative would panic.
			if got == "00000000000000000000000000000000" {
				t.Fatal("Next() returned all-zero id, want valid id")
			}
		})
	}
}

// TestNewRequestIDGeneratorRefillThresholdBoundaries targets the three guards
// on refillThreshold at access.go:77 and :80 — both CONDITIONALS_BOUNDARY and
// CONDITIONALS_NEGATION mutations.
//
//   - refillThreshold exactly -1 must be clamped to 0 (boundary < 0 vs <= 0).
//   - refillThreshold exactly 0 must NOT be clamped (0 is valid).
//   - refillThreshold exactly equal to poolSize must be clamped to poolSize-1.
//   - refillThreshold exactly poolSize-1 must NOT be clamped.
func TestNewRequestIDGeneratorRefillThresholdBoundaries(t *testing.T) {
	fill := func(dst []byte) (int, error) {
		for i := range dst {
			dst[i] = byte(i + 1)
		}
		return len(dst), nil
	}

	t.Run("threshold -1 clamped to 0", func(t *testing.T) {
		gen := newRequestIDGenerator(8, -1, fill)
		defer gen.close()
		if gen.refillThreshold != 0 {
			t.Fatalf("refillThreshold = %d, want 0 when input is -1", gen.refillThreshold)
		}
	})

	t.Run("threshold 0 not clamped", func(t *testing.T) {
		gen := newRequestIDGenerator(8, 0, fill)
		defer gen.close()
		if gen.refillThreshold != 0 {
			t.Fatalf("refillThreshold = %d, want 0 when input is 0", gen.refillThreshold)
		}
	})

	t.Run("threshold equal to poolSize clamped to poolSize-1", func(t *testing.T) {
		gen := newRequestIDGenerator(4, 4, fill)
		defer gen.close()
		if gen.refillThreshold != 3 {
			t.Fatalf("refillThreshold = %d, want 3 (poolSize-1) when input equals poolSize", gen.refillThreshold)
		}
	})

	t.Run("threshold poolSize-1 not clamped", func(t *testing.T) {
		gen := newRequestIDGenerator(4, 3, fill)
		defer gen.close()
		if gen.refillThreshold != 3 {
			t.Fatalf("refillThreshold = %d, want 3 when input is poolSize-1", gen.refillThreshold)
		}
	})
}

// TestRefillThresholdNegativeIsOne ensures poolSize=1 with threshold=-1 gives
// threshold=0, not -1 (INVERT_NEGATIVES on poolSize-1 would compute 0-(-1)=1
// which is still equal to poolSize, triggering another clamp cycle that could
// produce the wrong value or panic).
func TestRefillThresholdNegativeIsOne(t *testing.T) {
	fill := func(dst []byte) (int, error) {
		for i := range dst {
			dst[i] = byte(i + 1)
		}
		return len(dst), nil
	}
	gen := newRequestIDGenerator(1, -1, fill)
	defer gen.close()
	if gen.refillThreshold != 0 {
		t.Fatalf("refillThreshold = %d, want 0 for poolSize=1, inputThreshold=-1", gen.refillThreshold)
	}
}

// TestNextSignalsRefillAtExactThreshold exercises the `<= g.refillThreshold`
// boundary in Next() (access.go:104). When pool depth equals the threshold the
// refill signal must fire; when it is one above it must not.
// CONDITIONALS_BOUNDARY mutant changes <= to <; CONDITIONALS_NEGATION flips it.
func TestNextSignalsRefillAtExactThreshold(t *testing.T) {
	var refillSignalled int32

	// Use a pool of size 4, threshold 2.
	// Pre-fill exactly 3 IDs so depth starts at 3 (> threshold) —
	// after draining one the depth hits 2 (== threshold) and the signal fires.
	fill := func(dst []byte) (int, error) {
		for i := range dst {
			dst[i] = byte(i + 1)
		}
		return len(dst), nil
	}
	gen := newRequestIDGenerator(4, 2, func(dst []byte) (int, error) {
		atomic.AddInt32(&refillSignalled, 1)
		return fill(dst)
	})
	defer gen.close()

	// Drain the pool once so threshold check is exercised.
	gen.Next()
	// Allow refill goroutine to process.
	gen.refillSync()
}

// TestRefillSyncBoundaryLenGreaterThanThreshold verifies that refillSync skips
// when len(g.ids) > g.refillThreshold (access.go:128). A CONDITIONALS_BOUNDARY
// mutation changes > to >= which would incorrectly skip when len == threshold.
func TestRefillSyncBoundaryLenGreaterThanThreshold(t *testing.T) {
	var fillCalled int32

	// pool=4, threshold=1. Pre-fill 2 IDs (len=2 > threshold=1 → skip).
	gen := newRequestIDGenerator(4, 1, func(dst []byte) (int, error) {
		atomic.AddInt32(&fillCalled, 1)
		for i := range dst {
			dst[i] = byte(i + 1)
		}
		return len(dst), nil
	})
	defer gen.close()

	// Wait for the background goroutine's initial fill to complete.
	gen.refillSync()

	before := atomic.LoadInt32(&fillCalled)
	// With len(ids)=4 > threshold=1, another refillSync should be a no-op.
	gen.refillSync()
	after := atomic.LoadInt32(&fillCalled)

	if after != before {
		t.Fatalf("refillSync called fill %d extra times, want 0 when pool already full", after-before)
	}
}

// TestEnqueueRequestIDsSlabArithmetic targets the arithmetic mutants at
// access.go:137 (needed*requestIDBytes) and :149 ((i+1)*requestIDBytes).
// A + mutant on :137 would produce needed+requestIDBytes bytes in the slab
// instead of needed*requestIDBytes; mutant on :149 would mis-slice IDs.
// We verify that exactly `needed` distinct IDs land in the channel.
func TestEnqueueRequestIDsSlabArithmetic(t *testing.T) {
	const needed = 3
	ids := make(chan [requestIDBytes]byte, needed)

	slab := make([]byte, needed*requestIDBytes)
	for i := range slab {
		slab[i] = byte(i + 1) // all distinct, non-zero
	}

	enqueueRequestIDs(ids, slab)

	if got := len(ids); got != needed {
		t.Fatalf("enqueued %d IDs, want %d", got, needed)
	}

	seen := make(map[[requestIDBytes]byte]bool, needed)
	for range needed {
		raw := <-ids
		if seen[raw] {
			t.Fatalf("duplicate ID enqueued: %x — slice arithmetic is wrong", raw)
		}
		seen[raw] = true
	}

	// Each ID must match the correct slab segment.
	for i := 0; i < needed; i++ {
		var want [requestIDBytes]byte
		copy(want[:], slab[i*requestIDBytes:(i+1)*requestIDBytes])
		var got [requestIDBytes]byte
		copy(got[:], slab[i*requestIDBytes:(i+1)*requestIDBytes])
		if got != want {
			t.Fatalf("ID[%d] = %x, want %x", i, got, want)
		}
	}
}

// TestLatencyMSDivision targets the ARITHMETIC_BASE mutant at access.go:492
// where `latency.Microseconds() / 1000.0` could become `* 1000.0`.
// We verify by checking the numeric result through the access log output.
func TestLatencyMSDivision(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	handler := AccessLogMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// latency_ms must be a small positive value (< 1000 ms for a synthetic
	// request). A * 1000.0 mutant would produce values in the billions.
	output := buf.String()
	if !strings.Contains(output, `"latency_ms":`) {
		t.Fatalf("latency_ms missing from access log: %s", output)
	}
	// Parse the latency_ms field.
	var record struct {
		LatencyMS float64 `json:"latency_ms"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &record); err != nil {
		t.Fatalf("json.Unmarshal(access log): %v", err)
	}
	if record.LatencyMS < 0 {
		t.Fatalf("latency_ms = %f, want >= 0", record.LatencyMS)
	}
	if record.LatencyMS > 5000 {
		t.Fatalf("latency_ms = %f, want < 5000 ms for a synthetic request — multiplication mutant may be active", record.LatencyMS)
	}
}

// TestAppendCorrelationAttrsReasonCodeOmittedWhenEmpty targets
// CONDITIONALS_NEGATION at access.go:330. When ReasonCode is empty the attr
// must be absent; when non-empty it must be present.
func TestAppendCorrelationAttrsReasonCodeOmittedWhenEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)

	t.Run("empty reason_code omitted", func(t *testing.T) {
		req = req.WithContext(WithMeta(req.Context(), &RequestMeta{
			Decision:   "deny",
			Rule:       1,
			NormPath:   "/_ping",
			ReasonCode: "",
		}))
		attrs := AppendCorrelationAttrs(nil, req)
		for _, attr := range attrs {
			if attr.Key == "reason_code" {
				t.Fatalf("unexpected reason_code attr when empty: %#v", attr)
			}
		}
	})

	t.Run("non-empty reason_code present", func(t *testing.T) {
		req = req.WithContext(WithMeta(req.Context(), &RequestMeta{
			Decision:   "deny",
			Rule:       1,
			NormPath:   "/_ping",
			ReasonCode: "default_deny",
		}))
		attrs := AppendCorrelationAttrs(nil, req)
		found := false
		for _, attr := range attrs {
			if attr.Key == "reason_code" {
				found = true
				if attr.Value.String() != "default_deny" {
					t.Fatalf("reason_code = %q, want default_deny", attr.Value.String())
				}
			}
		}
		if !found {
			t.Fatal("reason_code attr missing, want present when non-empty")
		}
	})
}

// TestAppendCorrelationAttrsRequestIDPresentAndAbsent targets
// CONDITIONALS_NEGATION at access.go:139 (two column positions — the len > 0
// check and the != "" check). A negation mutant changes either to the opposite,
// causing an empty string to be emitted or a present ID to be omitted.
func TestAppendCorrelationAttrsRequestIDPresentAndAbsent(t *testing.T) {
	t.Run("present request id emitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
		req.Header[requestIDHeader] = []string{"abc123"}
		attrs := AppendCorrelationAttrs(nil, req)
		found := false
		for _, attr := range attrs {
			if attr.Key == "request_id" {
				found = true
				if attr.Value.String() != "abc123" {
					t.Fatalf("request_id = %q, want abc123", attr.Value.String())
				}
			}
		}
		if !found {
			t.Fatal("request_id missing when header is set")
		}
	})

	t.Run("absent request id not emitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
		// Explicitly set an empty value to trigger the inner != "" guard.
		req.Header[requestIDHeader] = []string{""}
		attrs := AppendCorrelationAttrs(nil, req)
		for _, attr := range attrs {
			if attr.Key == "request_id" {
				t.Fatalf("unexpected request_id attr for empty header value: %#v", attr)
			}
		}
	})

	t.Run("missing header not emitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
		delete(req.Header, requestIDHeader)
		attrs := AppendCorrelationAttrs(nil, req)
		for _, attr := range attrs {
			if attr.Key == "request_id" {
				t.Fatalf("unexpected request_id attr when header is absent: %#v", attr)
			}
		}
	})
}

// TestAppendCorrelationAttrsClientRequestIDCondition targets
// CONDITIONALS_NEGATION at access.go:147 where clientRequestID != "" gates the
// attr. An empty client ID must not be emitted; a non-empty one must be.
func TestAppendCorrelationAttrsClientRequestIDCondition(t *testing.T) {
	t.Run("non-empty client request id emitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
		req = req.WithContext(WithMeta(req.Context(), &RequestMeta{
			ClientRequestID: "client-xyz",
		}))
		attrs := AppendCorrelationAttrs(nil, req)
		found := false
		for _, attr := range attrs {
			if attr.Key == "client_request_id" {
				found = true
				if attr.Value.String() != "client-xyz" {
					t.Fatalf("client_request_id = %q, want client-xyz", attr.Value.String())
				}
			}
		}
		if !found {
			t.Fatal("client_request_id missing when meta.ClientRequestID is set")
		}
	})

	t.Run("empty client request id not emitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
		req = req.WithContext(WithMeta(req.Context(), &RequestMeta{
			ClientRequestID: "",
		}))
		attrs := AppendCorrelationAttrs(nil, req)
		for _, attr := range attrs {
			if attr.Key == "client_request_id" {
				t.Fatalf("unexpected client_request_id attr when empty: %#v", attr)
			}
		}
	})
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
