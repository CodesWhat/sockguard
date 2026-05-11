package logging

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuditLogMiddlewareEmitsDedicatedEventSchema(t *testing.T) {
	var buf bytes.Buffer
	auditLogger := NewAuditLogger(&buf)
	auditLogger.now = func() string { return "2026-04-18T12:34:56Z" }

	handler := AuditLogMiddleware(auditLogger, AuditOptions{
		OwnershipOwner:    "ci-job-123",
		OwnershipLabelKey: "com.sockguard.owner",
	})(RequestIDMiddleware()(TraceContextMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := MetaFromResponseWriter(w)
		if meta == nil {
			t.Fatal("expected request meta on wrapped response writer")
		}
		meta.Decision = "deny"
		meta.ReasonCode = "client_ip_not_allowed"
		meta.Reason = "client IP not allowed"
		meta.Rule = 7
		meta.NormPath = "/_ping"
		meta.Profile = "watchtower"
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"denied"}`))
	}))))

	req := httptest.NewRequest(http.MethodGet, "/v1.45/_ping", nil)
	req.RemoteAddr = "203.0.113.10:4444"
	req.Header.Set(requestIDHeader, "client-123")
	req.Header.Set(traceparentHeader, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	closeAuditLogger(t, auditLogger)

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, buf.String())
	}

	if got := event["event_type"]; got != "http_request" {
		t.Fatalf("event_type = %#v, want %q", got, "http_request")
	}
	if got := event["timestamp"]; got != "2026-04-18T12:34:56Z" {
		t.Fatalf("timestamp = %#v, want fixed test timestamp", got)
	}
	if got := event["method"]; got != http.MethodGet {
		t.Fatalf("method = %#v, want %q", got, http.MethodGet)
	}
	if got := event["raw_path"]; got != "/v1.45/_ping" {
		t.Fatalf("raw_path = %#v, want %q", got, "/v1.45/_ping")
	}
	if got := event["normalized_path"]; got != "/_ping" {
		t.Fatalf("normalized_path = %#v, want %q", got, "/_ping")
	}
	if got := event["decision"]; got != "deny" {
		t.Fatalf("decision = %#v, want %q", got, "deny")
	}
	if got := event["reason_code"]; got != "client_ip_not_allowed" {
		t.Fatalf("reason_code = %#v, want %q", got, "client_ip_not_allowed")
	}
	if got := event["reason"]; got != "client IP not allowed" {
		t.Fatalf("reason = %#v, want %q", got, "client IP not allowed")
	}
	if got := event["matched_rule"]; got != float64(7) {
		t.Fatalf("matched_rule = %#v, want %v", got, 7)
	}
	if got := event["selected_profile"]; got != "watchtower" {
		t.Fatalf("selected_profile = %#v, want %q", got, "watchtower")
	}
	if got := event["status"]; got != float64(http.StatusForbidden) {
		t.Fatalf("status = %#v, want %d", got, http.StatusForbidden)
	}

	requestID, _ := event["request_id"].(string)
	if requestID == "" || requestID == "client-123" {
		t.Fatalf("request_id = %#v, want generated canonical id distinct from caller header", event["request_id"])
	}
	if got := event["client_request_id"]; got != "client-123" {
		t.Fatalf("client_request_id = %#v, want %q", got, "client-123")
	}
	if got := event["trace_id"]; got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace_id = %#v, want W3C trace id", got)
	}
	if got := event["trace_parent_id"]; got != "00f067aa0ba902b7" {
		t.Fatalf("trace_parent_id = %#v, want incoming parent id", got)
	}
	if got := event["trace_span_id"]; got == "" || got == "00f067aa0ba902b7" {
		t.Fatalf("trace_span_id = %#v, want generated proxy span id", got)
	}
	if got := event["trace_sampled"]; got != true {
		t.Fatalf("trace_sampled = %#v, want true", got)
	}

	if got := event["actor_remote_addr"]; got != "203.0.113.10:4444" {
		t.Fatalf("actor_remote_addr = %#v, want %q", got, "203.0.113.10:4444")
	}
	if got := event["actor_source_ip"]; got != "203.0.113.10" {
		t.Fatalf("actor_source_ip = %#v, want %q", got, "203.0.113.10")
	}
	if got := event["transport_listener"]; got != "tcp" {
		t.Fatalf("transport_listener = %#v, want %q", got, "tcp")
	}
	if got := event["transport_scheme"]; got != "http" {
		t.Fatalf("transport_scheme = %#v, want %q", got, "http")
	}
	if got := event["transport_protocol"]; got != "HTTP/1.1" {
		t.Fatalf("transport_protocol = %#v, want %q", got, "HTTP/1.1")
	}
	if _, ok := event["actor_identity"]; ok {
		t.Fatalf("actor_identity should be flattened, got %#v", event["actor_identity"])
	}
	if _, ok := event["transport_identity"]; ok {
		t.Fatalf("transport_identity should be flattened, got %#v", event["transport_identity"])
	}

	ownership, ok := event["ownership"].(map[string]any)
	if !ok {
		t.Fatalf("ownership = %#v, want object", event["ownership"])
	}
	if got := ownership["enabled"]; got != true {
		t.Fatalf("ownership.enabled = %#v, want true", got)
	}
	if got := ownership["owner"]; got != "ci-job-123" {
		t.Fatalf("ownership.owner = %#v, want %q", got, "ci-job-123")
	}
	if got := ownership["label_key"]; got != "com.sockguard.owner" {
		t.Fatalf("ownership.label_key = %#v, want %q", got, "com.sockguard.owner")
	}
}

func TestAccessAndAuditLogMiddlewaresShareRequestMeta(t *testing.T) {
	var accessBuf bytes.Buffer
	accessLogger := slog.New(slog.NewJSONHandler(&accessBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var auditBuf bytes.Buffer
	auditLogger := NewAuditLogger(&auditBuf)

	handler := AccessLogMiddleware(accessLogger)(
		AuditLogMiddleware(auditLogger, AuditOptions{})(RequestIDMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			meta := MetaFromResponseWriter(w)
			if meta == nil {
				t.Fatal("expected shared request meta on wrapped response writer")
			}
			meta.Decision = "allow"
			meta.ReasonCode = "matched_allow_rule"
			meta.Rule = 0
			meta.NormPath = "/_ping"
			w.WriteHeader(http.StatusOK)
		}))),
	)

	req := httptest.NewRequest(http.MethodGet, "/v1.45/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	closeAuditLogger(t, auditLogger)

	if !strings.Contains(accessBuf.String(), `"decision":"allow"`) {
		t.Fatalf("expected allow decision in access log, got: %s", accessBuf.String())
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, auditBuf.String())
	}
	if got := event["decision"]; got != "allow" {
		t.Fatalf("decision = %#v, want %q", got, "allow")
	}
}

func TestAuditLogMiddlewareUsesConfiguredListener(t *testing.T) {
	tests := []struct {
		name       string
		opts       AuditOptions
		remoteAddr string
		want       string
	}{
		{name: "configured unix ignores remote address shape", opts: AuditOptions{Listener: "unix"}, remoteAddr: "198.51.100.10:4444", want: "unix"},
		{name: "default tcp does not infer unix from empty remote address", opts: AuditOptions{}, remoteAddr: "", want: "tcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			auditLogger := NewAuditLogger(&buf)
			handler := AuditLogMiddleware(auditLogger, tt.opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
			req.RemoteAddr = tt.remoteAddr
			handler.ServeHTTP(httptest.NewRecorder(), req)
			closeAuditLogger(t, auditLogger)

			var event map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
				t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, buf.String())
			}
			if got := event["transport_listener"]; got != tt.want {
				t.Fatalf("transport_listener = %#v, want %q", got, tt.want)
			}
		})
	}
}

func TestAuditLogMiddlewareNilLoggerIsNoop(t *testing.T) {
	called := false
	handler := AuditLogMiddleware(nil, AuditOptions{
		Listener:          "unix",
		OwnershipOwner:    "owner",
		OwnershipLabelKey: "com.sockguard.owner",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if meta := MetaFromResponseWriter(w); meta != nil {
			t.Fatalf("MetaFromResponseWriter() = %#v, want nil for no-op audit middleware", meta)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("wrapped handler was not called")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

func TestAuditLoggerLogAndCloseEdgeBranches(t *testing.T) {
	var nilLogger *AuditLogger
	nilLogger.log(auditEvent{EventType: "nil_logger"})
	if err := nilLogger.Close(); err != nil {
		t.Fatalf("nil AuditLogger Close() error = %v, want nil", err)
	}

	closedLogger := NewAuditLogger(&bytes.Buffer{})
	closeAuditLogger(t, closedLogger)
	closedLogger.log(auditEvent{EventType: "after_close"})

	fullQueueLogger := &AuditLogger{
		events: make(chan auditEvent, 1),
		done:   make(chan struct{}),
	}
	fullQueueLogger.events <- auditEvent{EventType: "queued"}
	fullQueueLogger.log(auditEvent{EventType: "dropped"})
}

func TestAuditLoggerDrainWritesQueuedEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := &AuditLogger{
		events: make(chan auditEvent, 1),
		enc:    json.NewEncoder(&buf),
	}
	logger.events <- auditEvent{EventType: "drained"}

	logger.drain()

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(drained event): %v\nbody: %s", err, buf.String())
	}
	if got := event["event_type"]; got != "drained" {
		t.Fatalf("event_type = %#v, want drained", got)
	}
}

func TestAuditRequestHelpersHandleNilAndTLS(t *testing.T) {
	if got := requestIDFromRequest(nil); got != "" {
		t.Fatalf("requestIDFromRequest(nil) = %q, want empty", got)
	}
	if got := requestMethod(nil); got != "" {
		t.Fatalf("requestMethod(nil) = %q, want empty", got)
	}
	if got := requestPath(nil); got != "" {
		t.Fatalf("requestPath(nil) = %q, want empty", got)
	}
	if got := requestPath(&http.Request{}); got != "" {
		t.Fatalf("requestPath(request without URL) = %q, want empty", got)
	}
	if remoteAddr, sourceIP := auditActorIdentity(nil); remoteAddr != "" || sourceIP != "" {
		t.Fatalf("auditActorIdentity(nil) = (%q, %q), want empty", remoteAddr, sourceIP)
	}

	listener, scheme, protocol := auditTransportIdentity(nil, "unix")
	if listener != "unix" || scheme != "http" || protocol != "" {
		t.Fatalf("auditTransportIdentity(nil) = (%q, %q, %q), want unix/http/empty", listener, scheme, protocol)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.test/_ping", nil)
	req.Proto = "HTTP/2.0"
	req.TLS = &tls.ConnectionState{}
	listener, scheme, protocol = auditTransportIdentity(req, "tcp")
	if listener != "tcp" || scheme != "https" || protocol != "HTTP/2.0" {
		t.Fatalf("auditTransportIdentity(TLS) = (%q, %q, %q), want tcp/https/HTTP/2.0", listener, scheme, protocol)
	}
}

func TestAuditEventDoesNotUseMapFields(t *testing.T) {
	eventType := reflect.TypeOf(auditEvent{})
	for i := 0; i < eventType.NumField(); i++ {
		field := eventType.Field(i)
		if field.Type.Kind() == reflect.Map {
			t.Fatalf("auditEvent field %s uses map type %s", field.Name, field.Type)
		}
	}
}

func TestNewAuditCreatesJSONFileSink(t *testing.T) {
	tmpDir := t.TempDir()
	restoreCwd := chdirForAuditTest(t, tmpDir)
	t.Cleanup(restoreCwd)

	auditLogger, closer, err := NewAudit("json", "audit.log")
	if err != nil {
		t.Fatalf("NewAudit() error = %v", err)
	}
	if auditLogger == nil {
		t.Fatal("NewAudit() logger = nil")
	}
	if closer == nil {
		t.Fatal("NewAudit() closer = nil")
	}

	auditLogger.log(auditEvent{EventType: "constructor_test"})

	if err := closer.Close(); err != nil {
		t.Fatalf("audit closer Close() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "audit.log"))
	if err != nil {
		t.Fatalf("ReadFile(audit.log): %v", err)
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit event): %v\nbody: %s", err, string(data))
	}
	if got := event["event_type"]; got != "constructor_test" {
		t.Fatalf("event_type = %#v, want constructor_test", got)
	}

	info, err := os.Stat(filepath.Join(tmpDir, "audit.log"))
	if err != nil {
		t.Fatalf("Stat(audit.log): %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("audit log mode = %04o, want 0600", got)
	}
}

func TestNewAuditCreatesStandardStreamSinks(t *testing.T) {
	for _, output := range []string{"stdout", "stderr"} {
		t.Run(output, func(t *testing.T) {
			auditLogger, closer, err := NewAudit("json", output)
			if err != nil {
				t.Fatalf("NewAudit() error = %v", err)
			}
			if auditLogger == nil {
				t.Fatal("NewAudit() logger = nil")
			}
			if closer == nil {
				t.Fatal("NewAudit() closer = nil")
			}
			if err := closer.Close(); err != nil {
				t.Fatalf("audit closer Close() error = %v", err)
			}
		})
	}
}

func TestNewAuditRejectsUnsupportedFormat(t *testing.T) {
	auditLogger, closer, err := NewAudit("text", "stderr")
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("NewAudit() error = nil, want unsupported format error")
	}
	if auditLogger != nil {
		t.Fatalf("NewAudit() logger = %#v, want nil", auditLogger)
	}
	if closer != nil {
		t.Fatalf("NewAudit() closer = %#v, want nil", closer)
	}
	if !strings.Contains(err.Error(), `unsupported audit log format "text"`) {
		t.Fatalf("NewAudit() error = %q, want unsupported format message", err.Error())
	}
}

func TestNewAuditRejectsInvalidOutput(t *testing.T) {
	tmpDir := t.TempDir()
	restoreCwd := chdirForAuditTest(t, tmpDir)
	t.Cleanup(restoreCwd)

	auditLogger, closer, err := NewAudit("json", filepath.Join("missing", "audit.log"))
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("NewAudit() error = nil, want invalid output error")
	}
	if auditLogger != nil {
		t.Fatalf("NewAudit() logger = %#v, want nil", auditLogger)
	}
	if closer != nil {
		t.Fatalf("NewAudit() closer = %#v, want nil", closer)
	}
	if !strings.Contains(err.Error(), `open log output "missing/audit.log"`) {
		t.Fatalf("NewAudit() error = %q, want invalid output path message", err.Error())
	}
}

// closerFunc is an io.Closer backed by a function.
type closerFunc func() error

func (fn closerFunc) Close() error { return fn() }

// TestAuditLogCloserOutputErrorOnlyWhenLoggerOK targets the CONDITIONALS_NEGATION
// mutant at audit.go:76 (`err == nil`). The output closer's error should only be
// stored when the logger Close succeeded (err == nil). If the mutant flips to
// `err != nil`, a successful logger + failing output would return nil instead.
func TestAuditLogCloserOutputErrorOnlyWhenLoggerOK(t *testing.T) {
	var buf bytes.Buffer
	realLogger := NewAuditLogger(&buf)

	outputErr := errors.New("disk full")
	c := auditLogCloser{
		logger: realLogger,
		output: closerFunc(func() error { return outputErr }),
	}
	err := c.Close()
	if err != outputErr {
		t.Fatalf("Close() = %v, want output error %v when logger Close() succeeds", err, outputErr)
	}
}

// TestAuditLogCloserNilOutputIsSkipped ensures the nil-output guard works.
func TestAuditLogCloserNilOutputIsSkipped(t *testing.T) {
	var buf bytes.Buffer
	realLogger := NewAuditLogger(&buf)
	c := auditLogCloser{logger: realLogger, output: nil}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil when output is nil", err)
	}
}

// TestAuditLogCloserOutputErrorNotStoredWhenLoggerFailed ensures that when
// the logger returns an error, the output closer's distinct error is NOT
// stored (the logger error is preserved). This is the other branch of audit.go:76.
// Since AuditLogger.Close() always returns nil, we test the nil-logger path
// plus an output that errors: the output error becomes the result because
// err starts as nil (no logger).
func TestAuditLogCloserNilLoggerOutputError(t *testing.T) {
	outputErr := errors.New("write error")
	c := auditLogCloser{
		logger: nil,
		output: closerFunc(func() error { return outputErr }),
	}
	err := c.Close()
	if err != outputErr {
		t.Fatalf("Close() = %v, want %v when logger is nil and output errors", err, outputErr)
	}
}

func TestAuditLogMiddlewareDoesNotBlockOnSlowSink(t *testing.T) {
	writer := newBlockingAuditWriter()
	t.Cleanup(writer.releaseWrites)

	auditLogger := NewAuditLogger(writer)
	handler := AuditLogMiddleware(auditLogger, AuditOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	done := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
		writer.releaseWrites()
		<-done
		t.Fatal("audit logging blocked request completion on a slow sink")
	}
	writer.releaseWrites()
	closeAuditLogger(t, auditLogger)
}

func closeAuditLogger(t *testing.T, logger *AuditLogger) {
	t.Helper()
	if err := logger.Close(); err != nil {
		t.Fatalf("audit logger close: %v", err)
	}
}

func chdirForAuditTest(t *testing.T, dir string) func() {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd(): %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%q): %v", dir, err)
	}
	return func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}
}

type blockingAuditWriter struct {
	release     chan struct{}
	releaseOnce sync.Once
}

func newBlockingAuditWriter() *blockingAuditWriter {
	return &blockingAuditWriter{
		release: make(chan struct{}),
	}
}

func (w *blockingAuditWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

func (w *blockingAuditWriter) releaseWrites() {
	w.releaseOnce.Do(func() {
		close(w.release)
	})
}
