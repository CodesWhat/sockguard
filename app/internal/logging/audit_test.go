package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditLogMiddlewareEmitsDedicatedEventSchema(t *testing.T) {
	var buf bytes.Buffer
	auditLogger := NewAuditLogger(&buf)
	auditLogger.now = func() string { return "2026-04-18T12:34:56Z" }

	handler := AuditLogMiddleware(auditLogger, AuditOptions{
		OwnershipOwner:    "ci-job-123",
		OwnershipLabelKey: "com.sockguard.owner",
	})(RequestIDMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})))

	req := httptest.NewRequest(http.MethodGet, "/v1.45/_ping", nil)
	req.RemoteAddr = "203.0.113.10:4444"
	req.Header.Set(requestIDHeader, "client-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

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

	actorIdentity, ok := event["actor_identity"].(map[string]any)
	if !ok {
		t.Fatalf("actor_identity = %#v, want object", event["actor_identity"])
	}
	if got := actorIdentity["remote_addr"]; got != "203.0.113.10:4444" {
		t.Fatalf("actor_identity.remote_addr = %#v, want %q", got, "203.0.113.10:4444")
	}
	if got := actorIdentity["source_ip"]; got != "203.0.113.10" {
		t.Fatalf("actor_identity.source_ip = %#v, want %q", got, "203.0.113.10")
	}

	transportIdentity, ok := event["transport_identity"].(map[string]any)
	if !ok {
		t.Fatalf("transport_identity = %#v, want object", event["transport_identity"])
	}
	if got := transportIdentity["listener"]; got != "tcp" {
		t.Fatalf("transport_identity.listener = %#v, want %q", got, "tcp")
	}
	if got := transportIdentity["scheme"]; got != "http" {
		t.Fatalf("transport_identity.scheme = %#v, want %q", got, "http")
	}
	if got := transportIdentity["protocol"]; got != "HTTP/1.1" {
		t.Fatalf("transport_identity.protocol = %#v, want %q", got, "HTTP/1.1")
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
