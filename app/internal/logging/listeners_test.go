package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/inbound"
)

func TestAccessLogListenerNameComesOnlyFromInboundIdentity(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	handler := AccessLogMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.Header.Set("X-Sockguard-Listener", "spoofed")
	req = req.WithContext(inbound.WithIdentity(req.Context(), inbound.Identity{
		Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix,
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(access log): %v\n%s", err, output.String())
	}
	if got := event["listener_name"]; got != "ci" {
		t.Fatalf("listener_name = %#v, want %q", got, "ci")
	}
	if strings.Contains(output.String(), "spoofed") {
		t.Fatalf("client-controlled listener header leaked into access log: %s", output.String())
	}
}

func TestAuditLogSeparatesListenerIdentityFromTransport(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	auditLogger := NewAuditLogger(&output)
	handler := AuditLogMiddleware(auditLogger, AuditOptions{Listener: "tcp"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.Header.Set("X-Sockguard-Listener", "spoofed")
	req = req.WithContext(inbound.WithIdentity(context.Background(), inbound.Identity{
		Name: "ops", Role: inbound.RoleMain, Network: inbound.NetworkTCP,
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)
	closeAuditLogger(t, auditLogger)

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("json.Unmarshal(audit log): %v\n%s", err, output.String())
	}
	if got := event["listener_name"]; got != "ops" {
		t.Fatalf("listener_name = %#v, want %q", got, "ops")
	}
	if got := event["transport_listener"]; got != "tcp" {
		t.Fatalf("transport_listener = %#v, want %q", got, "tcp")
	}
	if strings.Contains(output.String(), "spoofed") {
		t.Fatalf("client-controlled listener header leaked into audit log: %s", output.String())
	}
}
