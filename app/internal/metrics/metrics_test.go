package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/logging"
)

func TestMiddlewareRecordsRequestDecisionMetrics(t *testing.T) {
	registry := NewRegistry()
	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := logging.MetaForRequest(w, r)
		if meta == nil {
			t.Fatal("expected metrics middleware to expose request metadata")
		}
		meta.Decision = "deny"
		meta.Rule = 2
		meta.ReasonCode = "matched_deny_rule"
		meta.NormPath = "/containers/web/update"
		meta.Profile = "watchtower"
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/web/update", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_http_requests_total{decision="deny",method="POST",profile="watchtower",route="/containers/{id}/update",status="403"} 1`)
	assertContains(t, out, `sockguard_http_denied_requests_total{profile="watchtower",reason_code="matched_deny_rule",route="/containers/{id}/update",rule="2"} 1`)
	assertContains(t, out, `sockguard_http_request_duration_seconds_count{decision="deny",method="POST",profile="watchtower",route="/containers/{id}/update"} 1`)
	assertContains(t, out, "sockguard_http_requests_active 0")
}

func TestRouteCategoryKeepsDockerPathLabelsBounded(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "static ping", path: "/_ping", want: "/_ping"},
		{name: "container update id", path: "/containers/web/update", want: "/containers/{id}/update"},
		{name: "container list static", path: "/containers/json", want: "/containers/json"},
		{name: "exec start id", path: "/exec/abc/start", want: "/exec/{id}/start"},
		{name: "network connect id", path: "/networks/frontend/connect", want: "/networks/{id}/connect"},
		{name: "plugin upgrade name", path: "/plugins/example/upgrade", want: "/plugins/{name}/upgrade"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RouteCategory(tt.path); got != tt.want {
				t.Fatalf("RouteCategory(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestHandlerWritesPrometheusTextFormat(t *testing.T) {
	registry := NewRegistry()
	rec := httptest.NewRecorder()

	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if got := rec.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want Prometheus text format", got)
	}
	body := rec.Body.String()
	assertContains(t, body, "# HELP sockguard_http_requests_total Total HTTP requests handled by Sockguard.")
	assertContains(t, body, "# TYPE sockguard_http_requests_active gauge")
}

func renderMetrics(t *testing.T, registry *Registry) string {
	t.Helper()

	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()

	if !strings.Contains(got, want) {
		t.Fatalf("expected output to contain %q, got:\n%s", want, got)
	}
}
