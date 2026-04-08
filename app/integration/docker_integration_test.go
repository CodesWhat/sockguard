//go:build integration

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/health"
)

func TestProxyAllowsDockerPing(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	handler := newIntegrationProxyHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.TrimSpace(string(body)) != "OK" {
		t.Fatalf("body = %q, want OK", string(body))
	}
}

func TestProxyAllowsVersionWithDockerAPIPrefix(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	version := fetchDockerVersion(t, socketPath)

	handler := newIntegrationProxyHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/version"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v"+version.APIVersion+"/version", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body dockerVersionResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.APIVersion == "" {
		t.Fatal("expected ApiVersion in Docker version response")
	}
	if body.Version == "" {
		t.Fatal("expected Version in Docker version response")
	}
}

func TestHealthEndpointReportsHealthyAgainstDocker(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)

	handler := health.Handler(socketPath, time.Now().Add(-time.Second), newIntegrationLogger())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body health.HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "healthy" {
		t.Fatalf("status field = %q, want healthy", body.Status)
	}
	if body.Upstream != "connected" {
		t.Fatalf("upstream field = %q, want connected", body.Upstream)
	}
}
