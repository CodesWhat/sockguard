package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

func TestBuildkitMediatorUsesAssignedProfilePolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "buildkit-profile-upstream")
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "buildkit",
			RequestBody: config.RequestBodyConfig{
				Buildkit: config.BuildkitRequestBodyConfig{
					Control: config.BuildkitControlRequestBodyConfig{AllowInfo: true},
					Session: config.BuildkitSessionRequestBodyConfig{Health: true},
				},
			},
		},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "buildkit", CIDRs: []string{"192.0.2.0/24"}},
	}

	resolver := upstream.NewSingleSocket(cfg.Upstream.Socket)
	var nextCalls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := withClientACL(&cfg, resolver, newDiscardLogger())(
		withBuildkitMediator(&cfg, resolver, newDiscardLogger())(next),
	)

	for _, path := range []string{"/grpc", "/session"} {
		t.Run(path, func(t *testing.T) {
			before := nextCalls.Load()
			assigned := httptest.NewRequest(http.MethodPost, path, nil)
			assigned.RemoteAddr = "192.0.2.10:4000"
			assignedRec := httptest.NewRecorder()
			handler.ServeHTTP(assignedRec, assigned)

			if assignedRec.Code != http.StatusBadRequest {
				t.Fatalf("assigned status = %d, want mediated invalid-upgrade %d; body: %s", assignedRec.Code, http.StatusBadRequest, assignedRec.Body.String())
			}
			if got := nextCalls.Load(); got != before {
				t.Fatalf("fallthrough calls after assigned request = %d, want %d", got, before)
			}

			unassigned := httptest.NewRequest(http.MethodPost, path, nil)
			unassigned.RemoteAddr = "198.51.100.10:4000"
			unassignedRec := httptest.NewRecorder()
			handler.ServeHTTP(unassignedRec, unassigned)

			if unassignedRec.Code != http.StatusNoContent {
				t.Fatalf("unassigned status = %d, want fallthrough %d; body: %s", unassignedRec.Code, http.StatusNoContent, unassignedRec.Body.String())
			}
			if got := nextCalls.Load(); got != before+1 {
				t.Fatalf("fallthrough calls after unassigned request = %d, want %d", got, before+1)
			}
		})
	}
}

func TestBuildServeHandlerAppliesAssignedProfileResourceLimit(t *testing.T) {
	socketPath := shortSocketPath(t, "resource-profile-upstream")
	_ = os.Remove(socketPath)

	var inspectCalls atomic.Int32
	var updateCalls atomic.Int32
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/containers/demo/json":
			inspectCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"HostConfig":{"Memory":0}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/demo/update":
			updateCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected upstream request", http.StatusNotFound)
		}
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "strict",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/update"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
			},
			RequestBody: config.RequestBodyConfig{
				ContainerUpdate: config.ContainerUpdateRequestBodyConfig{
					AllowResourceUpdates: true,
					RequireMemoryLimit:   true,
				},
			},
		},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "strict", CIDRs: []string{"192.0.2.0/24"}},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	assigned := httptest.NewRequest(http.MethodPost, "/containers/demo/update", strings.NewReader(`{}`))
	assigned.RemoteAddr = "192.0.2.10:4000"
	assignedRec := httptest.NewRecorder()
	handler.ServeHTTP(assignedRec, assigned)
	if assignedRec.Code != http.StatusForbidden {
		t.Fatalf("assigned status = %d, want %d; body: %s", assignedRec.Code, http.StatusForbidden, assignedRec.Body.String())
	}

	unassigned := httptest.NewRequest(http.MethodPost, "/containers/demo/update", strings.NewReader(`{}`))
	unassigned.RemoteAddr = "198.51.100.10:4000"
	unassignedRec := httptest.NewRecorder()
	handler.ServeHTTP(unassignedRec, unassigned)
	if unassignedRec.Code != http.StatusNoContent {
		t.Fatalf("unassigned status = %d, want %d; body: %s", unassignedRec.Code, http.StatusNoContent, unassignedRec.Body.String())
	}

	if got := inspectCalls.Load(); got != 1 {
		t.Fatalf("resource-state inspect calls = %d, want assigned request only", got)
	}
	if got := updateCalls.Load(); got != 1 {
		t.Fatalf("upstream update calls = %d, want unassigned request only", got)
	}
}

func TestBuildServeHandlerAppliesAssignedProfileRateLimit(t *testing.T) {
	socketPath := shortSocketPath(t, "rate-profile-upstream")
	_ = os.Remove(socketPath)

	var upstreamCalls atomic.Int32
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/_ping" {
			http.Error(w, "unexpected upstream request", http.StatusNotFound)
			return
		}
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "limited",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
			},
			Limits: config.LimitsConfig{
				Rate: &config.RateLimitConfig{TokensPerSecond: 0.001, Burst: 1},
			},
		},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "limited", CIDRs: []string{"192.0.2.0/24"}},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	request := func(remoteAddr string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := request("192.0.2.10:4000"); rec.Code != http.StatusOK {
		t.Fatalf("first assigned status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec := request("192.0.2.10:4001"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second assigned status = %d, want %d; body: %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	if rec := request("198.51.100.10:4000"); rec.Code != http.StatusOK {
		t.Fatalf("unassigned status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want first assigned plus unassigned requests", got)
	}
}
