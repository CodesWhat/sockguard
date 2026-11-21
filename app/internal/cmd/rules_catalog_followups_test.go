package cmd

import (
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// catalogAckCase drives one allow rule through validateAndCompileRules with
// and without the acknowledgment that guards the catalog entry it reaches.
type catalogAckCase struct {
	name       string
	method     string
	path       string
	wantEntry  string
	blindWrite bool // true: insecure_allow_body_blind_writes guards it; false: read exfiltration
}

func catalogAckConfig(tc catalogAckCase, ack bool) config.Config {
	cfg := config.Defaults()
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: tc.method, Path: tc.path}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.Rules = rules
	if ack {
		if tc.blindWrite {
			cfg.InsecureAllowBodyBlindWrites = true
		} else {
			cfg.InsecureAllowReadExfiltration = true
		}
	}
	return cfg
}

func runCatalogAckCases(t *testing.T, cases []catalogAckCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := catalogAckConfig(tc, false)
			_, err := validateAndCompileRules(&cfg)
			if err == nil {
				t.Fatalf("expected %s %s without acknowledgment to fail validation", tc.method, tc.path)
			}
			if !strings.Contains(err.Error(), tc.wantEntry) {
				t.Fatalf("expected %q in error, got: %v", tc.wantEntry, err)
			}
			wantFlag := "insecure_allow_read_exfiltration"
			if tc.blindWrite {
				wantFlag = "insecure_allow_body_blind_writes"
			}
			if !strings.Contains(err.Error(), wantFlag) {
				t.Fatalf("expected %s hint in error, got: %v", wantFlag, err)
			}

			cfg = catalogAckConfig(tc, true)
			if _, err := validateAndCompileRules(&cfg); err != nil {
				t.Fatalf("acknowledged config rejected: %v", err)
			}
		})
	}
}

func TestDockerCheckpointRoutesRequireAcknowledgment(t *testing.T) {
	runCatalogAckCases(t, []catalogAckCase{
		{name: "ALLOW_DELETE shape reaches checkpoint delete", method: http.MethodDelete, path: "/containers/**", wantEntry: "DELETE /containers/sockguard-test/checkpoints/sockguard-test", blindWrite: true},
		{name: "exact checkpoint delete", method: http.MethodDelete, path: "/containers/*/checkpoints/*", wantEntry: "DELETE /containers/sockguard-test/checkpoints/sockguard-test", blindWrite: true},
		{name: "wildcard checkpoint create", method: http.MethodPost, path: "/containers/*/checkpoints", wantEntry: "POST /containers/sockguard-test/checkpoints", blindWrite: true},
		{name: "checkpoint list is an exfil surface", method: http.MethodGet, path: "/containers/*/checkpoints", wantEntry: "GET /containers/sockguard-test/checkpoints"},
		{name: "broad container GET reaches checkpoint list", method: http.MethodGet, path: "/containers/**", wantEntry: "GET /containers/sockguard-test/checkpoints"},
	})
}

func TestDockerCheckpointRoutesStayDeniedByDefault(t *testing.T) {
	cfg := config.Defaults()
	if _, err := validateAndCompileRules(&cfg); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}

func TestDaemonDebugRoutesRequireReadExfiltrationAcknowledgment(t *testing.T) {
	runCatalogAckCases(t, []catalogAckCase{
		{name: "expvar", method: http.MethodGet, path: "/debug/vars", wantEntry: "GET /debug/vars"},
		{name: "pprof index", method: http.MethodGet, path: "/debug/pprof", wantEntry: "GET /debug/pprof"},
		{name: "pprof cmdline", method: http.MethodGet, path: "/debug/pprof/cmdline", wantEntry: "GET /debug/pprof/cmdline"},
		{name: "pprof profile", method: http.MethodGet, path: "/debug/pprof/profile", wantEntry: "GET /debug/pprof/profile"},
		{name: "pprof trace", method: http.MethodGet, path: "/debug/pprof/trace", wantEntry: "GET /debug/pprof/trace"},
		{name: "arbitrary profile name", method: http.MethodGet, path: "/debug/pprof/heap", wantEntry: "GET /debug/pprof/heap"},
		{name: "debug glob", method: http.MethodGet, path: "/debug/**", wantEntry: "GET /debug/vars"},
		{name: "any method debug glob", method: "*", path: "/debug/**", wantEntry: "GET /debug/pprof"},
	})
}

func TestDaemonDebugRoutesPrecedingDenyKeepsConfigValid(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/debug/**"}, Action: "deny"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	_, err := validateAndCompileRules(&cfg)
	if err != nil && (strings.Contains(err.Error(), "/debug/")) {
		t.Fatalf("debug routes denied ahead of the allow were still reported: %v", err)
	}
}

func TestDaemonDebugRoutesReportedForClientProfile(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}
	cfg.Clients.Profiles = []config.ClientProfileConfig{{
		Name: "scraper",
		Rules: []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodGet, Path: "/debug/pprof/*"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		},
	}}
	_, err := validateAndCompileRules(&cfg)
	if err == nil || !strings.Contains(err.Error(), "/debug/pprof/") {
		t.Fatalf("expected profile debug allow to be refused without acknowledgment, got: %v", err)
	}
}

func TestKnownRouteCatalogCarriesDebugRoutes(t *testing.T) {
	routes, err := loadKnownAPIRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/debug/vars", "/debug/pprof/", "/debug/pprof/{name}"} {
		found := false
		for _, route := range routes {
			if route.Method == http.MethodGet && route.Path == want {
				found = true
			}
		}
		if !found {
			t.Errorf("known route catalog is missing GET %s", want)
		}
	}
}
