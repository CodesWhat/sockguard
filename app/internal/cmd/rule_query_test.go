package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// killQueryRules is the documented example: kill is allowed with USR1 only.
func killQueryRules() []config.RuleConfig {
	return []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/kill", Query: map[string][]string{"signal": {"USR1", "SIGUSR1"}}}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
}

// killChainDaemon is POST /containers/{id}/kill, recording the raw query of
// every kill that reaches it.
type killChainDaemon struct {
	mu    sync.Mutex
	kills []string
}

func (d *killChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(false))
	case r.Method == http.MethodPost && strings.HasSuffix(normPath, "/kill"):
		d.mu.Lock()
		d.kills = append(d.kills, r.URL.RawQuery)
		d.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *killChainDaemon) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.kills)
}

// TestServeChainRuleQueryConstrainsKill runs the documented example through the
// production chain and asserts on what reached the daemon.
func TestServeChainRuleQueryConstrainsKill(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantStatus int
		wantKills  []string
	}{
		{name: "listed signal", target: "/v1.45/containers/app/kill?signal=USR1", wantStatus: http.StatusNoContent, wantKills: []string{"signal=USR1"}},
		{name: "second listed signal", target: "/containers/app/kill?signal=SIGUSR1", wantStatus: http.StatusNoContent, wantKills: []string{"signal=SIGUSR1"}},
		{name: "percent-encoded listed signal", target: "/containers/app/kill?signal=%55SR1", wantStatus: http.StatusNoContent, wantKills: []string{"signal=%55SR1"}},
		{name: "no signal", target: "/containers/app/kill", wantStatus: http.StatusForbidden},
		{name: "default-kill spelled with an empty value", target: "/containers/app/kill?signal=", wantStatus: http.StatusForbidden},
		{name: "other signal", target: "/containers/app/kill?signal=KILL", wantStatus: http.StatusForbidden},
		{name: "repeated signal smuggles KILL", target: "/containers/app/kill?signal=USR1&signal=KILL", wantStatus: http.StatusForbidden},
		{name: "repeated signal smuggles KILL first", target: "/containers/app/kill?signal=KILL&signal=USR1", wantStatus: http.StatusForbidden},
		{name: "unparseable query", target: "/containers/app/kill?signal=USR1&x=%zz", wantStatus: http.StatusForbidden},
		{name: "semicolon separator", target: "/containers/app/kill?signal=USR1;signal=KILL", wantStatus: http.StatusForbidden},
		{name: "mixed-case variant smuggles KILL", target: "/containers/app/kill?signal=USR1&Signal=KILL", wantStatus: http.StatusForbidden},
		{name: "mixed-case variant first smuggles KILL", target: "/containers/app/kill?Signal=KILL&signal=USR1", wantStatus: http.StatusForbidden},
		{name: "mixed-case variants all listed", target: "/containers/app/kill?signal=USR1&SIGNAL=USR1", wantStatus: http.StatusNoContent, wantKills: []string{"signal=USR1&SIGNAL=USR1"}},
		{name: "different key case", target: "/containers/app/kill?Signal=USR1", wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &killChainDaemon{}
			addr := newEngineChain(t, "kill-q", daemon, func(cfg *config.Config) {
				cfg.Rules = killQueryRules()
			})
			status, body := sendChainRequest(t, http.MethodPost, "http://"+addr+tt.target)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if kills := daemon.seen(); !slices.Equal(kills, tt.wantKills) {
				t.Errorf("daemon kills = %q, want %q", kills, tt.wantKills)
			}
		})
	}
}

// A query-constrained deny fails closed on an unparseable query, so the allow
// below it is not reachable by a spelling the parser rejects.
func TestServeChainRuleQueryDenyFailsClosedOnUnparseable(t *testing.T) {
	daemon := &killChainDaemon{}
	addr := newEngineChain(t, "kill-qd", daemon, func(cfg *config.Config) {
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/kill", Query: map[string][]string{"signal": {"KILL"}}}, Action: "deny"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/kill"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}
	})
	for target, want := range map[string]int{
		"/containers/app/kill?signal=KILL":             http.StatusForbidden,
		"/containers/app/kill?signal=KILL&x=%zz":       http.StatusForbidden,
		"/containers/app/kill?x=%zz":                   http.StatusForbidden,
		"/containers/app/kill?signal=USR1":             http.StatusNoContent,
		"/containers/app/kill?signal=USR1&signal=KILL": http.StatusForbidden, // deny matches on any occurrence
		"/containers/app/kill?signal=USR1&Signal=KILL": http.StatusForbidden,
		"/containers/app/kill?signal=USR1&Signal=TERM": http.StatusNoContent,
	} {
		if status, body := sendChainRequest(t, http.MethodPost, "http://"+addr+target); status != want {
			t.Errorf("%s: status = %d, want %d; body: %s", target, status, want, body)
		}
	}
}

// Per-profile rules take query constraints too, and a rollout mode only
// changes what a deny does, not how a rule matches: in warn and audit the
// would-be deny from a failed constraint is passed through, and in enforce it
// stays a 403.
func TestServeChainProfileRuleQueryUnderRolloutModes(t *testing.T) {
	for _, tt := range []struct {
		mode       string
		wantStatus int
		wantKills  []string
	}{
		{mode: "enforce", wantStatus: http.StatusForbidden},
		{mode: "warn", wantStatus: http.StatusNoContent, wantKills: []string{"signal=KILL"}},
		{mode: "audit", wantStatus: http.StatusNoContent, wantKills: []string{"signal=KILL"}},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			daemon := &killChainDaemon{}
			addr := newEngineChain(t, "kill-qp", daemon, func(cfg *config.Config) {
				cfg.Rules = killQueryRules()
				cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "rollout", Mode: tt.mode, Rules: killQueryRules()}}
				cfg.Clients.DefaultProfile = "rollout"
			})
			status, body := sendChainRequest(t, http.MethodPost, "http://"+addr+"/containers/app/kill?signal=KILL")
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if kills := daemon.seen(); !slices.Equal(kills, tt.wantKills) {
				t.Errorf("daemon kills = %q, want %q", kills, tt.wantKills)
			}
			// A listed signal is allowed in every mode.
			if status, body := sendChainRequest(t, http.MethodPost, "http://"+addr+"/containers/app/kill?signal=USR1"); status != http.StatusNoContent {
				t.Errorf("USR1 status = %d, want 204; body: %s", status, body)
			}
		})
	}
}

// Hot reload recompiles rules, so a changed query constraint takes effect on
// the swapped-in handler.
func TestReloadCoordinatorAppliesChangedRuleQuery(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = killQueryRules()
	f := newReloadCoordinatorFixture(t, &initial)
	f.coordinator.deps.validateRules = validateAndCompileRules

	status := func(target string) int {
		rec := httptest.NewRecorder()
		f.swappable.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, nil))
		return rec.Code
	}

	candidate := initial
	candidate.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/kill", Query: map[string][]string{"signal": {"KILL"}}}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	f.loadCfg = &candidate
	f.coordinator.reload()

	// The initial handler is a stand-in; only the swapped-in chain evaluates
	// the rules. USR1 was the listed signal before, KILL is the listed one now.
	if got := status("/containers/app/kill?signal=USR1"); got != http.StatusForbidden {
		t.Fatalf("after reload USR1 = %d, want 403", got)
	}
	if got := status("/containers/app/kill?signal=KILL"); got == http.StatusForbidden {
		t.Fatalf("after reload KILL = %d, want it past the policy", got)
	}
}

// Startup analyses see a request with no query, so a query-constrained allow
// has to read as reachable or the exposure acknowledgments are bypassed by
// adding a query.
func TestRuleQueryDoesNotHideExposureFromStartupChecks(t *testing.T) {
	tests := []struct {
		name  string
		rules []config.RuleConfig
		want  string
	}{
		{
			name: "buildkit tunnel",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/grpc", Query: map[string][]string{"x": {"1"}}}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
			want: "opaque BuildKit",
		},
		{
			name: "read exfiltration",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/archive", Query: map[string][]string{"path": {"/tmp/*"}}}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
			want: "raw archive/export",
		},
		{
			name: "conditional deny does not shadow the allow below it",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/export", Query: map[string][]string{"x": {"1"}}}, Action: "deny"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/export"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
			want: "raw archive/export",
		},
		{
			// The catalog's representative id is denied outright, so only the
			// reachability walk can find the other ids; it must skip the
			// conditional deny and keep the allow.
			name: "reachability skips a conditional deny",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/export", Query: map[string][]string{"x": {"1"}}}, Action: "deny"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/sockguard-test/export"}, Action: "deny"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/export"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
			want: "raw archive/export",
		},
		{
			name: "reachability keeps a conditional allow",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/sockguard-test/export"}, Action: "deny"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/export", Query: map[string][]string{"x": {"1"}}}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
			want: "raw archive/export",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Rules = tt.rules
			_, err := validateAndCompileRules(&cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateAndCompileRules = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestWithoutQueryConstrainedDenies(t *testing.T) {
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/a", Query: map[string][]string{"x": {"1"}}}, Action: "deny"},
		{Match: config.MatchConfig{Method: "GET", Path: "/b", Query: map[string][]string{"x": {"1"}}}, Action: "allow"},
		{Match: config.MatchConfig{Method: "GET", Path: "/c"}, Action: "deny"},
	}
	got := withoutConditionalDenies(rules)
	if len(got) != 2 || got[0].Match.Path != "/b" || got[1].Match.Path != "/c" {
		t.Fatalf("withoutConditionalDenies = %+v", got)
	}
}

const matchQueryConfig = `
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: POST, path: "/containers/*/kill", query: { signal: ["USR1", "SIGUSR1"] } }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`

func writeMatchQueryConfig(t *testing.T) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte(matchQueryConfig), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return cfgPath
}

func TestExecuteMatchCommandEvaluatesQuery(t *testing.T) {
	cfgPath := writeMatchQueryConfig(t)

	stdout, stderr, err := executeRootCommand(t, "-c", cfgPath, "match", "--method", "post", "--path", "/containers/abc/kill?signal=USR1")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{
		"Path:            /containers/abc/kill",
		"Query:           signal=USR1",
		"Decision:        allow",
		"Matched rule:    #1",
		"Rule query:      signal=USR1|SIGUSR1 (constraints matched)",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, stdout)
		}
	}

	for _, target := range []string{
		"/containers/abc/kill",
		"/containers/abc/kill?signal=KILL",
		"/containers/abc/kill?signal=USR1&signal=KILL",
		"/containers/abc/kill?signal=%zz",
	} {
		stdout, stderr, err := executeRootCommand(t, "-c", cfgPath, "match", "--method", "post", "--path", target)
		if err != nil {
			t.Fatalf("%s: Execute() error = %v\nstderr:\n%s", target, err, stderr)
		}
		if !strings.Contains(stdout, "Decision:        deny") || !strings.Contains(stdout, "Matched rule:    #2") || strings.Contains(stdout, "Rule query:") {
			t.Fatalf("%s: expected a deny by rule #2, got:\n%s", target, stdout)
		}
	}
}

func TestExecuteMatchCommandJSONCarriesQuery(t *testing.T) {
	cfgPath := writeMatchQueryConfig(t)
	stdout, stderr, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST", "--path", "/containers/abc/kill?signal=SIGUSR1", "-o", "json")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	var result matchResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode %q: %v", stdout, err)
	}
	if result.Path != "/containers/abc/kill" || result.Query != "signal=SIGUSR1" || result.Decision != "allow" {
		t.Fatalf("result = %+v", result)
	}
	if result.MatchedRule == nil || !result.MatchedRule.QueryMatched || !slices.Equal(result.MatchedRule.Query["signal"], []string{"USR1", "SIGUSR1"}) {
		t.Fatalf("matched rule = %+v", result.MatchedRule)
	}
}

func TestRunValidateListsRuleQuery(t *testing.T) {
	clearSockguardEnv(t)
	cfgPath := writeMatchQueryConfig(t)
	stdout, stderr, err := executeRootCommand(t, "-c", cfgPath, "validate")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "/containers/*/kill ?signal=USR1|SIGUSR1") {
		t.Fatalf("expected the rule's query in the listing, got:\n%s", stdout)
	}
}

const matchQueryDenyConfig = `
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: POST, path: "/containers/*/kill", query: { signal: ["KILL"] } }
    action: deny
  - match: { method: GET, path: "/_ping" }
    action: allow
`

func TestExecuteMatchCommandUnparseableQueryDeny(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte(matchQueryDenyConfig), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stdout, stderr, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST", "--path", "/containers/abc/kill?signal=%zz", "-o", "json")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	var result matchResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode %q: %v", stdout, err)
	}
	if result.Decision != "deny" || result.MatchedRule == nil || result.MatchedRule.Index != 1 ||
		result.MatchedRule.QueryMatched || !result.MatchedRule.QueryParseError {
		t.Fatalf("result = %+v matched = %+v", result, result.MatchedRule)
	}

	stdout, stderr, err = executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST", "--path", "/containers/abc/kill?signal=%zz", "-o", "text")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "query failed to parse, rule matched fail-closed") || strings.Contains(stdout, "constraints matched") {
		t.Fatalf("text output:\n%s", stdout)
	}

	stdout, _, err = executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST", "--path", "/containers/abc/kill?signal=KILL", "-o", "text")
	if err != nil || !strings.Contains(stdout, "(constraints matched)") {
		t.Fatalf("parsed query: err=%v\n%s", err, stdout)
	}
}
