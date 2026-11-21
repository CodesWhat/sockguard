package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

const (
	profileRedactionRootAddr = "198.51.100.1:4000" // no profile: root redaction
	profileRedactionInherit  = "192.0.2.10:4000"   // profile "inherit": no overrides
	profileRedactionOverride = "192.0.2.200:4000"  // profile "override"
)

func boolPtr(v bool) *bool { return &v }

func profileRedactionConfig(t *testing.T, rootEnv bool, override *bool) *config.Config {
	t.Helper()
	socketPath := shortSocketPath(t, "prof-redact")
	_ = os.Remove(socketPath)
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Config":{"Env":["SECRET=value"]},"HostConfig":{"NetworkMode":"bridge"}}`)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Response.VisibleResourceLabels = nil
	cfg.Response.RedactContainerEnv = rootEnv
	allowInspect := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/json"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "profile deny"},
	}
	cfg.Rules = allowInspect
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "inherit", Rules: allowInspect},
		{Name: "override", Rules: allowInspect, Response: config.ClientProfileResponseConfig{RedactContainerEnv: override}},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "inherit", CIDRs: []string{"192.0.2.0/25"}},
		{Profile: "override", CIDRs: []string{"192.0.2.128/25"}},
	}
	return &cfg
}

// inspectEnv issues GET /containers/c1/json from remoteAddr through handler
// and returns Config.Env.
func inspectEnv(t *testing.T, handler http.Handler, remoteAddr string) []any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/c1/json", nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, rec.Body.String())
	}
	cfgBody, _ := payload["Config"].(map[string]any)
	env, _ := cfgBody["Env"].([]any)
	return env
}

func buildProfileRedactionHandler(t *testing.T, cfg *config.Config) http.Handler {
	t.Helper()
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return buildServeHandler(t, cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
}

func TestServeChainProfileRedactionOverrides(t *testing.T) {
	tests := []struct {
		name     string
		rootEnv  bool
		override *bool
		addr     string
		wantEnv  bool // true: Env is visible
	}{
		{"root redacts, anonymous client redacted", true, boolPtr(false), profileRedactionRootAddr, false},
		{"root redacts, profile inherits", true, nil, profileRedactionInherit, false},
		{"root redacts, other profile unaffected by sibling override", true, boolPtr(false), profileRedactionInherit, false},
		{"root redacts, profile turns it off", true, boolPtr(false), profileRedactionOverride, true},
		{"root redacts, profile explicitly keeps it on", true, boolPtr(true), profileRedactionOverride, false},
		{"root open, profile turns it on", false, boolPtr(true), profileRedactionOverride, false},
		{"root open, anonymous sees env", false, boolPtr(true), profileRedactionRootAddr, true},
		{"root open, profile inherits", false, nil, profileRedactionOverride, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := buildProfileRedactionHandler(t, profileRedactionConfig(t, tt.rootEnv, tt.override))
			env := inspectEnv(t, handler, tt.addr)
			if got := len(env) > 0; got != tt.wantEnv {
				t.Fatalf("Env visible = %v (%#v), want %v", got, env, tt.wantEnv)
			}
		})
	}
}

func TestServeChainProfileRedactionReloadPicksUpChange(t *testing.T) {
	// Drive the real reload coordinator: it must accept a profile response
	// edit and publish the rebuilt handler through the swappable.
	cfg := profileRedactionConfig(t, true, nil)
	f := newReloadCoordinatorFixture(t, cfg)
	t.Cleanup(f.coordinator.stop)
	f.swappable.Swap(buildProfileRedactionHandler(t, cfg))
	if env := inspectEnv(t, f.swappable, profileRedactionOverride); len(env) != 0 {
		t.Fatalf("before reload Env = %#v, want redacted", env)
	}

	next := *cfg
	next.Clients.Profiles = append([]config.ClientProfileConfig(nil), cfg.Clients.Profiles...)
	next.Clients.Profiles[1].Response.RedactContainerEnv = boolPtr(false)
	f.loadCfg = &next
	f.coordinator.reload()
	if env := inspectEnv(t, f.swappable, profileRedactionOverride); len(env) == 0 {
		t.Fatalf("after reload Env still redacted, want override to apply; log: %s", f.logBuf.String())
	}
}

func TestProfileRedactionWarning(t *testing.T) {
	warnings := func(cfg *config.Config) string {
		var out bytes.Buffer
		warnIfProfileDisablesRedaction(cfg, slog.New(slog.NewTextHandler(&out, nil)))
		return out.String()
	}
	cfg := config.Defaults()
	cfg.Response.RedactHostTopology = false
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "portainer", Response: config.ClientProfileResponseConfig{
			RedactContainerEnv: boolPtr(false),
			RedactMountPaths:   boolPtr(false),
			// Turning a redaction on, or restating one that is already off, never warns.
			RedactHostTopology: boolPtr(true),
		}},
		{Name: "quiet", Response: config.ClientProfileResponseConfig{RedactSensitiveData: boolPtr(true)}},
		{Name: "inherits"},
	}
	got := warnings(&cfg)
	if strings.Count(got, "client profile turns off response redaction") != 1 {
		t.Fatalf("want exactly one warning: %s", got)
	}
	for _, want := range []string{"profile=portainer", "clients.profiles[portainer].response.redact_container_env", "clients.profiles[portainer].response.redact_mount_paths"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning omits %q: %s", want, got)
		}
	}
	for _, unwanted := range []string{"quiet", "inherits", "redact_host_topology", "redact_network_topology"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("warning mentions %q: %s", unwanted, got)
		}
	}
}

func TestReloadWarnsAboutProfileDisabledRedaction(t *testing.T) {
	initial := config.Defaults()
	f := newReloadCoordinatorFixture(t, &initial)
	t.Cleanup(f.coordinator.stop)
	next := initial
	next.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "portainer", Response: config.ClientProfileResponseConfig{RedactContainerEnv: boolPtr(false)}},
	}
	f.loadCfg = &next
	var logged bytes.Buffer
	f.coordinator.logger = slog.New(slog.NewTextHandler(&logged, nil))
	f.coordinator.reload()
	if out := logged.String(); !strings.Contains(out, "profile=portainer") || !strings.Contains(out, "redact_container_env") {
		t.Fatalf("reload did not warn about the profile override: %s", out)
	}
}

func TestReplayRedactionWarningUsesProfileEffectiveRedaction(t *testing.T) {
	allow := []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
	off := boolPtr(false)
	on := boolPtr(true)
	tests := []struct {
		name    string
		setup   func(cfg *config.Config)
		want    bool
		wantKey string
	}{
		{"profile disables all three, root rules do not allow create", func(cfg *config.Config) {
			cfg.Clients.Profiles[0].Response = config.ClientProfileResponseConfig{RedactContainerEnv: off, RedactMountPaths: off, RedactNetworkTopology: off}
		}, false, ""},
		{"profile keeps one on", func(cfg *config.Config) {
			cfg.Clients.Profiles[0].Response = config.ClientProfileResponseConfig{RedactContainerEnv: off, RedactMountPaths: off}
		}, true, "redact_network_topology"},
		{"root off, profile turns env on", func(cfg *config.Config) {
			cfg.Response.RedactContainerEnv, cfg.Response.RedactMountPaths, cfg.Response.RedactNetworkTopology = false, false, false
			cfg.Clients.Profiles[0].Response = config.ClientProfileResponseConfig{RedactContainerEnv: on}
		}, true, "redact_container_env"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci", Rules: allow}}
			cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{{Profile: "ci", CIDRs: []string{"192.0.2.0/24"}}}
			tt.setup(&cfg)
			got := replayWarningOutput(&cfg)
			if (got != "") != tt.want {
				t.Fatalf("warned = %v, want %v: %s", got != "", tt.want, got)
			}
			if tt.wantKey != "" && !strings.Contains(got, tt.wantKey) {
				t.Fatalf("warning omits %q: %s", tt.wantKey, got)
			}
		})
	}
}
