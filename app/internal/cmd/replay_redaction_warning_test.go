package cmd

import (
	"bytes"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

func replayWarningOutput(cfg *config.Config) string {
	var out bytes.Buffer
	warnIfCreateAllowedWithResponseRedaction(cfg, slog.New(slog.NewTextHandler(&out, nil)))
	return out.String()
}

func TestReplayRedactionWarningCustomConfig(t *testing.T) {
	tests := []struct {
		name  string
		setup func(cfg *config.Config)
		want  bool
	}{
		{"docker create default rules", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
		}, true},
		{"libpod create default rules", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}}}
		}, true},
		{"create allowed by a profile only", func(cfg *config.Config) {
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci", Rules: []config.RuleConfig{
				{Action: "allow", Match: config.MatchConfig{Method: "*", Path: "/**"}},
			}}}
		}, true},
		{"deny create then allow all methods", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{
				{Action: "deny", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}},
				{Action: "deny", Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}},
				{Action: "allow", Match: config.MatchConfig{Method: "*", Path: "/**"}},
			}
		}, false},
		{"allow all methods before a later create deny", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{
				{Action: "allow", Match: config.MatchConfig{Method: "*", Path: "/**"}},
				{Action: "deny", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}},
			}
		}, true},
		{"default profile makes top-level rules unreachable", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
			cfg.Clients.DefaultProfile = "ro"
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ro", Rules: []config.RuleConfig{
				{Action: "allow", Match: config.MatchConfig{Method: http.MethodGet, Path: "/**"}},
			}}}
		}, false},
		{"create denied", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{
				{Action: "deny", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}},
				{Action: "allow", Match: config.MatchConfig{Method: http.MethodGet, Path: "/**"}},
			}
		}, false},
		{"read-only rules", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}}}
		}, false},
		{"redaction off", func(cfg *config.Config) {
			cfg.Response.RedactContainerEnv = false
			cfg.Response.RedactMountPaths = false
			cfg.Response.RedactNetworkTopology = false
			cfg.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			tc.setup(&cfg)
			got := replayWarningOutput(&cfg)
			if tc.want != (got != "") {
				t.Fatalf("warning present = %v, want %v: %s", got != "", tc.want, got)
			}
			if tc.want {
				if !strings.Contains(got, "allowed_by=") {
					t.Fatalf("warning does not name the allowing scope: %s", got)
				}
				for _, key := range []string{"redact_container_env", "redact_mount_paths", "redact_network_topology"} {
					if !strings.Contains(got, key) {
						t.Fatalf("warning does not name %s: %s", key, got)
					}
				}
			}
		})
	}
}

func TestReplayRedactionWarningNamesScopeAndCountsOthers(t *testing.T) {
	cfg := config.Defaults()
	allow := []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
	cfg.Rules = allow
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci", Rules: allow}, {Name: "deploy", Rules: allow}}
	got := replayWarningOutput(&cfg)
	if strings.Count(got, "container create is allowed") != 1 {
		t.Fatalf("want exactly one warning: %s", got)
	}
	if !strings.Contains(got, "allowed_by=rules") || !strings.Contains(got, "other_allowing_scopes=2") {
		t.Fatalf("unexpected scope fields: %s", got)
	}

	cfg.Clients.DefaultProfile = "ci"
	got = replayWarningOutput(&cfg)
	if !strings.Contains(got, "allowed_by=clients.profiles[ci].rules") || !strings.Contains(got, "other_allowing_scopes=1") {
		t.Fatalf("default profile should skip top-level rules and name the profile: %s", got)
	}
}

func TestReplayRedactionWarningNamesOnlyEnabledKeys(t *testing.T) {
	cfg := config.Defaults()
	cfg.Response.RedactContainerEnv = false
	cfg.Response.RedactNetworkTopology = false
	cfg.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
	got := replayWarningOutput(&cfg)
	if !strings.Contains(got, "redact_mount_paths") || strings.Contains(got, "redact_container_env") || strings.Contains(got, "redact_network_topology") {
		t.Fatalf("unexpected keys in warning: %s", got)
	}
}

func TestReplayRedactionWarningSilentForReplayPresets(t *testing.T) {
	for _, name := range []string{"drydock.yaml", "watchtower.yaml", "portwing.yaml", "portainer.yaml"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(filepath.Join("..", "..", "configs", name))
			if err != nil {
				t.Fatalf("Load(%s): %v", name, err)
			}
			if !rulesAllowReplayCreate(cfg.Rules) {
				t.Fatalf("%s must allow container create, otherwise this test is vacuous", name)
			}
			if got := replayWarningOutput(cfg); got != "" {
				t.Fatalf("%s must not warn: %s", name, got)
			}
		})
	}
}
