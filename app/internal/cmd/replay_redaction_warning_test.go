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
				for _, key := range []string{"redact_container_env", "redact_mount_paths", "redact_network_topology"} {
					if !strings.Contains(got, key) {
						t.Fatalf("warning does not name %s: %s", key, got)
					}
				}
			}
		})
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
			if got := replayWarningOutput(cfg); got != "" {
				t.Fatalf("%s must not warn: %s", name, got)
			}
		})
	}
}
