package cmd

import (
	"bytes"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func pingWarningOutput(cfg *config.Config) string {
	var out bytes.Buffer
	warnIfPingNotAllowed(cfg, slog.New(slog.NewTextHandler(&out, nil)))
	return out.String()
}

func pingCfg(setup func(cfg *config.Config)) *config.Config {
	cfg := &config.Config{}
	setup(cfg)
	return cfg
}

func allowRule(method, path string) config.RuleConfig {
	return config.RuleConfig{Action: "allow", Match: config.MatchConfig{Method: method, Path: path}}
}

func TestPingWarning(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(cfg *config.Config)
		wantScope string
	}{
		{"default rules without ping", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule(http.MethodGet, "/containers/**")}
		}, `scope=rules`},
		{"only HEAD allowed (GET missing)", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule(http.MethodHead, "/_ping")}
		}, `scope=rules`},
		{"profile without ping", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule("*", "/**")}
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci", Rules: []config.RuleConfig{allowRule(http.MethodGet, "/containers/**")}}}
		}, `clients.profiles[ci].rules`},
		{"ping denied before allow-all", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{
				{Action: "deny", Match: config.MatchConfig{Method: "*", Path: "/_ping"}},
				allowRule("*", "/**"),
			}
		}, `scope=rules`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pingWarningOutput(pingCfg(tc.setup))
			if !strings.Contains(got, "GET /_ping") || !strings.Contains(got, tc.wantScope) {
				t.Fatalf("warning = %q, want scope %q", got, tc.wantScope)
			}
		})
	}
}

func TestPingWarningSilent(t *testing.T) {
	tests := []struct {
		name  string
		setup func(cfg *config.Config)
	}{
		{"explicit GET and HEAD", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule(http.MethodGet, "/_ping"), allowRule(http.MethodHead, "/_ping")}
		}},
		{"GET only", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule(http.MethodGet, "/_ping")}
		}},
		{"allow all", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule("*", "/**")}
		}},
		{"any-method ping rule", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule("*", "/_ping")}
		}},
		{"empty rule sets", func(cfg *config.Config) {
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "empty"}}
		}},
		{"default profile makes top-level rules unreachable", func(cfg *config.Config) {
			cfg.Rules = []config.RuleConfig{allowRule(http.MethodGet, "/containers/**")}
			cfg.Clients.DefaultProfile = "ro"
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ro", Rules: []config.RuleConfig{allowRule("*", "/**")}}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pingWarningOutput(pingCfg(tc.setup)); got != "" {
				t.Fatalf("unexpected warning: %q", got)
			}
		})
	}
	if got := pingWarningOutput(nil); got != "" {
		t.Fatalf("nil config warned: %q", got)
	}
}

// Shipped presets must not trip the warning: they are the configs most
// operators copy, so a warning there reads as a defect in the preset.
func TestShippedPresetsDoNotTriggerPingWarning(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "configs", "*.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("glob presets: %v (%d found)", err, len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			clearSockguardEnv(t)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load(%s): %v", path, err)
			}
			if got := pingWarningOutput(cfg); got != "" {
				t.Fatalf("%s triggers the ping warning: %s", path, got)
			}
		})
	}
}
