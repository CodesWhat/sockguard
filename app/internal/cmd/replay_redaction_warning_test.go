package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
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
			cfg.Clients.DefaultProfile = "ci"
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
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "ci", CIDRs: []string{"192.0.2.0/25"}},
		{Profile: "deploy", CIDRs: []string{"192.0.2.128/25"}},
	}

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

func TestReplayRedactionWarningIgnoresUnselectedProfiles(t *testing.T) {
	cfg := config.Defaults()
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "unused", Rules: []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}}}
	if got := replayWarningOutput(&cfg); got != "" {
		t.Fatalf("unselected profile produced a warning: %s", got)
	}
}

func TestReplayRedactionWarningSelectableProfiles(t *testing.T) {
	for _, kind := range []string{"default", "certificate", "unix", "source"} {
		t.Run(kind, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci", Rules: []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}}}
			switch kind {
			case "default":
				cfg.Clients.DefaultProfile = "ci"
			case "certificate":
				cfg.Clients.ClientCertificateProfiles = []config.ClientCertificateProfileAssignmentConfig{{Profile: "ci", CommonNames: []string{"ci"}}}
			case "unix":
				cfg.Clients.UnixPeerProfiles = []config.ClientUnixPeerProfileAssignmentConfig{{Profile: "ci", UIDs: []uint32{1000}}}
			case "source":
				cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{{Profile: "ci", CIDRs: []string{"192.0.2.0/24"}}}
			}
			if got := replayWarningOutput(&cfg); got == "" {
				t.Fatal("selectable create profile did not warn")
			}
		})
	}
}

func TestReplayRedactionWarningStatesGlobalEffect(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
	got := replayWarningOutput(&cfg)
	for _, fact := range []string{"global", "every client", "dedicated instance"} {
		if !strings.Contains(got, fact) {
			t.Errorf("warning omits %q: %s", fact, got)
		}
	}
}

type replayWarningObserver func([]byte)

func (f replayWarningObserver) Write(p []byte) (int, error) { f(p); return len(p), nil }

func TestReloadWarnsAboutReplayRedactionBeforeSwap(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		name := "valid"
		if invalid {
			name = "invalid"
		}
		t.Run(name, func(t *testing.T) {
			initial := config.Defaults()
			f := newReloadCoordinatorFixture(t, &initial)
			t.Cleanup(f.coordinator.stop)
			next := initial
			next.Rules = []config.RuleConfig{{Action: "allow", Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}}}
			f.loadCfg = &next
			if invalid {
				f.validateErr = errors.New("invalid candidate")
			}
			seen, oldAtWarning := false, false
			oldTarget := fmt.Sprintf("%p", f.swappable.Current())
			observer := replayWarningObserver(func(p []byte) {
				if bytes.Contains(p, []byte("container create is allowed")) {
					seen = true
					oldAtWarning = fmt.Sprintf("%p", f.swappable.Current()) == oldTarget
				}
			})
			f.coordinator.logger = slog.New(slog.NewTextHandler(observer, nil))
			f.coordinator.reload()
			if seen == invalid {
				t.Fatalf("warning present=%v, invalid=%v", seen, invalid)
			}
			if !invalid && !oldAtWarning {
				t.Fatal("warning emitted after new handler became active")
			}
			result := "ok"
			if invalid {
				result = "reject_validation"
			}
			if count, ok := f.reloadCount(result); !ok || count != 1 {
				t.Fatalf("reload result %s=%d, present=%v", result, count, ok)
			}
		})
	}
}
