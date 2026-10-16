package cmd

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
	"github.com/spf13/cobra"
)

func TestValidateWarnsForUnknownGlobalAndProfileRoutes(t *testing.T) {
	clearSockguardEnv(t)
	file := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(file, []byte(`rules:
  - match: {method: GET, path: /contaniers/json}
    action: allow
  - match: {method: GET, path: /containers/ordinary-name/json}
    action: allow
  - match: {method: GET, path: /does-not-exist}
    action: deny
clients:
  profiles:
    - name: restricted
      rules:
        - match: {method: PATCH, path: /not-an-api}
          action: deny
        - match: {method: GET, path: /libpod/containers/ordinary-name/json}
          action: allow
`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := cfgFile
	cfgFile = file
	t.Cleanup(func() { cfgFile = previous })
	var out, diagnostics bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&out)
	command.SetErr(&diagnostics)
	if err := runValidate(command, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "validation passed") {
		t.Fatalf("validation did not succeed: %s", out.String())
	}
	if got := strings.Count(diagnostics.String(), "rule matches no known Docker or Podman API route"); got != 3 {
		t.Fatalf("got %d route warnings, want 3: %s", got, diagnostics.String())
	}
	for _, path := range []string{"/contaniers/json", "/does-not-exist", "/not-an-api"} {
		if !strings.Contains(diagnostics.String(), path) {
			t.Errorf("missing %s in %s", path, diagnostics.String())
		}
	}
	if strings.Contains(diagnostics.String(), "ordinary-name") {
		t.Fatalf("warned about a known route: %s", diagnostics.String())
	}
}

func TestKnownRouteWarningsMatchRouteLanguages(t *testing.T) {
	routes, err := loadKnownAPIRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/containers/a-real-name/json", true},
		{"GET", "/images/registry.example.com/team/app:release/json", true},
		{"GET", "/libpod/pods/a-real-name/json", true},
		{"POST", "/libpod/images/scp/registry.example.com/team/app", true},
		{"POST", "/moby.buildkit.v1.Control/Solve", true},
		{"POST", "/moby.buildkit.v1.Control/Prune", true},
		{"GET,POST", "/containers/create", true},
		{"HEAD", "/_ping", true},
		{"*", "/**", true},
		{"GET", "/containers/**/json", true},
		{"PATCH", "/containers/create", false},
		{"GET", "/typo/containers/json", false},
		{"GET", "/containers/json/typo", false},
		{"GET", "/typo/_ping", false},
		{"GET", "/_ping/typo", false},
		{"GET", "/containers/**/impossible-suffix", false},
		{"GET", "/containers/a-specific-typo/jsonn", false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			rule := config.RuleConfig{Action: "deny", Match: config.MatchConfig{Method: tc.method, Path: tc.path}}
			if got := ruleMatchesKnownAPIRoute(rule, routes); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStartupKnownRouteWarningsRemainAdvisoryAndBounded(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Action: "deny", Match: config.MatchConfig{Method: "GET", Path: "/a-misspelled-endpoint"}},
		{Action: "allow", Match: config.MatchConfig{Method: "GET", Path: "/" + strings.Repeat("a", 5000)}},
	}
	var out bytes.Buffer
	warnIfRulesMatchNoKnownRoute(&cfg, slog.New(slog.NewTextHandler(&out, nil)))
	if strings.Count(out.String(), "rule matches no known") != 1 || !strings.Contains(out.String(), "rules[0]") {
		t.Fatalf("wrong startup diagnostics: %s", out.String())
	}
	if len(cfg.Rules) != 2 || cfg.Rules[0].Action != "deny" {
		t.Fatal("diagnostics changed policy")
	}
}
