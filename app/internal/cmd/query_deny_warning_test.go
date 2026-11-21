package cmd

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func queryRule(action string, query map[string][]string) config.RuleConfig {
	return config.RuleConfig{
		Match:  config.MatchConfig{Method: "POST", Path: "/containers/*/kill", Query: query},
		Action: action,
	}
}

func TestQueryDenyWarning(t *testing.T) {
	warnings := func(cfg *config.Config) string {
		var out bytes.Buffer
		warnIfQueryDenyRules(cfg, slog.New(slog.NewTextHandler(&out, nil)))
		return out.String()
	}
	q := map[string][]string{"signal": {"KILL"}}

	top := config.Defaults()
	top.Rules = []config.RuleConfig{queryRule("allow", q), queryRule("deny", q)}
	got := warnings(&top)
	if strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "rules[2]") {
		t.Fatalf("top-level deny warning = %q, want exactly one for rules[2]", got)
	}

	prof := config.Defaults()
	prof.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "ci", Rules: []config.RuleConfig{queryRule("deny", q)}},
	}
	got = warnings(&prof)
	if strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "clients.profiles[ci].rules[1]") {
		t.Fatalf("profile deny warning = %q", got)
	}

	quiet := config.Defaults()
	quiet.Rules = []config.RuleConfig{queryRule("allow", q), queryRule("deny", nil)}
	if got := warnings(&quiet); got != "" {
		t.Fatalf("allow-with-query and deny-without-query warned: %q", got)
	}

	var out bytes.Buffer
	warnIfQueryDenyRules(nil, slog.New(slog.NewTextHandler(&out, nil)))
	warnIfQueryDenyRules(&top, nil)
}

func TestRunValidateWarnsOnQueryDeny(t *testing.T) {
	clearSockguardEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := `
listen:
  socket: /tmp/sockguard.sock
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: POST, path: "/containers/*/kill", query: { signal: ["KILL"] } }
    action: deny
  - match: { method: "*", path: "/**" }
    action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })

	var out, errOut bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)
	command.SetErr(&errOut)
	if err := runValidate(command, nil); err != nil {
		t.Fatalf("runValidate() error = %v", err)
	}
	if !strings.Contains(errOut.String(), "only matches the literal spellings") {
		t.Fatalf("validate stderr missing query deny warning:\n%s", errOut.String())
	}
}
