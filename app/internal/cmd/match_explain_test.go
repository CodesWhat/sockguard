package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const matchExplainConfig = `
listen:
  socket: /tmp/sockguard.sock
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
ownership:
  owner: root-team
  insecure_allow_weak_owner_selection: true
response:
  redact_container_env: true
  name_patterns: ["root-*"]
rules:
  - match: { method: GET, path: "/containers/json" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
clients:
  default_profile: fallback
  source_ip_profiles:
    - profile: watcher
      cidrs: ["10.0.0.0/24"]
    - profile: ci
      cidrs: ["10.0.0.0/16"]
  unix_peer_profiles:
    - profile: builder
      uids: [1000]
  profiles:
    - name: watcher
      mode: warn
      ownership:
        owner: watch-team
        allow_unowned_images: true
      response:
        redact_container_env: false
        name_patterns: ["watch-*"]
      rules:
        - match: { method: GET, path: "/containers/json" }
          action: allow
        - match: { method: POST, path: "/containers/*/kill", query: { signal: ["USR1"] } }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
          reason: watcher is read-mostly
    - name: builder
      ownership:
        scope: all
      rules:
        - match: { method: POST, path: "/build" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
    - name: ci
      rules:
        - match: { method: GET, path: "/containers/json" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
    - name: fallback
      rules:
        - match: { method: GET, path: "/_ping" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
`

func writeMatchExplainConfig(t *testing.T) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte(matchExplainConfig), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return cfgPath
}

func matchJSON(t *testing.T, cfgPath string, args ...string) matchResult {
	t.Helper()
	full := append([]string{"-c", cfgPath, "match", "-o", "json"}, args...)
	stdout, stderr, err := executeRootCommand(t, full...)
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	var got matchResult
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	return got
}

func TestMatchExplainRootScopeIsUnchangedAndStatesLimits(t *testing.T) {
	cfgPath := writeMatchExplainConfig(t)
	got := matchJSON(t, cfgPath, "-X", "GET", "--path", "/containers/json")

	if got.Decision != "allow" || got.MatchedRule == nil || got.MatchedRule.Index != 1 {
		t.Fatalf("root decision = %q rule %+v", got.Decision, got.MatchedRule)
	}
	if got.Selection == nil || got.Selection.Strategy != "none" || got.Selection.Profile != "" {
		t.Fatalf("selection = %+v", got.Selection)
	}
	if got.Ownership == nil || got.Ownership.Owner != "root-team" || got.Ownership.Source != "root" {
		t.Fatalf("ownership = %+v", got.Ownership)
	}
	if got.Response == nil || !got.Response.Redaction.ContainerEnv || got.Response.Root == nil || got.Response.Profile != nil {
		t.Fatalf("response = %+v", got.Response)
	}
	joined := strings.Join(got.NotInspected, "\n")
	for _, want := range []string{"request body", "live resources"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("not_inspected missing %q: %v", want, got.NotInspected)
		}
	}
	if strings.Contains(joined, "client certificate") {
		t.Fatalf("root run must not mention profile selection limits: %v", got.NotInspected)
	}
}

func TestMatchExplainExplicitProfile(t *testing.T) {
	cfgPath := writeMatchExplainConfig(t)

	t.Run("allow with query constraint", func(t *testing.T) {
		got := matchJSON(t, cfgPath, "-X", "POST", "--profile", "watcher", "--path", "/containers/abc/kill?signal=USR1")
		if got.Decision != "allow" || got.MatchedRule == nil || got.MatchedRule.Index != 2 || !got.MatchedRule.QueryMatched {
			t.Fatalf("got %q %+v", got.Decision, got.MatchedRule)
		}
		if got.Selection.Strategy != "explicit_profile" || got.Selection.Profile != "watcher" {
			t.Fatalf("selection = %+v", got.Selection)
		}
	})

	t.Run("deny passes through under warn mode", func(t *testing.T) {
		got := matchJSON(t, cfgPath, "-X", "DELETE", "--profile", "watcher", "--path", "/containers/abc")
		if got.Decision != "deny" || got.Reason != "watcher is read-mostly" {
			t.Fatalf("got %q %q", got.Decision, got.Reason)
		}
		if got.RolloutMode != "warn" || !got.PassThrough {
			t.Fatalf("rollout = %q pass_through = %v", got.RolloutMode, got.PassThrough)
		}
	})

	t.Run("profile rules replace root rules", func(t *testing.T) {
		// The root rules allow GET /containers/json; builder does not.
		got := matchJSON(t, cfgPath, "-X", "GET", "--profile", "builder", "--path", "/containers/json")
		if got.Decision != "deny" || got.PassThrough {
			t.Fatalf("got %q pass_through=%v", got.Decision, got.PassThrough)
		}
		if got.RolloutMode != "enforce" {
			t.Fatalf("rollout = %q", got.RolloutMode)
		}
	})

	t.Run("ownership and response come from the profile", func(t *testing.T) {
		got := matchJSON(t, cfgPath, "-X", "GET", "--profile", "watcher", "--path", "/containers/json")
		if got.Ownership.Owner != "watch-team" || !got.Ownership.AllowUnownedImages || got.Ownership.Source != "profile watcher" {
			t.Fatalf("ownership = %+v", got.Ownership)
		}
		if got.Response.Redaction.ContainerEnv {
			t.Fatalf("profile override should switch env redaction off: %+v", got.Response.Redaction)
		}
		if got.Response.Root == nil || got.Response.Profile == nil || got.Response.Profile.NamePatterns[0] != "watch-*" {
			t.Fatalf("response = %+v", got.Response)
		}
		if got.Response.Visibility == "" {
			t.Fatalf("visibility note missing: %+v", got.Response)
		}
	})

	t.Run("scope all", func(t *testing.T) {
		got := matchJSON(t, cfgPath, "-X", "POST", "--profile", "builder", "--path", "/build")
		if got.Decision != "allow" || !got.Ownership.AllOwners || got.Ownership.Owner != "root-team" {
			t.Fatalf("got %q ownership %+v", got.Decision, got.Ownership)
		}
	})
}

func TestMatchExplainSourceIPSelection(t *testing.T) {
	cfgPath := writeMatchExplainConfig(t)
	tests := []struct {
		name     string
		ip       string
		profile  string
		strategy string
	}{
		{"first matching assignment wins", "10.0.0.7", "watcher", "source_ip"},
		{"later assignment", "10.0.9.7", "ci", "source_ip"},
		{"ipv4-mapped address", "::ffff:10.0.0.7", "watcher", "source_ip"},
		{"falls back to default profile", "192.168.1.1", "fallback", "default_profile"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchJSON(t, cfgPath, "-X", "GET", "--source-ip", tc.ip, "--path", "/containers/json")
			if got.Selection.Profile != tc.profile || got.Selection.Strategy != tc.strategy {
				t.Fatalf("selection = %+v", got.Selection)
			}
			if !strings.Contains(strings.Join(got.NotInspected, "\n"), "unix peer") {
				t.Fatalf("source IP selection must disclose cert/peer precedence: %v", got.NotInspected)
			}
		})
	}
}

func TestMatchExplainSourceIPWithNoProfileUsesRootRules(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := `
listen:
  socket: /tmp/sockguard.sock
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := matchJSON(t, cfgPath, "-X", "GET", "--source-ip", "10.1.1.1", "--path", "/_ping")
	if got.Decision != "allow" || got.Selection.Strategy != "none" || got.Selection.SourceIP != "10.1.1.1" || got.Selection.Profile != "" {
		t.Fatalf("got %q selection %+v", got.Decision, got.Selection)
	}
	if got.Ownership.Owner != "" || got.Ownership.Source != "root" {
		t.Fatalf("ownership = %+v", got.Ownership)
	}
}

func TestMatchExplainRejectsInvalidSelection(t *testing.T) {
	cfgPath := writeMatchExplainConfig(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown profile", []string{"--profile", "ghost"}, `profile "ghost" is not defined`},
		{"both flags", []string{"--profile", "watcher", "--source-ip", "10.0.0.1"}, "mutually exclusive"},
		{"bad ip", []string{"--source-ip", "not-an-ip"}, "not a valid IP address"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-c", cfgPath, "match", "-X", "GET", "--path", "/containers/json"}, tc.args...)
			_, _, err := executeRootCommand(t, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMatchExplainTextOutput(t *testing.T) {
	cfgPath := writeMatchExplainConfig(t)
	stdout, stderr, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "DELETE", "--source-ip", "10.0.0.7", "--path", "/containers/abc")
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{
		"Profile:         watcher",
		"Selected by:     source_ip (10.0.0.7)",
		"Rollout mode:    warn (a deny passes through to Docker)",
		`Ownership:       owner "watch-team" (profile watcher)`,
		"Response:        redacts mount paths",
		"Profile visible: names watch-*",
		"Not inspected:   request body",
		"Not inspected:   live resources",
		"Not inspected:   client certificate and unix peer",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, stdout)
		}
	}
}
