package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteMatchCommandReportsMatchedRule(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: GET, path: "/containers/*/json" }
    action: allow
  - match: { method: POST, path: "/containers/*/exec" }
    action: deny
    reason: exec disabled
  - match: { method: "*", path: "/**" }
    action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stdout, stderr, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "post",
		"--path", "/v1.45/containers/abc/../abc/exec",
	)
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}

	for _, want := range []string{
		"Method:          POST",
		"Normalized path: /containers/abc/exec",
		"Decision:        deny",
		"Matched rule:    #2",
		"Rule:            deny POST /containers/*/exec",
		"Reason:          exec disabled",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, stdout)
		}
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got:\n%s", stderr)
	}
}

func TestExecuteMatchCommandEnforcesContainerTopReadAcknowledgment(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		acknowledged bool
		rules        string
	}{
		{
			name: "exact docker container",
			path: "/v1.53/containers/payments/top",
			rules: `
  - match: { method: GET, path: "/containers/payments/top" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny`,
		},
		{
			name: "exact libpod container",
			path: "/v5.0.0/libpod/containers/payments/top",
			rules: `
  - match: { method: GET, path: "/libpod/containers/payments/top" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny`,
		},
		{
			name: "representative deny shadows targeted allow",
			path: "/containers/payments/top",
			rules: `
  - match: { method: GET, path: "/containers/sockguard-test/top" }
    action: deny
  - match: { method: GET, path: "/containers/*/top" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny`,
		},
		{
			name:         "acknowledged docker container",
			path:         "/v1.53/containers/payments/top",
			acknowledged: true,
			rules: `
  - match: { method: GET, path: "/containers/payments/top" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "sockguard.yaml")
			acknowledgment := ""
			if tt.acknowledged {
				acknowledgment = "insecure_allow_read_exfiltration: true\n"
			}
			yaml := `
upstream:
  socket: /var/run/docker.sock
` + acknowledgment + "rules:" + tt.rules + "\n"
			if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			stdout, stderr, err := executeRootCommand(t,
				"-c", cfgPath,
				"match",
				"--method", "GET",
				"--path", tt.path,
				"-o", "json",
			)
			if err != nil {
				t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
			}

			var got struct {
				Decision    string `json:"decision"`
				Reason      string `json:"reason"`
				MatchedRule *struct {
					Action string `json:"action"`
				} `json:"matched_rule"`
			}
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v\nstdout:\n%s", err, stdout)
			}

			wantDecision := "deny"
			wantReason := "container process-list reads require insecure_allow_read_exfiltration: true"
			if tt.acknowledged {
				wantDecision = "allow"
				wantReason = ""
			}
			if got.Decision != wantDecision {
				t.Fatalf("decision = %q, want %s", got.Decision, wantDecision)
			}
			if got.Reason != wantReason {
				t.Fatalf("reason = %q, want %q", got.Reason, wantReason)
			}
			if got.MatchedRule == nil || got.MatchedRule.Action != "allow" {
				t.Fatalf("matched_rule = %#v, want matched allow rule", got.MatchedRule)
			}
			if stderr != "" {
				t.Fatalf("expected no stderr output, got:\n%s", stderr)
			}
		})
	}
}

func TestExecuteMatchCommandReportsDefaultDenyWhenNoRuleMatches(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stdout, stderr, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "DELETE",
		"--path", "/containers/json",
	)
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}

	for _, want := range []string{
		"Decision:        deny",
		"Matched rule:    none",
		"Reason:          no matching allow rule",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, stdout)
		}
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got:\n%s", stderr)
	}
}

func TestExecuteMatchCommandJSONOutput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
    reason: ping allowed
  - match: { method: "*", path: "/**" }
    action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stdout, stderr, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "GET",
		"--path", "/v1.45/_ping",
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}

	var got struct {
		Method         string `json:"method"`
		Path           string `json:"path"`
		NormalizedPath string `json:"normalized_path"`
		Decision       string `json:"decision"`
		Reason         string `json:"reason"`
		MatchedRule    *struct {
			Index  int    `json:"index"`
			Method string `json:"method"`
			Path   string `json:"path"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		} `json:"matched_rule"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nstdout:\n%s", err, stdout)
	}

	if got.Method != "GET" {
		t.Fatalf("method = %q, want GET", got.Method)
	}
	if got.Path != "/v1.45/_ping" {
		t.Fatalf("path = %q, want /v1.45/_ping", got.Path)
	}
	if got.NormalizedPath != "/_ping" {
		t.Fatalf("normalized_path = %q, want /_ping", got.NormalizedPath)
	}
	if got.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", got.Decision)
	}
	if got.Reason != "ping allowed" {
		t.Fatalf("reason = %q, want ping allowed", got.Reason)
	}
	if got.MatchedRule == nil {
		t.Fatal("matched_rule = nil, want populated rule")
	}
	if got.MatchedRule.Index != 1 {
		t.Fatalf("matched_rule.index = %d, want 1", got.MatchedRule.Index)
	}
	if got.MatchedRule.Method != "GET" {
		t.Fatalf("matched_rule.method = %q, want GET", got.MatchedRule.Method)
	}
	if got.MatchedRule.Path != "/_ping" {
		t.Fatalf("matched_rule.path = %q, want /_ping", got.MatchedRule.Path)
	}
	if got.MatchedRule.Action != "allow" {
		t.Fatalf("matched_rule.action = %q, want allow", got.MatchedRule.Action)
	}
	if got.MatchedRule.Reason != "ping allowed" {
		t.Fatalf("matched_rule.reason = %q, want ping allowed", got.MatchedRule.Reason)
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got:\n%s", stderr)
	}
}

func TestExecuteMatchCommandRejectsMissingConfig(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.yaml")

	_, _, err := executeRootCommand(t,
		"-c", missing,
		"match",
		"--method", "GET",
		"--path", "/_ping",
	)
	if err == nil {
		t.Fatal("expected match to fail when config file is missing")
	}
	if !strings.Contains(err.Error(), "config file") {
		t.Fatalf("error = %v, want reference to config file", err)
	}
}

func TestExecuteMatchCommandRejectsEmptyExplicitConfig(t *testing.T) {
	_, _, err := executeRootCommand(t,
		"-c", "",
		"match",
		"--method", "GET",
		"--path", "/_ping",
	)
	if err == nil {
		t.Fatal("expected match to fail when explicit config file is empty")
	}
	if !strings.Contains(err.Error(), "config preflight:") {
		t.Fatalf("error = %v, want config preflight failure", err)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error = %v, want empty config guidance", err)
	}
}

func TestExecuteMatchCommandRejectsNonAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _, err := executeRootCommand(t,
		"-c", cfgPath,
		"match",
		"--method", "GET",
		"--path", "containers/json",
	)
	if err == nil {
		t.Fatal("expected match to fail on a path without a leading slash")
	}
	if !strings.Contains(err.Error(), "start with") {
		t.Fatalf("error = %v, want guidance about leading slash", err)
	}
}

func executeRootCommand(t *testing.T, args ...string) (stdout string, stderr string, err error) {
	t.Helper()

	oldCfgFile := cfgFile
	oldMatchMethod := matchMethod
	oldMatchPath := matchPath
	oldMatchOutput := matchOutput

	var out bytes.Buffer
	var errOut bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	rootCmd.SetArgs(args)

	t.Cleanup(func() {
		cfgFile = oldCfgFile
		matchMethod = oldMatchMethod
		matchPath = oldMatchPath
		matchOutput = oldMatchOutput
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})

	err = Execute()
	return out.String(), errOut.String(), err
}
