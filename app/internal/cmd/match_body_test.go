package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const matchBodyConfig = `
listen:
  socket: /tmp/sockguard.sock
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: POST, path: "/containers/create" }
    action: allow
  - match: { method: POST, path: "/containers/*/kill" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
    reason: not allowed
clients:
  profiles:
    - name: strict
      mode: warn
      rules:
        - match: { method: POST, path: "/containers/create" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
`

func writeMatchBodyFixtures(t *testing.T, body string) (cfgPath, bodyPath string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte(matchBodyConfig), 0o644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
	bodyPath = filepath.Join(dir, "body.json")
	if err := os.WriteFile(bodyPath, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile body: %v", err)
	}
	return cfgPath, bodyPath
}

func TestMatchBodyFileAllow(t *testing.T) {
	cfgPath, bodyPath := writeMatchBodyFixtures(t, `{"Image":"alpine:3"}`)
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/containers/create", "--body-file", bodyPath)

	if got.Decision != "allow" {
		t.Fatalf("decision = %q reason %q", got.Decision, got.Reason)
	}
	if got.Body == nil || got.Body.Decision != "allow" || got.Body.Source != bodyPath {
		t.Fatalf("body = %+v", got.Body)
	}
	joined := strings.Join(got.Body.NotEvaluated, "\n")
	if !strings.Contains(joined, "upstream engine checks") {
		t.Fatalf("container create must disclose engine-dependent gates: %v", got.Body.NotEvaluated)
	}
	if strings.Contains(strings.Join(got.NotInspected, "\n"), "request body") {
		t.Fatalf("a body was inspected, not_inspected must not claim otherwise: %v", got.NotInspected)
	}
	if !strings.Contains(strings.Join(got.NotInspected, "\n"), "live resources") {
		t.Fatalf("live resources must still be reported as not inspected: %v", got.NotInspected)
	}
}

func TestMatchBodyFileDenyUsesInspectorReason(t *testing.T) {
	cfgPath, bodyPath := writeMatchBodyFixtures(t, `{"Image":"alpine:3","HostConfig":{"Privileged":true}}`)
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/containers/create", "--body-file", bodyPath)

	if got.Decision != "deny" {
		t.Fatalf("decision = %q, want deny from the body inspector", got.Decision)
	}
	if got.Body == nil || got.Body.Decision != "deny" || got.Body.ReasonCode != "request_body_policy_denied" {
		t.Fatalf("body = %+v", got.Body)
	}
	if !strings.Contains(got.Body.Reason, "privileged") || got.Reason != got.Body.Reason {
		t.Fatalf("reason = %q body reason = %q", got.Reason, got.Body.Reason)
	}
	if got.MatchedRule == nil || got.MatchedRule.Action != "allow" {
		t.Fatalf("the allow rule that matched must still be reported: %+v", got.MatchedRule)
	}
}

func TestMatchBodyFileInvalidJSON(t *testing.T) {
	cfgPath, bodyPath := writeMatchBodyFixtures(t, `{"Image": `)
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/containers/create", "--body-file", bodyPath)

	if got.Decision != "deny" || got.Body == nil || got.Body.Decision != "deny" {
		t.Fatalf("decision = %q body = %+v", got.Decision, got.Body)
	}
	if got.Body.Reason == "" {
		t.Fatalf("a malformed body must carry the inspector's reason: %+v", got.Body)
	}
}

func TestMatchBodyFileOversize(t *testing.T) {
	big := `{"Image":"alpine","Labels":{"x":"` + strings.Repeat("a", 2<<20) + `"}}`
	cfgPath, bodyPath := writeMatchBodyFixtures(t, big)
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/containers/create", "--body-file", bodyPath)

	if got.Decision != "deny" || got.Body == nil || got.Body.ReasonCode != "request_body_too_large" || got.Body.Status != 413 {
		t.Fatalf("decision = %q body = %+v", got.Decision, got.Body)
	}
}

func TestMatchBodyFileRouteWithoutInspector(t *testing.T) {
	cfgPath, bodyPath := writeMatchBodyFixtures(t, `{"anything":true}`)
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/containers/abc/kill", "--body-file", bodyPath)

	if got.Decision != "allow" {
		t.Fatalf("decision = %q", got.Decision)
	}
	if got.Body == nil || got.Body.Decision != "not_inspected" || !strings.Contains(got.Body.Note, "no request-body inspector") {
		t.Fatalf("body = %+v", got.Body)
	}
}

func TestMatchBodyFileSkippedWhenRulesDeny(t *testing.T) {
	cfgPath, bodyPath := writeMatchBodyFixtures(t, `{"Image":"alpine"}`)
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/volumes/create", "--body-file", bodyPath)

	if got.Decision != "deny" || got.Reason != "not allowed" {
		t.Fatalf("decision = %q reason %q", got.Decision, got.Reason)
	}
	if got.Body == nil || got.Body.Decision != "skipped" {
		t.Fatalf("body = %+v", got.Body)
	}
}

func TestMatchBodyFileExecStartIsNotEvaluated(t *testing.T) {
	dir := t.TempDir()
	cfg := "insecure_allow_body_blind_writes: true\n" + strings.Replace(matchBodyConfig, `  - match: { method: "*", path: "/**" }
    action: deny
    reason: not allowed`, `  - match: { method: POST, path: "/exec/*/start" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
    reason: not allowed`, 1)
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	bodyPath := filepath.Join(dir, "body.json")
	for path, content := range map[string]string{cfgPath: cfg, bodyPath: `{"Detach":true}`} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/exec/abc/start", "--body-file", bodyPath)

	if got.Decision != "allow" || got.Body == nil || got.Body.Decision != "not_inspected" {
		t.Fatalf("decision = %q body = %+v", got.Decision, got.Body)
	}
	if !strings.Contains(strings.Join(got.Body.NotEvaluated, "\n"), "exec start check") {
		t.Fatalf("not_evaluated = %v", got.Body.NotEvaluated)
	}
}

func TestMatchBodyFileProfileWarnPassThrough(t *testing.T) {
	cfgPath, bodyPath := writeMatchBodyFixtures(t, `{"Image":"alpine","HostConfig":{"Privileged":true}}`)
	got := matchJSON(t, cfgPath, "-X", "POST", "--profile", "strict", "--path", "/containers/create", "--body-file", bodyPath)

	if got.Decision != "deny" || got.RolloutMode != "warn" || !got.PassThrough {
		t.Fatalf("decision = %q mode %q passthrough %v", got.Decision, got.RolloutMode, got.PassThrough)
	}
}

func TestMatchBodyFileStdin(t *testing.T) {
	cfgPath, _ := writeMatchBodyFixtures(t, `{}`)
	rootCmd.SetIn(strings.NewReader(`{"Image":"alpine","HostConfig":{"Privileged":true}}`))
	got := matchJSON(t, cfgPath, "-X", "POST", "--path", "/containers/create", "--body-file", "-")

	if got.Body == nil || got.Body.Source != "stdin" || got.Body.Decision != "deny" {
		t.Fatalf("body = %+v", got.Body)
	}
}

func TestMatchBodyFileMissingFileFails(t *testing.T) {
	cfgPath, _ := writeMatchBodyFixtures(t, `{}`)
	_, _, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST", "--path", "/containers/create", "--body-file", filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "body file") {
		t.Fatalf("error = %v, want a body file error", err)
	}
}

func TestMatchBodyFileTextOutput(t *testing.T) {
	cfgPath, bodyPath := writeMatchBodyFixtures(t, `{"Image":"alpine","HostConfig":{"Privileged":true}}`)
	stdout, stderr, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST", "--path", "/containers/create", "--body-file", bodyPath)
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{"Body:", "Body decision:   deny:", "request_body_policy_denied", "Not evaluated:", "Not inspected:   live resources"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Not inspected:   request body") {
		t.Fatalf("body was inspected, got:\n%s", stdout)
	}
}
