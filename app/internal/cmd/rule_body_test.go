package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const matchBodyConfigYAML = `upstream:
  socket: /var/run/docker.sock
rules:
  - match:
      method: POST
      path: /libpod/containers/create
      body: { name: ["team-app-*"] }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`

func writeMatchBodyConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(path, []byte(matchBodyConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMatchWithBody covers the three answers an operator needs from the tool:
// an in-scope body allows, an out-of-scope one denies, and no body at all
// denies fail-closed rather than reading as reachable. Each case runs as its
// own subtest so the flag globals between invocations cannot leak.
func TestMatchWithBody(t *testing.T) {
	cfgPath := writeMatchBodyConfig(t)

	t.Run("in scope", func(t *testing.T) {
		stdout, _, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST",
			"--path", "/libpod/containers/create", "--body", `{"name":"team-app-7"}`)
		if err != nil {
			t.Fatalf("match: %v", err)
		}
		if !strings.Contains(stdout, "allow") || !strings.Contains(stdout, "name=team-app-* (constraints matched)") {
			t.Fatalf("in-scope body output = %q", stdout)
		}
	})

	t.Run("out of scope", func(t *testing.T) {
		stdout, _, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST",
			"--path", "/libpod/containers/create", "--body", `{"name":"other-team-7"}`)
		if err != nil {
			t.Fatalf("match: %v", err)
		}
		if !strings.Contains(stdout, "deny") {
			t.Fatalf("out-of-scope body output = %q, want deny", stdout)
		}
		if strings.Contains(stdout, "constraints matched") {
			t.Fatalf("out-of-scope body output = %q, want no matched-constraint note", stdout)
		}
	})

	t.Run("no body", func(t *testing.T) {
		stdout, _, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST",
			"--path", "/libpod/containers/create")
		if err != nil {
			t.Fatalf("match: %v", err)
		}
		if !strings.Contains(stdout, "deny") {
			t.Fatalf("missing --body output = %q, want deny", stdout)
		}
	})
}

// TestMatchUnreadableBody keeps the tool honest when a --body parses as a JSON
// object but the matcher cannot read it, here by outgrowing the match cap: the
// body-constrained deny that matched must be reported as a fail-closed match
// over an unreadable body, not as constraints satisfied.
func TestMatchUnreadableBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(path, []byte(`upstream:
  socket: /var/run/docker.sock
rules:
  - match:
      method: POST
      path: /libpod/containers/create
      body: { name: ["never-*"] }
    action: deny
  - match: { method: "*", path: "/**" }
    action: deny
`), 0o600); err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 1<<20)
	stdout, _, err := executeRootCommand(t, "-c", path, "match", "-X", "POST",
		"--path", "/libpod/containers/create", "--body", `{"name":"team-app-7","pad":"`+pad+`"}`)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if !strings.Contains(stdout, "body unreadable to matching, rule matched fail-closed") {
		t.Fatalf("oversized --body output = %q, want the unread-body note", stdout)
	}
	if strings.Contains(stdout, "name=never-* (constraints matched)") {
		t.Fatalf("oversized --body output = %q, want no matched-constraint note", stdout)
	}
}

func TestMatchRejectsMalformedBody(t *testing.T) {
	cfgPath := writeMatchBodyConfig(t)
	for _, body := range []string{"not json", "null"} {
		_, _, err := executeRootCommand(t, "-c", cfgPath, "match", "-X", "POST",
			"--path", "/libpod/containers/create", "--body", body)
		if err == nil || !strings.Contains(err.Error(), "body must be a JSON object") {
			t.Fatalf("--body %s: error = %v, want the JSON-object refusal", body, err)
		}
	}
}

// TestValidateListsBodyConstraints keeps the rule listing honest about the
// constraint a rule carries.
func TestValidateListsBodyConstraints(t *testing.T) {
	cfgPath := writeMatchBodyConfig(t)
	stdout, _, err := executeRootCommand(t, "-c", cfgPath, "validate")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !strings.Contains(stdout, "/libpod/containers/create {name=team-app-*}") {
		t.Fatalf("validate output does not show the body constraint:\n%s", stdout)
	}
}
