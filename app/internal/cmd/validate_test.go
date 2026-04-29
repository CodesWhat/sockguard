package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunValidateOutputSuccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
listen:
  socket: /tmp/sockguard.sock
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })

	var out bytes.Buffer
	var errOut bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)
	command.SetErr(&errOut)

	if err := runValidate(command, nil); err != nil {
		t.Fatalf("runValidate() error = %v", err)
	}

	stdout := out.String()
	if !strings.Contains(stdout, "Config  ") || !strings.Contains(stdout, cfgPath) {
		t.Fatalf("expected config path in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Rules (2)") {
		t.Fatalf("expected rules section in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "validation passed") {
		t.Fatalf("expected validation success in output, got:\n%s", stdout)
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected no stderr output, got:\n%s", errOut.String())
	}
}

func TestRunValidateOutputFailure(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	// globToRegex escapes all special chars, so no glob pattern produces an invalid
	// regex. Use an invalid action value instead to trigger a validation failure.
	yaml := `
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
rules:
  - match: { method: GET, path: "/_ping" }
    action: nope
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })

	var out bytes.Buffer
	var errOut bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)
	command.SetErr(&errOut)

	err := runValidate(command, nil)
	if err == nil {
		t.Fatal("expected runValidate() to fail for invalid rule action")
	}

	stderr := errOut.String()
	if !strings.Contains(stderr, "validation failed") {
		t.Fatalf("expected validation failure banner, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "rule 1:") {
		t.Fatalf("expected rule failure details, got:\n%s", stderr)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout output on failure, got:\n%s", out.String())
	}
}

func TestRunValidateLoadError(t *testing.T) {
	oldCfgFile := cfgFile
	cfgFile = t.TempDir()
	t.Cleanup(func() { cfgFile = oldCfgFile })

	command := &cobra.Command{Use: "validate"}
	err := runValidate(command, nil)
	if err == nil {
		t.Fatal("expected runValidate() to fail when config cannot be read")
	}
	if !strings.Contains(err.Error(), "config load:") {
		t.Fatalf("expected config load error, got: %v", err)
	}
}

func TestRunValidateCompatModeOutput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("CONTAINERS", "1")
	t.Setenv("SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION", "true")

	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })

	var out bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)

	if err := runValidate(command, nil); err != nil {
		t.Fatalf("runValidate() error = %v", err)
	}

	if !strings.Contains(out.String(), "tecnativa compatibility") || !strings.Contains(out.String(), "Mode    ") {
		t.Fatalf("expected compat mode line, got:\n%s", out.String())
	}
}

func TestRunValidatePrintsClientProfiles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
listen:
  socket: /tmp/sockguard.sock
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  format: json
  output: stderr
clients:
  default_profile: readonly
  profiles:
    - name: readonly
      rules:
        - match: { method: GET, path: "/_ping" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
rules:
  - match: { method: "*", path: "/**" }
    action: deny
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })

	var out bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)

	if err := runValidate(command, nil); err != nil {
		t.Fatalf("runValidate() error = %v", err)
	}

	stdout := out.String()
	if !strings.Contains(stdout, "Client Profiles (1)") {
		t.Fatalf("expected client profiles section, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "readonly (default)") {
		t.Fatalf("expected default profile label, got:\n%s", stdout)
	}
}
