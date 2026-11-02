package cmd

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const unknownKeysYAML = `
upstream:
  socket: /var/run/docker.sock
log:
  level: info
  bogus_key: true
clients:
  profiles:
    - name: a
      response:
        redact_container_env: true
      rules:
        - match: { method: GET, path: "/_ping" }
          action: allow
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`

func runValidateWithUnknownKeys(t *testing.T, strict bool) (stdout, stderr string, err error) {
	t.Helper()
	clearSockguardEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	if werr := os.WriteFile(cfgPath, []byte(unknownKeysYAML), 0o600); werr != nil {
		t.Fatal(werr)
	}
	oldCfg, oldStrict := cfgFile, validateStrict
	cfgFile, validateStrict = cfgPath, strict
	t.Cleanup(func() { cfgFile, validateStrict = oldCfg, oldStrict })

	var out, errOut bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)
	command.SetErr(&errOut)
	err = runValidate(command, nil)
	return out.String(), errOut.String(), err
}

func TestValidateWarnsOnUnknownKeysAndPasses(t *testing.T) {
	stdout, stderr, err := runValidateWithUnknownKeys(t, false)
	if err != nil {
		t.Fatalf("validate must exit 0 without --strict, got %v", err)
	}
	for _, key := range []string{"log.bogus_key", "clients.profiles[0].response.redact_container_env"} {
		if strings.Count(stderr, "key="+key) != 1 {
			t.Errorf("want exactly one warning for %s, stderr:\n%s", key, stderr)
		}
	}
	if !strings.Contains(stdout, "validation passed") {
		t.Fatalf("expected validation passed, got:\n%s", stdout)
	}
}

func TestValidateStrictFailsOnUnknownKeys(t *testing.T) {
	stdout, stderr, err := runValidateWithUnknownKeys(t, true)
	if err == nil {
		t.Fatal("validate --strict must fail with unknown keys")
	}
	if strings.Contains(stdout, "validation passed") {
		t.Fatalf("strict failure must not print success:\n%s", stdout)
	}
	if !strings.Contains(stderr, "key=log.bogus_key") {
		t.Fatalf("warnings should still be listed:\n%s", stderr)
	}
}

func TestValidateStrictFlagRegistered(t *testing.T) {
	f := validateCmd.Flags().Lookup("strict")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("--strict flag missing or not default false: %+v", f)
	}
}

func TestValidateStrictPassesCleanConfig(t *testing.T) {
	clearSockguardEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	clean := "upstream:\n  socket: /var/run/docker.sock\nrules:\n  - match: { method: GET, path: \"/_ping\" }\n    action: allow\n  - match: { method: \"*\", path: \"/**\" }\n    action: deny\n"
	if err := os.WriteFile(cfgPath, []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	oldCfg, oldStrict := cfgFile, validateStrict
	cfgFile, validateStrict = cfgPath, true
	t.Cleanup(func() { cfgFile, validateStrict = oldCfg, oldStrict })
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := runValidate(command, nil); err != nil {
		t.Fatalf("clean config under --strict: %v", err)
	}
}

func TestWarnUnknownConfigKeysLogsOncePerKey(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte(unknownKeysYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	warnUnknownConfigKeys(logger, cfgPath, nil)

	if got := strings.Count(buf.String(), "unrecognized configuration key"); got != 2 {
		t.Fatalf("want 2 warnings, got %d:\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), "file="+cfgPath) {
		t.Fatalf("warning should name the file:\n%s", buf.String())
	}

	// In-memory bytes path (verified bundle / reload).
	buf.Reset()
	warnUnknownConfigKeys(logger, cfgPath, []byte("zzz: 1\n"))
	if got := strings.Count(buf.String(), "key=zzz"); got != 1 {
		t.Fatalf("bytes path: want 1 warning, got %d:\n%s", got, buf.String())
	}

	// Nil logger and missing file are quiet no-ops.
	warnUnknownConfigKeys(nil, cfgPath, nil)
	buf.Reset()
	warnUnknownConfigKeys(logger, filepath.Join(t.TempDir(), "none.yaml"), nil)
	if buf.Len() != 0 {
		t.Fatalf("missing file should warn nothing:\n%s", buf.String())
	}
}
