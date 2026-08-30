package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// isolateReadExfilEnv clears every Tecnativa rule-generating variable already
// present in the process environment plus the two insecure-acknowledgment
// overrides, so a stray export in a contributor's shell (or an earlier test's
// leftovers) cannot decide the outcome of a test that is specifically about
// what happens with NO acknowledgment set. t.Setenv is called with the
// variable's current value purely to register the restore; the Unsetenv that
// follows is what the test actually needs.
func isolateReadExfilEnv(t *testing.T) {
	t.Helper()

	keys := config.CompatEnvironmentVariables()
	keys = append(keys,
		"SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION",
		"SOCKGUARD_INSECURE_ALLOW_BODY_BLIND_WRITES",
	)
	for _, key := range keys {
		value, ok := os.LookupEnv(key)
		if !ok {
			continue
		}
		t.Setenv(key, value)
		os.Unsetenv(key)
	}
}

// TestValidateRefusesCompatReadsWithoutExfiltrationAck pins the refusal that
// the Tecnativa compatibility layer deliberately does NOT paper over.
//
// CONTAINERS=1 with POST=0 generates `allow GET,HEAD /containers/**`, which
// admits the raw archive/export and log/attach streaming surface. Unlike
// GRPC=1/SESSION=1 — which auto-set insecure_accept_opaque_buildkit_tunnels to
// preserve the drop-in migration promise (see ApplyCompat, and
// TestCompatGrpcEnvAutoAcksBuildkitTunnel in the config package) — compat does
// not auto-set insecure_allow_read_exfiltration, so this configuration must
// fail validation rather than start.
//
// Every other test in this package that turns CONTAINERS=1 on also sets
// SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true to get past this gate, so
// without this test nothing asserts the gate exists at all: a future patch
// aimed at "preserving drop-in migration" could auto-acknowledge read
// exfiltration the way the BuildKit path already does, and the whole suite
// would still pass.
func TestValidateRefusesCompatReadsWithoutExfiltrationAck(t *testing.T) {
	isolateReadExfilEnv(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte("upstream:\n  socket: /var/run/docker.sock\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("CONTAINERS", "1")
	t.Setenv("POST", "0")

	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })

	command := &cobra.Command{Use: "validate"}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)

	err := runValidate(command, nil)
	if err == nil {
		t.Fatal("runValidate() succeeded for CONTAINERS=1 POST=0 without insecure_allow_read_exfiltration; the compat layer must not admit the archive/export/logs/attach surface unacknowledged")
	}

	msg := err.Error()
	if !strings.Contains(msg, "insecure_allow_read_exfiltration: true") {
		t.Fatalf("error does not name the acknowledgment operators must set: %v", err)
	}
	// The refusal has to name the endpoints, not just the flag — an operator
	// who cannot see which paths tripped it has no way to choose the
	// tighten-the-rules fix the message recommends over the acknowledgment.
	for _, want := range []string{
		"GET /containers/sockguard-test/archive",
		"GET /containers/sockguard-test/export",
		"GET /containers/sockguard-test/logs",
		"GET /containers/sockguard-test/attach/ws",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error does not name exposed endpoint %q: %v", want, err)
		}
	}

	// Same env, acknowledgment set: the identical rule set must now validate,
	// proving the refusal above is the read-exfiltration gate and not some
	// unrelated failure in the compat path.
	t.Setenv("SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION", "true")
	if err := runValidate(command, nil); err != nil {
		t.Fatalf("runValidate() with the acknowledgment set = %v, want success", err)
	}
}

// TestValidateRefusesCompatReadsWithoutExfiltrationAckPerProfile pins the same
// refusal for a named client profile. The acknowledgment is global, but the
// profile's rules are compiled and probed separately, so a profile that admits
// the streaming surface must be refused with a message naming the profile.
func TestValidateRefusesCompatReadsWithoutExfiltrationAckPerProfile(t *testing.T) {
	isolateReadExfilEnv(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	yaml := `
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/containers/json" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
clients:
  profiles:
    - name: broad-reader
      rules:
        - match: { method: GET, path: "/containers/**" }
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

	command := &cobra.Command{Use: "validate"}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)

	err := runValidate(command, nil)
	if err == nil {
		t.Fatal("runValidate() succeeded for a profile allowing GET /containers/** without insecure_allow_read_exfiltration")
	}
	if !strings.Contains(err.Error(), `client profile "broad-reader"`) {
		t.Fatalf("error does not name the offending profile: %v", err)
	}
	if !strings.Contains(err.Error(), "GET /containers/sockguard-test/archive") {
		t.Fatalf("error does not name the exposed endpoint: %v", err)
	}
}
