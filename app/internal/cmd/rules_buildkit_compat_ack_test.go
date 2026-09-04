package cmd

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// buildkitMediationConfigYAML is a config that has migrated off the
// deprecated acknowledgment: a request_body.buildkit policy and no rules:
// block at all, so the ruleset still matches the built-in default and
// Tecnativa compatibility mode is live.
const buildkitMediationConfigYAML = `upstream:
  socket: /var/run/docker.sock
request_body:
  buildkit:
    control:
      allow_info: true
      solve:
        allow: true
`

// isolateBuildkitCompatEnv extends isolateReadExfilEnv (which clears every
// Tecnativa rule-generating var plus the read-exfiltration and
// body-blind-write acknowledgments) with the BuildKit tunnel acknowledgment,
// so a stray export cannot decide the outcome of a test that is specifically
// about whether that flag ends up set.
func isolateBuildkitCompatEnv(t *testing.T) {
	t.Helper()

	isolateReadExfilEnv(t)

	const ackKey = "SOCKGUARD_INSECURE_ACCEPT_OPAQUE_BUILDKIT_TUNNELS"
	if value, ok := os.LookupEnv(ackKey); ok {
		t.Setenv(ackKey, value)
		if err := os.Unsetenv(ackKey); err != nil {
			t.Fatalf("Unsetenv(%q): %v", ackKey, err)
		}
	}
}

// profileOnlyBuildkitMediationConfigYAML puts the mediation policy on a
// client profile and nowhere else. The compat-generated rules are top-level,
// so nothing mediates them: a client that matches no profile would get the
// opaque tunnel. Startup has to refuse.
const profileOnlyBuildkitMediationConfigYAML = `upstream:
  socket: /var/run/docker.sock
clients:
  profiles:
    - name: builders
      rules:
        - match: { method: GET, path: "/_ping" }
          action: allow
      request_body:
        buildkit:
          control:
            allow_info: true
            solve:
              allow: true
`

func writeBuildkitCompatConfig(t *testing.T) {
	t.Helper()

	writeCompatConfig(t, buildkitMediationConfigYAML)
}

func writeCompatConfig(t *testing.T, yaml string) {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	oldCfgFile := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = oldCfgFile })
}

func newDiscardValidateCommand() *cobra.Command {
	command := &cobra.Command{Use: "validate"}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	return command
}

// TestValidateAcceptsCompatGrpcAlongsideBuildkitMediation pins the end-to-end
// shape of the collision S21 fixes. ApplyCompat runs before validation, so
// GRPC=1 / SESSION=1 auto-setting insecure_accept_opaque_buildkit_tunnels
// used to hand an operator who had already migrated to request_body.buildkit
// a startup refusal naming a key they never wrote — their old Tecnativa env
// var, not their config, decided it.
//
// Compat must leave the ack unset here. The rules it generates for those two
// vars are still admitted, by validateBuildkitTunnelRulesForPolicy's
// buildkitConfigured arm rather than the acknowledgment arm, which is the
// tighter of the two: POST /session and POST /grpc then reach
// buildkitproxy.Mediator's per-message policy instead of being wholesale
// admitted with zero inspection.
func TestValidateAcceptsCompatGrpcAlongsideBuildkitMediation(t *testing.T) {
	isolateBuildkitCompatEnv(t)
	writeBuildkitCompatConfig(t)

	t.Setenv("GRPC", "1")
	t.Setenv("SESSION", "1")
	// POST=1 widens the generated rules to every method, so POST /grpc and
	// POST /session really are allowed and the tunnel-admission check has
	// something to admit. Without it the rules are GET,HEAD only and the
	// check passes vacuously.
	t.Setenv("POST", "1")

	if err := runValidate(newDiscardValidateCommand(), nil); err != nil {
		t.Fatalf("runValidate() = %v, want success: a migrated request_body.buildkit config must not be refused because of a leftover GRPC/SESSION env var", err)
	}

	// Non-vacuity: the generated rules really do allow the two tunnel
	// endpoints, so the success above is the buildkitConfigured arm admitting
	// them under mediation rather than nothing having reached the check.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !config.ApplyCompat(cfg, discardLogger) {
		t.Fatal("expected compat mode to be active")
	}
	if cfg.InsecureAcceptOpaqueBuildkitTunnels { //nolint:staticcheck // SA1019: asserting the deprecated flag was NOT set
		t.Fatal("compat set InsecureAcceptOpaqueBuildkitTunnels despite request_body.buildkit being configured")
	}
	compiled, err := compileConfiguredRules(cfg.Rules)
	if err != nil {
		t.Fatalf("compileConfiguredRules: %v", err)
	}
	exposed := allowedBuildkitTunnelEndpoints(compiled)
	for _, want := range []string{"POST /session", "POST /grpc"} {
		if !slices.Contains(exposed, want) {
			t.Fatalf("compat rules do not allow %s (allowed: %v); the acceptance above proves nothing", want, exposed)
		}
	}
}

// TestValidateStillRefusesExplicitAckAlongsideBuildkitMediation is the
// adversarial half. The fix above must come from compat declining to set the
// flag, NOT from the mutual-exclusion gate being loosened: an operator who
// writes insecure_accept_opaque_buildkit_tunnels themselves alongside
// request_body.buildkit still has a config where the global ack would admit
// the same tunnel uninspected, and startup must still refuse.
func TestValidateStillRefusesExplicitAckAlongsideBuildkitMediation(t *testing.T) {
	isolateBuildkitCompatEnv(t)
	writeBuildkitCompatConfig(t)

	t.Setenv("GRPC", "1")
	t.Setenv("POST", "1")
	t.Setenv("SOCKGUARD_INSECURE_ACCEPT_OPAQUE_BUILDKIT_TUNNELS", "true")

	err := runValidate(newDiscardValidateCommand(), nil)
	if err == nil {
		t.Fatal("runValidate() succeeded with an explicit insecure_accept_opaque_buildkit_tunnels alongside request_body.buildkit; the mutual-exclusion gate is gone")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected the mutual-exclusion refusal, got: %v", err)
	}
}

// TestValidateRefusesProfileOnlyBuildkitMediationWithCompatGrpc pins the case
// the any-scope compat skip deliberately leaves failing. request_body.buildkit
// on a client profile cannot mediate the TOP-LEVEL rules GRPC=1/SESSION=1
// generate, and those rules apply to every client that matches no profile, so
// admitting them would open an unmediated tunnel for exactly the clients the
// profile does not cover. The refusal is correct; what it must not do is
// leave the operator guessing, so the message has to name the env vars that
// produced the rules and the two cures that actually work.
func TestValidateRefusesProfileOnlyBuildkitMediationWithCompatGrpc(t *testing.T) {
	isolateBuildkitCompatEnv(t)
	writeCompatConfig(t, profileOnlyBuildkitMediationConfigYAML)

	t.Setenv("GRPC", "1")
	t.Setenv("POST", "1")

	err := runValidate(newDiscardValidateCommand(), nil)
	if err == nil {
		t.Fatal("runValidate() succeeded with profile-only BuildKit mediation and GRPC=1; the top-level compat rules open an unmediated tunnel for every client outside that profile")
	}

	msg := err.Error()
	for _, want := range []string{
		"POST /grpc",
		"GRPC",
		"SESSION",
		"top level",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal does not mention %q, so it does not name the origin or the cure: %v", want, err)
		}
	}
	// The dead-end cure must not be offered: setting the acknowledgment here
	// only trades this error for the mutual-exclusion one against the
	// profile's own policy.
	if strings.Contains(msg, "set insecure_accept_opaque_buildkit_tunnels=true to acknowledge this risk") {
		t.Fatalf("refusal steers the operator toward the acknowledgment, which their profile policy makes impossible: %v", err)
	}
}

// handWrittenTunnelRuleConfigYAML allows the tunnel through the operator's own
// rules. Because they differ from the built-in defaults, compat mode never
// activates, so GRPC=1 in the environment is inert here.
const handWrittenTunnelRuleConfigYAML = `upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: POST, path: "/grpc" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`

// TestValidateTunnelRefusalDoesNotBlameCompatForHandWrittenRules is the
// false-positive guard on the message above. GRPC=1 sitting in the
// environment does not mean a rule came from it: compat only generates rules
// while the ruleset still matches the defaults, so a hand-written rule with
// the same env var set must keep the original message and its acknowledgment
// cure, which is available precisely because no mediation policy exists to
// conflict with it. Detecting the origin from the environment rather than
// from what ApplyCompat actually did would get this case wrong.
func TestValidateTunnelRefusalDoesNotBlameCompatForHandWrittenRules(t *testing.T) {
	isolateBuildkitCompatEnv(t)
	writeCompatConfig(t, handWrittenTunnelRuleConfigYAML)

	t.Setenv("GRPC", "1")

	err := runValidate(newDiscardValidateCommand(), nil)
	if err == nil {
		t.Fatal("runValidate() succeeded for a hand-written POST /grpc allow with no acknowledgment and no mediation")
	}

	msg := err.Error()
	if strings.Contains(msg, "Tecnativa compat env vars") {
		t.Fatalf("refusal blames compat for a rule the operator wrote themselves: %v", err)
	}
	if !strings.Contains(msg, "set insecure_accept_opaque_buildkit_tunnels=true to acknowledge this risk") {
		t.Fatalf("refusal dropped the acknowledgment cure, which is available for a hand-written rule: %v", err)
	}
}
