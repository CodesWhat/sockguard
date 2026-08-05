//go:build podmanintegration

package cmd

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
)

// TestLibpodPlayKubeRequiresBlindWriteAckAgainstRealPodman pins #148 design
// decision C2 (see rules.go's bodySensitiveWriteEndpoints and
// bodyInspectionConfiguredForEndpoint doc comments, and the synthetic-config
// table in TestValidateAndCompileRulesLibpodGates) against a genuine Podman
// system service, not just fixture configs: play/kube has no request-body
// inspector at all (full YAML/PodSpec modeling is deferred past v1.6), so an
// operator pointed at a real podman socket cannot start sockguard with an
// allow rule for POST /libpod/play/kube unless
// insecure_allow_body_blind_writes=true acknowledges the risk. This
// validation never dials the daemon itself (see validateAndCompileRules) —
// the real socket is only used to gate the test the same way every other
// podman-tagged integration test is gated, and as a sanity check that this
// guardrail is exercised in the same CI job that proves the rest of the
// libpod surface against a live daemon
// (.github/workflows/quality-integration-podman.yml).
func TestLibpodPlayKubeRequiresBlindWriteAckAgainstRealPodman(t *testing.T) {
	socketPath := os.Getenv("SOCKGUARD_TEST_PODMAN_SOCKET")
	if socketPath == "" {
		t.Skip("SOCKGUARD_TEST_PODMAN_SOCKET not set; skipping real-Podman integration test")
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Skipf("podman socket %q not found: %v", socketPath, err)
	}

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/play/kube"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected validateAndCompileRules to reject an unacknowledged play/kube allow rule")
	}
	if !strings.Contains(err.Error(), "insecure_allow_body_blind_writes=true") || !strings.Contains(err.Error(), "POST /libpod/play/kube") {
		t.Fatalf("error = %q, want mention of insecure_allow_body_blind_writes and POST /libpod/play/kube", err.Error())
	}

	cfg.InsecureAllowBodyBlindWrites = true
	if _, err := validateAndCompileRules(&cfg); err != nil {
		t.Fatalf("validateAndCompileRules with insecure_allow_body_blind_writes=true: %v", err)
	}
}
