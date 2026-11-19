package buildkitproxy

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/control"
)

// TestEvaluateSolveRefusesEverySolveUnderOwnership pins the interim refusal:
// build sources are not owner-checked, so a Solve under owner isolation is
// denied before anything about it is read, whatever it exports.
func TestEvaluateSolveRefusesEverySolveUnderOwnership(t *testing.T) {
	policy := allowAllPolicy
	policy.ImageOwnership = ImageOwnershipPolicy{Owner: "team-a", LabelKey: "owner"}

	payloads := map[string][]byte{
		"dockerfile frontend, image export": mustMarshal(t, &control.SolveRequest{
			Ref:           "ref-1",
			Session:       "0123456789abcdefghijklmno",
			Frontend:      "dockerfile.v0",
			FrontendAttrs: map[string]string{"filename": "Dockerfile", "context": "docker-image://theirs/private:latest"},
			Exporters:     []*control.Exporter{{Type: "image", Attrs: map[string]string{"name": "mine/app:v1"}}},
		}),
		"local output only": mustMarshal(t, &control.SolveRequest{
			Ref:       "ref-2",
			Session:   "0123456789abcdefghijklmno",
			Frontend:  "dockerfile.v0",
			Exporters: []*control.Exporter{{Type: "local"}},
		}),
		"empty request": mustMarshal(t, &control.SolveRequest{}),
		"undecodable":   malformedPayload,
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			req, d := evaluateSolveRequest(payload, policy)
			if req != nil || d == nil {
				t.Fatalf("solve under ownership was admitted: req=%v denial=%v", req, d)
			}
			if d.reasonCode != "buildkit_build_denied_under_ownership" || d.code != grpcCodePermissionDenied {
				t.Fatalf("denial = %q / %d", d.reasonCode, d.code)
			}
		})
	}

	t.Run("without an owner the solve is evaluated as before", func(t *testing.T) {
		policy := allowAllPolicy
		_, d := evaluateSolveRequest(malformedPayload, policy)
		if d == nil || d.reasonCode != "buildkit_protocol_error" {
			t.Fatalf("denial = %v, want the ordinary protocol error", d)
		}
	})
}
