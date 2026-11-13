package buildkitproxy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/caps"
	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/gateway"
)

func TestRewrittenFramesAtMessageBudget(t *testing.T) {
	t.Parallel()
	dockerfile := mustMarshal(t, &gateway.SolveRequest{Frontend: "dockerfile.v0"})
	image := mustMarshal(t, &gateway.ReturnRequest{Result: &gateway.Result{Metadata: map[string][]byte{imageConfigKey: []byte(`{}`)}}})
	pong := grpcFrame(mustMarshal(t, &gateway.PongResponse{FrontendAPICaps: []*caps.APICap{{ID: "solve.base", Enabled: true}}}))
	ref := mustMarshal(t, &control.SolveRequest{Ref: "client-ref", Session: "client-session"})
	for _, tt := range []struct {
		name    string
		rewrite func(int64) ([]byte, bool)
	}{
		{name: "Dockerfile", rewrite: func(limit int64) ([]byte, bool) {
			frame, denial := rewriteGatewayDockerfile(dockerfile, Policy{}, limit)
			return frame, denial != nil
		}},
		{name: "owned image", rewrite: func(limit int64) ([]byte, bool) {
			policy := Policy{ImageOwnership: ImageOwnershipPolicy{Owner: "alice", LabelKey: "owner", RequireConfig: true}}
			frame, denial := rewriteGatewayImageOwnership(image, policy, limit)
			return frame, denial != nil
		}},
		{name: "capabilities", rewrite: func(limit int64) ([]byte, bool) {
			frame, denial := filterGatewayPong(bytes.NewReader(pong), limit, Policy{})
			return frame, denial != nil
		}},
		{name: "scoped references", rewrite: func(limit int64) ([]byte, bool) {
			frame, err := controlRefFrame(ref, "scoped-build-reference", "scoped-build-session", limit)
			return frame, err != nil
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			unlimited, denied := tt.rewrite(0)
			if denied || len(unlimited) <= grpcMessageHeaderLen {
				t.Fatalf("unlimited rewrite returned %d bytes, denied=%v", len(unlimited), denied)
			}
			if got := binary.BigEndian.Uint32(unlimited[1:5]); int(got) != len(unlimited)-grpcMessageHeaderLen {
				t.Fatalf("declared payload length=%d, actual=%d", got, len(unlimited)-grpcMessageHeaderLen)
			}
			for _, delta := range []int64{-1, 0, 1} {
				limit := int64(len(unlimited)) + delta
				frame, denied := tt.rewrite(limit)
				if delta < 0 {
					if !denied || len(frame) != 0 {
						t.Fatalf("rewrite above limit %d returned %d bytes, denied=%v", limit, len(frame), denied)
					}
				} else if denied || !bytes.Equal(frame, unlimited) {
					t.Fatalf("rewrite within limit %d returned %d bytes, denied=%v", limit, len(frame), denied)
				}
			}
		})
	}
}
