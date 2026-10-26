package buildkitproxy

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
)

func TestBridgeSolveFrontendOverrideRespectsRunRestriction(t *testing.T) {
	for _, allowRun := range []bool{false, true} {
		policy := allowAllPolicy
		policy.Control.Solve.AllowRunInstructions = allowRun
		var called atomic.Bool
		tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true); writeGRPCStatus(w, 0, "") }))
		req := &control.SolveRequest{Ref: "build", Session: testBuildkitSessionID, Frontend: "dockerfile.v0", FrontendAttrs: map[string]string{"build-arg:BUILDKIT_SYNTAX": "untrusted.example/compiler"}}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", req))
		if err != nil {
			t.Fatal(err)
		}
		code, _ := grpcStatusOf(t, resp)
		if (code == 0) != allowRun || called.Load() != allowRun {
			t.Fatalf("allow RUN=%v: status=%d, daemon=%v", allowRun, code, called.Load())
		}
	}
}
