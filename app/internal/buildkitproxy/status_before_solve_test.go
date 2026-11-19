package buildkitproxy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
)

// Buildx opens Control/Status concurrently with its Solve. Without owner
// isolation the Status can still beat the Solve's admission, so it must wait
// for that admission instead of being refused as an unowned ref.
func TestStatusBeforeSolveWaitsWithoutOwnership(t *testing.T) {
	solveRelease := make(chan struct{})
	defer func() {
		select {
		case <-solveRelease:
		default:
			close(solveRelease)
		}
	}()
	policy := allowAllPolicy
	policy.Control.Solve.AllowedExporters = []string{"image"}
	tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/Solve") {
			<-solveRelease
		}
		writeGRPCStatus(w, 0, "")
	}))
	queryDone := make(chan int, 1)
	go func() {
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", &control.StatusRequest{Ref: "build"}))
		if err != nil {
			queryDone <- -1
			return
		}
		code, _ := grpcStatusOf(t, resp)
		queryDone <- code
	}()
	select {
	case code := <-queryDone:
		t.Fatalf("Status returned %d before its Solve was sent", code)
	case <-time.After(100 * time.Millisecond):
	}
	solveDone := make(chan int, 1)
	go func() {
		req := &control.SolveRequest{Ref: "build", Session: testBuildkitSessionID, Frontend: "dockerfile.v0", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"name": "mine/app:v1"}}}}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", req))
		if err != nil {
			solveDone <- -1
			return
		}
		code, _ := grpcStatusOf(t, resp)
		solveDone <- code
	}()
	select {
	case code := <-queryDone:
		if code != 0 {
			t.Fatalf("Status status=%d after Solve admission, want 0", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Status did not complete after Solve admission")
	}
	close(solveRelease)
	select {
	case code := <-solveDone:
		if code != 0 {
			t.Fatalf("Solve status=%d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Solve did not complete")
	}
}
