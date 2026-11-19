package buildkitproxy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/gateway"
)

// Buildx opens Control/Status concurrently with its Solve. Without owner
// isolation the Status can still beat the Solve's admission, so it must wait
// for that admission instead of being refused as an unowned ref.
func TestStatusBeforeSolveWaitsWithoutOwnership(t *testing.T) {
	for _, method := range []string{"Status", "Ping"} {
		t.Run(method, func(t *testing.T) { testQueryBeforeSolveWaits(t, method) })
	}
}

func testQueryBeforeSolveWaits(t *testing.T, method string) {
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
	policy.Control.Solve.AllowFrontendGateway = method == "Ping"
	tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/Solve") {
			<-solveRelease
		}
		writeGRPCStatus(w, 0, "")
		if strings.HasSuffix(r.URL.Path, "/Ping") {
			_, _ = w.Write(grpcFrame(mustMarshal(t, &gateway.PongResponse{})))
		}
	}))
	queryDone := make(chan int, 1)
	go func() {
		request := newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", &control.StatusRequest{Ref: "build"})
		if method == "Ping" {
			request = newFramedGRPCRequest(t, "/"+gatewayService+"/Ping", &gateway.PingRequest{})
			request.Header.Set(gatewayBuildHeader, "build")
		}
		resp, err := tb.driver.RoundTrip(request)
		if err != nil {
			queryDone <- -1
			return
		}
		code, _ := grpcStatusOf(t, resp)
		queryDone <- code
	}()
	select {
	case code := <-queryDone:
		t.Fatalf("%s returned %d before its Solve was sent", method, code)
	case <-time.After(100 * time.Millisecond):
	}
	solveDone := make(chan int, 1)
	go func() {
		frontend := "dockerfile.v0"
		if method == "Ping" {
			frontend = ""
		}
		req := &control.SolveRequest{Ref: "build", Session: testBuildkitSessionID, Frontend: frontend, Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"name": "mine/app:v1"}}}}
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
