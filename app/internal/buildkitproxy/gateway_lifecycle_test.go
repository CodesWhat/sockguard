package buildkitproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
)

type gatewayCompletionDaemon struct {
	finish   func()
	canceled bool
}

func (d *gatewayCompletionDaemon) Close() error { return nil }
func (d *gatewayCompletionDaemon) RoundTrip(r *http.Request) (*http.Response, error) {
	d.finish()
	if d.canceled {
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-time.After(2 * time.Second):
			return nil, context.DeadlineExceeded
		}
	}
	// Model a daemon that completes Control.Solve before flushing Return.
	select {
	case <-r.Context().Done():
		return nil, r.Context().Err()
	case <-time.After(20 * time.Millisecond):
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/grpc"}, "Grpc-Status": {"0"}}, Body: io.NopCloser(bytes.NewReader(grpcFrame(nil)))}, nil
}

func TestGatewayReturnCompletionRace(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "normal completion"
		if canceled {
			name = "root canceled"
		}
		t.Run(name, func(t *testing.T) {
			daemon := &gatewayCompletionDaemon{canceled: canceled}
			b := newUnitTestBridge(t, daemon)
			b.policy.Control.Solve.AllowFrontendGateway = true
			t.Cleanup(func() { b.closeAll(nil) })
			g, d := b.registry.beginGatewayBuild(context.Background(), b.session, "build", testBuildkitSessionID, b.policy)
			if d != nil {
				t.Fatal(d)
			}
			t.Cleanup(func() { b.registry.endGatewayBuild(g) })
			if result := b.registry.admitSolve(b.session, testBuildkitSessionID, "build", nil, 0, 0); result != solveAdmissionSucceeded {
				t.Fatal(result)
			}
			daemon.finish = func() {
				if canceled {
					g.cancel(context.Canceled)
				} else {
					b.registry.endGatewayBuild(g)
				}
			}
			req := newFramedGRPCRequest(t, "/"+gatewayService+"/Return", &gateway.ReturnRequest{Result: &gateway.Result{Result: &gateway.Result_Ref{Ref: &gateway.Ref{Id: "result"}}}})
			req.Header.Set(gatewayBuildHeader, "build")
			rec := httptest.NewRecorder()
			started := time.Now()
			b.handleStream(rec, req)
			if canceled {
				if rec.Header().Get("Grpc-Status") == "0" || time.Since(started) > time.Second {
					t.Fatal("root cancellation did not promptly stop Return")
				}
			} else if got := rec.Header().Get("Grpc-Status"); got != "0" {
				t.Fatalf("completed root canceled its successful Return: %s", got)
			}
		})
	}
}
