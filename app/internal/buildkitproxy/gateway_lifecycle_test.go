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

type gatewayLifecycleLeg func(*http.Request) (*http.Response, error)

func (f gatewayLifecycleLeg) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func (f gatewayLifecycleLeg) Close() error                                      { return nil }

type gatewayEOFBody struct {
	io.ReadCloser
	atEOF func()
}

func (b *gatewayEOFBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && b.atEOF != nil {
		f := b.atEOF
		b.atEOF = nil
		f()
	}
	return n, err
}

func newGatewayLifecycleBridge(t *testing.T, leg clientLegConn) (*bridge, *gatewayBuild) {
	t.Helper()
	b := newUnitTestBridge(t, leg)
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
	return b, g
}

func TestGatewayCancellationBeforeDispatch(t *testing.T) {
	for _, method := range []string{"Inputs", "Ping"} {
		for _, cause := range []string{"root canceled", "root completed", "request canceled"} {
			t.Run(method+"/"+cause, func(t *testing.T) {
				called := false
				leg := gatewayLifecycleLeg(func(r *http.Request) (*http.Response, error) {
					called = true
					return nil, context.Canceled
				})
				b, g := newGatewayLifecycleBridge(t, leg)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				req := newFramedGRPCRequest(t, "/"+gatewayService+"/"+method, &gateway.InputsRequest{}).WithContext(ctx)
				req.Header.Set(gatewayBuildHeader, "build")
				req.Body = &gatewayEOFBody{ReadCloser: req.Body, atEOF: func() {
					switch cause {
					case "root canceled":
						g.cancel(context.Canceled)
					case "root completed":
						b.registry.endGatewayBuild(g)
					case "request canceled":
						cancel()
					}
				}}
				rec := httptest.NewRecorder()
				b.handleStream(rec, req)
				if called {
					t.Fatal("canceled gateway request reached daemon transport")
				}
				if got := rec.Header().Get("Grpc-Status"); got != "7" {
					t.Fatalf("status = %q, want PermissionDenied", got)
				}
			})
		}
	}
}

func TestGatewayRootCancellationIsSynchronous(t *testing.T) {
	var g *gatewayBuild
	called := false
	leg := gatewayLifecycleLeg(func(r *http.Request) (*http.Response, error) {
		called = true
		g.cancel(context.Canceled)
		if r.Context().Err() != context.Canceled {
			t.Error("root cancellation returned before outgoing context was canceled")
		}
		return nil, context.Canceled
	})
	b, build := newGatewayLifecycleBridge(t, leg)
	g = build
	req := newFramedGRPCRequest(t, "/"+gatewayService+"/Inputs", &gateway.InputsRequest{})
	req.Header.Set(gatewayBuildHeader, "build")
	b.handleStream(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("active request did not reach daemon transport")
	}
}

func TestGatewayIncomingCancellationStopsForwarding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	leg := gatewayLifecycleLeg(func(r *http.Request) (*http.Response, error) {
		called = true
		cancel()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			t.Error("incoming request cancellation did not cancel daemon transport")
		}
		return nil, context.Canceled
	})
	b, _ := newGatewayLifecycleBridge(t, leg)
	req := newFramedGRPCRequest(t, "/"+gatewayService+"/Inputs", &gateway.InputsRequest{}).WithContext(ctx)
	req.Header.Set(gatewayBuildHeader, "build")
	b.handleStream(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("active request did not reach daemon transport")
	}
}
