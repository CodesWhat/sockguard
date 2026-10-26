package buildkitproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/caps"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/worker"
)

type gatewayDaemon struct {
	mu          sync.Mutex
	rootStarted chan struct{}
	calls       []string
	buildIDs    []string
	definitions []*pb.Definition
}

func (d *gatewayDaemon) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/moby.buildkit.v1.Control/Solve" {
		close(d.rootStarted)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	_, payload, err := readUnaryGRPCMessage(r.Body, DefaultLimits().MaxMessageBytes)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, r.URL.Path)
	d.buildIDs = append(d.buildIDs, r.Header.Get("buildkit-controlapi-buildid"))
	var response proto.Message = &gateway.PongResponse{
		Workers:         []*worker.WorkerRecord{{ID: "worker", Labels: map[string]string{"hostname": "private-host"}, GCPolicy: []*worker.GCPolicy{{All: true}}}},
		FrontendAPICaps: []*caps.APICap{{ID: "solve.base", Enabled: true}, {ID: "gateway.exec", Enabled: true}, {ID: "unknown.future", Enabled: true}},
	}
	if strings.HasSuffix(r.URL.Path, "/Solve") {
		var req gateway.SolveRequest
		if err := proto.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		d.definitions = append(d.definitions, req.Definition)
		response = &gateway.SolveResponse{Result: &gateway.Result{Result: &gateway.Result_Ref{Ref: &gateway.Ref{Id: "result"}}}}
	}
	body, err := proto.Marshal(response)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/grpc"}, "Grpc-Status": {"0"}}, Body: io.NopCloser(bytes.NewReader(grpcFrame(body)))}, nil
}

func (d *gatewayDaemon) Close() error { return nil }

func TestGatewayBindsCallsToActiveRootPolicy(t *testing.T) {
	execDigest := func(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
	daemon := &gatewayDaemon{rootStarted: make(chan struct{})}
	root := newUnitTestBridge(t, daemon)
	root.policy.Control.Solve.AllowFrontendGateway = true
	op := &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Meta: &pb.Meta{Args: []string{"/bin/true"}}}}}
	opBytes := mustMarshal(t, op)
	root.policy.Control.Solve.AllowedExecDigests = map[string]struct{}{execDigest(opBytes): {}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "build", Session: testBuildkitSessionID}).WithContext(ctx)
		root.handleStream(httptest.NewRecorder(), req)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("root Solve did not stop")
		}
		root.closeAll(nil)
	})
	select {
	case <-daemon.rootStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("root Solve did not reach daemon")
	}
	client := newUnitTestBridge(t, daemon)
	client.registry.Close(client.session.ID)
	client.registry = root.registry
	client.session = root.registry.Open(root.session.Key, EndpointGRPC, "")
	client.policy.Control.Solve.AllowFrontendGateway = true
	t.Cleanup(func() { client.closeAll(nil) })
	call := func(method string, message proto.Message, ids ...string) *httptest.ResponseRecorder {
		t.Helper()
		req := newFramedGRPCRequest(t, "/moby.buildkit.v1.frontend.LLBBridge/"+method, message)
		for _, id := range ids {
			req.Header.Add("buildkit-controlapi-buildid", id)
		}
		rec := httptest.NewRecorder()
		client.handleStream(rec, req)
		return rec
	}
	ping := call("Ping", &gateway.PingRequest{}, "build")
	if got := ping.Header().Get("Grpc-Status"); got != "0" {
		t.Fatalf("own active gateway Ping status=%q", got)
	}
	var pong gateway.PongResponse
	if err := proto.Unmarshal(ping.Body.Bytes()[grpcMessageHeaderLen:], &pong); err != nil {
		t.Fatal(err)
	}
	if len(pong.Workers) != 1 || len(pong.Workers[0].Labels) != 0 || len(pong.Workers[0].GCPolicy) != 0 || len(pong.FrontendAPICaps) != 1 || pong.FrontendAPICaps[0].ID != "solve.base" {
		t.Fatal("gateway Ping disclosed host metadata or unsupported capabilities")
	}
	approved := &gateway.SolveRequest{Definition: &pb.Definition{Def: [][]byte{opBytes}}}
	if got := call("Solve", approved, "build").Header().Get("Grpc-Status"); got != "0" {
		t.Fatalf("root-approved operation status=%q", got)
	}
	if len(daemon.definitions) != 1 || !bytes.Equal(daemon.definitions[0].Def[0], opBytes) {
		t.Fatal("gateway changed approved operation bytes")
	}
	for _, id := range daemon.buildIDs {
		if id != daemonBuildRef(root.session.Key, "build") {
			t.Fatal("gateway forwarded an unscoped build ID")
		}
	}
	op.GetExec().Meta.Args = []string{"/bin/false"}
	changedBytes := mustMarshal(t, op)
	client.policy.Control.Solve.AllowedExecDigests = map[string]struct{}{execDigest(changedBytes): {}}
	changed := &gateway.SolveRequest{Definition: &pb.Definition{Def: [][]byte{changedBytes}}}
	before := len(daemon.calls)
	if got := call("Solve", changed, "build").Header().Get("Grpc-Status"); got != "7" {
		t.Fatalf("connection policy overrode root execution policy: %q", got)
	}
	for _, ids := range [][]string{nil, {"build", "build"}, {"missing"}} {
		if got := call("Ping", &gateway.PingRequest{}, ids...).Header().Get("Grpc-Status"); got == "0" {
			t.Fatalf("unbound gateway call accepted: %v", ids)
		}
	}
	client.session.Key.ClientIdentity = "other-client"
	if got := call("Ping", &gateway.PingRequest{}, "build").Header().Get("Grpc-Status"); got != "7" {
		t.Fatalf("foreign build was admitted: %q", got)
	}
	client.session.Key = root.session.Key
	for _, method := range []string{"NewContainer", "ExecProcess"} {
		if got := call(method, &gateway.PingRequest{}, "build").Header().Get("Grpc-Status"); got != "7" {
			t.Fatalf("%s bypassed LLB admission: %q", method, got)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled root is still active")
	}
	if got := call("Ping", &gateway.PingRequest{}, "build").Header().Get("Grpc-Status"); got != "7" {
		t.Fatalf("finished build remained usable: %q", got)
	}
	if len(daemon.calls) != before {
		t.Fatal("a denied or stale gateway call reached the daemon")
	}
}

func TestGatewayRequestPolicy(t *testing.T) {
	for _, tc := range []struct {
		method  string
		request proto.Message
		allow   bool
	}{
		{"ResolveImageConfig", &gateway.ResolveImageConfigRequest{Ref: "docker.io/library/busybox:latest"}, true},
		{"ResolveImageConfig", &gateway.ResolveImageConfigRequest{Ref: "image", SessionID: "other"}, false},
		{"ResolveImageConfig", &gateway.ResolveImageConfigRequest{Ref: "image", StoreID: "host"}, false},
		{"ResolveImageConfig", &gateway.ResolveImageConfigRequest{Ref: "image", ResolverType: 1}, false},
		{"ResolveSourceMeta", &gateway.ResolveSourceMetaRequest{Source: &pb.SourceOp{Identifier: "docker-image://busybox"}}, true},
		{"ResolveSourceMeta", &gateway.ResolveSourceMetaRequest{Source: &pb.SourceOp{Identifier: "https://example.com/context"}}, false},
		{"ResolveSourceMeta", &gateway.ResolveSourceMetaRequest{Source: &pb.SourceOp{Identifier: "local://context", Attrs: map[string]string{"local.session": "other"}}}, false},
		{"ReadFile", &gateway.ReadFileRequest{Ref: "result", FilePath: "Dockerfile"}, true},
		{"ReadFile", &gateway.ReadFileRequest{Ref: "result", Range: &gateway.FileRange{Offset: -1}}, false},
		{"ReadDir", &gateway.ReadDirRequest{Ref: "result", DirPath: "/"}, true},
		{"ReadDir", &gateway.ReadDirRequest{Ref: "result", MountIndex: 1}, false},
		{"StatFile", &gateway.StatFileRequest{Ref: "result", Path: "/Dockerfile"}, true},
		{"StatFile", &gateway.StatFileRequest{}, false},
		{"Evaluate", &gateway.EvaluateRequest{Ref: "result"}, true},
		{"Inputs", &gateway.InputsRequest{}, true},
		{"Warn", &gateway.WarnRequest{Short: []byte("warning")}, true},
		{"Return", &gateway.ReturnRequest{Result: &gateway.Result{Result: &gateway.Result_Ref{Ref: &gateway.Ref{Id: "result"}}}}, true},
		{"Return", &gateway.ReturnRequest{}, false},
		{"Solve", &gateway.SolveRequest{Frontend: "gateway.v0"}, false},
		{"Solve", &gateway.SolveRequest{Final: true}, false},
		{"Solve", &gateway.SolveRequest{FrontendOpt: map[string]string{"source": "image"}}, false},
	} {
		t.Run(tc.method+fmt.Sprint(tc.request), func(t *testing.T) {
			if d := evaluateGatewayRequest(tc.method, mustMarshal(t, tc.request), allowAllPolicy); (d == nil) != tc.allow {
				t.Fatalf("allow=%v denial=%v", tc.allow, d)
			}
			if tc.allow {
				tc.request.ProtoReflect().SetUnknown(unknownFieldBytes())
				if d := evaluateGatewayRequest(tc.method, mustMarshal(t, tc.request), allowAllPolicy); d == nil {
					t.Fatal("unknown frontend fields were admitted")
				}
			}
		})
	}
}
