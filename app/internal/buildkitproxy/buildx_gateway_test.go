package buildkitproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/pb"
	"google.golang.org/protobuf/proto"
)

func TestBuildxBuiltinDockerfilePolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*gateway.SolveRequest)
		allowed bool
	}{
		{"builtin local", func(*gateway.SolveRequest) {}, true},
		{"external compiler", func(r *gateway.SolveRequest) { r.Frontend = "gateway.v0" }, false},
		{"syntax argument", func(r *gateway.SolveRequest) { r.FrontendOpt["build-arg:BUILDKIT_SYNTAX"] = "evil/compiler" }, false},
		{"command override", func(r *gateway.SolveRequest) { r.FrontendOpt["cmdline"] = "evil" }, false},
		{"unknown attribute", func(r *gateway.SolveRequest) { r.FrontendOpt["future"] = "value" }, false},
		{"host network", func(r *gateway.SolveRequest) { r.FrontendOpt["force-network-mode"] = "host" }, false},
		{"remote context", func(r *gateway.SolveRequest) { r.FrontendOpt["context"] = "https://example.com/context.tar" }, false},
		{"mixed graph", func(r *gateway.SolveRequest) { r.Definition = &pb.Definition{} }, false},
		{"inline output", func(r *gateway.SolveRequest) { r.Final = true }, false},
		{"frontend inputs", func(r *gateway.SolveRequest) { r.FrontendInputs = map[string]*pb.Definition{"context": {}} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &gateway.SolveRequest{Frontend: "dockerfile.v0", FrontendOpt: map[string]string{"filename": "Dockerfile", "image-resolve-mode": "local"}, AllowResultReturn: true, AllowResultArrayRef: true}
			tc.change(r)
			if d := evaluateGatewayRequest("Solve", mustMarshal(t, r), allowAllPolicy); (d == nil) != tc.allowed {
				t.Fatalf("allowed=%v denial=%v", tc.allowed, d)
			}
		})
	}
}

func TestBuildxBuiltinDockerfileBridge(t *testing.T) {
	for _, owner := range []string{"", "team-a", strings.Repeat("x", 1024)} {
		t.Run("owner="+owner[:min(len(owner), 6)], func(t *testing.T) {
			daemon := &fakeClientLeg{resp: &http.Response{StatusCode: 200, Header: http.Header{"Grpc-Status": {"0"}}, Body: io.NopCloser(strings.NewReader(""))}}
			b := newUnitTestBridge(t, daemon)
			defer b.closeAll(nil)
			b.limits.MaxMessageBytes = 512
			b.policy.Control.Solve.AllowFrontendGateway = true
			policy := b.policy
			policy.Control.Solve.AllowFrontendGateway = true
			policy.ImageOwnership = ImageOwnershipPolicy{Owner: owner, LabelKey: "owner"}
			g, d := b.registry.beginGatewayBuild(context.Background(), b.session, "build", testBuildkitSessionID, policy)
			if d != nil {
				t.Fatal(d)
			}
			defer b.registry.endGatewayBuild(g)
			if b.registry.admitSolve(b.session, testBuildkitSessionID, "build", nil, b.limits.MaxRefsPerSession, b.limits.MaxUploadKeysPerSession) != solveAdmissionSucceeded {
				t.Fatal("root Solve admission failed")
			}
			r := newFramedGRPCRequest(t, "/"+gatewayService+"/Solve", &gateway.SolveRequest{Frontend: "dockerfile.v0", FrontendOpt: map[string]string{"filename": "Dockerfile"}})
			r.Header.Set(gatewayBuildHeader, "build")
			rec := httptest.NewRecorder()
			b.handleStream(rec, r)
			if len(owner) > 512 {
				if rec.Header().Get("Grpc-Status") != "8" || daemon.gotReq != nil {
					t.Fatal("expanded request reached daemon")
				}
			} else {
				if daemon.gotReq == nil {
					t.Fatalf("builtin compiler denied: %s", rec.Header().Get("Grpc-Message"))
				}
				_, payload, err := readUnaryGRPCMessage(daemon.gotReq.Body, DefaultLimits().MaxMessageBytes)
				if err != nil {
					t.Fatal(err)
				}
				var got gateway.SolveRequest
				if err := proto.Unmarshal(payload, &got); err != nil {
					t.Fatal(err)
				}
				if value, present := got.FrontendOpt["cmdline"]; !present || value != "" {
					t.Error("syntax delegation was not disabled")
				}
				if owner != "" && got.FrontendOpt["label:owner"] != owner {
					t.Error("owner was not stamped")
				}
			}
		})
	}
}

func TestBuildxReturnedSourceSessionIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, method, source string
		denied               bool
	}{
		{"own returned metadata", "Return", "own", false},
		{"other client", "Return", "client", true},
		{"other profile", "Return", "profile", true},
		{"unscoped session", "Return", "raw", true},
		{"own explicit input still denied", "Solve", "own", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			daemon := &fakeClientLeg{resp: &http.Response{StatusCode: 200, Header: http.Header{"Grpc-Status": {"0"}}, Body: io.NopCloser(strings.NewReader(""))}}
			b := newUnitTestBridge(t, daemon)
			defer b.closeAll(nil)
			b.policy.Control.Solve.AllowFrontendGateway = true
			g, d := b.registry.beginGatewayBuild(context.Background(), b.session, "build", testBuildkitSessionID, b.policy)
			if d != nil {
				t.Fatal(d)
			}
			defer b.registry.endGatewayBuild(g)
			if b.registry.admitSolve(b.session, testBuildkitSessionID, "build", nil, b.limits.MaxRefsPerSession, b.limits.MaxUploadKeysPerSession) != solveAdmissionSucceeded {
				t.Fatal("root admission failed")
			}
			key := b.session.Key
			if tc.source == "client" {
				key.ClientIdentity = "other"
			}
			if tc.source == "profile" {
				key.Profile = "other"
			}
			session := b.registry.daemonSessionID(key, testBuildkitSessionID)
			if tc.source == "raw" {
				session = testBuildkitSessionID
			}
			def := &pb.Definition{Def: [][]byte{mustMarshal(t, &pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: "local://context", Attrs: map[string]string{"local.session": session}}}})}}
			var msg proto.Message = &gateway.ReturnRequest{Result: &gateway.Result{Result: &gateway.Result_Ref{Ref: &gateway.Ref{Id: "result", Def: def}}}}
			if tc.method == "Solve" {
				msg = &gateway.SolveRequest{Definition: def}
			}
			r := newFramedGRPCRequest(t, "/"+gatewayService+"/"+tc.method, msg)
			r.Header.Set(gatewayBuildHeader, "build")
			rec := httptest.NewRecorder()
			b.handleStream(rec, r)
			if (daemon.gotReq == nil) != tc.denied {
				t.Fatalf("denied=%v daemon=%v message=%s", tc.denied, daemon.gotReq != nil, rec.Header().Get("Grpc-Message"))
			}
		})
	}
}
