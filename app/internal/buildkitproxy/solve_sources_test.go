package buildkitproxy

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"google.golang.org/protobuf/proto"
)

func sourceGraph(t *testing.T, identifier string, approvedExec bool) *pb.Definition {
	t.Helper()
	source := mustMarshal(t, &pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: identifier}}})
	ops := [][]byte{source}
	if approvedExec {
		ops = append(ops, mustMarshal(t, &pb.Op{Inputs: []*pb.Input{{Digest: sourceOpDigest(source)}}, Op: &pb.Op_Exec{Exec: &pb.ExecOp{Meta: &pb.Meta{Args: []string{"true"}}, Network: pb.NetMode_NONE}}}))
	}
	return &pb.Definition{Def: append(ops, mustMarshal(t, &pb.Op{Inputs: []*pb.Input{{Digest: sourceOpDigest(ops[len(ops)-1])}}}))}
}

func TestRawSolveRemoteSources(t *testing.T) {
	for _, identifier := range []string{"http://example.com/context", "https://example.com/context", "git://example.com/repo"} {
		for _, allowRun := range []bool{false, true} {
			for _, allowRemote := range []bool{false, true} {
				for _, approvedExec := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/run=%t/remote=%t/approved=%t", identifier, allowRun, allowRemote, approvedExec), func(t *testing.T) {
						def := sourceGraph(t, identifier, approvedExec)
						policy := Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true, AllowRunInstructions: allowRun, AllowRemoteContext: allowRemote}}}
						if approvedExec {
							policy.Control.Solve.AllowedExecDigests = map[string]struct{}{sourceOpDigest(def.Def[1]): {}}
						}
						req := &control.SolveRequest{Ref: "source-build", Session: testBuildkitSessionID, Definition: def}
						if d := checkGatewayDefinition(def, policy.Control.Solve); (d == nil) != allowRemote {
							t.Fatalf("gateway remote-source policy diverged: %v", d)
						}
						frontendReq := proto.Clone(req).(*control.SolveRequest)
						frontendReq.Frontend = "dockerfile.v0"
						if _, d := evaluateSolveRequest(mustMarshal(t, frontendReq), policy); (d == nil) != allowRemote {
							t.Fatalf("frontend selection changed raw-source policy: %v", d)
						}
						admitted, d := evaluateSolveRequest(mustMarshal(t, req), policy)
						if !allowRemote {
							if d == nil || d.code != grpcCodePermissionDenied || d.reasonCode != "buildkit_policy_denied" {
								t.Errorf("evaluator denial = %v, want remote source permission denial", d)
							}
						} else if d != nil || !proto.Equal(admitted.Definition, def) {
							t.Fatalf("evaluator changed or denied permitted definition: %v", d)
						}
						var calls atomic.Int32
						daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); echoDaemonHandler().ServeHTTP(w, r) })
						tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), daemon)
						resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", req))
						if err != nil {
							t.Fatal(err)
						}
						if !allowRemote {
							code, _ := grpcStatusOf(t, resp)
							if code != grpcCodePermissionDenied || calls.Load() != 0 {
								t.Fatalf("bridge status=%d daemon calls=%d, want denial before daemon", code, calls.Load())
							}
							return
						}
						body, err := io.ReadAll(resp.Body)
						if err != nil {
							t.Fatal(err)
						}
						_ = resp.Body.Close()
						expected := proto.Clone(req).(*control.SolveRequest)
						expected.Ref = daemonBuildRef(tb.session.Key, req.Ref)
						expected.Session = tb.registry.daemonSessionID(tb.session.Key, req.Session)
						if calls.Load() != 1 || !bytes.Equal(body, grpcFrame(mustMarshal(t, expected))) {
							t.Fatal("permitted source graph was not forwarded with original operation bytes and scoped ref/session")
						}
					})
				}
			}
		}
	}
}

func TestRawSolveSourceCompatibility(t *testing.T) {
	for _, identifier := range []string{"local://context", "docker-image://busybox", "oci-layout://image"} {
		t.Run(identifier, func(t *testing.T) {
			def := sourceGraph(t, identifier, false)
			_, d := evaluateSolveRequest(mustMarshal(t, &control.SolveRequest{Ref: "r", Session: testBuildkitSessionID, Definition: def}), Policy{})
			if d != nil {
				t.Fatalf("source compatibility denied: %v", d)
			}
			gatewayDenial := checkGatewayDefinition(def, SolvePolicy{})
			if (gatewayDenial == nil) != (identifier != "oci-layout://image") {
				t.Fatalf("gateway source allowlist changed: %v", gatewayDenial)
			}
		})
	}
	for _, allowRun := range []bool{false, true} {
		for _, kind := range []string{"malformed", "unknown", "local.session", "oci.session"} {
			t.Run(fmt.Sprintf("%s/run=%t", kind, allowRun), func(t *testing.T) {
				op := &pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: "local://context"}}}
				if kind == "unknown" {
					op.ProtoReflect().SetUnknown(unknownFieldBytes())
				}
				if kind == "local.session" || kind == "oci.session" {
					op.GetSource().Attrs = map[string]string{kind: "other-session"}
				}
				raw := mustMarshal(t, op)
				if kind == "malformed" {
					raw = malformedPayload
				}
				_, d := evaluateSolveRequest(mustMarshal(t, &control.SolveRequest{Ref: "r", Session: testBuildkitSessionID, Definition: &pb.Definition{Def: [][]byte{raw}}}), Policy{Control: ControlPolicy{Solve: SolvePolicy{AllowRunInstructions: allowRun, AllowRemoteContext: true}}})
				if d == nil || d.code != grpcCodePermissionDenied {
					t.Fatalf("unsafe source admitted: %v", d)
				}
			})
		}
	}
}

func sourceOpDigest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
