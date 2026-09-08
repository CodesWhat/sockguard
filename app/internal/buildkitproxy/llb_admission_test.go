package buildkitproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
)

func TestExecDigestDoesNotOverrideExecutionGuards(t *testing.T) {
	cases := map[string]func(*pb.ExecOp){
		"host network":          func(op *pb.ExecOp) { op.Network = pb.NetMode_HOST },
		"unknown network":       func(op *pb.ExecOp) { op.Network = pb.NetMode(99) },
		"insecure execution":    func(op *pb.ExecOp) { op.Security = pb.SecurityMode_INSECURE },
		"unknown security mode": func(op *pb.ExecOp) { op.Security = pb.SecurityMode(99) },
		"CDI device":            func(op *pb.ExecOp) { op.CdiDevices = []*pb.CDIDevice{{Name: "example.com/device=all"}} },
		"empty command":         func(op *pb.ExecOp) { op.Meta.Args = nil },
		"unknown metadata":      func(op *pb.ExecOp) { op.Meta.ProtoReflect().SetUnknown(unknownFieldBytes()) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			op := &pb.ExecOp{Meta: &pb.Meta{Args: []string{"/bin/true"}}}
			mutate(op)
			raw := mustMarshal(t, &pb.Op{Op: &pb.Op_Exec{Exec: op}})
			sum := sha256.Sum256(raw)
			policy := Policy{Control: ControlPolicy{Solve: SolvePolicy{
				Allow: true, AllowedExecDigests: map[string]struct{}{"sha256:" + hex.EncodeToString(sum[:]): {}},
			}}}
			req := &control.SolveRequest{Ref: "build-1", Session: "session-1", Definition: &pb.Definition{Def: [][]byte{raw}}}
			if _, denial := evaluateSolveRequest(mustMarshal(t, req), policy); denial == nil {
				t.Fatal("digest approval bypassed an execution guard")
			}
		})
	}
}

func TestSolveExecDigestAdmission(t *testing.T) {
	op := &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{
		Meta:    &pb.Meta{Args: []string{"/bin/echo", "approved"}},
		Network: pb.NetMode_NONE,
	}}}
	raw := mustMarshal(t, op)
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	policy := Policy{Control: ControlPolicy{Solve: SolvePolicy{
		Allow: true, AllowedExecDigests: map[string]struct{}{digest: {}},
	}}}
	req := &control.SolveRequest{
		Ref: "build-1", Session: "session-1", Definition: &pb.Definition{Def: [][]byte{raw}},
	}
	if _, denial := evaluateSolveRequest(mustMarshal(t, req), policy); denial != nil {
		t.Fatalf("approved ExecOp denied: %+v", denial)
	}

	op.GetExec().Meta.Env = []string{"LD_PRELOAD=/changed.so"}
	req.Definition.Def = [][]byte{mustMarshal(t, op)}
	if _, denial := evaluateSolveRequest(mustMarshal(t, req), policy); denial == nil {
		t.Fatal("changing an approved operation's environment retained its approval")
	}
}

func TestExecDigestCoversOperationBytes(t *testing.T) {
	original := &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Meta: &pb.Meta{Args: []string{"/bin/echo", "approved"}}}}}
	raw := mustMarshal(t, original)
	sum := sha256.Sum256(raw)
	policy := SolvePolicy{AllowedExecDigests: map[string]struct{}{"sha256:" + hex.EncodeToString(sum[:]): {}}}
	for name, mutate := range map[string]func(*pb.Op){
		"argument":          func(op *pb.Op) { op.GetExec().Meta.Args[1] = "changed" },
		"environment":       func(op *pb.Op) { op.GetExec().Meta.Env = []string{"PATH=/changed"} },
		"working directory": func(op *pb.Op) { op.GetExec().Meta.Cwd = "/changed" },
		"user":              func(op *pb.Op) { op.GetExec().Meta.User = "changed" },
		"mount":             func(op *pb.Op) { op.GetExec().Mounts = []*pb.Mount{{Dest: "/changed"}} },
		"input":             func(op *pb.Op) { op.Inputs = []*pb.Input{{Digest: "sha256:changed"}} },
	} {
		t.Run(name, func(t *testing.T) {
			op := proto.Clone(original).(*pb.Op)
			mutate(op)
			if definitionExecAllowed(&pb.Definition{Def: [][]byte{mustMarshal(t, op)}}, policy) {
				t.Fatal("modified operation retained its approval")
			}
		})
	}
	if !definitionExecAllowed(&pb.Definition{Def: [][]byte{raw, raw}}, policy) {
		t.Fatal("repeating an approved operation was denied")
	}
	unapproved := proto.Clone(original).(*pb.Op)
	unapproved.GetExec().Meta.Args[1] = "unapproved"
	if definitionExecAllowed(&pb.Definition{Def: [][]byte{raw, mustMarshal(t, unapproved)}}, policy) {
		t.Fatal("one approved operation granted the entire graph")
	}
}

func TestExecDigestHostNetworkRequiresBothGrants(t *testing.T) {
	op := &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Meta: &pb.Meta{Args: []string{"/bin/true"}}, Network: pb.NetMode_HOST}}}
	raw := mustMarshal(t, op)
	sum := sha256.Sum256(raw)
	policy := SolvePolicy{AllowHostNetwork: true, AllowedExecDigests: map[string]struct{}{"sha256:" + hex.EncodeToString(sum[:]): {}}}
	if !definitionExecAllowed(&pb.Definition{Def: [][]byte{raw}}, policy) {
		t.Fatal("host-network operation with both grants was denied")
	}
	policy.AllowedExecDigests = nil
	if definitionExecAllowed(&pb.Definition{Def: [][]byte{raw}}, policy) {
		t.Fatal("host-network grant also granted execution")
	}
}

func TestBridgeExecDigestAdmission(t *testing.T) {
	op := &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Meta: &pb.Meta{Args: []string{"/bin/true"}}}}}
	raw := mustMarshal(t, op)
	sum := sha256.Sum256(raw)
	for _, approved := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "approved"}[approved], func(t *testing.T) {
			var calls atomic.Int32
			daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				echoDaemonHandler().ServeHTTP(w, r)
			})
			policy := Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true}}}
			if approved {
				policy.Control.Solve.AllowedExecDigests = map[string]struct{}{"sha256:" + hex.EncodeToString(sum[:]): {}}
			}
			tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), daemon)
			req := &control.SolveRequest{Ref: "build-1", Session: testBuildkitSessionID, Definition: &pb.Definition{Def: [][]byte{raw}}}
			frame := grpcFrame(mustMarshal(t, req))
			resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", string(frame)))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if approved {
				body, err := io.ReadAll(resp.Body)
				req.Ref = daemonBuildRef(tb.session.Key, req.Ref)
				req.Session = tb.registry.daemonSessionID(tb.session.Key, req.Session)
				expected := grpcFrame(mustMarshal(t, req))
				if err != nil || string(body) != string(expected) || calls.Load() != 1 {
					t.Fatalf("approved operation bytes changed during ref scoping: calls=%d err=%v", calls.Load(), err)
				}
			} else {
				code, _ := grpcStatusOf(t, resp)
				if code != grpcCodePermissionDenied || calls.Load() != 0 {
					t.Fatalf("denial: code=%d daemon calls=%d", code, calls.Load())
				}
			}
			if tb.registry.OwnsRef(tb.session.Key, "build-1") != approved {
				t.Fatal("ref ownership did not match operation admission")
			}
		})
	}
}

func TestSolveDeniesUninspectableLLB(t *testing.T) {
	unknown := &pb.Op{}
	unknown.ProtoReflect().SetUnknown(unknownFieldBytes())
	cases := map[string]*pb.Op{
		"filesystem supplied nested graph": {
			Op: &pb.Op_Build{Build: &pb.BuildOp{
				Inputs: map[string]*pb.BuildInput{"buildkit.llb.definition": {Input: 0}},
			}},
		},
		"unknown operation": unknown,
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			req := &control.SolveRequest{
				Ref: "build-1", Session: "session-1",
				Definition: &pb.Definition{Def: [][]byte{mustMarshal(t, op)}},
			}
			if _, denial := evaluateSolveRequest(mustMarshal(t, req), Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true}}}); denial == nil {
				t.Fatal("uninspectable operation was admitted while RUN instructions are restricted")
			}
		})
	}
}
