package buildkitproxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/internal/buildkitproto/control"
)

// newFramedGRPCRequest is newGRPCRequest's sibling for forwardControlMediated's
// two mediated RPCs: it wraps a marshaled protobuf message in a valid gRPC
// length-prefixed frame (see framing_test.go's grpcFrame) rather than
// sending it as a raw string body.
func newFramedGRPCRequest(t *testing.T, path string, msg proto.Message) *http.Request {
	t.Helper()
	payload := mustMarshal(t, msg)
	return newGRPCRequest(t, path, string(grpcFrame(payload)))
}

// TestBridgeControlMediatedSolve covers forwardControlMediated's Solve path
// end to end through a live bridge: framing/decode failures, each policy
// denial reason, ref-cap enforcement, and the admitted case's byte-verbatim
// forward plus ref registration. Every denial case also asserts the daemon
// handler was never invoked — a Solve mediation failure must never reach
// the daemon.
func TestBridgeControlMediatedSolve(t *testing.T) {
	const solvePath = "/moby.buildkit.v1.Control/Solve"

	t.Run("malformed framing", func(t *testing.T) {
		daemonCalled := false
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, solvePath, "not a valid gRPC frame"))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, msg := grpcStatusOf(t, resp)
		if code != grpcCodeInvalidArgument {
			t.Fatalf("Grpc-Status = %d, want %d (INVALID_ARGUMENT); message = %q", code, grpcCodeInvalidArgument, msg)
		}
		if daemonCalled {
			t.Fatal("malformed framing reached the daemon")
		}
	})

	t.Run("message exceeds size cap", func(t *testing.T) {
		daemonCalled := false
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
		limits := DefaultLimits()
		limits.MaxMessageBytes = 4
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, daemon)

		payload := mustMarshal(t, &control.SolveRequest{Ref: "a-ref-longer-than-four-bytes"})
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, solvePath, string(grpcFrame(payload))))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeResourceExhausted {
			t.Fatalf("Grpc-Status = %d, want %d (RESOURCE_EXHAUSTED)", code, grpcCodeResourceExhausted)
		}
		if daemonCalled {
			t.Fatal("an oversized message reached the daemon")
		}
	})

	t.Run("unknown fields", func(t *testing.T) {
		daemonCalled := false
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon)

		req := &control.SolveRequest{Ref: "ref"}
		req.ProtoReflect().SetUnknown(unknownFieldBytes())
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeFailedPrecondition {
			t.Fatalf("Grpc-Status = %d, want %d (FAILED_PRECONDITION)", code, grpcCodeFailedPrecondition)
		}
		if daemonCalled {
			t.Fatal("a message with unknown fields reached the daemon")
		}
	})

	t.Run("entitlement denied by policy", func(t *testing.T) {
		daemonCalled := false
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
		policy := Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true}}}
		tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), daemon)

		req := &control.SolveRequest{Ref: "ref", Entitlements: []string{"network.host"}}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, msg := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED); message = %q", code, grpcCodePermissionDenied, msg)
		}
		if !strings.Contains(msg, "network.host") {
			t.Fatalf("Grpc-Message = %q, want it to mention network.host", msg)
		}
		if daemonCalled {
			t.Fatal("an entitlement the policy denies reached the daemon")
		}
	})

	t.Run("ref cap exceeded denies the second solve", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxRefsPerSession = 1
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler())

		resp1, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, &control.SolveRequest{Ref: "ref-1"}))
		if err != nil {
			t.Fatalf("RoundTrip 1: %v", err)
		}
		if _, _ = io.Copy(io.Discard, resp1.Body); resp1.StatusCode != http.StatusOK {
			t.Fatalf("first Solve status = %d, want 200", resp1.StatusCode)
		}
		_ = resp1.Body.Close()

		resp2, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, &control.SolveRequest{Ref: "ref-2"}))
		if err != nil {
			t.Fatalf("RoundTrip 2: %v", err)
		}
		code, msg := grpcStatusOf(t, resp2)
		if code != grpcCodeResourceExhausted {
			t.Fatalf("second Solve Grpc-Status = %d, want %d (RESOURCE_EXHAUSTED); message = %q", code, grpcCodeResourceExhausted, msg)
		}
	})

	t.Run("admitted Solve forwards the exact frame and registers the ref", func(t *testing.T) {
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler())

		payload := mustMarshal(t, &control.SolveRequest{Ref: "admitted-ref"})
		frame := grpcFrame(payload)
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, solvePath, string(frame)))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading response body: %v", err)
		}
		if string(body) != string(frame) {
			t.Fatalf("response body does not match the original frame verbatim (no re-encoding expected)")
		}
		if !tb.registry.OwnsRef(tb.session.Key, "admitted-ref") {
			t.Fatal("registry does not own the ref from an admitted Solve")
		}
	})
}

// TestBridgeControlMediatedStatus covers forwardControlMediated's Status
// path: decode failures and the ref-ownership gate (denied for an unowned
// ref, admitted for a ref this same session's Solve registered).
func TestBridgeControlMediatedStatus(t *testing.T) {
	const (
		solvePath  = "/moby.buildkit.v1.Control/Solve"
		statusPath = "/moby.buildkit.v1.Control/Status"
	)

	t.Run("unknown fields", func(t *testing.T) {
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler())

		req := &control.StatusRequest{Ref: "ref"}
		req.ProtoReflect().SetUnknown(unknownFieldBytes())
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, statusPath, req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeFailedPrecondition {
			t.Fatalf("Grpc-Status = %d, want %d (FAILED_PRECONDITION)", code, grpcCodeFailedPrecondition)
		}
	})

	t.Run("ref not owned by this session", func(t *testing.T) {
		daemonCalled := false
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, statusPath, &control.StatusRequest{Ref: "never-solved"}))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, msg := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED); message = %q", code, grpcCodePermissionDenied, msg)
		}
		if daemonCalled {
			t.Fatal("Status for an unowned ref reached the daemon")
		}
	})

	t.Run("ref owned via a prior admitted Solve on the same session", func(t *testing.T) {
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler())

		solveResp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, &control.SolveRequest{Ref: "owned-ref"}))
		if err != nil {
			t.Fatalf("Solve RoundTrip: %v", err)
		}
		_, _ = io.Copy(io.Discard, solveResp.Body)
		_ = solveResp.Body.Close()

		statusResp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, statusPath, &control.StatusRequest{Ref: "owned-ref"}))
		if err != nil {
			t.Fatalf("Status RoundTrip: %v", err)
		}
		if statusResp.StatusCode != http.StatusOK {
			code, msg := grpcStatusOf(t, statusResp)
			t.Fatalf("Status for an owned ref was denied: Grpc-Status = %d, message = %q", code, msg)
		}
		_, _ = io.Copy(io.Discard, statusResp.Body)
		_ = statusResp.Body.Close()
	})
}
