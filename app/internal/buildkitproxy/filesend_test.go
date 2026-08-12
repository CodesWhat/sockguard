package buildkitproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newFileSendTestBridge builds a live end-to-end testBridge (real h2c
// framing both directions) wired for moby.filesync.v1.FileSend/DiffCopy,
// admitting a Solve ref for key first when admitSolve is true — mirroring
// filesend.go's own precondition that FileSend requires an admitted
// Control/Solve from the same SessionKey.
func newFileSendTestBridge(t *testing.T, limits Limits, daemonHandler http.Handler, admitSolve bool) *testBridge {
	t.Helper()
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, limits, daemonHandler)
	if admitSolve {
		if !tb.registry.PutRef(tb.session, "ref-1", 0) {
			t.Fatal("PutRef failed to admit ref-1")
		}
	}
	return tb
}

func TestFileSendDeniesWithoutAdmittedSolve(t *testing.T) {
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
	tb := newFileSendTestBridge(t, DefaultLimits(), daemon, false)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.FileSend/DiffCopy", string(grpcFrame([]byte("payload")))))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied)", code, grpcCodePermissionDenied)
	}
	if daemonCalled {
		t.Fatal("FileSend reached the daemon handler without an admitted Solve")
	}
}

func TestFileSendAdmittedSolveRelaysVerbatimBothDirections(t *testing.T) {
	var daemonSawBody []byte
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		daemonSawBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(grpcFrame([]byte("exported-bytes")))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	tb := newFileSendTestBridge(t, DefaultLimits(), daemon, true)

	reqBody := grpcFrame([]byte("some-non-bytesmessage-shaped-payload"))
	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.FileSend/DiffCopy", string(reqBody)))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("Grpc-Status = %d, want 0 (OK)", code)
	}
	if !bytes.Equal(daemonSawBody, reqBody) {
		t.Fatalf("daemon saw body %v, want the original request frame verbatim %v — FileSend must never re-encode", daemonSawBody, reqBody)
	}
	want := grpcFrame([]byte("exported-bytes"))
	if !bytes.Equal(body, want) {
		t.Fatalf("client saw body %v, want the original response frame verbatim %v", body, want)
	}
}

// TestFileSendRequestByteCapExceeded exercises the request-direction byte
// cap via a unit-level bridge (drainingFakeClientLeg, defined in
// streammediation_test.go) rather than a live daemon connection: for a
// STREAMING relay, the daemon's HTTP/2 handler is invoked as soon as headers
// arrive, before the (capped) body has been fully read, so "the daemon must
// never be called" isn't a meaningful assertion here the way it is for
// forwardWithBody's single-buffered-message case — see
// TestBridgeForwardRequestSizeCapTripsResourceExhaustedWithoutClosingTunnel's
// own doc comment for the same tradeoff on the Phase 2 path.
func TestFileSendRequestByteCapExceeded(t *testing.T) {
	fake := &drainingFakeClientLeg{}
	b := newUnitTestBridge(t, fake)
	if !b.registry.PutRef(b.session, "ref-1", 0) {
		t.Fatal("PutRef failed to admit ref-1")
	}
	b.limits.MaxFileSendBytes = 5

	req := httptest.NewRequest(http.MethodPost, "/moby.filesync.v1.FileSend/DiffCopy", bytes.NewReader(grpcFrame(bytes.Repeat([]byte("x"), 100))))
	rec := httptest.NewRecorder()

	b.forwardFileSendMediated(rec, req, "moby.filesync.v1.FileSend", "DiffCopy")

	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (ResourceExhausted)", code, grpcCodeResourceExhausted)
	}
	if b.closeErr != nil {
		t.Fatalf("closeErr = %v, want nil — a size-cap trip is stream-local", b.closeErr)
	}
}

func TestFileSendResponseByteCapExceeded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFileSendBytes = 5
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(grpcFrame(bytes.Repeat([]byte("y"), 100)))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	tb := newFileSendTestBridge(t, limits, daemon, true)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.FileSend/DiffCopy", string(grpcFrame([]byte("x")))))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (ResourceExhausted)", code, grpcCodeResourceExhausted)
	}
}

// TestFileSendNeverDecodesPayload confirms rawByteCapValidator's own
// contract end-to-end through forwardFileSendMediated: bytes that would fail
// proto.Unmarshal as any known message type must still relay/cap correctly,
// since FileSend's wire shape is ambiguous (Packet-shaped in "outdir" export
// mode, BytesMessage-shaped in "single file" mode — see rawByteCapValidator's
// doc comment) and this package must never attempt to interpret it.
func TestFileSendNeverDecodesPayload(t *testing.T) {
	garbage := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// body is already a complete gRPC-framed frame (verbatim, including
		// its own length-prefix header) — echo it as-is rather than
		// re-wrapping it in another grpcFrame().
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	tb := newFileSendTestBridge(t, DefaultLimits(), daemon, true)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.FileSend/DiffCopy", string(grpcFrame(garbage))))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("Grpc-Status = %d, want 0 (OK) — non-protobuf-shaped bytes must still relay, never rejected as malformed", code)
	}
	want := grpcFrame(garbage)
	if !bytes.Equal(body, want) {
		t.Fatalf("body = %v, want the garbage relayed verbatim %v", body, want)
	}
}

// TestForwardFileSendMediatedDenialAudited is a focused unit test (no live
// driver connection) confirming the session-mismatch denial path never
// touches b.clientLeg at all.
func TestForwardFileSendMediatedDenialNeverCallsClientLeg(t *testing.T) {
	fake := &fakeClientLeg{}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.filesync.v1.FileSend/DiffCopy", bytes.NewReader(nil))
	rec := httptest.NewRecorder()

	b.forwardFileSendMediated(rec, req, "moby.filesync.v1.FileSend", "DiffCopy")

	if fake.gotReq != nil {
		t.Fatal("forwardFileSendMediated called RoundTrip despite no admitted Solve")
	}
	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied)", code, grpcCodePermissionDenied)
	}
}
