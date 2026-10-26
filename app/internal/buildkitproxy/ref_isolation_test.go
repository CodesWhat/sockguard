package buildkitproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
)

// Like BuildKit, the daemon keys jobs and retained history by Ref alone.
type refHistoryDaemon struct {
	history map[string]string
}

func (d *refHistoryDaemon) RoundTrip(r *http.Request) (*http.Response, error) {
	_, payload, err := readUnaryGRPCMessage(r.Body, DefaultLimits().MaxMessageBytes)
	if err != nil {
		return nil, err
	}
	status, body := "0", ""
	if strings.HasSuffix(r.URL.Path, "/Solve") {
		var req control.SolveRequest
		if err := proto.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		if _, exists := d.history[req.Ref]; exists {
			status = "6"
		} else {
			d.history[req.Ref] = req.Session
		}
	} else {
		var req control.StatusRequest
		if err := proto.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		body = d.history[req.Ref]
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/grpc"}, "Grpc-Status": {status}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func (d *refHistoryDaemon) Close() error { return nil }

func TestControlRefIsolationAcrossPrincipals(t *testing.T) {
	victim := SessionKey{ClientIdentity: "victim", Profile: "builder"}
	for name, attacker := range map[string]SessionKey{
		"different client":  {ClientIdentity: "attacker", Profile: "builder"},
		"different profile": {ClientIdentity: "victim", Profile: "other-builder"},
	} {
		for _, closed := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/live", true: "/retained-history"}[closed], func(t *testing.T) {
				daemon := &refHistoryDaemon{history: make(map[string]string)}
				bridges := make([]*bridge, 0, 2)
				for _, key := range []SessionKey{victim, attacker} {
					b := newUnitTestBridge(t, daemon)
					b.registry.Close(b.session.ID)
					b.session = b.registry.Open(key, EndpointGRPC, "")
					bridges = append(bridges, b)
					t.Cleanup(func() { b.closeAll(nil) })
				}
				call := func(b *bridge, method string, req proto.Message) *httptest.ResponseRecorder {
					t.Helper()
					rec := httptest.NewRecorder()
					b.handleStream(rec, newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/"+method, req))
					return rec
				}
				first := call(bridges[0], "Solve", &control.SolveRequest{Ref: "shared-ref", Session: "victim-session"})
				if first.Header().Get("Grpc-Status") != "0" {
					t.Fatal("victim Solve failed")
				}
				if closed {
					bridges[0].registry.Close(bridges[0].session.ID)
				}
				call(bridges[1], "Solve", &control.SolveRequest{Ref: "shared-ref", Session: "attacker-session"})
				status := call(bridges[1], "Status", &control.StatusRequest{Ref: "shared-ref"})
				if bytes.Contains(status.Body.Bytes(), []byte(bridges[0].registry.daemonSessionID(victim, "victim-session"))) {
					t.Fatal("duplicate Solve granted access to another principal's build status")
				}
				if status.Body.String() != bridges[1].registry.daemonSessionID(attacker, "attacker-session") {
					t.Fatalf("own build status = %q, want attacker-session", status.Body.String())
				}
			})
		}
	}
}

func TestDaemonBuildRefTupleBoundaries(t *testing.T) {
	tuples := []struct {
		key SessionKey
		ref string
	}{
		{SessionKey{"ab", "c"}, "d"},
		{SessionKey{"a", "bc"}, "d"},
		{SessionKey{"a", "b"}, "cd"},
		{SessionKey{"a\x00b", "c"}, "d"},
		{SessionKey{"a", "b\x00c"}, "d"},
		{SessionKey{"a", "b"}, "\x00cd"},
	}
	seen := make(map[string]bool)
	for _, tuple := range tuples {
		ref := daemonBuildRef(tuple.key, tuple.ref)
		if seen[ref] || ref != daemonBuildRef(tuple.key, tuple.ref) {
			t.Fatal("daemon ref is colliding or unstable")
		}
		if len(ref) > maxBuildkitRefBytes {
			t.Fatal("namespaced ref exceeds the protocol identifier limit")
		}
		seen[ref] = true
	}
}

func TestControlRefFramePreservesOtherWireBytes(t *testing.T) {
	// An overlong but valid length varint would change under proto.Marshal.
	sessionField := []byte{0x2a, 0x81, 0x00, 's'}
	definition := []byte{0x12, 0x03, 0x0a, 0x01, 'x'}
	refField := func(value string) []byte {
		return protowire.AppendString([]byte{0x0a}, value)
	}
	payload := append(refField("earlier-ref"), sessionField...)
	payload = append(payload, refField("final-ref")...)
	payload = append(payload, definition...)
	var req control.SolveRequest
	if err := proto.Unmarshal(payload, &req); err != nil || req.Ref != "final-ref" {
		t.Fatalf("invalid fixture: %v", err)
	}
	frame, err := controlRefFrame(payload, "scoped-ref", "", 1024)
	if err != nil {
		t.Fatal(err)
	}
	expected := append(refField("scoped-ref"), sessionField...)
	expected = append(expected, definition...)
	if !bytes.Equal(frame, grpcFrame(expected)) {
		t.Fatal("ref translation modified other wire bytes or retained an earlier ref")
	}
	if err := proto.Unmarshal(frame[grpcMessageHeaderLen:], &req); err != nil || req.Ref != "scoped-ref" {
		t.Fatalf("translated request: ref=%q error=%v", req.Ref, err)
	}
}

func TestControlRefFrameRejectsMalformedFields(t *testing.T) {
	for _, payload := range [][]byte{nil, {0x80}, {0x0a, 0x80}, {0x08, 0x01}, {0x2a, 0x01, 's'}} {
		if _, err := controlRefFrame(payload, "scoped-ref", "", 1024); err == nil {
			t.Fatalf("accepted malformed or missing ref: %x", payload)
		}
	}
}

func TestControlRefExpansionDoesNotPublishAdmission(t *testing.T) {
	daemon := &refHistoryDaemon{history: make(map[string]string)}
	b := newUnitTestBridge(t, daemon)
	t.Cleanup(func() { b.closeAll(nil) })
	b.limits.MaxMessageBytes = 64
	rec := httptest.NewRecorder()
	b.handleStream(rec, newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "r", Session: "s"}))
	if rec.Header().Get("Grpc-Status") != "8" {
		t.Fatalf("oversized translated frame status = %q", rec.Header().Get("Grpc-Status"))
	}
	if len(daemon.history) != 0 || b.registry.OwnsRef(b.session.Key, "r") || b.registry.HasAdmittedSolve(b.session.Key, "s") {
		t.Fatal("size denial published a build or session admission")
	}
}
