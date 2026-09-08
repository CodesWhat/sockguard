package buildkitproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
)

// Capture the actual upstream upgrade headers. Rejecting the handshake keeps
// this test focused on the daemon's global session lookup, without live tunnels.
func captureSessionUpgrade(t *testing.T, registry *SessionRegistry, key SessionKey, id string) http.Header {
	t.Helper()
	daemon, upstream := net.Pipe()
	t.Cleanup(func() { _ = daemon.Close(); _ = upstream.Close() })
	_ = daemon.SetDeadline(time.Now().Add(5 * time.Second))
	result := make(chan http.Header, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(daemon))
		if err != nil {
			result <- nil
			return
		}
		_ = req.Body.Close()
		result <- req.Header
		_, _ = daemon.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"))
	}()
	m := NewMediator(&fakeDialer{conn: upstream}, noopLogger())
	m.Registry = registry
	r := newUpgradeRequest(t, "/session")
	r.Header.Set(sessionUUIDHeader, id)
	m.ServeSession(httptest.NewRecorder(), r, allowAllPolicy, key)
	header := <-result
	if header == nil {
		t.Fatal("daemon did not receive the upgrade")
	}
	if r.Header.Get(sessionUUIDHeader) != id {
		t.Fatal("namespace rewrite mutated the client request")
	}
	return header
}

func TestSolveRejectsExplicitSourceSessions(t *testing.T) {
	for _, allowRun := range []bool{false, true} {
		for _, attr := range []string{"local.session", "oci.session"} {
			for _, id := range []string{"", "own-session", "prefix:other-session"} {
				req := &control.SolveRequest{Ref: "r", Session: "own-session", Definition: &pb.Definition{Def: [][]byte{mustMarshal(t, &pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: "local://context", Attrs: map[string]string{attr: id}}}})}}}
				policy := allowAllPolicy
				policy.Control.Solve.AllowRunInstructions = allowRun
				_, d := evaluateSolveRequest(mustMarshal(t, req), policy)
				if (d != nil) != (id != "") {
					t.Fatalf("allowRun=%v %s=%q: denial=%v", allowRun, attr, id, d)
				}
			}
		}
	}
}

func TestDaemonSessionIsolation(t *testing.T) {
	victim := SessionKey{ClientIdentity: "victim", Profile: "builder"}
	for name, attacker := range map[string]SessionKey{
		"different client":  {ClientIdentity: "attacker", Profile: "builder"},
		"different profile": {ClientIdentity: "victim", Profile: "other"},
	} {
		t.Run(name, func(t *testing.T) {
			registry := NewSessionRegistry()
			victimID := captureSessionUpgrade(t, registry, victim, "shared-session").Get(sessionUUIDHeader)
			attackerID := captureSessionUpgrade(t, registry, attacker, "shared-session").Get(sessionUUIDHeader)
			if victimID == attackerID || victimID == "shared-session" {
				t.Fatal("different principals select the same daemon callback session")
			}
			if again := captureSessionUpgrade(t, registry, victim, "shared-session").Get(sessionUUIDHeader); again != victimID {
				t.Fatal("same-principal reconnect lost its session namespace")
			}
			if replay := captureSessionUpgrade(t, registry, attacker, victimID).Get(sessionUUIDHeader); replay == victimID {
				t.Fatal("replaying a daemon identifier selected another principal's session")
			}
			for _, pair := range []struct {
				key SessionKey
				id  string
			}{{victim, victimID}, {attacker, attackerID}} {
				daemon := &fakeClientLeg{resp: &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}}
				b := newUnitTestBridge(t, daemon)
				b.registry.Close(b.session.ID)
				b.registry = registry
				b.session = registry.Open(pair.key, EndpointGRPC, "")
				t.Cleanup(func() { b.closeAll(nil) })
				rec := httptest.NewRecorder()
				b.handleStream(rec, newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "r", Session: "shared-session"}))
				var req control.SolveRequest
				if daemon.gotReq == nil {
					t.Fatal("Solve was not forwarded")
				}
				_, payload, err := readUnaryGRPCMessage(daemon.gotReq.Body, DefaultLimits().MaxMessageBytes)
				if err != nil {
					t.Fatal(err)
				}
				if err := proto.Unmarshal(payload, &req); err != nil {
					t.Fatal(err)
				}
				if req.Session != pair.id {
					t.Fatalf("Solve selected %q, own callback session is %q", req.Session, pair.id)
				}
				if !registry.HasAdmittedSolve(pair.key, "shared-session") {
					t.Fatal("client-facing callback authorization lost its original session id")
				}
			}
		})
	}
}

func TestDaemonSessionNamespaceSecretAndTupleBoundaries(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{"client", "profile"}
	if registry.daemonSessionID(key, "session") == NewSessionRegistry().daemonSessionID(key, "session") {
		t.Fatal("independent registries use a predictable session namespace")
	}
	seen := make(map[string]bool)
	for _, tuple := range []struct {
		key SessionKey
		id  string
	}{
		{SessionKey{"ab", "c"}, "d"}, {SessionKey{"a", "bc"}, "d"},
		{SessionKey{"a", "b"}, "cd"}, {SessionKey{"a\x00b", "c"}, "d"},
		{SessionKey{"a", "b\x00c"}, "d"},
	} {
		id := registry.daemonSessionID(tuple.key, tuple.id)
		if _, ok := canonicalBuildkitSessionID(id); !ok || seen[id] {
			t.Fatal("invalid or colliding session namespace")
		}
		seen[id] = true
	}
}

func TestControlSessionFramePreservesOperationBytes(t *testing.T) {
	ref := protowire.AppendString([]byte{0x0a}, "r")
	// Both identity fields have duplicate values. Definition's valid overlong
	// varint must survive unchanged, so re-marshaling the protobuf is unsafe.
	definition := []byte{0x12, 0x83, 0x00, 0x0a, 0x01, 'x'}
	payload := append(append([]byte{}, ref...), protowire.AppendString([]byte{0x2a}, "first")...)
	payload = append(payload, definition...)
	payload = append(payload, protowire.AppendString([]byte{0x2a}, "last")...)
	payload = append(payload, ref...)
	frame, err := controlRefFrame(payload, "scoped-ref", "scoped-session", 1024)
	if err != nil {
		t.Fatal(err)
	}
	want := protowire.AppendString([]byte{0x0a}, "scoped-ref")
	want = append(want, protowire.AppendString([]byte{0x2a}, "scoped-session")...)
	want = append(want, definition...)
	if !bytes.Equal(frame, grpcFrame(want)) {
		t.Fatal("identity rewrite retained a duplicate or changed definition bytes")
	}
	for _, invalid := range [][]byte{ref, append(append([]byte{}, ref...), 0x28, 0x01)} {
		if _, err := controlRefFrame(invalid, "ref", "session", 1024); !errors.Is(err, errUnaryFrameProtocolError) {
			t.Fatalf("missing or malformed session: %v", err)
		}
	}
}

func TestSessionNamespaceExpansionIsBoundedBeforeAdmission(t *testing.T) {
	daemon := &refHistoryDaemon{history: make(map[string]string)}
	b := newUnitTestBridge(t, daemon)
	t.Cleanup(func() { b.closeAll(nil) })
	// The ref-only rewrite fits. Adding the scoped session must also be capped.
	b.limits.MaxMessageBytes = 100
	rec := httptest.NewRecorder()
	b.handleStream(rec, newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "r", Session: "s"}))
	if rec.Header().Get("Grpc-Status") != "8" || len(daemon.history) != 0 || b.registry.OwnsRef(b.session.Key, "r") || b.registry.HasAdmittedSolve(b.session.Key, "s") {
		t.Fatal("oversized session rewrite reached the daemon or published admission")
	}
}
