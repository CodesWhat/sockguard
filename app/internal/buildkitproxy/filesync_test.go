package buildkitproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/fsutiltypes"
)

func statPacket(path string) *fsutiltypes.Packet {
	return &fsutiltypes.Packet{Type: fsutiltypes.Packet_PACKET_STAT, Stat: &fsutiltypes.Stat{Path: path}}
}

func statPacketWithLinkname(path, linkname string) *fsutiltypes.Packet {
	return &fsutiltypes.Packet{Type: fsutiltypes.Packet_PACKET_STAT, Stat: &fsutiltypes.Stat{Path: path, Linkname: linkname}}
}

func statTerminatorPacket() *fsutiltypes.Packet {
	return &fsutiltypes.Packet{Type: fsutiltypes.Packet_PACKET_STAT}
}

func dataPacket(id uint32, data []byte) *fsutiltypes.Packet {
	return &fsutiltypes.Packet{Type: fsutiltypes.Packet_PACKET_DATA, ID: id, Data: data}
}

func dataEOFPacket(id uint32) *fsutiltypes.Packet {
	return &fsutiltypes.Packet{Type: fsutiltypes.Packet_PACKET_DATA, ID: id}
}

func finPacket() *fsutiltypes.Packet {
	return &fsutiltypes.Packet{Type: fsutiltypes.Packet_PACKET_FIN}
}

func reqPacket(id uint32) *fsutiltypes.Packet {
	return &fsutiltypes.Packet{Type: fsutiltypes.Packet_PACKET_REQ, ID: id}
}

// framedPackets marshals and gRPC-frames each packet in order, concatenating
// the result into one byte stream suitable as a FileSync/DiffCopy request or
// response body.
func framedPackets(t *testing.T, pkts ...*fsutiltypes.Packet) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, pkt := range pkts {
		buf.Write(grpcFrame(mustMarshal(t, pkt)))
	}
	return buf.Bytes()
}

func newFileSyncGRPCRequest(t *testing.T, dirName string, reqBody []byte) *http.Request {
	t.Helper()
	req := newGRPCRequest(t, "/moby.filesync.v1.FileSync/DiffCopy", string(reqBody))
	if dirName != "" {
		req.Header.Set(fsutilDirNameHeader, dirName)
	}
	return req
}

// fileSyncDaemonHandler stands in for the CLI-hosted fsutil sender: it reads
// (and discards) whatever the request direction carries, then writes
// respBody as the response, followed by a Grpc-Status: 0 trailer.
func fileSyncDaemonHandler(respBody []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
}

func TestFileSyncTarStreamStaysHardDenied(t *testing.T) {
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.FileSync/TarStream", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied) — TarStream must stay hard-denied even under an allow-all policy", code, grpcCodePermissionDenied)
	}
	if daemonCalled {
		t.Fatal("TarStream must never reach the daemon")
	}
}

func TestFileSyncContextStreamNoContentInspection(t *testing.T) {
	// A "context"-named sync carrying content that WOULD trip Dockerfile
	// inspection (a RUN instruction) must pass through untouched — only
	// caps/structural validation apply outside "dockerfile" dir-name.
	respBody := framedPackets(t,
		statPacket("Dockerfile"),
		statTerminatorPacket(),
		dataPacket(0, []byte("FROM busybox\nRUN echo hi\n")),
		dataEOFPacket(0),
		finPacket(),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, "context", framedPackets(t, reqPacket(0), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("Grpc-Status = %d, want 0 (OK) — a context-named sync must never be content-inspected", code)
	}
	if !bytes.Equal(body, respBody) {
		t.Fatalf("body = %v, want the original frames verbatim %v", body, respBody)
	}
}

func TestFileSyncDockerfileHoldAndInspectAllowsCleanFile(t *testing.T) {
	respBody := framedPackets(t,
		statPacket("Dockerfile"),
		statTerminatorPacket(),
		dataPacket(0, []byte("FROM busybox\n")),
		dataEOFPacket(0),
		finPacket(),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, fsutilDirNameDockerfile, framedPackets(t, reqPacket(0), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("Grpc-Status = %d, want 0 (OK)", code)
	}
	if !bytes.Equal(body, respBody) {
		t.Fatalf("body = %v, want the held frames released verbatim once admitted %v", body, respBody)
	}
}

func TestFileSyncDockerfileHoldAndInspectDeniesRunInstruction(t *testing.T) {
	respBody := framedPackets(t,
		statPacket("Dockerfile"),
		statTerminatorPacket(),
		dataPacket(0, []byte("FROM busybox\nRUN echo hi\n")),
		dataEOFPacket(0),
		finPacket(),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, fsutilDirNameDockerfile, framedPackets(t, reqPacket(0), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied)", code, grpcCodePermissionDenied)
	}
	if bytes.Contains(body, []byte("RUN echo hi")) {
		t.Fatal("held Dockerfile content leaked to the client despite being denied")
	}
	// PACKET_STAT entries (path-only, no file content) are forwarded
	// immediately, regardless of holdForInspection — only the DATA frames
	// for the "Dockerfile"-named entry are held, and those never reach the
	// client once the RUN instruction denies the stream.
	want := framedPackets(t, statPacket("Dockerfile"), statTerminatorPacket())
	if !bytes.Equal(body, want) {
		t.Fatalf("body = %v, want only the two admitted STAT frames %v — the held DATA frames must never leak", body, want)
	}
}

func TestFileSyncDockerfileHoldAndInspectDeniesSyntaxFrontend(t *testing.T) {
	respBody := framedPackets(t,
		statPacket("Dockerfile"),
		statTerminatorPacket(),
		dataPacket(0, []byte("# syntax=docker/dockerfile:1\nFROM busybox\n")),
		dataEOFPacket(0),
		finPacket(),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, fsutilDirNameDockerfile, framedPackets(t, reqPacket(0), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied) for a syntax frontend directive", code, grpcCodePermissionDenied)
	}
}

func TestFileSyncAllowRunInstructionsSkipsHolding(t *testing.T) {
	policy := allowAllPolicy
	policy.Control.Solve.AllowRunInstructions = true

	respBody := framedPackets(t,
		statPacket("Dockerfile"),
		statTerminatorPacket(),
		dataPacket(0, []byte("FROM busybox\nRUN echo hi\n")),
		dataEOFPacket(0),
		finPacket(),
	)
	tb := newTestBridge(t, EndpointSession, policy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, fsutilDirNameDockerfile, framedPackets(t, reqPacket(0), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("Grpc-Status = %d, want 0 (OK) — AllowRunInstructions must skip holding entirely, behaving like a context stream", code)
	}
	if !bytes.Equal(body, respBody) {
		t.Fatalf("body = %v, want the original frames relayed verbatim (no holding) %v", body, respBody)
	}
}

func TestFileSyncFileCountCapExceeded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFileSyncFiles = 1
	respBody := framedPackets(t,
		statPacket("a.txt"),
		statPacket("b.txt"),
		statTerminatorPacket(),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, limits, fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, "context", framedPackets(t, finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (ResourceExhausted)", code, grpcCodeResourceExhausted)
	}
}

func TestFileSyncPerFileByteCapExceeded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFileSyncFileBytes = 5
	respBody := framedPackets(t,
		statPacket("a.txt"),
		statTerminatorPacket(),
		dataPacket(0, bytes.Repeat([]byte("x"), 100)),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, limits, fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, "context", framedPackets(t, reqPacket(0), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (ResourceExhausted)", code, grpcCodeResourceExhausted)
	}
}

func TestFileSyncTotalByteCapExceeded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFileSyncTotalBytes = 5
	respBody := framedPackets(t,
		statPacket("a.txt"),
		statPacket("b.txt"),
		statTerminatorPacket(),
		dataPacket(0, bytes.Repeat([]byte("x"), 3)),
		dataPacket(1, bytes.Repeat([]byte("y"), 3)),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, limits, fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, "context", framedPackets(t, reqPacket(0), reqPacket(1), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (ResourceExhausted)", code, grpcCodeResourceExhausted)
	}
}

func TestFileSyncResponseUnknownFieldsDenied(t *testing.T) {
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(grpcFrame(unknownFieldBytes())))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, "context", framedPackets(t, finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeFailedPrecondition {
		t.Fatalf("Grpc-Status = %d, want %d (FailedPrecondition)", code, grpcCodeFailedPrecondition)
	}
}

func TestFileSyncRequestUnknownFieldsDenied(t *testing.T) {
	fake := &drainingFakeClientLeg{}
	b := newUnitTestBridge(t, fake)
	b.legs.endpoint = EndpointSession

	req := httptest.NewRequest(http.MethodPost, "/moby.filesync.v1.FileSync/DiffCopy", bytes.NewReader(grpcFrame(unknownFieldBytes())))
	rec := httptest.NewRecorder()

	b.forwardFileSyncMediated(rec, req, "moby.filesync.v1.FileSync", "DiffCopy")

	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeFailedPrecondition {
		t.Fatalf("Grpc-Status = %d, want %d (FailedPrecondition)", code, grpcCodeFailedPrecondition)
	}
}

func TestFileSyncRequestWrongPacketTypeDenied(t *testing.T) {
	// PACKET_STAT/PACKET_DATA must never appear in the REQUEST direction —
	// only PACKET_REQ/PACKET_FIN/PACKET_ERR are legitimate there.
	fake := &drainingFakeClientLeg{}
	b := newUnitTestBridge(t, fake)
	b.legs.endpoint = EndpointSession

	req := httptest.NewRequest(http.MethodPost, "/moby.filesync.v1.FileSync/DiffCopy", bytes.NewReader(framedPackets(t, statPacket("x"))))
	rec := httptest.NewRecorder()

	b.forwardFileSyncMediated(rec, req, "moby.filesync.v1.FileSync", "DiffCopy")

	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeInvalidArgument {
		t.Fatalf("Grpc-Status = %d, want %d (InvalidArgument)", code, grpcCodeInvalidArgument)
	}
}

func TestFileSyncResponseWrongPacketTypeDenied(t *testing.T) {
	// PACKET_REQ must never appear in the RESPONSE direction.
	respBody := framedPackets(t, reqPacket(0))
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, "context", framedPackets(t, finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeInvalidArgument {
		t.Fatalf("Grpc-Status = %d, want %d (InvalidArgument)", code, grpcCodeInvalidArgument)
	}
}

func TestFileSyncPathTraversalDenied(t *testing.T) {
	cases := []struct {
		name string
		stat *fsutiltypes.Packet
	}{
		{"absolute path", statPacket("/etc/passwd")},
		{"traversal", statPacket("../../etc/passwd")},
		{"NUL byte", statPacket("a\x00b")},
		{"traversal via linkname", statPacketWithLinkname("safe/path", "../../escape")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			respBody := framedPackets(t, tc.stat, statTerminatorPacket())
			tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

			resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, "context", framedPackets(t, finPacket())))
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			code, _ := grpcStatusOf(t, resp)
			if code != grpcCodePermissionDenied {
				t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied)", code, grpcCodePermissionDenied)
			}
		})
	}
}

func TestFileSyncInterleavedMultiFileDataHandledPerID(t *testing.T) {
	// Two files' DATA chunks interleaved on the wire (as fsutil's real
	// 4-parallel-worker sender genuinely produces) must be tracked
	// independently by ID, not corrupted by cross-file interleaving. Content
	// arrives in the order: file0-chunk-a, file1-chunk-a, file0-chunk-b,
	// file1-chunk-b, file1-EOF, file0-EOF — but since fileSyncRespRelay holds
	// each file's DATA independently and only releases a file's frames once
	// THAT file's own EOF arrives, the frames actually reach the client in
	// per-file-COMPLETION order (file 1 first, since its EOF arrives first),
	// not the original cross-file wire-interleaving order — a documented,
	// accepted consequence of per-ID (not per-stream) hold-and-release (see
	// filesync.go's package doc and handleData's doc comment). Each file's
	// OWN frames still relay in their own original relative order.
	statFrames := framedPackets(t, statPacket("Dockerfile"), statPacket("other-file"), statTerminatorPacket())
	file1Frames := framedPackets(t, dataPacket(1, []byte("unrelated-a")), dataPacket(1, []byte("unrelated-b")), dataEOFPacket(1))
	file0Frames := framedPackets(t, dataPacket(0, []byte("FROM busy")), dataPacket(0, []byte("box\n")), dataEOFPacket(0))
	finFrame := framedPackets(t, finPacket())

	// What the daemon (the CLI-hosted fsutil sender) actually puts on the
	// wire: STAT entries, then the two files' DATA chunks genuinely
	// interleaved, file 1 finishing (EOF) before file 0.
	respBody := framedPackets(t,
		statPacket("Dockerfile"),
		statPacket("other-file"),
		statTerminatorPacket(),
		dataPacket(0, []byte("FROM busy")),
		dataPacket(1, []byte("unrelated-a")),
		dataPacket(0, []byte("box\n")),
		dataPacket(1, []byte("unrelated-b")),
		dataEOFPacket(1),
		dataEOFPacket(0),
		finPacket(),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, fsutilDirNameDockerfile, framedPackets(t, reqPacket(0), reqPacket(1), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("Grpc-Status = %d, want 0 (OK) — both files are clean and must reassemble correctly from interleaved chunks", code)
	}
	want := concatBytes(statFrames, file1Frames, file0Frames, finFrame)
	if !bytes.Equal(body, want) {
		t.Fatalf("body = %v, want frames released in per-file-completion order %v", body, want)
	}
}

func concatBytes(parts ...[]byte) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(p)
	}
	return buf.Bytes()
}

func TestFileSyncInterleavedMultiFileDataDeniesOnlyOffendingFile(t *testing.T) {
	// File ID 0 is a clean Dockerfile; file ID 1 (also named "dockerfile"
	// dir but a second, unrelated file within it — exercising per-ID
	// isolation) contains a RUN instruction and must be denied even though
	// its DATA chunks are interleaved with the clean file's.
	respBody := framedPackets(t,
		statPacket("Dockerfile"),
		statPacket("other"),
		statTerminatorPacket(),
		dataPacket(1, []byte("RUN ec")),
		dataPacket(0, []byte("FROM busybox\n")),
		dataPacket(1, []byte("ho hi\n")),
		dataEOFPacket(0),
		dataEOFPacket(1),
		finPacket(),
	)
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), fileSyncDaemonHandler(respBody))

	resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, fsutilDirNameDockerfile, framedPackets(t, reqPacket(0), reqPacket(1), finPacket())))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied) — file 1's RUN instruction must deny the stream even though file 0 was clean", code, grpcCodePermissionDenied)
	}
}

// --- validateFileSyncRequestPacket / fileSyncRespRelay.relay direct unit tests ---
//
// These exercise branches (malformed decode on both directions, response
// framing errors, and write-failure propagation) that are impractical to
// reach deterministically through a live h2c round trip — mirroring
// pathsafety_test.go's and streammediation_test.go's own direct-function
// testing convention for this package's pure/near-pure helpers.

func TestValidateFileSyncRequestPacketMalformedDecode(t *testing.T) {
	d := validateFileSyncRequestPacket([]byte{0xff, 0xff, 0xff})
	if d == nil || d.reasonCode != "buildkit_protocol_error" {
		t.Fatalf("validateFileSyncRequestPacket() = %+v, want buildkit_protocol_error", d)
	}
}

func TestValidateFileSyncRequestPacketAdmitsKnownTypes(t *testing.T) {
	for _, typ := range []fsutiltypes.Packet_PacketType{
		fsutiltypes.Packet_PACKET_REQ,
		fsutiltypes.Packet_PACKET_FIN,
		fsutiltypes.Packet_PACKET_ERR,
	} {
		payload := mustMarshal(t, &fsutiltypes.Packet{Type: typ})
		if d := validateFileSyncRequestPacket(payload); d != nil {
			t.Fatalf("validateFileSyncRequestPacket(type=%v) = %+v, want nil (admitted)", typ, d)
		}
	}
}

func TestFileSyncRespRelayMalformedFraming(t *testing.T) {
	s := newFileSyncRespRelay(false, 0, 0, 0, 0)
	src := bytes.NewReader([]byte{0, 0, 0, 0, 5, 'h', 'i'})
	rec := httptest.NewRecorder()

	d, err := s.relay(rec, src, 0)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if d == nil || d.reasonCode != "buildkit_protocol_error" {
		t.Fatalf("relay() denial = %+v, want buildkit_protocol_error", d)
	}
}

func TestFileSyncRespRelayOversizedFrame(t *testing.T) {
	s := newFileSyncRespRelay(false, 0, 0, 0, 0)
	src := bytes.NewReader(grpcFrame(bytes.Repeat([]byte("x"), 100)))
	rec := httptest.NewRecorder()

	d, err := s.relay(rec, src, 10)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if d == nil || d.reasonCode != "buildkit_message_too_large" {
		t.Fatalf("relay() denial = %+v, want buildkit_message_too_large", d)
	}
}

func TestFileSyncRespRelayMalformedDecode(t *testing.T) {
	s := newFileSyncRespRelay(false, 0, 0, 0, 0)
	src := bytes.NewReader(grpcFrame([]byte{0xff, 0xff, 0xff}))
	rec := httptest.NewRecorder()

	d, err := s.relay(rec, src, 0)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if d == nil || d.reasonCode != "buildkit_protocol_error" {
		t.Fatalf("relay() denial = %+v, want buildkit_protocol_error", d)
	}
}

func TestFileSyncRespRelayStatWriteError(t *testing.T) {
	s := newFileSyncRespRelay(false, 0, 0, 0, 0)
	src := bytes.NewReader(framedPackets(t, statPacket("a.txt")))
	w := &failingResponseWriter{httptest.NewRecorder(), io.ErrClosedPipe}

	d, err := s.relay(w, src, 0)
	if d != nil {
		t.Fatalf("denial = %+v, want nil (this is a transport failure)", d)
	}
	if err == nil {
		t.Fatal("err = nil, want the write failure")
	}
}

// writeFailAfter passes the first ok Writes through to the wrapped recorder,
// then fails every Write after that — needed to reach handleData's write-
// error path now that a PACKET_DATA must be preceded by a successful
// PACKET_STAT (which introduces its ID) to get that far.
type writeFailAfter struct {
	*httptest.ResponseRecorder
	ok  int
	err error
}

func (w *writeFailAfter) Write(p []byte) (int, error) {
	if w.ok > 0 {
		w.ok--
		return w.ResponseRecorder.Write(p)
	}
	return 0, w.err
}

func TestFileSyncRespRelayDataWriteError(t *testing.T) {
	s := newFileSyncRespRelay(false, 0, 0, 0, 0)
	// STAT introduces ID 0 (and writes successfully), then the DATA frame's
	// write fails — the branch under test.
	src := bytes.NewReader(framedPackets(t, statPacket("a.txt"), dataPacket(0, []byte("hi"))))
	w := &writeFailAfter{ResponseRecorder: httptest.NewRecorder(), ok: 1, err: io.ErrClosedPipe}

	d, err := s.relay(w, src, 0)
	if d != nil {
		t.Fatalf("denial = %+v, want nil (this is a transport failure)", d)
	}
	if err == nil {
		t.Fatal("err = nil, want the write failure")
	}
}

func TestFileSyncRespRelayDataAfterEOFDenied(t *testing.T) {
	// Regression for the hold-and-inspect EOF-window bypass: a sender must not
	// be able to split one file across multiple empty-Data "EOF windows" for
	// the same ID — each inspected in isolation — to sneak a RUN keyword past
	// inspection (window 1 = "R", window 2 = "UN echo evil"; the daemon
	// reassembles "RUN echo evil"). fsutil sends exactly one EOF per file, so
	// DATA after that file's EOF is a protocol error.
	s := newFileSyncRespRelay(true, 0, 0, 0, 0)
	src := bytes.NewReader(framedPackets(t,
		statPacket("Dockerfile"),
		dataPacket(0, []byte("R")),
		dataEOFPacket(0), // window 1 closes: content "R", inspected clean
		dataPacket(0, []byte("UN echo evil\n")),
	))
	d, err := s.relay(httptest.NewRecorder(), src, 0)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if d == nil || d.reasonCode != "buildkit_protocol_error" {
		t.Fatalf("relay() denial = %+v, want buildkit_protocol_error (DATA after this file's EOF)", d)
	}
}

func TestFileSyncRespRelayDataWithoutStatDenied(t *testing.T) {
	// A PACKET_DATA whose ID was never introduced by a prior PACKET_STAT is
	// rejected as a protocol error. Without this, a malicious sender could
	// stream unbounded distinct IDs — each with empty Data, which never grows
	// totalBytes — and grow the per-ID maps without ever tripping the
	// file-count or byte caps: an OOM against sockguard itself. Regression
	// test for the phase-5 security review's HIGH finding.
	for _, tc := range []struct {
		name string
		pkt  *fsutiltypes.Packet
	}{
		{"nonzero-data", dataPacket(7, []byte("x"))},
		{"empty-data", dataEOFPacket(3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newFileSyncRespRelay(false, 10, 0, 0, 0)
			src := bytes.NewReader(framedPackets(t, tc.pkt))
			d, err := s.relay(httptest.NewRecorder(), src, 0)
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if d == nil || d.reasonCode != "buildkit_protocol_error" {
				t.Fatalf("relay() denial = %+v, want buildkit_protocol_error", d)
			}
		})
	}
}

func TestFileSyncRespRelayFinWriteError(t *testing.T) {
	s := newFileSyncRespRelay(false, 0, 0, 0, 0)
	src := bytes.NewReader(framedPackets(t, finPacket()))
	w := &failingResponseWriter{httptest.NewRecorder(), io.ErrClosedPipe}

	d, err := s.relay(w, src, 0)
	if d != nil {
		t.Fatalf("denial = %+v, want nil (this is a transport failure)", d)
	}
	if err == nil {
		t.Fatal("err = nil, want the write failure")
	}
}
