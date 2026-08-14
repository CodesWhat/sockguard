// Package buildkitproxy — this file carries Phase 5 (issue #185)'s
// mediation of moby.filesync.v1.FileSync/DiffCopy: the RPC buildx's build
// context (and, separately, its Dockerfile) is synced INTO the daemon
// through. See PROVENANCE.md and this file's own comments for the exact
// upstream behavior this mediation is built against — verified directly
// against moby/buildkit's session/filesync/{filesync,diffcopy}.go and
// tonistiigi/fsutil's send.go/receive.go source (not just the vendored
// .proto/.pb.go descriptors), since the wire-level packet semantics
// (direction, ID assignment, interleaving) aren't visible from the
// descriptors alone.
//
// # Which stream direction carries what
//
// EndpointSession's roles are reversed from EndpointGRPC (see bridge.go's
// bridgeLegs doc comment): buildkitd dials INTO the session as the gRPC
// CLIENT, and the actual FileSync implementation lives on the CLI side,
// which sockguard's clientLeg reaches as a gRPC client in turn. Confirmed
// directly from moby/buildkit's session/filesync/filesync.go: FSSync (the
// CLIENT-side caller of FileSync.DiffCopy, invoked by whichever side wants
// to RECEIVE files into a destination directory) calls
// `pr.recvFn(stream, opt.DestDir, ...)` where recvFn=recvDiffCopy passes the
// gRPC ClientStream directly to fsutil.Receive — i.e. buildkitd, as the gRPC
// client for this call, is fsutil's *receiver*. tonistiigi/fsutil's
// receiver only ever transmits PACKET_REQ (to request a specific file by
// its Stat-enumeration index) and PACKET_FIN/PACKET_ERR (stream lifecycle) —
// never PACKET_STAT or PACKET_DATA. Symmetrically, fsutil's *sender* (the
// CLI-hosted implementation, reached as the gRPC call's "response" stream)
// transmits PACKET_STAT (the file listing, terminated by a Packet with a nil
// Stat) and PACKET_DATA (file content, requested piecemeal via the
// receiver's PACKET_REQ, terminated per-file by an empty-Data Packet for
// that file's ID) plus PACKET_FIN/PACKET_ERR.
//
// So: bridge.go's forwardStreamRelay's REQUEST direction (r.Body ->
// outReq.Body, i.e. what handleStream's caller — buildkitd — sends) carries
// only PACKET_REQ/PACKET_FIN/PACKET_ERR — no file content, no paths beyond
// an already-STAT'd numeric ID. The RESPONSE direction (resp.Body -> w, i.e.
// what sockguard's clientLeg RoundTrip receives from the CLI) carries
// PACKET_STAT (every path in the sync) and PACKET_DATA (every byte of every
// file) — this is where path validation, byte caps, and Dockerfile
// hold-and-inspect all apply. See validateFileSyncRequestPacket for the
// (structural-only) request-direction check and fileSyncRespRelay for the
// response-direction one.
//
// # Stat-index (ID) assignment and interleaving
//
// tonistiigi/fsutil's sender (send.go's sender.walk) assigns each Stat entry
// an ID by a simple 0-based counter incremented once per walked entry, in
// walk order — matching exactly the order Stat packets arrive on the wire,
// which is what fileSyncRespRelay's own per-arrival counter (nextStatIndex)
// replicates. A file's PACKET_DATA chunks reference that same ID. Critically,
// send.go's sender.run pulls queued file-send jobs through FOUR parallel
// worker goroutines (sendpipeline, buffered channel + a fixed pool of 4
// senders) — so DATA packets for MULTIPLE DIFFERENT files are genuinely
// interleaved on the wire in production, not just a hypothetical edge case.
// fileSyncRespRelay's per-ID held-buffer map (heldFiles) is what makes
// holding the Dockerfile's data safe under this interleaving: a DATA packet
// for a different, in-flight file never gets attributed to the Dockerfile's
// buffer or vice versa.
//
// # Dockerfile hold-and-inspect
//
// Per the #185 phase 5 synthesis, a FileSync/DiffCopy stream whose "dir-name"
// gRPC metadata (surfaced as an HTTP/2 header — confirmed via
// moby/buildkit's filesync.go: `opts[keyDirName] = []string{opt.Name}` on the
// client side, `opts[keyDirName]` read via metadata.FromIncomingContext on
// the server side, and buildx's build/opt.go: `setLocalMount("dockerfile",
// dockerfileDir, target)` — "dockerfile" and "context" are the two literal
// names buildx uses) equals "dockerfile" gets its PACKET_DATA content held
// (buffered, subject to the same MaxFileSyncFileBytes/MaxFileSyncTotalBytes
// caps every stream is already subject to) until that specific file's own
// per-file EOF (an empty-Data Packet for its ID), at which point the SAME
// dockerfileinspect logic classic POST /build's build.go applies
// (SyntaxFrontend, ContainsRunInstruction) runs against the reassembled
// bytes; only on a clean result are that file's held frames flushed
// (verbatim, in original arrival order) to the daemon. A denied file
// discards its own held buffer and ends the whole stream with a per-stream
// gRPC status — any OTHER file's data already flushed earlier in the same
// stream (a scenario that only arises if a "dockerfile"-named sync ever
// legitimately carries more than one file, which real buildx builds do not)
// stays sent; there is no way to retract bytes already relayed over HTTP/2,
// and the stream ending in error immediately after is sockguard's fail-closed
// response to that file specifically. Holding is skipped entirely when
// AllowRunInstructions is true, mirroring classic build.go's own
// `allowRunInstructions || ...: return "", nil` early exit — an operator who
// has already opted into unrestricted RUN instructions gets the Dockerfile
// stream treated exactly like a context stream (caps + structural validation
// only), avoiding the hold/buffer cost entirely when it would have no policy
// effect.
package buildkitproxy

import (
	"errors"
	"io"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/fsutiltypes"
	"github.com/codeswhat/sockguard/app/internal/dockerfileinspect"
)

// fsutilDirNameHeader is the gRPC metadata key — surfaced as an HTTP/2
// header by the h2c mediation this package builds on — buildx sets on every
// FileSync/DiffCopy call to name which local directory the sync is for. See
// this file's package doc for the upstream source confirming both the key
// name and buildx's two literal values.
const fsutilDirNameHeader = "dir-name"

// fsutilDirNameDockerfile is the one dir-name value that triggers hold-and-
// inspect. Every other value (buildx's "context", any named additional
// build context, or an absent/empty header) gets caps + structural
// validation only — the #185 synthesis's "context filesync gets caps +
// structural validation but NOT content inspection" applied literally: only
// this exact name is treated specially, nothing else is guessed at.
const fsutilDirNameDockerfile = "dockerfile"

// forwardFileSyncMediated is bridge.go's dispatch target for
// moby.filesync.v1.FileSync/DiffCopy (see streammediation.go's
// isStreamMediatedMethod/forwardStreamMediated). It builds the request- and
// response-direction validators/relays described in this file's package doc
// and hands them to forwardStreamRelay, which owns the actual RoundTrip/
// header-copy/audit plumbing shared by every Phase 5 streaming method.
func (b *bridge) forwardFileSyncMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	isDockerfile := r.Header.Get(fsutilDirNameHeader) == fsutilDirNameDockerfile
	holdForInspection := isDockerfile && !b.policy.Control.Solve.AllowRunInstructions

	resp := newFileSyncRespRelay(holdForInspection, b.limits.MaxFileSyncFiles, b.limits.MaxFileSyncPathLength, b.limits.MaxFileSyncFileBytes, b.limits.MaxFileSyncTotalBytes)

	b.forwardStreamRelay(w, r, service, method, validateFileSyncRequestPacket, func(w http.ResponseWriter, src io.Reader) (*mediationDenial, error) {
		return resp.relay(w, src, b.limits.MaxMessageBytes)
	})
}

// validateFileSyncRequestPacket is the per-message validator for FileSync/
// DiffCopy's REQUEST direction: structural validation only (decode, unknown
// fields, and a packet-type check restricted to the three types fsutil's
// receiver ever actually sends — see this file's package doc). No path or
// byte-cap concern lives on this side; those apply to the response
// direction's PACKET_STAT/PACKET_DATA instead (fileSyncRespRelay).
func validateFileSyncRequestPacket(payload []byte) *mediationDenial {
	pkt := &fsutiltypes.Packet{}
	if err := proto.Unmarshal(payload, pkt); err != nil {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed FileSync packet")
	}
	if hasUnknownFields(pkt) {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	switch pkt.GetType() {
	case fsutiltypes.Packet_PACKET_REQ, fsutiltypes.Packet_PACKET_FIN, fsutiltypes.Packet_PACKET_ERR:
		return nil
	default:
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "unexpected FileSync packet type for this stream direction")
	}
}

// heldFileSyncEntry accumulates one file's PACKET_DATA content (and the
// original frame bytes to replay verbatim once released) while
// fileSyncRespRelay holds it for Dockerfile inspection.
type heldFileSyncEntry struct {
	content []byte
	frames  [][]byte
}

// fileSyncRespRelay is the stateful, per-stream response-direction handler
// for FileSync/DiffCopy: it decodes every Packet, enforces the file-count/
// path-length/byte caps described in limits.go's Phase 5 field doc comments,
// and — when holdForInspection is true — buffers each file's DATA
// independently (keyed by its Stat-assigned ID; see this file's package doc
// on interleaving) until that file's own EOF, running dockerfileinspect
// against the reassembled bytes before releasing them.
type fileSyncRespRelay struct {
	holdForInspection bool
	maxFiles          int
	maxPathLength     int
	maxFileBytes      int64
	maxTotalBytes     int64

	fileCount     int
	totalBytes    int64
	nextStatIndex uint32
	fileBytes     map[uint32]int64
	held          map[uint32]*heldFileSyncEntry
	doneFiles     map[uint32]bool
}

func newFileSyncRespRelay(holdForInspection bool, maxFiles, maxPathLength int, maxFileBytes, maxTotalBytes int64) *fileSyncRespRelay {
	return &fileSyncRespRelay{
		holdForInspection: holdForInspection,
		maxFiles:          maxFiles,
		maxPathLength:     maxPathLength,
		maxFileBytes:      maxFileBytes,
		maxTotalBytes:     maxTotalBytes,
		fileBytes:         make(map[uint32]int64),
		held:              make(map[uint32]*heldFileSyncEntry),
		doneFiles:         make(map[uint32]bool),
	}
}

// relay is fileSyncRespRelay's read loop: decode one gRPC frame at a time
// from src (readGRPCFrame — the same streaming framing every Phase 5 method
// uses), dispatch by Packet type, and write admitted frames to w. Matches
// forwardStreamRelay's relayResponse signature.
func (s *fileSyncRespRelay) relay(w http.ResponseWriter, src io.Reader, maxMessageBytes int64) (*mediationDenial, error) {
	fw := flushWriter{w}
	for {
		frame, payload, err := readGRPCFrame(src, maxMessageBytes)
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		if err != nil {
			if errors.Is(err, errMessageTooLarge) {
				return deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "a message exceeds sockguard's size cap"), nil
			}
			return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed BuildKit gRPC stream framing"), nil
		}

		pkt := &fsutiltypes.Packet{}
		if err := proto.Unmarshal(payload, pkt); err != nil {
			return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed FileSync packet"), nil
		}
		if hasUnknownFields(pkt) {
			return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema"), nil
		}

		switch pkt.GetType() {
		case fsutiltypes.Packet_PACKET_STAT:
			if d := s.handleStat(pkt); d != nil {
				return d, nil
			}
			if _, werr := fw.Write(frame); werr != nil {
				return nil, werr
			}
		case fsutiltypes.Packet_PACKET_DATA:
			d, release := s.handleData(pkt, frame)
			if d != nil {
				return d, nil
			}
			for _, rframe := range release {
				if _, werr := fw.Write(rframe); werr != nil {
					return nil, werr
				}
			}
		case fsutiltypes.Packet_PACKET_FIN, fsutiltypes.Packet_PACKET_ERR:
			if _, werr := fw.Write(frame); werr != nil {
				return nil, werr
			}
		default:
			return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "unexpected FileSync packet type for this stream direction"), nil
		}
	}
}

// handleStat validates one PACKET_STAT entry: a nil Stat is fsutil's
// end-of-listing terminator (send.go's sender.walk sends exactly one,
// unconditionally, after every real entry) and carries no path to check or
// index to assign. A non-nil Stat is counted against maxFiles and has its
// Path/Linkname checked via validateFsutilPath (see pathsafety.go), then is
// assigned the next sequential index — matching fsutil's own 0-based,
// walk-order ID assignment (send.go's sender.walk increments its own
// counter once per entry in exactly this order) — that later PACKET_DATA
// packets will reference via their own ID field.
func (s *fileSyncRespRelay) handleStat(pkt *fsutiltypes.Packet) *mediationDenial {
	stat := pkt.GetStat()
	if stat == nil {
		return nil
	}

	s.fileCount++
	if s.maxFiles > 0 && s.fileCount > s.maxFiles {
		return deny(grpcCodeResourceExhausted, "buildkit_file_limit_exceeded", "FileSync stream exceeds sockguard's configured file-count limit")
	}
	if d := validateFsutilPath(stat.GetPath(), s.maxPathLength); d != nil {
		return d
	}
	if stat.GetLinkname() != "" {
		if d := validateFsutilPath(stat.GetLinkname(), s.maxPathLength); d != nil {
			return d
		}
	}

	s.fileBytes[s.nextStatIndex] = 0
	s.nextStatIndex++
	return nil
}

// handleData validates and, in holdForInspection mode, buffers one
// PACKET_DATA chunk. It returns a non-nil denial to end the stream, or a
// (possibly empty) list of original frames now safe to forward: in
// non-holding mode this is always exactly the frame just validated; in
// holding mode it is empty until the file's own EOF chunk (an empty Data
// payload) arrives, at which point — if dockerfileinspect finds nothing
// disqualifying in the reassembled content — it is every frame held for
// that file's ID, in original arrival order, including this EOF frame.
// Unlike relay's readGRPCFrame/proto.Unmarshal calls, nothing in this
// function can itself fail (no I/O, no decode) — its only failure mode is
// the denials in its own return value — so, unlike relay's other
// dispatch arms, there is no separate error to propagate here.
func (s *fileSyncRespRelay) handleData(pkt *fsutiltypes.Packet, frame []byte) (denial *mediationDenial, release [][]byte) {
	id := pkt.GetID()
	n := int64(len(pkt.GetData()))

	// Every PACKET_DATA must reference an ID a prior PACKET_STAT already
	// introduced — fsutil assigns IDs 0-based in STAT arrival order (see
	// handleStat), so a valid ID is always < nextStatIndex. Rejecting an
	// out-of-range ID here is what makes maxFiles an actual bound on the
	// fileBytes/held map sizes: without it, a malicious sender could stream
	// PACKET_DATA with unbounded distinct IDs (each with empty Data, which
	// never grows totalBytes) and grow those maps without ever tripping the
	// file-count or byte caps — an OOM against sockguard itself.
	if uint64(id) >= uint64(s.nextStatIndex) {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "FileSync data references an unknown file"), nil
	}
	// fsutil sends exactly one empty-Data packet per file as its EOF marker
	// (see below), so any DATA after that EOF is a protocol violation. Without
	// this, in holdForInspection mode a sender could split one file's content
	// across several empty-Data "EOF windows" for the same ID — each window
	// inspected in isolation — so a RUN instruction (or a syntax-frontend
	// directive) straddling two windows would pass inspection while the daemon
	// reassembles the whole file. Rejecting post-EOF DATA closes that bypass
	// and is a correct invariant in non-holding mode too.
	if s.doneFiles[id] {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "FileSync data follows this file's end-of-file packet"), nil
	}

	s.fileBytes[id] += n
	s.totalBytes += n
	if s.maxFileBytes > 0 && s.fileBytes[id] > s.maxFileBytes {
		return deny(grpcCodeResourceExhausted, "buildkit_file_limit_exceeded", "a FileSync file exceeds sockguard's configured single-file byte limit"), nil
	}
	if s.maxTotalBytes > 0 && s.totalBytes > s.maxTotalBytes {
		return deny(grpcCodeResourceExhausted, "buildkit_file_limit_exceeded", "FileSync stream exceeds sockguard's configured total byte limit"), nil
	}

	// An empty Data payload is this file's EOF marker in both modes.
	isEOF := n == 0

	if !s.holdForInspection {
		if isEOF {
			s.doneFiles[id] = true
		}
		return nil, [][]byte{frame}
	}

	entry, ok := s.held[id]
	if !ok {
		entry = &heldFileSyncEntry{}
		s.held[id] = entry
	}
	entry.content = append(entry.content, pkt.GetData()...)
	entry.frames = append(entry.frames, frame)

	if !isEOF {
		// Not this file's EOF chunk yet — keep holding.
		return nil, nil
	}

	s.doneFiles[id] = true
	delete(s.held, id)
	if frontend := dockerfileinspect.SyntaxFrontend(entry.content); frontend != "" {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "BuildKit syntax frontend directives cannot be inspected while RUN instructions are restricted"), nil
	}
	if dockerfileinspect.ContainsRunInstruction(entry.content) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "RUN instructions are not allowed"), nil
	}
	return nil, entry.frames
}
