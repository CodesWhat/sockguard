// Package buildkitproxy — this file carries Phase 3 (issue #185)'s gRPC
// length-prefixed message framing helper: reading exactly one buffered
// message off a unary-request RPC's request stream, for the per-message
// decode bridge.go's forwardControlMediated performs before deciding
// whether to admit Control/Solve or Control/Status. See bridge.go's package
// doc for how this fits alongside Phase 2's byte-verbatim relay.
package buildkitproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// grpcMessageHeaderLen is the 1-byte compression flag + 4-byte big-endian
// length prefix every gRPC length-prefixed message frame carries, per the
// gRPC-over-HTTP/2 wire format (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#length-prefixed-message-framing).
const grpcMessageHeaderLen = 5

// errUnaryFrameProtocolError is returned by readUnaryGRPCMessage for any
// framing violation that is NOT a size-cap trip: a nonzero/compressed flag,
// a truncated frame, or trailing bytes after the one message a unary RPC's
// request stream is allowed to carry. bridge.go's forwardControlMediated
// maps this to the buildkit_protocol_error audit reason and a per-stream
// gRPC status — never a whole-tunnel teardown, per the #185 Phase 3
// constraint that a single stream's decode failure stays stream-local.
var errUnaryFrameProtocolError = errors.New("buildkitproxy: malformed or multi-message gRPC unary request framing")

// readUnaryGRPCMessage reads exactly one gRPC length-prefixed message frame
// from r — the shape every unary-request RPC this package mediates
// (Control/Solve, Control/Status) presents on its request stream — and
// confirms no further bytes follow. It returns the COMPLETE original frame
// (5-byte header + payload, byte-for-byte as read) for forwarding to the
// daemon untouched on allow — per the #185 Phase 3 constraint "on allow
// forward the ORIGINAL bytes, never a re-encoded message" — and the payload
// alone, separately, for proto.Unmarshal to decode for the policy decision.
//
// A nonzero compression flag is rejected outright: sockguard's mediator
// never negotiates message-level gRPC compression, so a compressed frame is
// either a client sockguard's mediation was never designed against, or an
// attempt to hide message content from the very inspection this function
// exists to perform — either way, fail closed rather than decompress
// untrusted input.
//
// maxLen bounds the payload length the frame's own header declares — a
// frame declaring more than maxLen fails closed with errMessageTooLarge
// BEFORE any attempt to read that many bytes, so an attacker-controlled
// length prefix can never itself force a large allocation. maxLen <= 0
// disables the cap.
func readUnaryGRPCMessage(r io.Reader, maxLen int64) (frame, payload []byte, err error) {
	var header [grpcMessageHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: reading message header: %w", errUnaryFrameProtocolError, err)
	}
	if header[0] != 0 {
		return nil, nil, fmt.Errorf("%w: compressed message flag set", errUnaryFrameProtocolError)
	}

	length := int64(binary.BigEndian.Uint32(header[1:5]))
	if maxLen > 0 && length > maxLen {
		return nil, nil, errMessageTooLarge
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, fmt.Errorf("%w: reading message payload: %w", errUnaryFrameProtocolError, err)
	}

	// A unary RPC's request stream carries exactly one message; anything
	// beyond it (a second frame, or stray bytes) is a protocol violation to
	// fail closed on, not a valid continuation sockguard should keep reading.
	var extra [1]byte
	switch n, err := io.ReadFull(r, extra[:]); {
	case n > 0:
		return nil, nil, fmt.Errorf("%w: trailing bytes after the single expected message", errUnaryFrameProtocolError)
	case !errors.Is(err, io.EOF):
		return nil, nil, fmt.Errorf("%w: confirming end of stream: %w", errUnaryFrameProtocolError, err)
	}

	frame = make([]byte, grpcMessageHeaderLen+len(payload))
	copy(frame, header[:])
	copy(frame[grpcMessageHeaderLen:], payload)
	return frame, payload, nil
}
