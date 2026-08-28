// Package buildkitproxy — this file carries Phase 5 (issue #185)'s streaming
// sibling to framing.go's readUnaryGRPCMessage: readGRPCFrame reads exactly
// ONE gRPC length-prefixed message frame and returns cleanly at io.EOF on a
// clean frame boundary, instead of readUnaryGRPCMessage's "confirm no
// further bytes follow" behavior — the shape every method this file's
// callers mediate (FileSync/DiffCopy, FileSend/DiffCopy, Upload/Pull) needs,
// since each is a bidirectional STREAM of many messages rather than a single
// buffered request. See filesync.go, filesend.go, and upload.go for the
// per-message decode/validation loops built on top of this.
package buildkitproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// errStreamFrameProtocolError is readGRPCFrame's framing-violation sentinel —
// the streaming-loop analog of errUnaryFrameProtocolError. A nonzero
// compression flag or a truncated frame both fail closed with this; a clean
// EOF at a frame boundary (no bytes at all read for the next header) is NOT
// an error at all — see readGRPCFrame's own doc comment.
var errStreamFrameProtocolError = errors.New("buildkitproxy: malformed gRPC stream message framing")

// readGRPCFrame reads exactly one gRPC length-prefixed message frame from r:
// the COMPLETE original frame (5-byte header + payload, byte-for-byte as
// read, returned so a caller can relay it verbatim on allow — the same "on
// allow forward the ORIGINAL bytes, never a re-encoded message" constraint
// framing.go's readUnaryGRPCMessage documents) and the payload alone,
// separately, for proto.Unmarshal to decode.
//
// Returns io.EOF (with nil frame/payload) when r is exhausted at a clean
// frame boundary — zero bytes read before the header's io.ReadFull fails —
// which callers must treat as "the stream ended normally," not a protocol
// violation: unlike a unary RPC's single buffered request, a streaming
// DiffCopy/Pull call's request or response stream legitimately ends after
// an arbitrary number of frames once its peer stops writing and closes its
// side. A truncated frame (some but not all of the header, or a short read
// on the payload) is a genuine protocol violation and fails closed with
// errStreamFrameProtocolError, same as a nonzero compression flag.
//
// maxLen bounds the payload length the frame's own header declares, exactly
// like readUnaryGRPCMessage's maxLen: a frame declaring more than maxLen
// fails closed with errMessageTooLarge BEFORE any attempt to read that many
// bytes, so an attacker-controlled length prefix can never itself force a
// large allocation. maxLen <= 0 disables the cap.
func readGRPCFrame(r io.Reader, maxLen int64) (frame, payload []byte, err error) {
	var header [grpcMessageHeaderLen]byte
	n, err := io.ReadFull(r, header[:])
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return nil, nil, io.EOF
		}
		return nil, nil, fmt.Errorf("%w: reading message header: %w", errStreamFrameProtocolError, err)
	}
	if header[0] != 0 {
		return nil, nil, fmt.Errorf("%w: compressed message flag set", errStreamFrameProtocolError)
	}

	length := int64(binary.BigEndian.Uint32(header[1:5]))
	if maxLen > 0 && length > maxLen {
		return nil, nil, errMessageTooLarge
	}

	frame = make([]byte, grpcMessageHeaderLen+length)
	copy(frame, header[:])
	payload = frame[grpcMessageHeaderLen:]
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, fmt.Errorf("%w: reading message payload: %w", errStreamFrameProtocolError, err)
	}

	return frame, payload, nil
}
