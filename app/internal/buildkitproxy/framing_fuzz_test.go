package buildkitproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// FuzzReadUnaryGRPCMessage fuzzes readUnaryGRPCMessage's byte-level framing
// decode — the function forwardControlMediated calls to pull exactly one
// gRPC length-prefixed message off a Control/Solve or Control/Status
// request stream before anything downstream trusts its shape. Per this
// package's #185 Phase 6 hardening scope, the invariants under fuzzing are:
//
//  1. Never panics, for any byte stream and any maxLen.
//  2. The error return is always exactly one of: nil, errMessageTooLarge, or
//     an error wrapping errUnaryFrameProtocolError — never some other,
//     unclassified error (see framing.go's own doc comment on the two
//     failure sentinels).
//  3. On a nil error, frame is byte-identical to the ENTIRE input (a
//     successful unary read always consumes exactly frame's length and
//     confirms no trailing bytes remain — see readUnaryGRPCMessage's own
//     "confirming end of stream" check), and the frame's own declared
//     length prefix matches len(payload) exactly.
//  4. On any non-nil error, both frame and payload are nil — a caller must
//     never partially trust a failed decode's return values.
//
// maxLen itself is deliberately clamped to a small, fixed bound (see
// capBound below) rather than fuzzed unbounded: readUnaryGRPCMessage's own
// contract is that a maxLen <= 0 DISABLES the cap entirely (already covered
// by TestReadUnaryGRPCMessage's "maxLen <= 0 disables the cap" case), and an
// attacker-shaped header can declare a length up to MaxUint32 (~4 GiB) — if
// the fuzzer were allowed to pair that with an uncapped maxLen, every such
// input would attempt a multi-gigabyte make([]byte, ...) allocation inside
// the fuzz worker itself, which is a resource-exhaustion risk to the fuzzing
// process, not a meaningful test of the function's own cap enforcement (that
// enforcement is the maxLen>0 path this clamp keeps exercised). Clamping
// maxLen structurally guarantees every allocation this fuzz target can ever
// trigger stays bounded by capBound, regardless of what the header declares.
func FuzzReadUnaryGRPCMessage(f *testing.F) {
	// Seeds mirror TestReadUnaryGRPCMessage's table (framing_test.go) plus a
	// few shapes that table doesn't cover: a multi-message stream (two valid
	// frames back to back — must be rejected as trailing bytes after the
	// first) and a header declaring a length far beyond any sane cap.
	f.Add(grpcFrame(nil), int64(0))
	f.Add(grpcFrame([]byte("hello")), int64(0))
	f.Add([]byte{1, 0, 0, 0, 0}, int64(0))                                     // compressed flag set
	f.Add([]byte{0, 0, 0}, int64(0))                                           // truncated header
	f.Add([]byte{0, 0, 0, 0, 5, 'h', 'i'}, int64(0))                           // truncated payload
	f.Add(append(grpcFrame([]byte("hello")), 'X'), int64(0))                   // trailing byte
	f.Add(grpcFrame(bytes.Repeat([]byte("x"), 10)), int64(5))                  // exceeds cap
	f.Add(grpcFrame(bytes.Repeat([]byte("x"), 5)), int64(5))                   // exactly at cap
	f.Add(grpcFrame(bytes.Repeat([]byte("x"), 10000)), int64(0))               // large payload, cap disabled
	f.Add(append(grpcFrame([]byte("a")), grpcFrame([]byte("b"))...), int64(0)) // multi-message stream
	f.Add([]byte{0, 0xFF, 0xFF, 0xFF, 0xFF}, int64(100))                       // huge declared length, rejected before any read/alloc
	f.Add([]byte{}, int64(0))                                                  // empty input
	f.Add([]byte{0}, int64(0))                                                 // single byte, not even a full header
	f.Add(grpcFrame([]byte("x")), int64(-1))                                   // negative maxLen also disables the cap

	f.Fuzz(func(t *testing.T, data []byte, rawMaxLen int64) {
		const capBound = 64 << 10 // 64 KiB — see doc comment above.
		mod := rawMaxLen % capBound
		if mod < 0 {
			mod = -mod
		}
		maxLen := mod + 1 // always in [1, capBound]

		frame, payload, err := readUnaryGRPCMessage(bytes.NewReader(data), maxLen)

		switch {
		case err == nil:
			if frame == nil || payload == nil {
				t.Fatalf("nil error but frame=%v payload=%v, want both non-nil", frame, payload)
			}
			wantFrameLen := grpcMessageHeaderLen + len(payload)
			if len(frame) != wantFrameLen {
				t.Fatalf("len(frame) = %d, want header+payload = %d", len(frame), wantFrameLen)
			}
			if len(data) != len(frame) {
				t.Fatalf("readUnaryGRPCMessage succeeded having read %d of %d input bytes — a successful unary decode must consume the input exactly (no trailing bytes tolerated)", len(frame), len(data))
			}
			if !bytes.Equal(frame, data) {
				t.Fatalf("frame is not byte-identical to the input it was read from: frame=%v data=%v", frame, data)
			}
			declared := binary.BigEndian.Uint32(frame[1:grpcMessageHeaderLen])
			if int(declared) != len(payload) {
				t.Fatalf("frame's declared length %d does not match returned payload length %d", declared, len(payload))
			}
			if !bytes.Equal(frame[grpcMessageHeaderLen:], payload) {
				t.Fatalf("frame's payload segment does not match the returned payload")
			}
			if int64(len(payload)) > maxLen {
				t.Fatalf("payload of %d bytes exceeds maxLen %d but was admitted without error", len(payload), maxLen)
			}
		case errors.Is(err, errMessageTooLarge):
			if frame != nil || payload != nil {
				t.Fatalf("errMessageTooLarge but frame=%v payload=%v, want both nil", frame, payload)
			}
		case errors.Is(err, errUnaryFrameProtocolError):
			if frame != nil || payload != nil {
				t.Fatalf("errUnaryFrameProtocolError but frame=%v payload=%v, want both nil", frame, payload)
			}
		default:
			t.Fatalf("error taxonomy violated: got %v, want nil, errMessageTooLarge, or an error wrapping errUnaryFrameProtocolError", err)
		}
	})
}
