package buildkitproxy

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadGRPCFrame(t *testing.T) {
	cases := []struct {
		name        string
		input       []byte
		maxLen      int64
		wantErr     error
		wantEOF     bool
		wantPayload []byte
	}{
		{
			name:    "empty reader is a clean EOF, not a protocol error",
			input:   nil,
			wantEOF: true,
		},
		{
			name:        "valid empty payload",
			input:       grpcFrame(nil),
			wantPayload: []byte{},
		},
		{
			name:        "valid non-empty payload",
			input:       grpcFrame([]byte("hello")),
			wantPayload: []byte("hello"),
		},
		{
			name:    "compressed flag set is rejected",
			input:   []byte{1, 0, 0, 0, 0},
			wantErr: errStreamFrameProtocolError,
		},
		{
			name:    "truncated header (some but not all bytes) is a protocol error, not EOF",
			input:   []byte{0, 0, 0},
			wantErr: errStreamFrameProtocolError,
		},
		{
			name:    "truncated payload",
			input:   []byte{0, 0, 0, 0, 5, 'h', 'i'},
			wantErr: errStreamFrameProtocolError,
		},
		{
			name:    "declared length exceeds cap",
			input:   grpcFrame(bytes.Repeat([]byte("x"), 10)),
			maxLen:  5,
			wantErr: errMessageTooLarge,
		},
		{
			name:        "declared length exactly at cap is admitted",
			input:       grpcFrame(bytes.Repeat([]byte("x"), 5)),
			maxLen:      5,
			wantPayload: bytes.Repeat([]byte("x"), 5),
		},
		{
			name:        "maxLen <= 0 disables the cap",
			input:       grpcFrame(bytes.Repeat([]byte("x"), 10000)),
			wantPayload: bytes.Repeat([]byte("x"), 10000),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame, payload, err := readGRPCFrame(bytes.NewReader(tc.input), tc.maxLen)
			if tc.wantEOF {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("err = %v, want io.EOF", err)
				}
				if frame != nil || payload != nil {
					t.Fatalf("on EOF, frame/payload must be nil; got frame=%v payload=%v", frame, payload)
				}
				return
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if frame != nil || payload != nil {
					t.Fatalf("on error, frame/payload must be nil; got frame=%v payload=%v", frame, payload)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !bytes.Equal(payload, tc.wantPayload) {
				t.Fatalf("payload = %q, want %q", payload, tc.wantPayload)
			}
			wantFrame := grpcFrame(tc.wantPayload)
			if !bytes.Equal(frame, wantFrame) {
				t.Fatalf("frame = %v, want the original verbatim frame %v", frame, wantFrame)
			}
		})
	}
}

// TestReadGRPCFrameEmptyReaderIsNotAlsoAProtocolError pins the n == 0 half
// of readGRPCFrame's EOF-vs-protocol-error branch directly: a clean EOF at a
// frame boundary must return the bare io.EOF sentinel, never a
// errStreamFrameProtocolError wrapping it. errors.Is(err, io.EOF) alone
// can't tell these apart — Go's multi-%w wrapping means a wrapped error
// satisfies errors.Is for EVERY error it wraps, including io.EOF, so a
// protocol-error-wrapping-EOF still passes an io.EOF check
// (TestReadGRPCFrame's "empty reader" case above uses exactly that check).
// Only asserting the ABSENCE of errStreamFrameProtocolError distinguishes
// the two.
func TestReadGRPCFrameEmptyReaderIsNotAlsoAProtocolError(t *testing.T) {
	_, _, err := readGRPCFrame(bytes.NewReader(nil), 0)
	if errors.Is(err, errStreamFrameProtocolError) {
		t.Fatalf("err = %v, a clean EOF must not also satisfy errors.Is(err, errStreamFrameProtocolError)", err)
	}
}

func TestReadGRPCFramePayloadSharesFrameAllocation(t *testing.T) {
	frame, payload, err := readGRPCFrame(bytes.NewReader(grpcFrame([]byte("payload"))), 0)
	if err != nil {
		t.Fatalf("readGRPCFrame: %v", err)
	}
	if &frame[grpcMessageHeaderLen] != &payload[0] {
		t.Fatal("payload does not share the frame backing allocation")
	}
}

// TestReadGRPCFrameMultipleFramesInSequence confirms readGRPCFrame reads one
// frame at a time off a stream carrying several — the streaming shape every
// caller in this package actually needs, unlike readUnaryGRPCMessage's
// single-message contract.
func TestReadGRPCFrameMultipleFramesInSequence(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(grpcFrame([]byte("one")))
	buf.Write(grpcFrame([]byte("two")))

	_, p1, err := readGRPCFrame(&buf, 0)
	if err != nil {
		t.Fatalf("first readGRPCFrame: %v", err)
	}
	if string(p1) != "one" {
		t.Fatalf("first payload = %q, want %q", p1, "one")
	}

	_, p2, err := readGRPCFrame(&buf, 0)
	if err != nil {
		t.Fatalf("second readGRPCFrame: %v", err)
	}
	if string(p2) != "two" {
		t.Fatalf("second payload = %q, want %q", p2, "two")
	}

	_, _, err = readGRPCFrame(&buf, 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("third readGRPCFrame err = %v, want io.EOF", err)
	}
}
