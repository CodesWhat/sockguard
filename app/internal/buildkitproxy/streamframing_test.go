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
