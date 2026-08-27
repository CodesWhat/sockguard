package buildkitproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// grpcFrame builds a valid gRPC length-prefixed message frame (uncompressed
// flag + big-endian length + payload) for use as readUnaryGRPCMessage test
// input.
func grpcFrame(payload []byte) []byte {
	frame := make([]byte, grpcMessageHeaderLen+len(payload))
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func TestReadUnaryGRPCMessage(t *testing.T) {
	cases := []struct {
		name        string
		input       []byte
		maxLen      int64
		wantErr     error
		wantPayload []byte
	}{
		{
			name:        "valid empty payload",
			input:       grpcFrame(nil),
			maxLen:      0,
			wantPayload: []byte{},
		},
		{
			name:        "valid non-empty payload",
			input:       grpcFrame([]byte("hello")),
			maxLen:      0,
			wantPayload: []byte("hello"),
		},
		{
			name:    "compressed flag set is rejected",
			input:   []byte{1, 0, 0, 0, 0},
			maxLen:  0,
			wantErr: errUnaryFrameProtocolError,
		},
		{
			name:    "truncated header",
			input:   []byte{0, 0, 0},
			maxLen:  0,
			wantErr: errUnaryFrameProtocolError,
		},
		{
			name:    "truncated payload",
			input:   []byte{0, 0, 0, 0, 5, 'h', 'i'},
			maxLen:  0,
			wantErr: errUnaryFrameProtocolError,
		},
		{
			name:    "trailing bytes after the single message",
			input:   append(grpcFrame([]byte("hello")), 'X'),
			maxLen:  0,
			wantErr: errUnaryFrameProtocolError,
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
			maxLen:      0,
			wantPayload: bytes.Repeat([]byte("x"), 10000),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame, payload, err := readUnaryGRPCMessage(bytes.NewReader(tc.input), tc.maxLen)
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

func TestReadUnaryGRPCMessagePayloadSharesFrameAllocation(t *testing.T) {
	frame, payload, err := readUnaryGRPCMessage(bytes.NewReader(grpcFrame([]byte("payload"))), 0)
	if err != nil {
		t.Fatalf("readUnaryGRPCMessage: %v", err)
	}
	if &frame[grpcMessageHeaderLen] != &payload[0] {
		t.Fatal("payload does not share the frame backing allocation")
	}
}

// errReaderAfterN returns nBytes bytes of 'a' then a permanent error on any
// further Read — used to exercise readUnaryGRPCMessage's "confirming end of
// stream" branch when the underlying reader fails (rather than cleanly
// EOFs) on the trailing-byte probe read.
type errReaderAfterN struct {
	remaining int
	err       error
}

func (r *errReaderAfterN) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, r.err
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := range p[:n] {
		p[i] = 'a'
	}
	r.remaining -= n
	if r.remaining == 0 {
		return n, nil
	}
	return n, nil
}

func TestReadUnaryGRPCMessageTrailingProbeReadError(t *testing.T) {
	frame := grpcFrame([]byte("hi"))
	// Feed exactly the valid frame, then a non-EOF error on the trailing-byte
	// probe read.
	multi := io.MultiReader(bytes.NewReader(frame), &errReaderAfterN{remaining: 0, err: errors.New("read boom")})

	_, _, err := readUnaryGRPCMessage(multi, 0)
	if !errors.Is(err, errUnaryFrameProtocolError) {
		t.Fatalf("err = %v, want errUnaryFrameProtocolError", err)
	}
	if !strings.Contains(err.Error(), "confirming end of stream") {
		t.Fatalf("err = %v, want it to mention confirming end of stream", err)
	}
}
