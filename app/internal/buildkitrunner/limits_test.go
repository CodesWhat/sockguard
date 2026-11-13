package buildkitrunner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestFrameMessageSizeBoundary(t *testing.T) {
	t.Parallel()
	atLimit := make([]byte, maxMessageBytes-5)
	if frame := frameMessage(atLimit); frame == nil || len(frame) != maxMessageBytes {
		t.Fatalf("frameMessage(limit) = %d bytes, want %d", len(frame), maxMessageBytes)
	}
	if frame := frameMessage(make([]byte, maxMessageBytes-4)); frame != nil {
		t.Fatalf("frameMessage(limit+1) = %d bytes, want nil", len(frame))
	}
}

func TestReadMessageSizeBoundary(t *testing.T) {
	t.Parallel()
	header := func(size uint32) *bytes.Reader {
		var h [5]byte
		binary.BigEndian.PutUint32(h[1:], size)
		return bytes.NewReader(h[:])
	}
	// A header declaring exactly the limit passes the size check and only
	// then fails reading the missing payload.
	_, err := readMessage(header(maxMessageBytes - 5))
	if err == nil || strings.Contains(err.Error(), "oversized") {
		t.Fatalf("readMessage(limit) error = %v, want a payload read error", err)
	}
	_, err = readMessage(header(maxMessageBytes - 4))
	if err == nil || !strings.Contains(err.Error(), "oversized") {
		t.Fatalf("readMessage(limit+1) error = %v, want the oversized error", err)
	}
}

func TestFrontendArgsOptionLimits(t *testing.T) {
	t.Parallel()
	base := Options{
		Image:          "example.com/frontend@sha256:" + strings.Repeat("a", 64),
		RuntimeContext: "default",
	}

	opts := base
	for i := 0; i < 64; i++ {
		opts.FrontendOptions = append(opts.FrontendOptions, fmt.Sprintf("k%d=v", i))
	}
	if _, err := frontendArgs(opts, "name", "oci"); err != nil {
		t.Fatalf("frontendArgs(64 options) error = %v", err)
	}
	opts.FrontendOptions = append(opts.FrontendOptions, "k64=v")
	if _, err := frontendArgs(opts, "name", "oci"); err == nil {
		t.Fatal("frontendArgs(65 options) succeeded, want error")
	}

	opts = base
	opts.FrontendOptions = []string{"k=" + strings.Repeat("v", 8192-2)}
	if _, err := frontendArgs(opts, "name", "oci"); err != nil {
		t.Fatalf("frontendArgs(8192-byte option) error = %v", err)
	}
	opts.FrontendOptions = []string{"k=" + strings.Repeat("v", 8192-1)}
	if _, err := frontendArgs(opts, "name", "oci"); err == nil {
		t.Fatal("frontendArgs(8193-byte option) succeeded, want error")
	}
}
