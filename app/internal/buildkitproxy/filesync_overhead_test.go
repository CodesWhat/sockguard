package buildkitproxy

import (
	"bytes"
	"fmt"
	"math"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/fsutiltypes"
	"google.golang.org/protobuf/encoding/protowire"
)

func paddedFileSyncFrame(t *testing.T, id uint32, padding int, duplicate bool) []byte {
	t.Helper()
	pkt := dataPacket(id, []byte("#"))
	if duplicate {
		pkt.Data = bytes.Repeat([]byte("x"), padding)
		raw := mustMarshal(t, pkt)
		raw = protowire.AppendTag(raw, 4, protowire.BytesType)
		return grpcFrame(protowire.AppendBytes(raw, []byte("#")))
	}
	pkt.Stat = &fsutiltypes.Stat{Path: strings.Repeat("x", padding)}
	return grpcFrame(mustMarshal(t, pkt))
}

func TestFileSyncRetainedOverheadLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		padding   int
		duplicate bool
		files     int
	}{
		{"known fields", 100, false, 1}, {"duplicate data", 100, true, 1},
		{"ordinary tiny frames", 0, false, 1}, {"interleaved files", 50, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const maxMessage = 256
			s := newFileSyncRespRelay(true, 10, 1024, 1000, 2000)
			var stream bytes.Buffer
			for id := 0; id < tc.files; id++ {
				stream.Write(framedPackets(t, statPacket(fmt.Sprintf("file%d", id))))
			}
			prefix := bytes.Clone(stream.Bytes())
			remaining := maxMessage + 5 + 64
			accepted := 0
			for i := 0; ; i++ {
				var frame []byte
				if tc.padding == 0 {
					frame = framedPackets(t, dataPacket(uint32(i%tc.files), []byte("#")))
				} else {
					frame = paddedFileSyncFrame(t, uint32(i%tc.files), tc.padding, tc.duplicate)
				}
				stream.Write(frame)
				charge := len(frame) - 1 + 64
				if charge > remaining {
					break
				}
				remaining -= charge
				accepted++
			}
			w := httptest.NewRecorder()
			d, err := s.relay(w, bytes.NewReader(stream.Bytes()), maxMessage)
			if err != nil || d == nil || d.code != grpcCodeResourceExhausted || d.reasonCode != "buildkit_file_limit_exceeded" {
				t.Fatalf("denial=%v err=%v, want FileSync resource limit", d, err)
			}
			count, content := 0, 0
			for _, entry := range s.held {
				count += len(entry.frames)
				content += len(entry.content)
			}
			if s.retainedOverhead != uint64(maxMessage+5+64-remaining) {
				t.Fatalf("rejected frame changed retained overhead: %d", s.retainedOverhead)
			}
			if count != accepted || content != accepted {
				t.Fatalf("retained %d frames/%d content bytes, want %d admitted frames only", count, content, accepted)
			}
			if !bytes.Equal(w.Body.Bytes(), prefix) {
				t.Fatal("held DATA escaped before inspection")
			}
		})
	}
}

func TestFileSyncRetainedOverheadReleasesAndReplays(t *testing.T) {
	for _, hold := range []bool{false, true} {
		t.Run(fmt.Sprintf("hold=%t", hold), func(t *testing.T) {
			var stream bytes.Buffer
			stream.Write(framedPackets(t, statPacket("first"), statPacket("second")))
			for id := uint32(0); id < 2; id++ {
				stream.Write(paddedFileSyncFrame(t, id, 100, true))
				stream.Write(framedPackets(t, dataEOFPacket(id)))
			}
			s := newFileSyncRespRelay(hold, 10, 1024, 1, 2)
			w := httptest.NewRecorder()
			d, err := s.relay(w, bytes.NewReader(stream.Bytes()), 256)
			if err != nil || d != nil {
				t.Fatalf("exact decoded limits and completed-file release denied: %v, %v", d, err)
			}
			if !bytes.Equal(w.Body.Bytes(), stream.Bytes()) {
				t.Fatal("duplicate-field frames did not replay byte-for-byte")
			}
			if len(s.held) != 0 || s.totalBytes != 2 || s.retainedOverhead != 0 {
				t.Fatalf("completed stream state: held=%d decoded=%d", len(s.held), s.totalBytes)
			}
		})
	}
}

func TestFileSyncRetainedOverheadAdmitsMaximalFrame(t *testing.T) {
	frame := paddedFileSyncFrame(t, 0, 200, true)
	maxMessage := int64(len(frame) - 5)
	stream := append(framedPackets(t, statPacket("Dockerfile")), frame...)
	s := newFileSyncRespRelay(true, 10, 1024, 1, 1)
	d, err := s.relay(httptest.NewRecorder(), bytes.NewReader(stream), maxMessage)
	if err != nil || d != nil || len(s.held[0].frames) != 1 {
		t.Fatalf("one permitted maximal frame denied: %v, %v", d, err)
	}
}

func TestFileSyncNonholdingOverheadIsNotCharged(t *testing.T) {
	stream := framedPackets(t, statPacket("context"))
	for range 10 {
		stream = append(stream, paddedFileSyncFrame(t, 0, 100, true)...)
	}
	stream = append(stream, framedPackets(t, dataEOFPacket(0))...)
	s := newFileSyncRespRelay(false, 10, 1024, 10, 10)
	w := httptest.NewRecorder()
	d, err := s.relay(w, bytes.NewReader(stream), 256)
	if err != nil || d != nil || !bytes.Equal(w.Body.Bytes(), stream) {
		t.Fatalf("nonholding wire replay failed: %v, %v", d, err)
	}
}

func TestFileSyncRetainedOverheadMessageAllowance(t *testing.T) {
	for _, maxMessage := range []int64{0, -1, math.MaxInt64} {
		t.Run(fmt.Sprint(maxMessage), func(t *testing.T) {
			stream := framedPackets(t, statPacket("Dockerfile"), dataPacket(0, []byte("#")), dataEOFPacket(0))
			s := newFileSyncRespRelay(true, 10, 1024, 1, 1)
			w := httptest.NewRecorder()
			d, err := s.relay(w, bytes.NewReader(stream), maxMessage)
			if err != nil || d != nil || !bytes.Equal(w.Body.Bytes(), stream) {
				t.Fatalf("message allowance rejected ordinary file: %v, %v", d, err)
			}
		})
	}
}
