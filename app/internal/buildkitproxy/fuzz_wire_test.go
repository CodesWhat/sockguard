package buildkitproxy

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/fsutiltypes"
)

func FuzzValidateFsutilPath(f *testing.F) {
	f.Add("src/main.go", 4096)
	f.Add("../etc/passwd", 4096)
	f.Add("/abs/path", 4096)
	f.Add("a/../b", 0)
	f.Add("bad\x00name", 4096)
	f.Add("", 4096)
	f.Add(strings.Repeat("a/", 100), 16)

	f.Fuzz(func(t *testing.T, path string, maxLen int) {
		denial := validateFsutilPath(path, maxLen)
		if denial != nil {
			return
		}
		// An accepted path must never be empty, absolute, NUL-bearing, or
		// carry a ".." segment.
		if path == "" || strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) {
			t.Fatalf("accepted unsafe path %q", path)
		}
		for _, part := range strings.Split(path, "/") {
			if part == ".." {
				t.Fatalf("accepted traversal path %q", path)
			}
		}
	})
}

func FuzzParseGRPCPath(f *testing.F) {
	f.Add("/moby.buildkit.v1.Control/Solve")
	f.Add("/grpc.health.v1.Health/Check")
	f.Add("/")
	f.Add("//")
	f.Add("/svc/")
	f.Add("/a/b/c")
	f.Add("no-leading-slash/Method")

	f.Fuzz(func(t *testing.T, path string) {
		service, method, ok := ParseGRPCPath(path)
		if !ok {
			if service != "" || method != "" {
				t.Fatalf("not ok but returned %q, %q", service, method)
			}
			return
		}
		if service == "" || method == "" || strings.Contains(service, "/") || strings.Contains(method, "/") {
			t.Fatalf("ok with malformed parts %q, %q for %q", service, method, path)
		}
		if "/"+service+"/"+method != path {
			t.Fatalf("round trip mismatch: %q vs %q", "/"+service+"/"+method, path)
		}
	})
}

func FuzzReadGRPCFrame(f *testing.F) {
	f.Add(grpcFrame(nil), int64(0))
	f.Add(grpcFrame([]byte("hello")), int64(0))
	f.Add(grpcFrame(bytes.Repeat([]byte("x"), 10)), int64(5))
	f.Add([]byte{1, 0, 0, 0, 0}, int64(0))
	f.Add([]byte{0, 0, 0}, int64(0))
	f.Add([]byte{0, 0xFF, 0xFF, 0xFF, 0xFF}, int64(100))
	f.Add([]byte{}, int64(0))

	f.Fuzz(func(t *testing.T, data []byte, rawMaxLen int64) {
		const capBound = 64 << 10
		maxLen := rawMaxLen % capBound
		if maxLen < 0 {
			maxLen = -maxLen
		}
		r := bytes.NewReader(data)
		// Drain every frame the stream yields; each must be well formed.
		for i := 0; i < 64; i++ {
			frame, payload, err := readGRPCFrame(r, maxLen)
			if err != nil {
				return
			}
			if len(frame) != grpcMessageHeaderLen+len(payload) {
				t.Fatalf("frame/payload length mismatch: %d vs %d", len(frame), len(payload))
			}
			if maxLen > 0 && int64(len(payload)) > maxLen {
				t.Fatalf("payload %d exceeds cap %d", len(payload), maxLen)
			}
		}
	})
}

func FuzzValidateFileSyncRequestPacket(f *testing.F) {
	for _, pkt := range []*fsutiltypes.Packet{
		{Type: fsutiltypes.Packet_PACKET_REQ},
		{Type: fsutiltypes.Packet_PACKET_FIN},
		{Type: fsutiltypes.Packet_PACKET_ERR},
		{Type: fsutiltypes.Packet_PACKET_STAT, Stat: &fsutiltypes.Stat{Path: "a"}},
		{Type: fsutiltypes.Packet_PACKET_DATA, Data: []byte("x")},
	} {
		b, err := proto.Marshal(pkt)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = validateFileSyncRequestPacket(payload)
	})
}
