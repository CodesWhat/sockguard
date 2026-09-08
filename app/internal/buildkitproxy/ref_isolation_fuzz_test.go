package buildkitproxy

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
)

func FuzzControlRefFrame(f *testing.F) {
	for _, payload := range [][]byte{
		{0x0a, 0x01, 'r', 0x2a, 0x01, 's'},
		{0x0a, 0x01, 'r', 0x2a, 0x81, 0x00, 's', 0x0a, 0x01, 'x'},
		{0x0a, 0x80},
	} {
		f.Add(payload)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			return
		}
		var original control.SolveRequest
		if proto.Unmarshal(payload, &original) != nil || original.Ref == "" || hasUnknownFields(&original) {
			return
		}
		ref := daemonBuildRef(SessionKey{"client", "profile"}, original.Ref)
		frame, err := controlRefFrame(payload, ref, 1<<20)
		if errors.Is(err, errMessageTooLarge) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		_, rewritten, err := readUnaryGRPCMessage(bytes.NewReader(frame), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		var got control.SolveRequest
		if err := proto.Unmarshal(rewritten, &got); err != nil {
			t.Fatal(err)
		}
		if got.Ref != ref {
			t.Fatal("translated ref was not canonical")
		}
		original.Ref = ref
		if !proto.Equal(&original, &got) {
			t.Fatal("ref translation changed another field")
		}
	})
}
