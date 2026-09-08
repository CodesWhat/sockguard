package buildkitproxy

import (
	"bytes"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"google.golang.org/protobuf/proto"
)

func FuzzEvaluateGatewayRequest(f *testing.F) {
	methods := []string{"Ping", "Solve", "ResolveImageConfig", "ResolveSourceMeta", "ReadFile", "ReadDir", "StatFile", "Evaluate", "Return", "Inputs", "Warn", "ExecProcess"}
	for i := range methods {
		f.Add(uint8(i), []byte{}, false)
	}
	f.Add(uint8(1), []byte{0x0a, 0x02, 0x0a, 0x00}, true)
	f.Fuzz(func(t *testing.T, which uint8, payload []byte, broad bool) {
		if len(payload) > 1<<20 {
			return
		}
		p := allowAllPolicy
		p.Control.Solve.AllowRunInstructions = broad
		method := methods[int(which)%len(methods)]
		d := evaluateGatewayRequest(method, payload, p)
		if method == "ExecProcess" && d == nil {
			t.Fatal("interactive execution was admitted")
		}
		if d == nil {
			// An otherwise admitted request must fail closed on an unknown field.
			mutated := append(append([]byte(nil), payload...), unknownFieldBytes()...)
			if evaluateGatewayRequest(method, mutated, p) == nil {
				t.Fatal("unknown field was admitted")
			}
		}
	})
}

func FuzzFilterGatewayPong(f *testing.F) {
	f.Add(grpcFrame(nil))
	f.Add([]byte{0, 0, 0, 0, 1, 0xff})
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > 1<<20 {
			return
		}
		filtered, d := filterGatewayPong(bytes.NewReader(frame), 1<<20, Policy{})
		if d != nil || len(filtered) == 0 {
			return
		}
		_, payload, err := readUnaryGRPCMessage(bytes.NewReader(filtered), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		var pong gateway.PongResponse
		if err := proto.Unmarshal(payload, &pong); err != nil {
			t.Fatal(err)
		}
		if hasUnknownFields(&pong) {
			t.Fatal("unknown response fields survived filtering")
		}
		for _, w := range pong.Workers {
			if len(w.Labels) != 0 || len(w.GCPolicy) != 0 || len(w.CDIDevices) != 0 {
				t.Fatal("private worker metadata survived filtering")
			}
		}
		again, d := filterGatewayPong(bytes.NewReader(filtered), 1<<20, Policy{})
		if d != nil || !bytes.Equal(again, filtered) {
			t.Fatal("response filtering is not stable")
		}
	})
}
