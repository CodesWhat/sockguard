package buildkitproxy

import (
	"bytes"
	"io"
	"testing"
)

func TestFileSyncDockerfileSyntaxFormats(t *testing.T) {

	const frontend = "example.invalid/inert-compiler:review"
	cases := []struct{ name, dockerfile string }{
		{"hash", "# syntax=" + frontend + "\nFROM scratch\n"},
		{"BOM", "\ufeff# syntax=" + frontend + "\nFROM scratch\n"},
		{"shebang", "#!/usr/bin/env builder\n# syntax=" + frontend + "\nFROM scratch\n"},
		{"BOM and shebang", "\ufeff#!/usr/bin/env builder\n# syntax=" + frontend + "\n"},
		{"slash", "// syntax=" + frontend + "\n"},
		{"JSON", `{"syntax":"` + frontend + `"}`},
		{"check", "# check=skip=all\n# syntax=" + frontend + "\nFROM scratch\n"},
	}

	for _, tc := range cases {
		for _, allowRun := range []bool{false, true} {
			name := tc.name + "/restricted"
			if allowRun {
				name = tc.name + "/allow RUN"
			}
			t.Run(name, func(t *testing.T) {
				policy := allowAllPolicy
				policy.Control.Solve.AllowRunInstructions = allowRun
				respBody := framedPackets(t, statPacket("Dockerfile"), statTerminatorPacket(), dataPacket(0, []byte(tc.dockerfile)), dataEOFPacket(0), finPacket())
				tb := newTestBridge(t, EndpointSession, policy, DefaultLimits(), fileSyncDaemonHandler(respBody))
				resp, err := tb.driver.RoundTrip(newFileSyncGRPCRequest(t, fsutilDirNameDockerfile, framedPackets(t, reqPacket(0), finPacket())))
				if err != nil {
					t.Fatalf("RoundTrip: %v", err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				code, _ := grpcStatusOf(t, resp)
				if allowRun {
					if err != nil {
						t.Fatal(err)
					}
					if code != 0 {
						t.Fatalf("Grpc-Status = %d, want OK", code)
					}
					if !bytes.Equal(body, respBody) {
						t.Fatal("allowed stream was not relayed verbatim")
					}
					return
				}
				if code != grpcCodePermissionDenied {
					t.Fatalf("Grpc-Status = %d, want PermissionDenied", code)
				}
				want := framedPackets(t, statPacket("Dockerfile"), statTerminatorPacket())
				if !bytes.Equal(body, want) {
					t.Fatal("denied Dockerfile delivered held content")
				}
			})
		}
	}
}
