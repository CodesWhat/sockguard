//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproxy"
)

type llbDaemonDialer struct{ socket string }

func (d llbDaemonDialer) DialRequest(ctx context.Context, req *http.Request) (net.Conn, *http.Request, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", d.socket)
	return conn, req, err
}

type llbBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c llbBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func TestBuildkitExecDigestRealDaemon(t *testing.T) {
	socket := dockerSocketForIntegration(t)
	marshal := func(msg proto.Message) []byte {
		t.Helper()
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	digest := func(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }
	platform := &pb.Platform{OS: "linux", Architecture: runtime.GOARCH}
	source := marshal(&pb.Op{
		Platform: platform,
		Op:       &pb.Op_Source{Source: &pb.SourceOp{Identifier: "docker-image://docker.io/library/" + busyboxPinnedRef}},
	})
	execution := marshal(&pb.Op{
		Platform: platform,
		Inputs:   []*pb.Input{{Digest: digest(source)}},
		Op: &pb.Op_Exec{Exec: &pb.ExecOp{
			Meta: &pb.Meta{Args: []string{"/bin/true"}, Cwd: "/"}, Network: pb.NetMode_NONE,
			Mounts: []*pb.Mount{{Input: 0, Dest: "/", Output: 0}},
		}},
	})
	terminal := marshal(&pb.Op{Inputs: []*pb.Input{{Digest: digest(execution)}}})
	definition := &pb.Definition{Def: [][]byte{source, execution, terminal}}
	for _, approved := range []bool{false, true} {
		t.Run(fmt.Sprintf("approved=%t", approved), func(t *testing.T) {
			policy := buildkitproxy.Policy{Control: buildkitproxy.ControlPolicy{Solve: buildkitproxy.SolvePolicy{Allow: true}}}
			if approved {
				policy.Control.Solve.AllowedExecDigests = map[string]struct{}{digest(execution): {}}
			}
			mediator := buildkitproxy.NewMediator(llbDaemonDialer{socket}, newIntegrationLogger())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mediator.ServeGRPC(w, r, policy, buildkitproxy.SessionKey{ClientIdentity: "integration", Profile: "builder"})
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			upgrade, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/grpc", nil)
			if err != nil {
				t.Fatal(err)
			}
			upgrade.Header.Set("Connection", "Upgrade")
			upgrade.Header.Set("Upgrade", "h2c")
			if err := upgrade.Write(conn); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, upgrade)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusSwitchingProtocols {
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				t.Fatalf("upgrade: %s: %s", response.Status, body)
			}
			transport := &http2.Transport{}
			client, err := transport.NewClientConn(llbBufferedConn{Conn: conn, reader: reader})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			payload := marshal(&control.SolveRequest{
				Ref:     fmt.Sprintf("sockguard-llb-%d", time.Now().UnixNano()),
				Session: "sockguard-integration", Definition: definition,
			})
			frame := make([]byte, 5+len(payload))
			binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
			copy(frame[5:], payload)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/moby.buildkit.v1.Control/Solve", bytes.NewReader(frame))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("Te", "trailers")
			resp, err := client.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			status := resp.Trailer.Get("Grpc-Status")
			if status == "" {
				status = resp.Header.Get("Grpc-Status")
			}
			want := "7"
			if approved {
				want = "0"
			}
			if status != want {
				t.Fatalf("gRPC status=%q, want %q; header=%v trailer=%v", status, want, resp.Header, resp.Trailer)
			}
		})
	}
}
