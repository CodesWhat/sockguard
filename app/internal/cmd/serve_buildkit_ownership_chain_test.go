package cmd

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/h2conn"
	"github.com/codeswhat/sockguard/v3/app/internal/testhelp"
	"github.com/codeswhat/sockguard/v3/app/internal/upstream"
)

// bufferedH2Conn replays bytes a bufio.Reader already pulled off the wire
// before the h2c preface, so the HTTP/1 101 read cannot swallow h2 frames.
type bufferedH2Conn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedH2Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// startBuildkitDaemonStub serves a unix socket that answers the h2c upgrade
// with 101 and then serves an h2c handler counting every RPC that reaches it,
// standing in for buildkitd.
func startBuildkitDaemonStub(t *testing.T, calls *atomic.Int32) string {
	t.Helper()
	socketPath := shortSocketPath(t, "bk-owner-upstream")
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = os.Remove(socketPath) })
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
					return
				}
				if _, err := conn.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")); err != nil {
					return
				}
				_ = h2conn.Serve(context.Background(), conn, h2conn.ServerConfig{Handler: handler})
			}()
		}
	}()
	return socketPath
}

// solveOverGRPC upgrades POST /grpc on addr and sends one BuildKit Solve,
// returning the gRPC status and message the proxy answered with.
func solveOverGRPC(t *testing.T, addr string) (int, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("POST /grpc HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nContent-Length: 0\r\n\r\n")); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upgrade status = %d, want 101; body: %s", resp.StatusCode, body)
	}
	cc, err := h2conn.NewClientConn(&bufferedH2Conn{Conn: conn, r: br}, nil)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	payload, err := proto.Marshal(&control.SolveRequest{
		Ref:      "ref-1",
		Session:  "0123456789abcdefghijklmno",
		Frontend: "dockerfile.v0",
		FrontendAttrs: map[string]string{
			"context": "docker-image://theirs/private:latest",
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	req, err := http.NewRequest(http.MethodPost, "http://buildkit-test/moby.buildkit.v1.Control/Solve", strings.NewReader(string(frame)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	grpcResp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("Solve RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, grpcResp.Body)
	_ = grpcResp.Body.Close()
	status := grpcResp.Header.Get("Grpc-Status")
	message := grpcResp.Header.Get("Grpc-Message")
	if status == "" {
		status = grpcResp.Trailer.Get("Grpc-Status")
		message = grpcResp.Trailer.Get("Grpc-Message")
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		t.Fatalf("Grpc-Status %q is not an integer", status)
	}
	return code, message
}

// TestServeChainBuildkitSolveRefusedUnderOwnership pins that, with owner
// isolation on, a BuildKit Solve over POST /grpc is refused before it can reach
// the daemon, both on the default request_body.buildkit policy and on a client
// profile's. The ImageOwnership copy in withBuildkitMediator is what carries
// the owner into each resolved policy, so dropping it lets the Solve through.
func TestServeChainBuildkitSolveRefusedUnderOwnership(t *testing.T) {
	solveAllowed := config.BuildkitControlRequestBodyConfig{Solve: config.BuildkitSolveRequestBodyConfig{Allow: true}}
	tests := []struct {
		name  string
		tweak func(*config.Config)
	}{
		{"default policy", func(cfg *config.Config) {
			cfg.RequestBody.Buildkit.Control = solveAllowed
		}},
		{"client profile", func(cfg *config.Config) {
			cfg.Clients.Profiles = []config.ClientProfileConfig{{
				Name:        "builder",
				RequestBody: config.RequestBodyConfig{Buildkit: config.BuildkitRequestBodyConfig{Control: solveAllowed}},
			}}
			cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
				{Profile: "builder", CIDRs: []string{"127.0.0.0/8"}},
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var daemonCalls atomic.Int32
			socketPath := startBuildkitDaemonStub(t, &daemonCalls)
			cfg := config.Defaults()
			cfg.Upstream.Socket = socketPath
			cfg.Ownership.Owner = "team-a"
			cfg.Ownership.LabelKey = "owner"
			tt.tweak(&cfg)

			collector := &testhelp.CollectingHandler{}
			resolver := upstream.NewSingleSocket(socketPath)
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			handler := withClientACL(&cfg, resolver, newDiscardLogger())(
				withBuildkitMediator(&cfg, resolver, collector.Logger(), "docker")(next),
			)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			srv := &http.Server{Handler: handler}
			go func() { _ = srv.Serve(ln) }()
			t.Cleanup(func() { _ = srv.Close() })

			code, message := solveOverGRPC(t, ln.Addr().String())
			if code != 7 || !strings.Contains(message, "owner isolation") {
				t.Fatalf("Grpc-Status = %d, message = %q, want 7 (PERMISSION_DENIED) naming owner isolation", code, message)
			}
			var denied bool
			for _, rec := range collector.Records() {
				if rec.Attrs["reason_code"] == "buildkit_build_denied_under_ownership" {
					denied = true
				}
			}
			if !denied {
				t.Fatalf("no audit record carries reason_code buildkit_build_denied_under_ownership: %#v", collector.Records())
			}
			if got := daemonCalls.Load(); got != 0 {
				t.Fatalf("daemon RPCs = %d, want 0: the Solve reached buildkitd", got)
			}
		})
	}
}
