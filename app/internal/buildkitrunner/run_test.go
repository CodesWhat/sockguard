package buildkitrunner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/worker"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

func TestRunnerFixtureProcess(t *testing.T) {
	if os.Getenv("RUNNER_FIXTURE_PROCESS") != "1" {
		return
	}
	if err := runFixtureFrontend(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Exit(0)
}

func runFixtureFrontend() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := (&http2.Transport{}).NewClientConn(&pipeConn{read: os.Stdin, write: os.Stdout})
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	op, err := proto.Marshal(&pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: "docker-image://example/source"}}})
	if err != nil {
		return err
	}
	_, err = unary(ctx, cc, "/"+gatewayService+"/Solve", "", &gateway.SolveRequest{Definition: &pb.Definition{Def: [][]byte{op}}})
	if err != nil {
		return err
	}
	if os.Getenv("RUNNER_FIXTURE_CASE") == "process-error" {
		return errors.New("fixture frontend failed after Solve")
	}
	_, err = unary(ctx, cc, "/"+gatewayService+"/Return", "", &gateway.ReturnRequest{})
	if err != nil {
		return err
	}
	if os.Getenv("RUNNER_FIXTURE_CASE") == "root-first" {
		// A frontend may still be finishing after the root reply arrives.
		time.Sleep(75 * time.Millisecond)
	}
	return nil
}

func TestRunOrchestration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wantErr  string
		launched bool
	}{
		{"success", "", true},
		{"root-first", "", true},
		{"root-error", "root denied", true},
		{"process-error", "frontend process failed", true},
		{"cleanup-error", "verify frontend container cleanup", true},
		{"canceled", "context canceled", true},
		{"canceled-cleanup-error", "verify frontend container cleanup", true},
		{"root-refused", "root denied", false},
		{"root-ended", "root Solve ended before gateway became available", false},
		{"gateway-malformed", "cannot parse invalid wire-format data", false},
		{"image-rejected", "declares volumes", false},
		{"session-refused", "proxy refused /session upgrade", false},
		{"upgrade-refused", "proxy refused /grpc upgrade", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := installRunnerFixture(t, tc.name)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			fixtureCtx, stopFixture := context.WithCancel(t.Context())
			defer stopFixture()
			var mu sync.Mutex
			var root *control.SolveRequest
			var sessionID string
			var callbacks, forwarded int
			registered, returned := make(chan struct{}), make(chan struct{})
			sessionReady := make(chan struct{})
			var connections sync.WaitGroup
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if (r.URL.Path == "/session" && tc.name == "session-refused") || tc.name == "upgrade-refused" {
					http.Error(w, "upgrade denied", http.StatusForbidden)
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				connections.Add(1)
				defer connections.Done()
				defer conn.Close()
				if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"); err != nil {
					t.Error(err)
					return
				}
				if err := rw.Flush(); err != nil {
					t.Error(err)
					return
				}
				upgraded := &bufferedConn{Conn: conn, reader: rw.Reader}
				if r.URL.Path == "/session" {
					mu.Lock()
					sessionID = r.Header.Get("X-Docker-Expose-Session-Uuid")
					mu.Unlock()
					methods := r.Header.Values("X-Docker-Expose-Session-Grpc-Method")
					if strings.Join(methods, ",") != "/grpc.health.v1.Health/Check,/moby.filesync.v1.Auth/Credentials" {
						t.Errorf("unexpected session providers: %v", methods)
					}
					cc, err := (&http2.Transport{}).NewClientConn(upgraded)
					if err != nil {
						t.Error(err)
						return
					}
					defer func() { _ = cc.Close() }()
					for _, path := range methods {
						_, callbackErr := unary(fixtureCtx, cc, path, "", &gateway.PingRequest{})
						if callbackErr == nil {
							mu.Lock()
							callbacks++
							mu.Unlock()
						}
					}
					close(sessionReady)
					<-fixtureCtx.Done()
					return
				}
				(&http2.Server{}).ServeConn(upgraded, &http2.ServeConnOpts{Context: fixtureCtx, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					payload, err := readMessage(r.Body)
					if err != nil {
						t.Error(err)
						rpcError(w, "3", "bad fixture request")
						return
					}
					if r.URL.Path == "/moby.buildkit.v1.Control/Solve" {
						var request control.SolveRequest
						if err := proto.Unmarshal(payload, &request); err != nil {
							t.Error(err)
							return
						}
						mu.Lock()
						root = &request
						mu.Unlock()
						close(registered)
						if tc.name == "root-refused" {
							rpcError(w, "7", "root denied")
							return
						}
						if tc.name == "root-ended" {
							fixtureRPCReply(w, nil)
							return
						}
						select {
						case <-returned:
						case <-r.Context().Done():
							return
						}
						if tc.name == "root-error" {
							rpcError(w, "7", "root denied")
							return
						}
						if tc.name == "success" {
							// The daemon can finish the root after the frontend exits.
							select {
							case <-time.After(75 * time.Millisecond):
							case <-r.Context().Done():
								return
							}
						}
						fixtureRPCReply(w, nil)
						return
					}
					select {
					case <-registered:
					case <-r.Context().Done():
						return
					}
					mu.Lock()
					build := root.Ref
					mu.Unlock()
					if r.Header.Get(buildHeader) != build {
						t.Errorf("gateway lost build identity: %q, want %q", r.Header.Get(buildHeader), build)
					}
					switch r.URL.Path {
					case "/" + gatewayService + "/Ping":
						select {
						case <-sessionReady:
						case <-r.Context().Done():
							return
						}
						if tc.name == "root-refused" || tc.name == "root-ended" {
							rpcError(w, "14", "not registered")
							return
						}
						if tc.name == "gateway-malformed" {
							fixtureRPCReply(w, []byte{0xff})
							return
						}
						pong, err := proto.Marshal(&gateway.PongResponse{Workers: []*worker.WorkerRecord{{ID: "fixture-worker", Platforms: []*pb.Platform{{OS: "linux", Architecture: "amd64"}}}}})
						if err != nil {
							t.Error(err)
							return
						}
						fixtureRPCReply(w, pong)
					case "/" + gatewayService + "/Solve":
						var solve gateway.SolveRequest
						if err := proto.Unmarshal(payload, &solve); err != nil || len(solve.GetDefinition().GetDef()) != 1 {
							t.Errorf("invalid forwarded definition: %v", err)
						}
						mu.Lock()
						forwarded++
						mu.Unlock()
						if strings.HasPrefix(tc.name, "canceled") {
							cancel()
							<-r.Context().Done()
							return
						}
						fixtureRPCReply(w, nil)
					case "/" + gatewayService + "/Return":
						close(returned)
						fixtureRPCReply(w, nil)
					default:
						t.Errorf("unexpected upstream call %s", r.URL.Path)
						rpcError(w, "12", "unexpected call")
					}
				})})
			}))
			defer func() { stopFixture(); server.Close(); connections.Wait() }()
			var operations, stderr bytes.Buffer
			err := Run(ctx, Options{Host: server.URL, Image: "example/frontend@sha256:" + strings.Repeat("a", 64), RuntimeContext: "isolated", ExportName: "example/output:fixture", Operations: &operations, Stderr: &stderr})
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Run error = %v; frontend: %s", err, &stderr)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Run error = %v, want %q; frontend: %s", err, tc.wantErr, &stderr)
			}
			if strings.HasPrefix(tc.name, "canceled") && !errors.Is(err, context.Canceled) {
				t.Errorf("lost cancellation outcome: %v", err)
			}
			if tc.launched {
				var record operationRecord
				if err := json.NewDecoder(&operations).Decode(&record); err != nil || !strings.HasPrefix(record.Digest, "sha256:") {
					t.Fatalf("missing operation evidence: %v, %+v", err, record)
				}
				mu.Lock()
				defer mu.Unlock()
				if root == nil || root.Ref == "" || root.Session != sessionID || root.Cache == nil || root.Frontend != "" {
					t.Errorf("invalid root/session registration: root=%v session=%q", root, sessionID)
				}
				if len(root.Exporters) != 1 || root.Exporters[0].Type != "moby" || root.Exporters[0].Attrs["name"] != "example/output:fixture" {
					t.Errorf("export configuration lost: %v", root.Exporters)
				}
				if forwarded != 1 || callbacks != 2 {
					t.Errorf("forwarded=%d callbacks=%d, want 1 and 2", forwarded, callbacks)
				}
			}
			calls, readErr := os.ReadFile(log)
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				t.Fatal(readErr)
			}
			if got := strings.Contains(string(calls), "\trun\t"); got != tc.launched {
				t.Errorf("launched=%v, want %v: %s", got, tc.launched, calls)
			}
			if tc.launched && (!strings.Contains(string(calls), "\trm\t-f\t") || !strings.Contains(string(calls), "\tcontainer\tls\t")) {
				t.Errorf("missing cleanup evidence: %s", calls)
			}
			if tc.launched && !strings.Contains(string(calls), `BUILDKIT_WORKERS=[{"ID":"fixture-worker","Platforms":[{"Architecture":"amd64","OS":"linux"}]}]`) {
				t.Errorf("worker metadata missing from launch: %s", calls)
			}
		})
	}
}

func fixtureRPCReply(w http.ResponseWriter, payload []byte) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "0")
	_, _ = w.Write(frameMessage(payload))
}

func installRunnerFixture(t *testing.T, scenario string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf '%s\t' "$@" >> "$RUNNER_FIXTURE_CALLS"
printf '\n' >> "$RUNNER_FIXTURE_CALLS"
shift 2
case "$1 $2" in
  'image inspect')
    if [ "$RUNNER_FIXTURE_CASE" = image-rejected ]; then echo 1; else echo 0; fi;;
  'run '*) exec "$RUNNER_FIXTURE_BINARY" -test.run '^TestRunnerFixtureProcess$';;
  'rm '*) :;;
  'container ls')
    case "$RUNNER_FIXTURE_CASE" in cleanup-error|canceled-cleanup-error) exit 1;; esac;;
  *) exit 2;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUNNER_FIXTURE_BINARY", binary)
	t.Setenv("RUNNER_FIXTURE_CALLS", log)
	t.Setenv("RUNNER_FIXTURE_CASE", scenario)
	t.Setenv("RUNNER_FIXTURE_PROCESS", "1")
	return log
}

func TestRunRejectsInvalidOptionsBeforeDial(t *testing.T) {
	if err := Run(t.Context(), Options{Image: "example/frontend:latest"}); err == nil || !strings.Contains(err.Error(), "must be pinned") {
		t.Fatalf("invalid image error = %v", err)
	}
}

func TestWaitGatewayReadiness(t *testing.T) {
	for _, scenario := range []string{"retry", "root-error", "root-ended", "canceled", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			rootDone := make(chan struct{})
			var rootErr error
			if scenario == "root-error" {
				rootErr = errors.New("root registration denied")
				close(rootDone)
			}
			if scenario == "root-ended" {
				close(rootDone)
			}
			var attempts atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				attempt := attempts.Add(1)
				if scenario == "malformed" {
					fixtureRPCReply(w, []byte{0xff})
					return
				}
				if scenario == "retry" && attempt == 2 {
					fixtureRPCReply(w, nil)
					return
				}
				if scenario == "canceled" {
					cancel()
				}
				rpcError(w, "14", "gateway pending")
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			conn, err := dialUpgradeForFixture(server)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			cc, err := (&http2.Transport{}).NewClientConn(conn)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cc.Close() }()
			var pong gateway.PongResponse
			err = waitGateway(ctx, cc, "fixture-build", rootDone, &rootErr, &pong)
			switch scenario {
			case "retry":
				if err != nil || attempts.Load() != 2 {
					t.Fatalf("readiness attempts=%d error=%v", attempts.Load(), err)
				}
			case "root-error":
				if !errors.Is(err, rootErr) {
					t.Fatalf("root error lost: %v", err)
				}
			case "root-ended":
				if err == nil || !strings.Contains(err.Error(), "root Solve ended") {
					t.Fatalf("premature root success: %v", err)
				}
			case "canceled":
				if ctx.Err() == nil || err == nil || !strings.Contains(err.Error(), "gateway did not become ready") {
					t.Fatalf("cancellation error=%v context=%v", err, ctx.Err())
				}
			case "malformed":
				if err == nil {
					t.Fatal("malformed readiness response accepted")
				}
			}
		})
	}
}

func dialUpgradeForFixture(server *httptest.Server) (net.Conn, error) {
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.NextProtos = []string{"h2"}
	return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Listener.Addr().String(), config)
}
