package buildkitrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

// Run executes one pinned frontend. The proxy remains the authority for every
// operation; operation reports never grant execution or change policy.
func Run(ctx context.Context, opts Options) (retErr error) {
	if _, err := frontendArgs(opts, "validation", "[]"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var id [16]byte
	_, _ = rand.Read(id[:])
	build := "sockguard-frontend-" + hex.EncodeToString(id[:])
	session := build + "-session"
	conn, err := dialUpgrade(ctx, opts, "/grpc", nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	client, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	stopConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopConn()

	headers := http.Header{"X-Docker-Expose-Session-Uuid": {session}, "X-Docker-Expose-Session-Grpc-Method": {"/grpc.health.v1.Health/Check", "/moby.filesync.v1.Auth/Credentials"}}
	sessionConn, err := dialUpgrade(ctx, opts, "/session", headers)
	if err != nil {
		return err
	}
	defer sessionConn.Close()
	sessionDone := make(chan struct{})
	go func() {
		defer close(sessionDone)
		(&http2.Server{MaxConcurrentStreams: 8}).ServeConn(sessionConn, &http2.ServeConnOpts{Context: ctx, Handler: http.HandlerFunc(serveSession)})
	}()
	defer func() { _ = sessionConn.Close(); <-sessionDone }()

	root := &control.SolveRequest{Ref: build, Session: session, Cache: &control.CacheOptions{}}
	if opts.ExportName != "" {
		root.Exporters = []*control.Exporter{{Type: "moby", Attrs: map[string]string{"name": opts.ExportName}}}
	}
	rootCtx, stopRoot := context.WithCancel(ctx)
	rootDone := make(chan struct{})
	var rootErr error
	go func() {
		defer close(rootDone)
		_, rootErr = unary(rootCtx, client, "/moby.buildkit.v1.Control/Solve", "", root)
	}()
	defer func() { stopRoot(); <-rootDone }()

	// Root registration and gateway availability race on different HTTP/2 streams.
	var pong gateway.PongResponse
	readyCtx, stopReady := context.WithTimeout(ctx, 15*time.Second)
	err = waitGateway(readyCtx, client, build, rootDone, &rootErr, &pong)
	stopReady()
	if err != nil {
		return err
	}
	workers := make([]map[string]any, 0, len(pong.Workers))
	for _, w := range pong.Workers {
		workers = append(workers, map[string]any{"ID": w.ID, "Platforms": w.Platforms})
	}
	workerJSON, err := json.Marshal(workers)
	if err != nil {
		return err
	}
	process, err := startFrontend(ctx, opts, build, string(workerJSON))
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, process.close()) }()
	served := make(chan struct{})
	relay := &gatewayRelay{client: client, build: build, report: newOperationReporter(opts.Operations)}
	go func() {
		defer close(served)
		(&http2.Server{MaxConcurrentStreams: 16}).ServeConn(process.conn, &http2.ServeConnOpts{Context: ctx, BaseConfig: &http.Server{MaxHeaderBytes: 64 << 10, ReadHeaderTimeout: 10 * time.Second}, Handler: relay})
	}()
	defer func() { _ = process.conn.Close(); <-served }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-process.done:
		if process.err != nil {
			return fmt.Errorf("frontend process failed: %w", process.err)
		}
	case <-rootDone:
		// Return can finish the root before the frontend receives its reply.
		select {
		case <-process.done:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
			return errors.New("frontend did not exit after root Solve completed")
		}
		if rootErr != nil {
			return rootErr
		}
		if process.err != nil {
			return fmt.Errorf("frontend process failed: %w", process.err)
		}
	}
	select {
	case <-rootDone:
		return rootErr
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return errors.New("frontend exited without completing root Solve")
	}
}

func waitGateway(ctx context.Context, client *http2.ClientConn, build string, rootDone <-chan struct{}, rootErr *error, pong *gateway.PongResponse) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		payload, err := unary(ctx, client, "/"+gatewayService+"/Ping", build, &gateway.PingRequest{})
		if err == nil {
			return proto.Unmarshal(payload, pong)
		}
		select {
		case <-rootDone:
			if *rootErr != nil {
				return *rootErr
			}
			return errors.New("root Solve ended before gateway became available")
		case <-ctx.Done():
			return fmt.Errorf("gateway did not become ready: %w", err)
		case <-ticker.C:
		}
	}
}

func serveSession(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/moby.filesync.v1.Auth/") {
		if _, err := readMessage(r.Body); err != nil {
			rpcError(w, "3", "invalid anonymous auth request")
			return
		}
		if r.URL.Path == "/moby.filesync.v1.Auth/Credentials" {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "0")
			_, _ = w.Write(frameMessage(nil))
		} else {
			// Let BuildKit fall back to anonymous registry authentication.
			rpcError(w, "12", "only anonymous registry credentials are available")
		}
		return
	}

	if r.Method != http.MethodPost || r.URL.Path != "/grpc.health.v1.Health/Check" {
		rpcError(w, "7", "callback provider is not available")
		return
	}
	payload, err := readMessage(r.Body)
	if err != nil {
		rpcError(w, "3", "invalid health request")
		return
	}
	if len(payload) != 0 {
		rpcError(w, "5", "only the default session health service is available")
		return
	}
	// HealthCheckResponse.status = SERVING (field 1, enum value 1).
	// Keep this fixed reply on the wire: Sigstore already registers the
	// official health descriptor, so importing our vendored copy conflicts.
	body := []byte{0x08, 0x01}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "0")
	_, _ = w.Write(frameMessage(body))
}
