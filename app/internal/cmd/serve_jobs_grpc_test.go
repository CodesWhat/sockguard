package cmd

// The moby Jobs extension (org.mobyproject.extension.jobs.api.v0.Jobs, 13 RPCs
// defined in moby/moby extpoints/jobs/api/v0/jobs.proto) is served as native
// gRPC on the Docker socket. It is not an HTTP route in the Engine API, so
// authz plugins never see it. Sockguard refuses it because the listener has
// no h2c support: a prior-knowledge HTTP/2 client never gets a session, so the
// call cannot reach the daemon. This pins that refusal with a permissive
// allow-all rule set, so the transport is what refuses it, not a deny rule.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func TestServeHandlerRefusesJobsGRPCOverH2C(t *testing.T) {
	socketPath := shortSocketPath(t, "jobs-grpc-upstream")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	var upstreamHits atomic.Int32
	upstream := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upstreamHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = upstream.Serve(ln) }()
	t.Cleanup(func() { _ = upstream.Close() })

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "allow"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	srv := httptest.NewServer(buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps()))
	defer srv.Close()

	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: &protocols}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	// Empty gRPC frame: compressed flag 0, length 0.
	req, err := http.NewRequest(http.MethodPost,
		"http://"+srv.Listener.Addr().String()+"/org.mobyproject.extension.jobs.api.v0.Jobs/List",
		strings.NewReader("\x00\x00\x00\x00\x00"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.ProtoMajor == 2 {
			t.Fatalf("server answered over HTTP/2 (%s); Jobs gRPC must not get an h2c session", resp.Proto)
		}
		if resp.StatusCode < 400 {
			t.Fatalf("status = %d, want a refusal for the Jobs gRPC call", resp.StatusCode)
		}
	}

	if hits := upstreamHits.Load(); hits != 0 {
		t.Fatalf("Jobs gRPC call reached the upstream %d time(s), want 0", hits)
	}
}
