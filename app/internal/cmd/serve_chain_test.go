package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/proxy"
	"github.com/codeswhat/sockguard/internal/testhelp"
)

func TestFullProxyChainHTTPIntegration(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-http")
	_ = os.Remove(socketPath)

	upstreamPaths := make(chan string, 1)
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPaths <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))

	handler, _, collector := newFullProxyChainHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	addr, waitForRequest := startProxyChainServer(t, handler)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/v1.45/_ping")
	if err != nil {
		t.Fatalf("proxy GET /_ping: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, string(body))
	}
	if string(body) != "upstream-ok" {
		t.Fatalf("body = %q, want %q", string(body), "upstream-ok")
	}

	waitForRequest()

	select {
	case got := <-upstreamPaths:
		if got != "/v1.45/_ping" {
			t.Fatalf("upstream path = %q, want %q", got, "/v1.45/_ping")
		}
	default:
		t.Fatal("expected upstream request")
	}

	// Assert on structured log: expect a "request" access-log record with decision=allow and normalized_path=/_ping.
	requestRecs := collector.FindMessage("request")
	if len(requestRecs) == 0 {
		t.Fatalf("no 'request' access-log record; all records: %#v", collector.Records())
	}
	if got, _ := requestRecs[0].Attrs["decision"].(string); got != "allow" {
		t.Fatalf("access log decision = %q, want %q", got, "allow")
	}
	if got, _ := requestRecs[0].Attrs["normalized_path"].(string); got != "/_ping" {
		t.Fatalf("access log normalized_path = %q, want %q", got, "/_ping")
	}
}

func TestFullProxyChainErrorHandling_SocketDown(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-socket-down")

	handler, _, collector := newBuildServeChainHandler(t, socketPath)

	assertFullProxyChainUpstreamError(t, handler, collector, socketPath, "")
}

func TestFullProxyChainErrorHandling_PermissionDenied(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "dp-chain-perm-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "docker.sock")
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("unexpected-upstream-ok"))
	}))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod upstream dir: %v", err)
	}

	probeConn, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond)
	if err == nil {
		_ = probeConn.Close()
		t.Skip("permission-denied socket setup did not block unix dial on this platform")
	}
	if !errors.Is(err, os.ErrPermission) && !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Skipf("permission-denied socket setup yielded %v, want permission denied", err)
	}

	handler, _, collector := newBuildServeChainHandler(t, socketPath)

	assertFullProxyChainUpstreamError(t, handler, collector, socketPath, "permission denied")
}

func TestFullProxyChainHijackIntegration(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-hijack")
	_ = os.Remove(socketPath)

	const (
		clientMsg   = "ping"
		echoPayload = "hello from upstream"
	)

	type upstreamHijackRequest struct {
		host     string
		path     string
		rawQuery string
	}
	upstreamRequest := make(chan upstreamHijackRequest, 1)
	upstreamDone := make(chan struct{})

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix upstream: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})

	go func() {
		defer close(upstreamDone)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("upstream read request: %v", err)
			return
		}
		upstreamRequest <- upstreamHijackRequest{
			host:     req.Host,
			path:     req.URL.Path,
			rawQuery: req.URL.RawQuery,
		}
		if req.Body != nil {
			_ = req.Body.Close()
		}

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		resp.Header.Set("Content-Type", "application/vnd.docker.raw-stream")

		if err := resp.Write(conn); err != nil {
			t.Errorf("upstream write 101: %v", err)
			return
		}

		buf := make([]byte, len(clientMsg))
		if _, err := io.ReadFull(reader, buf); err != nil {
			t.Errorf("upstream read hijacked payload: %v", err)
			return
		}
		if _, err := conn.Write(buf); err != nil {
			t.Errorf("upstream echo payload: %v", err)
			return
		}
		if _, err := conn.Write([]byte(echoPayload)); err != nil {
			t.Errorf("upstream write payload: %v", err)
		}
	}()

	handler, _, hijackCollector := newFullProxyChainHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/attach"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	addr, waitForRequest := startProxyChainServer(t, handler)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy server: %v", err)
	}

	reqStr := "POST /v1.45/containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		_ = clientConn.Close()
		t.Fatalf("write hijack request: %v", err)
	}

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		_ = clientConn.Close()
		t.Fatalf("read hijack response: %v", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = clientConn.Close()
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	if upgrade := resp.Header.Get("Upgrade"); upgrade != "tcp" {
		_ = clientConn.Close()
		t.Fatalf("upgrade header = %q, want %q", upgrade, "tcp")
	}

	if _, err := clientConn.Write([]byte(clientMsg)); err != nil {
		_ = clientConn.Close()
		t.Fatalf("write hijacked payload: %v", err)
	}
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		if err := tcpConn.CloseWrite(); err != nil {
			_ = clientConn.Close()
			t.Fatalf("close client write side: %v", err)
		}
	}

	result := make([]byte, len(clientMsg)+len(echoPayload))
	if _, err := io.ReadFull(clientBuf, result); err != nil {
		_ = clientConn.Close()
		t.Fatalf("read hijacked response payload: %v", err)
	}
	if got, want := string(result), clientMsg+echoPayload; got != want {
		_ = clientConn.Close()
		t.Fatalf("hijacked payload = %q, want %q", got, want)
	}

	if err := clientConn.Close(); err != nil {
		t.Fatalf("close client connection: %v", err)
	}

	waitForRequest()

	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream hijack server")
	}

	select {
	case got := <-upstreamRequest:
		if got.host != "docker" {
			t.Fatalf("upstream host = %q, want %q", got.host, "docker")
		}
		if got.path != "/containers/abc/attach" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/containers/abc/attach")
		}
		if got.rawQuery != "stream=1" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "stream=1")
		}
	default:
		t.Fatal("expected upstream hijack request")
	}

	// Assert on structured log: expect a "request" access-log record with decision=allow and normalized_path=/containers/abc/attach.
	hijackRecs := hijackCollector.FindMessage("request")
	if len(hijackRecs) == 0 {
		t.Fatalf("no 'request' access-log record; all records: %#v", hijackCollector.Records())
	}
	if got, _ := hijackRecs[0].Attrs["decision"].(string); got != "allow" {
		t.Fatalf("access log decision = %q, want %q", got, "allow")
	}
	if got, _ := hijackRecs[0].Attrs["normalized_path"].(string); got != "/containers/abc/attach" {
		t.Fatalf("access log normalized_path = %q, want %q", got, "/containers/abc/attach")
	}
}

func TestFullProxyChainHijackDenied(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-deny")
	handler, _, collector := newFullProxyChainHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	addr, waitForRequest := startProxyChainServer(t, handler)

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1.45/containers/abc/attach?stream=1", nil)
	if err != nil {
		t.Fatalf("new denied hijack request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send denied hijack request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read denied hijack response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusForbidden, string(body))
	}
	if !strings.Contains(string(body), "request denied by sockguard policy") {
		t.Fatalf("expected denial body, got: %s", string(body))
	}

	waitForRequest()

	// Assert on structured log: expect a "request_denied" record with normalized_path attr.
	denied := collector.FindMessage("request_denied")
	if len(denied) == 0 {
		t.Fatalf("no request_denied log record; all records: %#v", collector.Records())
	}
	if got, _ := denied[0].Attrs["normalized_path"].(string); got != "/containers/abc/attach" {
		t.Fatalf("request_denied normalized_path = %q, want %q", denied[0].Attrs["normalized_path"], "/containers/abc/attach")
	}
}

func TestBuildServeHandlerExercisesClientACLVisibilityFilterAndResponseFilter(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-full")
	_ = os.Remove(socketPath)

	var mu sync.Mutex
	upstreamHits := make(map[string]int)

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits[r.URL.Path]++
		mu.Unlock()

		switch r.URL.Path {
		case "/containers/visible/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"Config":{"Labels":{"com.sockguard.client":"watchtower"}}
			}`)
		case "/v1.45/containers/visible/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"Config":{
					"Env":["SECRET=value"],
					"Labels":{"com.sockguard.client":"watchtower"}
				},
				"HostConfig":{
					"Binds":["/srv/secrets:/run/secrets:ro"],
					"NetworkMode":"bridge"
				},
				"Mounts":[
					{"Source":"/srv/secrets","Destination":"/run/secrets"}
				],
				"NetworkSettings":{
					"IPAddress":"172.18.0.2",
					"Networks":{
						"bridge":{
							"IPAddress":"172.18.0.2",
							"NetworkID":"deadbeef"
						}
					}
				}
			}`)
		default:
			t.Fatalf("unexpected upstream path %q", r.URL.Path)
		}
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Response.VisibleResourceLabels = nil
	cfg.Response.RedactContainerEnv = true
	cfg.Response.RedactMountPaths = true
	cfg.Response.RedactNetworkTopology = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "watchtower",
			Response: config.ClientProfileResponseConfig{
				VisibleResourceLabels: []string{"com.sockguard.client=watchtower"},
			},
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/json"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "profile deny"},
			},
		},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "watchtower", CIDRs: []string{"127.0.0.0/8"}},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	addr, waitForRequest := startProxyChainServer(t, handler)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/v1.45/containers/visible/json")
	if err != nil {
		t.Fatalf("proxy GET /containers/visible/json: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, string(body))
	}

	waitForRequest()

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody: %s", err, string(body))
	}

	configBody, _ := payload["Config"].(map[string]any)
	if env, _ := configBody["Env"].([]any); len(env) != 0 {
		t.Fatalf("Config.Env = %#v, want empty redacted array", configBody["Env"])
	}

	hostConfig, _ := payload["HostConfig"].(map[string]any)
	if got, _ := hostConfig["NetworkMode"].(string); got != "<redacted>" {
		t.Fatalf("HostConfig.NetworkMode = %q, want %q", got, "<redacted>")
	}
	binds, _ := hostConfig["Binds"].([]any)
	if got, _ := binds[0].(string); got != "<redacted>:/run/secrets:ro" {
		t.Fatalf("HostConfig.Binds[0] = %q, want %q", got, "<redacted>:/run/secrets:ro")
	}

	mounts, _ := payload["Mounts"].([]any)
	firstMount, _ := mounts[0].(map[string]any)
	if got, _ := firstMount["Source"].(string); got != "<redacted>" {
		t.Fatalf("Mounts[0].Source = %q, want %q", got, "<redacted>")
	}

	networkSettings, _ := payload["NetworkSettings"].(map[string]any)
	if got, _ := networkSettings["IPAddress"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.IPAddress = %q, want %q", got, "<redacted>")
	}
	networks, _ := networkSettings["Networks"].(map[string]any)
	bridge, _ := networks["bridge"].(map[string]any)
	if got, _ := bridge["NetworkID"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.Networks[bridge].NetworkID = %q, want %q", got, "<redacted>")
	}

	mu.Lock()
	gotVersioned := upstreamHits["/v1.45/containers/visible/json"]
	gotInspect := upstreamHits["/containers/visible/json"]
	mu.Unlock()
	if gotInspect != 1 {
		t.Fatalf("visibility inspect hits = %d, want 1", gotInspect)
	}
	if gotVersioned != 1 {
		t.Fatalf("proxied inspect hits = %d, want 1", gotVersioned)
	}
}

func TestBuildServeHandlerExercisesOwnershipForNodesAndSwarm(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-ownership")
	_ = os.Remove(socketPath)

	var mu sync.Mutex
	upstreamHits := make(map[string]int)
	var gotNodeUpdateBody map[string]any
	var gotSwarmUpdateBody map[string]any

	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits[r.URL.Path]++
		mu.Unlock()

		switch r.URL.Path {
		case "/nodes/node-owned":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Spec":{"Labels":{"com.sockguard.owner":"job-123"}}}`)
		case "/v1.45/nodes/node-owned":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ID":"node-owned","Spec":{"Labels":{"com.sockguard.owner":"job-123"}}}`)
		case "/nodes/node-claim":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Spec":{"Labels":{}}}`)
		case "/v1.45/nodes/node-claim/update":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewDecoder(r.Body).Decode(&gotNodeUpdateBody); err != nil {
				t.Fatalf("decode node update body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/swarm":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Spec":{"Labels":{}}}`)
		case "/v1.45/swarm/update":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewDecoder(r.Body).Decode(&gotSwarmUpdateBody); err != nil {
				t.Fatalf("decode swarm update body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected upstream path %q", r.URL.Path)
		}
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Ownership.Owner = "job-123"
	cfg.Ownership.LabelKey = "com.sockguard.owner"
	cfg.RequestBody.Node.AllowNameChange = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/nodes/*"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/nodes/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	addr, waitForRequest := startProxyChainServer(t, handler)

	client := &http.Client{Timeout: 2 * time.Second}

	resp, err := client.Get("http://" + addr + "/v1.45/nodes/node-owned")
	if err != nil {
		t.Fatalf("proxy GET /nodes/node-owned: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read node inspect body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node inspect status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, string(body))
	}

	waitForRequest()

	nodeReq, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1.45/nodes/node-claim/update?version=42", strings.NewReader(`{"Name":"node-claim"}`))
	if err != nil {
		t.Fatalf("new node update request: %v", err)
	}
	nodeReq.Header.Set("Content-Type", "application/json")
	nodeResp, err := client.Do(nodeReq)
	if err != nil {
		t.Fatalf("proxy POST /nodes/node-claim/update: %v", err)
	}
	defer nodeResp.Body.Close()
	if nodeResp.StatusCode != http.StatusNoContent {
		nodeBody, _ := io.ReadAll(nodeResp.Body)
		t.Fatalf("node update status = %d, want %d; body: %s", nodeResp.StatusCode, http.StatusNoContent, string(nodeBody))
	}

	swarmReq, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1.45/swarm/update?version=42", strings.NewReader(`{"Name":"cluster-1"}`))
	if err != nil {
		t.Fatalf("new swarm update request: %v", err)
	}
	swarmReq.Header.Set("Content-Type", "application/json")
	swarmResp, err := client.Do(swarmReq)
	if err != nil {
		t.Fatalf("proxy POST /swarm/update: %v", err)
	}
	defer swarmResp.Body.Close()
	if swarmResp.StatusCode != http.StatusNoContent {
		swarmBody, _ := io.ReadAll(swarmResp.Body)
		t.Fatalf("swarm update status = %d, want %d; body: %s", swarmResp.StatusCode, http.StatusNoContent, string(swarmBody))
	}

	nodeLabels, _ := gotNodeUpdateBody["Labels"].(map[string]any)
	if got := nodeLabels["com.sockguard.owner"]; got != "job-123" {
		t.Fatalf("node update owner label = %#v, want job-123", got)
	}
	if got := gotNodeUpdateBody["Name"]; got != "node-claim" {
		t.Fatalf("node update Name = %#v, want node-claim", got)
	}

	swarmLabels, _ := gotSwarmUpdateBody["Labels"].(map[string]any)
	if got := swarmLabels["com.sockguard.owner"]; got != "job-123" {
		t.Fatalf("swarm update owner label = %#v, want job-123", got)
	}
	if got := gotSwarmUpdateBody["Name"]; got != "cluster-1" {
		t.Fatalf("swarm update Name = %#v, want cluster-1", got)
	}

	mu.Lock()
	gotNodeInspect := upstreamHits["/nodes/node-owned"]
	gotVersionedNodeInspect := upstreamHits["/v1.45/nodes/node-owned"]
	gotNodeClaimInspect := upstreamHits["/nodes/node-claim"]
	gotNodeClaimUpdate := upstreamHits["/v1.45/nodes/node-claim/update"]
	gotSwarmInspect := upstreamHits["/swarm"]
	gotSwarmUpdate := upstreamHits["/v1.45/swarm/update"]
	mu.Unlock()

	if gotNodeInspect != 1 || gotVersionedNodeInspect != 1 {
		t.Fatalf("node inspect hits = (%d inspect, %d proxied), want 1/1", gotNodeInspect, gotVersionedNodeInspect)
	}
	if gotNodeClaimInspect != 1 || gotNodeClaimUpdate != 1 {
		t.Fatalf("node claim hits = (%d inspect, %d proxied), want 1/1", gotNodeClaimInspect, gotNodeClaimUpdate)
	}
	if gotSwarmInspect != 1 || gotSwarmUpdate != 1 {
		t.Fatalf("swarm hits = (%d inspect, %d proxied), want 1/1", gotSwarmInspect, gotSwarmUpdate)
	}
}

func newBuildServeChainHandler(t *testing.T, socketPath string) (http.Handler, *bytes.Buffer, *testhelp.CollectingHandler) {
	t.Helper()

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = true

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	var logBuf bytes.Buffer
	collector := &testhelp.CollectingHandler{}
	logger := testhelp.NewTeeLogger(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}), collector)

	return buildServeHandler(&cfg, logger, nil, rules, newServeTestDeps()), &logBuf, collector
}

func assertFullProxyChainUpstreamError(
	t *testing.T,
	handler http.Handler,
	collector *testhelp.CollectingHandler,
	upstreamSocket string,
	wantErrSubstring string,
) {
	t.Helper()

	addr, waitForRequest := startProxyChainServer(t, handler)

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/v1.45/_ping", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Request-ID", "client-123")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy GET /_ping: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusBadGateway, string(body))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q, want %q", ct, "application/json")
	}

	requestID := resp.Header.Get("X-Request-Id")
	if requestID == "" {
		t.Fatal("expected generated X-Request-Id response header")
	}
	if requestID == "client-123" {
		t.Fatalf("expected proxy-generated request id, got caller id %q", requestID)
	}

	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody: %s", err, string(body))
	}
	if got := payload["message"]; got != "upstream Docker socket unreachable" {
		t.Fatalf("message = %q, want %q", got, "upstream Docker socket unreachable")
	}
	if strings.Contains(string(body), upstreamSocket) {
		t.Fatalf("response leaked upstream socket path: %s", string(body))
	}

	waitForRequest()

	// Assert on structured log records instead of parsing JSON text output.

	// 1. "upstream request failed" record (from proxy error handler).
	failedRecs := collector.FindMessage("upstream request failed")
	if len(failedRecs) == 0 {
		t.Fatalf("no 'upstream request failed' log record; all records: %#v", collector.Records())
	}

	// 2. "request" access-log record with correlation attrs.
	requestRecs := collector.FindMessage("request")
	if len(requestRecs) == 0 {
		t.Fatalf("no 'request' access-log record; all records: %#v", collector.Records())
	}
	accessRec := requestRecs[0]
	if got, _ := accessRec.Attrs["request_id"].(string); got != requestID {
		t.Fatalf("access log request_id = %q, want %q", accessRec.Attrs["request_id"], requestID)
	}
	if got, _ := accessRec.Attrs["client_request_id"].(string); got != "client-123" {
		t.Fatalf("access log client_request_id = %q, want %q", accessRec.Attrs["client_request_id"], "client-123")
	}
	if got, _ := accessRec.Attrs["normalized_path"].(string); got != "/_ping" {
		t.Fatalf("access log normalized_path = %q, want %q", accessRec.Attrs["normalized_path"], "/_ping")
	}
	if got, _ := accessRec.Attrs["decision"].(string); got != "allow" {
		t.Fatalf("access log decision = %q, want %q", accessRec.Attrs["decision"], "allow")
	}
	if got, _ := accessRec.Attrs["rule"].(int64); got != 0 {
		t.Fatalf("access log rule = %v, want 0", accessRec.Attrs["rule"])
	}
	if got, _ := accessRec.Attrs["status"].(int64); got != 502 {
		t.Fatalf("access log status = %v, want 502", accessRec.Attrs["status"])
	}

	// 3. If wantErrSubstring is non-empty, verify the upstream error record contains it.
	if wantErrSubstring != "" {
		var found bool
		for _, r := range failedRecs {
			if errVal, ok := r.Attrs["error"]; ok {
				if strings.Contains(strings.ToLower(fmt.Sprintf("%v", errVal)), wantErrSubstring) {
					found = true
					break
				}
			}
		}
		if !found {
			t.Fatalf("expected %q in upstream error; 'upstream request failed' records: %#v", wantErrSubstring, failedRecs)
		}
	}
}

func newFullProxyChainHandler(t *testing.T, socketPath string, rules []config.RuleConfig) (http.Handler, *bytes.Buffer, *testhelp.CollectingHandler) {
	t.Helper()

	compiled, err := compileRuleConfigsForTest(rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	var logBuf bytes.Buffer
	collector := &testhelp.CollectingHandler{}
	logger := testhelp.NewTeeLogger(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}), collector)

	var handler http.Handler = proxy.New(socketPath, logger)
	handler = proxy.HijackHandler(socketPath, logger, handler)
	handler = filter.Middleware(compiled, logger)(handler)
	handler = logging.AccessLogMiddleware(logger)(handler)

	return handler, &logBuf, collector
}

func compileRuleConfigsForTest(rules []config.RuleConfig) ([]*filter.CompiledRule, error) {
	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i, rule := range rules {
		spec := filter.Rule{
			Methods: splitConfiguredMethods(rule.Match.Method),
			Pattern: rule.Match.Path,
			Action:  filter.Action(rule.Action),
			Reason:  rule.Reason,
			Index:   i,
		}

		compiledRule, err := filter.CompileRule(spec)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compiledRule)
	}
	return compiled, nil
}

func splitConfiguredMethods(methods string) []string {
	parts := strings.Split(methods, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func startProxyChainServer(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	done := make(chan struct{})
	var once sync.Once

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		once.Do(func() {
			close(done)
		})
	})

	srv := newHTTPServer(wrapped)
	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})

	waitForRequest := func() {
		t.Helper()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for proxy request to finish")
		}
	}

	return ln.Addr().String(), waitForRequest
}

func startUnixHTTPUpstream(t *testing.T, socketPath string, handler http.Handler) {
	t.Helper()

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})
}
