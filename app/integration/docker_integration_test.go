//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/health"
	"github.com/codeswhat/sockguard/v3/app/internal/ownership"
	"github.com/codeswhat/sockguard/v3/app/internal/proxy"
)

func TestProxyAllowsDockerPing(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	handler := newIntegrationProxyHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.TrimSpace(string(body)) != "OK" {
		t.Fatalf("body = %q, want OK", string(body))
	}
}

func TestProxyAllowsVersionWithDockerAPIPrefix(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	version := fetchDockerVersion(t, socketPath)

	handler := newIntegrationProxyHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/version"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v"+version.APIVersion+"/version", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body dockerVersionResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.APIVersion == "" {
		t.Fatal("expected ApiVersion in Docker version response")
	}
	if body.Version == "" {
		t.Fatal("expected Version in Docker version response")
	}
}

func TestProxyDeniesContainerCreateByPolicyAgainstRealDocker(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	handler := newIntegrationProxyHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "deny", Reason: "create denied by policy"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox:1.37"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "create denied by policy") {
		t.Fatalf("deny body = %q, want policy reason", rec.Body.String())
	}
}

func TestProxyAllowsSafeContainerCreateByRequestBodyPolicyAgainstRealDocker(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	handler := newIntegrationProxyHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	})

	payload := `{"Image":"` + busyboxPinnedRef + `","Cmd":["sh","-c","sleep 1"]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var body dockerContainerCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ID == "" {
		t.Fatal("expected create response Id")
	}
	removeDockerContainer(t, socketPath, body.ID)
}

func TestProxyDeniesDangerousContainerCreateBodiesAgainstRealDocker(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)

	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "privileged container",
			payload: `{"Image":"busybox:1.37","HostConfig":{"Privileged":true}}`,
			want:    "privileged",
		},
		{
			name:    "host network",
			payload: `{"Image":"busybox:1.37","HostConfig":{"NetworkMode":"host"}}`,
			want:    "host network",
		},
	}

	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Fatalf("deny body = %q, want substring %q", rec.Body.String(), tt.want)
			}
		})
	}
}

func TestProxyEnforcesContainerOwnerLabelsAgainstRealDocker(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)

	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/json"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}

	ownerA := newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{}, ownership.Options{
		Owner:              "tenant-a",
		LabelKey:           "com.sockguard.owner",
		AllowUnownedImages: true,
	})
	ownerB := newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{}, ownership.Options{
		Owner:              "tenant-b",
		LabelKey:           "com.sockguard.owner",
		AllowUnownedImages: true,
	})

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"`+busyboxPinnedRef+`","Cmd":["sh","-c","sleep 1"]}`))
	createReq.Header.Set("Content-Type", "application/json")
	ownerA.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body: %s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}

	var createBody dockerContainerCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&createBody); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createBody.ID == "" {
		t.Fatal("expected created container ID")
	}
	t.Cleanup(func() {
		removeDockerContainer(t, socketPath, createBody.ID)
	})

	ownedInspectRec := httptest.NewRecorder()
	ownedInspectReq := httptest.NewRequest(http.MethodGet, "/containers/"+url.PathEscape(createBody.ID)+"/json", nil)
	ownerA.ServeHTTP(ownedInspectRec, ownedInspectReq)
	if ownedInspectRec.Code != http.StatusOK {
		t.Fatalf("owner inspect status = %d, want %d; body: %s", ownedInspectRec.Code, http.StatusOK, ownedInspectRec.Body.String())
	}

	var ownedInspect struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(ownedInspectRec.Body).Decode(&ownedInspect); err != nil {
		t.Fatalf("decode owner inspect: %v", err)
	}
	if ownedInspect.Config.Labels["com.sockguard.owner"] != "tenant-a" {
		t.Fatalf("owner label = %q, want tenant-a", ownedInspect.Config.Labels["com.sockguard.owner"])
	}

	crossInspectRec := httptest.NewRecorder()
	crossInspectReq := httptest.NewRequest(http.MethodGet, "/containers/"+url.PathEscape(createBody.ID)+"/json", nil)
	ownerB.ServeHTTP(crossInspectRec, crossInspectReq)
	if crossInspectRec.Code != http.StatusForbidden {
		t.Fatalf("cross-owner inspect status = %d, want %d; body: %s", crossInspectRec.Code, http.StatusForbidden, crossInspectRec.Body.String())
	}
}

// dockerHijackProxy serves handler with the client's upgrade choice passed
// through, as production does for an upstream probed as Docker.
func dockerHijackProxy(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	return startIntegrationProxyServer(t, proxy.PassClientUpgrade(handler))
}

// readDockerHijackResponse sends rawRequest to the proxy and returns the
// parsed response head and the reader positioned at the stream.
func readDockerHijackResponse(t *testing.T, addr, rawRequest string) (net.Conn, *http.Response, *bufio.Reader) {
	t.Helper()

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy server: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	if _, err := clientConn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write hijack request: %v", err)
	}
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("read hijack response: %v", err)
	}
	return clientConn, resp, clientBuf
}

// assertDockerHijackHead checks the daemon's answer matches the client's
// choice: 101 with Upgrade headers when it asked, a plain 200 raw stream when
// it did not.
func assertDockerHijackHead(t *testing.T, resp *http.Response, upgrade bool) {
	t.Helper()

	if !upgrade {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if resp.Header.Get("Upgrade") != "" {
			t.Fatalf("unexpected Upgrade header %q on a 200 stream", resp.Header.Get("Upgrade"))
		}
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	if upgradeHdr := resp.Header.Get("Upgrade"); upgradeHdr != "tcp" {
		t.Fatalf("upgrade header = %q, want %q", upgradeHdr, "tcp")
	}
	if connection := resp.Header.Get("Connection"); connection != "Upgrade" {
		t.Fatalf("connection header = %q, want %q", connection, "Upgrade")
	}
}

const dockerUpgradeRequestHeaders = "Connection: Upgrade\r\nUpgrade: tcp\r\n"

func TestProxyAllowsDockerAttachEndToEndHijack(t *testing.T) {
	for _, upgrade := range []bool{true, false} {
		name := "without Upgrade"
		if upgrade {
			name = "with Upgrade"
		}
		t.Run(name, func(t *testing.T) {
			socketPath := dockerSocketForIntegration(t)
			containerID := createDockerContainer(t, socketPath, dockerContainerCreateRequest{
				Image:        busyboxPinnedRef,
				Cmd:          []string{"sh", "-c", "sleep 1; printf hello; sleep 1"},
				AttachStdout: true,
				AttachStderr: true,
				Tty:          false,
			})
			startDockerContainer(t, socketPath, containerID)
			waitForDockerContainerRunning(t, socketPath, containerID)

			handler := newIntegrationProxyHandler(t, socketPath, []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/attach"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
			})
			addr, waitForRequest := dockerHijackProxy(t, handler)

			reqPath := "/containers/" + containerID + "/attach?stream=1&stdin=1&stdout=1&stderr=1"
			reqStr := "POST " + reqPath + " HTTP/1.1\r\nHost: localhost\r\n"
			if upgrade {
				reqStr += dockerUpgradeRequestHeaders
			}
			reqStr += "Content-Length: 0\r\n\r\n"
			clientConn, resp, clientBuf := readDockerHijackResponse(t, addr, reqStr)
			assertDockerHijackHead(t, resp, upgrade)

			stream, echoed := readDockerHijackFrame(t, clientBuf)
			if stream != 1 {
				t.Fatalf("frame stream = %d, want %d", stream, 1)
			}
			if string(echoed) != "hello" {
				t.Fatalf("frame payload = %q, want %q", string(echoed), "hello")
			}

			if err := clientConn.Close(); err != nil {
				t.Fatalf("close proxy client connection: %v", err)
			}

			waitForRequest()
		})
	}
}

func TestProxyAllowsDockerExecStartEndToEndHijack(t *testing.T) {
	for _, upgrade := range []bool{true, false} {
		name := "without Upgrade"
		if upgrade {
			name = "with Upgrade"
		}
		t.Run(name, func(t *testing.T) {
			socketPath := dockerSocketForIntegration(t)
			containerID := createDockerContainer(t, socketPath, dockerContainerCreateRequest{
				Image: busyboxPinnedRef,
				Cmd:   []string{"sleep", "60"},
			})
			startDockerContainer(t, socketPath, containerID)
			waitForDockerContainerRunning(t, socketPath, containerID)

			execID := createDockerExec(t, socketPath, containerID, []string{"printf", "hello"})

			handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
			}, filter.Options{PolicyConfig: filter.PolicyConfig{Exec: filter.ExecOptions{
				AllowedCommands: [][]string{{"printf", "hello"}},
				InspectStart:    filter.NewDockerExecInspector(socketPath),
			}}}, ownership.Options{})
			addr, waitForRequest := dockerHijackProxy(t, handler)

			body := `{"Detach":false,"Tty":false}`
			reqStr := "POST /exec/" + url.PathEscape(execID) + "/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
			if upgrade {
				reqStr += dockerUpgradeRequestHeaders
			}
			reqStr += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			clientConn, resp, clientBuf := readDockerHijackResponse(t, addr, reqStr)
			assertDockerHijackHead(t, resp, upgrade)

			stream, payload := readDockerHijackFrame(t, clientBuf)
			if stream != 1 {
				t.Fatalf("frame stream = %d, want %d (stdout)", stream, 1)
			}
			if string(payload) != "hello" {
				t.Fatalf("frame payload = %q, want %q", string(payload), "hello")
			}

			if err := clientConn.Close(); err != nil {
				t.Fatalf("close proxy client connection: %v", err)
			}

			waitForRequest()
		})
	}
}

func createDockerExec(t *testing.T, socketPath, containerID string, cmd []string) string {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	payload, err := json.Marshal(map[string]any{"Cmd": cmd, "User": "nobody", "AttachStdout": true, "AttachStderr": true})
	if err != nil {
		t.Fatalf("marshal exec create: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://docker/containers/"+url.PathEscape(containerID)+"/exec", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new exec create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("exec create request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		t.Fatalf("exec create status = %d, want %d; body: %s", resp.StatusCode, http.StatusCreated, strings.TrimSpace(string(out)))
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode exec create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("exec create response missing Id")
	}
	return created.ID
}

func TestHealthEndpointReportsHealthyAgainstDocker(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)

	handler := health.Handler(socketPath, time.Now().Add(-time.Second), newIntegrationLogger())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body health.HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "healthy" {
		t.Fatalf("status field = %q, want healthy", body.Status)
	}
	if body.Upstream != "connected" {
		t.Fatalf("upstream field = %q, want connected", body.Upstream)
	}
}
