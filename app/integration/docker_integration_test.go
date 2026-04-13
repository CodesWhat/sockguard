//go:build integration

package integration_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/ownership"
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

	payload := `{"Image":"busybox:1.37","Cmd":["sh","-c","sleep 1"]}`
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
		Owner:    "tenant-a",
		LabelKey: "com.sockguard.owner",
	})
	ownerB := newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{}, ownership.Options{
		Owner:    "tenant-b",
		LabelKey: "com.sockguard.owner",
	})

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox:1.37","Cmd":["sh","-c","sleep 1"]}`))
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

func TestProxyAllowsDockerAttachEndToEndHijack(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	containerID := createDockerContainer(t, socketPath, dockerContainerCreateRequest{
		Image:        "busybox:1.37",
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
	addr, waitForRequest := startIntegrationProxyServer(t, handler)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy server: %v", err)
	}
	defer clientConn.Close()

	reqPath := "/containers/" + containerID + "/attach?stream=1&stdin=1&stdout=1&stderr=1"
	reqStr := "POST " + reqPath + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write attach request: %v", err)
	}

	clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("read attach response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	if upgrade := resp.Header.Get("Upgrade"); upgrade != "tcp" {
		t.Fatalf("upgrade header = %q, want %q", upgrade, "tcp")
	}
	if connection := resp.Header.Get("Connection"); connection != "Upgrade" {
		t.Fatalf("connection header = %q, want %q", connection, "Upgrade")
	}

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
