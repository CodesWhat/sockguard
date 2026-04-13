//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/ownership"
	"github.com/codeswhat/sockguard/internal/proxy"
)

const defaultDockerSocket = "/var/run/docker.sock"

type dockerVersionResponse struct {
	APIVersion string `json:"ApiVersion"`
	Version    string `json:"Version"`
}

type dockerContainerCreateRequest struct {
	Image        string                    `json:"Image"`
	Cmd          []string                  `json:"Cmd,omitempty"`
	AttachStdin  bool                      `json:"AttachStdin,omitempty"`
	AttachStdout bool                      `json:"AttachStdout,omitempty"`
	AttachStderr bool                      `json:"AttachStderr,omitempty"`
	OpenStdin    bool                      `json:"OpenStdin,omitempty"`
	StdinOnce    bool                      `json:"StdinOnce,omitempty"`
	Tty          bool                      `json:"Tty,omitempty"`
	HostConfig   dockerContainerHostConfig `json:"HostConfig,omitempty"`
}

type dockerContainerHostConfig struct {
	Privileged  bool   `json:"Privileged,omitempty"`
	NetworkMode string `json:"NetworkMode,omitempty"`
}

type dockerContainerCreateResponse struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

type dockerContainerInspectResponse struct {
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
}

func dockerSocketForIntegration(t *testing.T) string {
	t.Helper()

	socketPath := os.Getenv("SOCKGUARD_TEST_DOCKER_SOCKET")
	if socketPath == "" {
		socketPath = defaultDockerSocket
	}

	if _, err := os.Stat(socketPath); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("docker socket %q not found; set SOCKGUARD_TEST_DOCKER_SOCKET to override", socketPath)
		}
		t.Fatalf("stat docker socket %q: %v", socketPath, err)
	}

	if err := pingDockerSocket(socketPath); err != nil {
		t.Fatalf("docker daemon unavailable at %q: %v", socketPath, err)
	}

	return socketPath
}

func newIntegrationProxyHandler(t *testing.T, socketPath string, rules []config.RuleConfig) http.Handler {
	return newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{}, ownership.Options{})
}

func newIntegrationProxyHandlerWithOptions(t *testing.T, socketPath string, rules []config.RuleConfig, filterOpts filter.Options, ownerOpts ownership.Options) http.Handler {
	t.Helper()

	compiled, err := compileRulesForTest(rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	logger := newIntegrationLogger()

	var handler http.Handler = proxy.New(socketPath, logger)
	handler = proxy.HijackHandler(socketPath, logger, handler)
	handler = ownership.Middleware(socketPath, logger, ownerOpts)(handler)
	handler = filter.MiddlewareWithOptions(compiled, logger, filterOpts)(handler)
	return handler
}

func newIntegrationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startIntegrationProxyServer(t *testing.T, handler http.Handler) (string, func()) {
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

	srv := &http.Server{Handler: wrapped}
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

func createDockerContainer(t *testing.T, socketPath string, spec dockerContainerCreateRequest) string {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	t.Cleanup(closeIdle)

	payload, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal docker create request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://docker/containers/create", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new docker create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("docker create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		t.Fatalf("docker create status = %d, want %d; body: %s", resp.StatusCode, http.StatusCreated, strings.TrimSpace(string(body)))
	}

	var body dockerContainerCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode docker create response: %v", err)
	}
	if body.ID == "" {
		t.Fatal("docker create response missing Id")
	}

	t.Cleanup(func() {
		removeDockerContainer(t, socketPath, body.ID)
	})

	return body.ID
}

func startDockerContainer(t *testing.T, socketPath, containerID string) {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodPost, "http://docker/containers/"+url.PathEscape(containerID)+"/start", nil)
	if err != nil {
		t.Fatalf("new docker start request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("docker start request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		t.Fatalf("docker start status = %d, want %d; body: %s", resp.StatusCode, http.StatusNoContent, strings.TrimSpace(string(body)))
	}
}

func waitForDockerContainerRunning(t *testing.T, socketPath, containerID string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		client, closeIdle := dockerHTTPClient(socketPath)

		req, err := http.NewRequest(http.MethodGet, "http://docker/containers/"+url.PathEscape(containerID)+"/json", nil)
		if err != nil {
			closeIdle()
			t.Fatalf("new docker inspect request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			closeIdle()
			t.Fatalf("docker inspect request failed: %v", err)
		}

		var body dockerContainerInspectResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		closeErr := resp.Body.Close()
		closeIdle()
		if decodeErr != nil {
			t.Fatalf("decode docker inspect response: %v", decodeErr)
		}
		if closeErr != nil {
			t.Fatalf("close docker inspect response body: %v", closeErr)
		}

		if body.State.Running {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("docker container did not reach running state")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func removeDockerContainer(t *testing.T, socketPath, containerID string) {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodDelete, "http://docker/containers/"+url.PathEscape(containerID)+"?force=1&v=1", nil)
	if err != nil {
		t.Fatalf("new docker remove request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("docker remove request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		t.Fatalf("docker remove status = %d, want %d or %d; body: %s", resp.StatusCode, http.StatusNoContent, http.StatusOK, strings.TrimSpace(string(body)))
	}
}

func readDockerHijackFrame(t *testing.T, r *bufio.Reader) (byte, []byte) {
	t.Helper()

	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatalf("read hijack frame header: %v", err)
	}

	payloadLen := binary.BigEndian.Uint32(header[4:])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read hijack frame payload: %v", err)
	}

	return header[0], payload
}

func compileRulesForTest(rules []config.RuleConfig) ([]*filter.CompiledRule, error) {
	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i, rule := range rules {
		spec := filter.Rule{
			Methods: splitRuleMethods(rule.Match.Method),
			Pattern: rule.Match.Path,
			Action:  filter.Action(rule.Action),
			Reason:  rule.Reason,
			Index:   i,
		}

		compiledRule, err := filter.CompileRule(spec)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		compiled = append(compiled, compiledRule)
	}
	return compiled, nil
}

func splitRuleMethods(methods string) []string {
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

func fetchDockerVersion(t *testing.T, socketPath string) dockerVersionResponse {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodGet, "http://docker/version", nil)
	if err != nil {
		t.Fatalf("new version request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("direct docker /version request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("direct docker /version status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var body dockerVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode docker version response: %v", err)
	}
	if body.APIVersion == "" {
		t.Fatal("docker /version response missing ApiVersion")
	}

	return body
}

func pingDockerSocket(socketPath string) error {
	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return fmt.Errorf("new ping request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		return fmt.Errorf("/_ping status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(body)) != "OK" {
		return fmt.Errorf("/_ping body = %q, want OK", string(body))
	}

	return nil
}

func dockerHTTPClient(socketPath string) (*http.Client, func()) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}, transport.CloseIdleConnections
}
