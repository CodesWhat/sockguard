//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/proxy"
)

const defaultDockerSocket = "/var/run/docker.sock"

type dockerVersionResponse struct {
	APIVersion string `json:"ApiVersion"`
	Version    string `json:"Version"`
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
	t.Helper()

	compiled, err := compileRulesForTest(rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	logger := newIntegrationLogger()

	var handler http.Handler = proxy.New(socketPath, logger)
	handler = proxy.HijackHandler(socketPath, logger, handler)
	handler = filter.Middleware(compiled, logger)(handler)
	return handler
}

func newIntegrationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
