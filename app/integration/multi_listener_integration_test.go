//go:build integration

package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type synchronizedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestMultiListenerUnixProfileIsolation(t *testing.T) {
	workDir, err := os.MkdirTemp("/tmp", "sockguard-multi-listener-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })

	upstreamPath := filepath.Join(workDir, "docker.sock")
	ciPath := filepath.Join(workDir, "ci.sock")
	opsPath := filepath.Join(workDir, "ops.sock")
	upstreamListener, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatalf("listen mock upstream: %v", err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	})}
	go func() { _ = upstream.Serve(upstreamListener) }()
	t.Cleanup(func() {
		_ = upstream.Close()
		_ = upstreamListener.Close()
	})

	configPath := filepath.Join(workDir, "sockguard.yaml")
	configYAML := fmt.Sprintf(`upstream:
  socket: %q
  flavor: docker
log:
  level: error
  format: json
  access_log: false
health:
  enabled: false
admin:
  enabled: false
listeners:
  - name: ci
    socket: %q
    socket_mode: "0600"
    allowed_profiles: [ci]
  - name: ops
    socket: %q
    socket_mode: "0600"
    allowed_profiles: [ops]
clients:
  unix_peer_profiles:
    - profile: ci
      uids: [%d]
  profiles:
    - name: ci
      rules:
        - match: {method: GET, path: "/_ping"}
          action: allow
        - match: {method: "*", path: "/**"}
          action: deny
    - name: ops
      rules:
        - match: {method: GET, path: "/_ping"}
          action: allow
        - match: {method: "*", path: "/**"}
          action: deny
rules:
  - match: {method: "*", path: "/**"}
    action: deny
`, upstreamPath, ciPath, opsPath, os.Getuid())
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	binaryPath := filepath.Join(workDir, "sockguard")
	build := exec.Command("go", "build", "-o", binaryPath, "../cmd/sockguard")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build sockguard: %v\n%s", err, output)
	}

	var processOutput synchronizedBuffer
	command := exec.Command(binaryPath, "--config", configPath, "serve")
	command.Stdout = &processOutput
	command.Stderr = &processOutput
	if err := command.Start(); err != nil {
		t.Fatalf("start sockguard: %v", err)
	}
	processDone := make(chan struct{})
	var processErr error
	go func() {
		processErr = command.Wait()
		close(processDone)
	}()
	t.Cleanup(func() {
		if command.Process == nil {
			return
		}
		_ = command.Process.Signal(os.Interrupt)
		select {
		case <-processDone:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-processDone
		}
	})

	ciResponse := waitForUnixResponse(t, ciPath, processDone, &processErr, &processOutput)
	defer ciResponse.Body.Close()
	if ciResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(ciResponse.Body)
		t.Fatalf("ci listener status = %d, want 200; body=%s", ciResponse.StatusCode, strings.TrimSpace(string(body)))
	}

	opsClient, closeOpsClient := dockerHTTPClient(opsPath)
	defer closeOpsClient()
	opsResponse, err := opsClient.Get("http://sockguard/_ping")
	if err != nil {
		t.Fatalf("GET ops listener: %v\nprocess output:\n%s", err, processOutput.String())
	}
	defer opsResponse.Body.Close()
	if opsResponse.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(opsResponse.Body)
		t.Fatalf("same ci-profile client on ops listener status = %d, want 403; body=%s", opsResponse.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(opsResponse.Body)
	if err != nil {
		t.Fatalf("read ops denial: %v", err)
	}
	if !strings.Contains(string(body), "client profile not allowed on this listener") {
		t.Fatalf("ops denial body = %q, want listener admission denial", body)
	}
}

func waitForUnixResponse(t *testing.T, socketPath string, processDone <-chan struct{}, processErr *error, processOutput fmt.Stringer) *http.Response {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-processDone:
			t.Fatalf("sockguard exited before serving: %v\n%s", *processErr, processOutput.String())
		default:
		}

		client, closeClient := dockerHTTPClient(socketPath)
		client.Timeout = 250 * time.Millisecond
		response, err := client.Get("http://sockguard/_ping")
		closeClient()
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatalf("read startup response: %v", readErr)
			}
			response.Body = io.NopCloser(bytes.NewReader(body))
			return response
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for unix listener %s\nprocess output:\n%s", socketPath, processOutput.String())
	return nil
}
