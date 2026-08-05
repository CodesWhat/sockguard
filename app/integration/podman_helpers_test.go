//go:build podmanintegration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// podmanSocketEnvVar names the environment variable the libpod integration
// suite reads to find a real Podman API socket. Unlike
// dockerSocketForIntegration's SOCKGUARD_TEST_DOCKER_SOCKET, there is no
// filesystem-path default: rootful and rootless podman listen on very
// different paths (a well-known root-owned path vs. a per-UID
// XDG_RUNTIME_DIR path), and guessing wrong would either silently skip real
// coverage or dial the wrong daemon. The CI workflow
// (.github/workflows/quality-integration-podman.yml) always sets this
// explicitly for both the rootful and rootless legs.
const podmanSocketEnvVar = "SOCKGUARD_TEST_PODMAN_SOCKET"

type libpodVersionResponse struct {
	Version struct {
		APIVersion string `json:"APIVersion"`
		Version    string `json:"Version"`
	} `json:"Version"`
}

// libpodContainerCreateResponse mirrors dockerContainerCreateResponse
// (helpers_test.go): Podman's native POST /libpod/containers/create returns
// the identical {"Id":...,"Warnings":[...]} shape as the Docker-compat
// endpoint.
type libpodContainerCreateResponse struct {
	Id       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

type libpodContainerInspectResponse struct {
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
}

// podmanSocketForIntegration returns the real Podman socket path from
// podmanSocketEnvVar, skipping the test cleanly when it is unset or the
// socket is unreachable — the same pattern dockerSocketForIntegration uses,
// so `go test ./...` without the podmanintegration build tag (and even with
// it, off the dedicated CI job) stays green.
func podmanSocketForIntegration(t *testing.T) string {
	t.Helper()

	socketPath := os.Getenv(podmanSocketEnvVar)
	if socketPath == "" {
		t.Skipf("%s not set; skipping real-Podman integration test", podmanSocketEnvVar)
	}

	if _, err := os.Stat(socketPath); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("podman socket %q not found; set %s to override", socketPath, podmanSocketEnvVar)
		}
		t.Fatalf("stat podman socket %q: %v", socketPath, err)
	}

	if err := pingPodmanSocket(socketPath); err != nil {
		t.Fatalf("podman daemon unavailable at %q: %v", socketPath, err)
	}

	return socketPath
}

func pingPodmanSocket(socketPath string) error {
	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodGet, "http://podman/libpod/_ping", nil)
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
		return fmt.Errorf("/libpod/_ping status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	return nil
}

func fetchLibpodVersion(t *testing.T, socketPath string) libpodVersionResponse {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodGet, "http://podman/libpod/version", nil)
	if err != nil {
		t.Fatalf("new version request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("direct podman /libpod/version request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("direct podman /libpod/version status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var body libpodVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode podman version response: %v", err)
	}
	if body.Version.APIVersion == "" {
		t.Fatal("podman /libpod/version response missing Version.APIVersion")
	}

	return body
}

// waitForLibpodContainerRunning polls GET /libpod/containers/{id}/json
// directly against the real daemon (bypassing sockguard) until the
// container reports Running, mirroring waitForDockerContainerRunning. Used
// before issuing an exec against a just-started container so a slow start
// can't race the exec-create/start calls that follow.
func waitForLibpodContainerRunning(t *testing.T, socketPath, containerID string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		client, closeIdle := dockerHTTPClient(socketPath)

		req, err := http.NewRequest(http.MethodGet, "http://podman/libpod/containers/"+url.PathEscape(containerID)+"/json", nil)
		if err != nil {
			closeIdle()
			t.Fatalf("new libpod inspect request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			closeIdle()
			t.Fatalf("libpod inspect request failed: %v", err)
		}

		var body libpodContainerInspectResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		closeErr := resp.Body.Close()
		closeIdle()
		if decodeErr != nil {
			t.Fatalf("decode libpod inspect response: %v", decodeErr)
		}
		if closeErr != nil {
			t.Fatalf("close libpod inspect response body: %v", closeErr)
		}

		if body.State.Running {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("libpod container did not reach running state")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func removeLibpodContainer(t *testing.T, socketPath, containerID string) {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodDelete, "http://podman/libpod/containers/"+url.PathEscape(containerID)+"?force=true", nil)
	if err != nil {
		t.Fatalf("new libpod remove request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("libpod remove request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		t.Fatalf("libpod remove status = %d, want %d or %d; body: %s", resp.StatusCode, http.StatusOK, http.StatusNoContent, strings.TrimSpace(string(body)))
	}
}
