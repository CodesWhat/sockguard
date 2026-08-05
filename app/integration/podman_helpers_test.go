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

// podmanLibpodAPIVersion returns the running daemon's native libpod API
// version, read off the Libpod-API-Version response header of a bare GET
// /libpod/_ping — the same negotiation mechanism a real Podman client
// bindings library performs before issuing any other request. This suite
// hits it directly rather than assuming a version: the installed podman on
// GitHub's ubuntu-latest runner (4.9.3, from the distro repos) 404s several
// libpod routes — including POST /libpod/containers/create — when called
// bare with no version prefix, even though GET /libpod/_ping itself is
// (deliberately, matching the Docker Engine API convention) version-
// independent. Every request this suite sends that needs to actually reach
// Podman is prefixed with "/v" + this value, exactly as a real client would.
func podmanLibpodAPIVersion(t *testing.T, socketPath string) string {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodGet, "http://podman/libpod/_ping", nil)
	if err != nil {
		t.Fatalf("new ping request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("direct podman /libpod/_ping request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("direct podman /libpod/_ping status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	version := resp.Header.Get("Libpod-Api-Version")
	if version == "" {
		t.Fatal("podman /libpod/_ping response missing Libpod-Api-Version header")
	}

	return version
}

// waitForLibpodContainerRunning polls GET /libpod/containers/{id}/json
// directly against the real daemon (bypassing sockguard) until the
// container reports Running, mirroring waitForDockerContainerRunning. Used
// before issuing an exec against a just-started container so a slow start
// can't race the exec-create/start calls that follow. apiVersion (from
// podmanLibpodAPIVersion) prefixes the request the same way every other
// non-_ping libpod call in this suite does.
func waitForLibpodContainerRunning(t *testing.T, socketPath, apiVersion, containerID string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		client, closeIdle := dockerHTTPClient(socketPath)

		req, err := http.NewRequest(http.MethodGet, "http://podman/v"+apiVersion+"/libpod/containers/"+url.PathEscape(containerID)+"/json", nil)
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

// removeLibpodContainerTimeout is longer than dockerHTTPClient's shared 5s
// default: force-removing a RUNNING container makes Podman stop it first
// (SIGTERM, then a grace period before SIGKILL), which alone can take
// several seconds — well-behaved on a real daemon, but past the 5s budget
// dockerHTTPClient uses for quick, non-lifecycle calls like the _ping check
// in podmanSocketForIntegration.
const removeLibpodContainerTimeout = 30 * time.Second

func removeLibpodContainer(t *testing.T, socketPath, apiVersion, containerID string) {
	t.Helper()

	transport := dockerSocketRoundTripper(socketPath)
	client := &http.Client{Transport: transport, Timeout: removeLibpodContainerTimeout}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodDelete, "http://podman/v"+apiVersion+"/libpod/containers/"+url.PathEscape(containerID)+"?force=true", nil)
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
