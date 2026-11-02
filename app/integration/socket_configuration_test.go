//go:build integration || podmanintegration

package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSocketConfiguration(t *testing.T) {
	if os.Getenv("SOCKGUARD_SOCKET_TEST_CHILD") == "docker" {
		dockerSocketForIntegration(t)
		t.Fatal("missing socket was accepted")
	}

	t.Run("configured missing socket fails", func(t *testing.T) {
		output, err := runSocketConfigurationChild(t, "docker", "TestDockerSocketConfiguration", "SOCKGUARD_TEST_DOCKER_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
		if err == nil || !strings.Contains(output, "FAIL") || !strings.Contains(output, "stat docker socket") {
			t.Fatalf("configured missing socket must fail, got err=%v output=%s", err, output)
		}
	})
	t.Run("absent default socket skips", func(t *testing.T) {
		if _, err := os.Stat(defaultDockerSocket); !os.IsNotExist(err) {
			t.Skip("default socket is present or cannot be inspected; do not contact a daemon")
		}
		output, err := runSocketConfigurationChild(t, "docker", "TestDockerSocketConfiguration", "SOCKGUARD_TEST_DOCKER_SOCKET", "")
		if err != nil || !strings.Contains(output, "SKIP") {
			t.Fatalf("absent optional default socket must skip, got err=%v output=%s", err, output)
		}
	})
}

func runSocketConfigurationChild(t *testing.T, engine, testName, envName, socketPath string) (string, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), "SOCKGUARD_SOCKET_TEST_CHILD="+engine, envName+"="+socketPath)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("socket configuration subprocess did not finish: %v", ctx.Err())
	}
	return string(output), err
}
