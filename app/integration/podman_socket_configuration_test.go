//go:build podmanintegration

package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPodmanSocketConfiguration(t *testing.T) {
	if os.Getenv("SOCKGUARD_SOCKET_TEST_CHILD") == "podman" {
		podmanSocketForIntegration(t)
		t.Fatal("missing socket was accepted")
	}

	for _, tc := range []struct {
		name string
		path string
		fail bool
	}{
		{name: "configured missing socket fails", path: filepath.Join(t.TempDir(), "missing.sock"), fail: true},
		{name: "unconfigured socket skips"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := runSocketConfigurationChild(t, "podman", "TestPodmanSocketConfiguration", podmanSocketEnvVar, tc.path)
			if tc.fail {
				if err == nil || !strings.Contains(output, "FAIL") || !strings.Contains(output, "stat podman socket") {
					t.Fatalf("configured missing socket must fail, got err=%v output=%s", err, output)
				}
			} else if err != nil || !strings.Contains(output, "SKIP") {
				t.Fatalf("unconfigured socket must skip, got err=%v output=%s", err, output)
			}
		})
	}
}
