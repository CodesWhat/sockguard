//go:build integration

package integration_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproxy"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
	"github.com/codeswhat/sockguard/v2/app/internal/ownership"
	"github.com/codeswhat/sockguard/v2/app/internal/proxy"
)

func TestBuildxBuiltinDockerfileRealDaemon(t *testing.T) {
	socket := dockerSocketForIntegration(t)
	direct := "unix://" + socket
	env := append(os.Environ(), "DOCKER_CONFIG="+t.TempDir(), "DOCKER_CONTEXT=", "DOCKER_TLS_VERIFY=", "DOCKER_TLS=")
	docker := func(host string, stdin []byte, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", append([]string{"--host", host}, args...)...)
		cmd.Env, cmd.Stdin = env, bytes.NewReader(stdin)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	if output, err := docker(direct, nil, "buildx", "version"); err != nil {
		t.Fatalf("Buildx must be installed for integration: %v: %s", err, output)
	}
	name := fmt.Sprintf("sockguard-buildx-%d", time.Now().UnixNano())
	mine, foreign := name+":mine", name+":foreign"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "--host", direct, "image", "rm", "--force", mine, foreign)
		cmd.Env = env
		_ = cmd.Run()
	})
	var empty bytes.Buffer
	if err := tar.NewWriter(&empty).Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := docker(direct, empty.Bytes(), "image", "import", "--change", "LABEL com.sockguard.owner=team-b", "-", foreign); err != nil {
		t.Fatalf("prepare foreign image: %v: %s", err, output)
	}
	before, err := docker(direct, nil, "image", "inspect", "--format", "{{.Id}}", foreign)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join("..", "configs", "drydock-with-mediated-build.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	policy := cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build)
	policy.ImageOwnership = buildkitproxy.ImageOwnershipPolicy{Owner: "team-a", LabelKey: "com.sockguard.owner", Authorize: ownership.NewBuildkitImageAuthorizer(dockerSocketRoundTripper(socket), ownership.Options{Owner: "team-a", LabelKey: "com.sockguard.owner"})}
	logger := newIntegrationLogger()
	mediator := buildkitproxy.NewMediator(llbDaemonDialer{socket}, logger)
	ordinary := proxy.NewWithOptions(socket, logger, proxy.Options{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := buildkitproxy.SessionKey{ClientIdentity: "buildx-integration", Profile: "builder"}
		switch r.URL.Path {
		case "/grpc":
			mediator.ServeGRPC(w, r, policy, key)
		case "/session":
			mediator.ServeSession(w, r, policy, key)
		default:
			ordinary.ServeHTTP(w, r)
		}
	}))
	defer server.Close()
	host := "tcp://" + strings.TrimPrefix(server.URL, "http://")
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "marker"), []byte("owner proof"), 0600); err != nil {
		t.Fatal(err)
	}
	build := func(dockerfile, tag string) (string, error) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
			t.Fatal(err)
		}
		return docker(host, nil, "buildx", "build", "--builder", "default", "--progress=plain", "--provenance=false", "--load", "--tag", tag, directory)
	}
	const source = "FROM scratch\nLABEL com.sockguard.owner=forged\nCOPY marker /marker\n"
	if output, err := build(source, mine); err != nil {
		t.Fatalf("Buildx failed: %v: %s", err, output)
	}
	label, err := docker(direct, nil, "image", "inspect", "--format", `{{index .Config.Labels "com.sockguard.owner"}}`, mine)
	if err != nil || strings.TrimSpace(label) != "team-a" {
		t.Fatalf("owner label=%q error=%v", label, err)
	}
	if output, err := build(source, foreign); err == nil || !strings.Contains(output, "image export cannot satisfy owner isolation") {
		t.Fatalf("foreign destination: %v: %s", err, output)
	}
	after, err := docker(direct, nil, "image", "inspect", "--format", "{{.Id}}", foreign)
	if err != nil || after != before {
		t.Fatal("foreign image changed")
	}
	for _, tc := range []struct{ file, reason string }{
		{"FROM scratch\nRUN echo forbidden\n", "RUN instructions are not allowed"},
		{"# syntax=bad.invalid/never-run:latest\nFROM scratch\n", "syntax frontend directives"},
	} {
		if output, err := build(tc.file, mine); err == nil || !strings.Contains(output, tc.reason) {
			t.Fatalf("expected policy refusal %q: %v: %s", tc.reason, err, output)
		}
	}
}
