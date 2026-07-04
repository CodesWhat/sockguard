//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/ownership"
)

// gitlabPresetConfigPath returns the absolute path to the GitLab Runner preset
// YAML.
func gitlabPresetConfigPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate preset config")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(thisFile)), "configs", "gitlab-runner.yaml")
}

// newGitLabPresetHandler loads the gitlab-runner.yaml preset and builds the
// full sockguard middleware chain pointing at socketPath.
func newGitLabPresetHandler(t *testing.T, socketPath string) http.Handler {
	t.Helper()

	cfg, err := config.Load(gitlabPresetConfigPath(t))
	if err != nil {
		t.Fatalf("load GitLab Runner preset: %v", err)
	}

	policyConfig := cfg.RequestBody.ToFilterOptions()
	policyConfig.DenyResponseVerbosity = filter.DenyResponseVerbosityVerbose
	// insecure_allow_body_blind_writes is a top-level Config field, wired at
	// serve time by internal/cmd/serve.go's attachRuntimeInspectors. Mirror
	// that assignment here so this preset's own opt-in (see
	// configs/gitlab-runner.yaml) takes effect in this handler too.
	policyConfig.Exec.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites

	return newIntegrationProxyHandlerWithOptions(
		t,
		socketPath,
		cfg.Rules,
		filter.Options{PolicyConfig: policyConfig},
		ownership.Options{},
	)
}

// gitlabBodyDenied fires a single container-create request and asserts that the
// body inspector denies it with the given substring.
func gitlabBodyDenied(t *testing.T, handler http.Handler, name, body, wantSubstring string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		respBody := rec.Body.String()
		if rec.Code != http.StatusForbidden {
			t.Fatalf("GitLab Runner preset: container create: status = %d, want %d (body: %s)",
				rec.Code, http.StatusForbidden, clipResponseBody(respBody))
		}
		if !strings.Contains(respBody, wantSubstring) {
			t.Fatalf("GitLab Runner preset: container create: deny body = %q, want substring %q",
				clipResponseBody(respBody), wantSubstring)
		}
	})
}

// TestGitLabRunner fires a representative request matrix at a sockguard chain
// loaded from the gitlab-runner.yaml preset. The GitLab Docker executor surface
// is intentionally similar to the GHA runner preset; the distinct security note
// is the explicit rejection of HostConfig.Privileged=true, which maps to
// gitlab-runner's config.toml `privileged = true` option — that must fail at
// the proxy rather than reaching dockerd.
func TestGitLabRunner(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	handler := newGitLabPresetHandler(t, socketPath)

	// ── Rule-layer assertions ────────────────────────────────────────────────

	ruleExpectations := []presetExpectation{
		// Allowed reads.
		{http.MethodGet, "/containers/json", true},
		{http.MethodGet, "/containers/abc/json", true},
		{http.MethodGet, "/containers/abc/logs", true},
		{http.MethodGet, "/containers/abc/stats", true},
		{http.MethodGet, "/events?until=0", true},
		// Container lifecycle — all allowed.
		{http.MethodPost, "/containers/abc/start", true},
		{http.MethodPost, "/containers/abc/stop", true},
		{http.MethodPost, "/containers/abc/kill", true},
		{http.MethodPost, "/containers/abc/wait", true},
		{http.MethodDelete, "/containers/abc", true},
		// Exec allowed — the Docker executor injects job steps via exec.
		{http.MethodPost, "/containers/abc/exec", true},
		{http.MethodPost, "/exec/abc/start", true},
		// Image pull allowed; build denied.
		{http.MethodPost, "/images/create", true},
		{http.MethodPost, "/build", false},
		// Network lifecycle allowed.
		{http.MethodPost, "/networks/create", true},
		// Volume lifecycle allowed.
		{http.MethodPost, "/volumes/create", true},
		// Swarm denied.
		{http.MethodPost, "/swarm/init", false},
	}

	// The GitLab Runner preset declares its own explicit catch-all rule with reason
	// "not allowed by gitlab-runner preset" (configs/gitlab-runner.yaml), so override
	// the default Tecnativa-compat catch-all substring.
	for _, exp := range ruleExpectations {
		runPresetExpectationWithReason(t, handler, "gitlab-runner", exp, "not allowed by gitlab-runner preset")
	}

	// ── Body-inspection assertions ───────────────────────────────────────────

	// The primary security note for the GitLab Runner preset: config.toml
	// `privileged = true` causes the runner to set HostConfig.Privileged=true
	// in every container_create body. The proxy must reject this before dockerd
	// acts on it. This is the whole point of deploying sockguard in front of a
	// privileged runner — the 403 here proves the proxy enforces it.
	gitlabBodyDenied(t, handler,
		"privileged-true-config-toml",
		`{"Image":"scratch","HostConfig":{"Privileged":true}}`,
		"privileged containers are not allowed",
	)

	// Host network denied.
	gitlabBodyDenied(t, handler,
		"host-network",
		`{"Image":"scratch","HostConfig":{"NetworkMode":"host"}}`,
		"host network mode is not allowed",
	)

	// Host PID namespace denied.
	gitlabBodyDenied(t, handler,
		"host-pid",
		`{"Image":"scratch","HostConfig":{"PidMode":"host"}}`,
		"host PID mode is not allowed",
	)

	// Bind mount denied (allowed_bind_mounts is empty by default).
	gitlabBodyDenied(t, handler,
		"bind-mount-host-path",
		`{"Image":"scratch","HostConfig":{"Binds":["/etc:/etc"]}}`,
		"bind mount source",
	)

	// no-new-privileges required.
	gitlabBodyDenied(t, handler,
		"no-new-privileges-missing",
		`{"Image":"scratch","HostConfig":{}}`,
		"no-new-privileges is required",
	)

	// ── Compliant body → passes body inspector ───────────────────────────────
	// The GitLab Runner preset does not require read-only rootfs, CapDrop ALL,
	// or resource limits. A non-privileged body with no-new-privileges satisfies
	// the preset. Non-existent image → dockerd 404, which is non-403 and
	// therefore counts as "allowed" at the rule+body-inspector layer.
	t.Run("compliant-body-allowed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		payload := `{
			"Image": "gitlab-conformance-nonexistent:nosuchtag",
			"HostConfig": {
				"SecurityOpt": ["no-new-privileges:true"]
			}
		}`

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(payload)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		deniedByCatchAll := rec.Code == http.StatusForbidden &&
			strings.Contains(rec.Body.String(), "not allowed by gitlab-runner preset")
		deniedByBodyInspector := rec.Code == http.StatusForbidden &&
			strings.Contains(rec.Body.String(), "container create denied")

		if deniedByCatchAll || deniedByBodyInspector {
			t.Fatalf("GitLab Runner preset: compliant container create was denied (status %d, body %s)",
				rec.Code, clipResponseBody(rec.Body.String()))
		}
	})
}
