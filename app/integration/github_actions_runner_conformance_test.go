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

// ghaPresetConfigPath returns the absolute path to the GitHub Actions Runner
// preset YAML.
func ghaPresetConfigPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate preset config")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(thisFile)), "configs", "github-actions-runner.yaml")
}

// newGHAPresetHandler loads the github-actions-runner.yaml preset and builds the
// full sockguard middleware chain pointing at socketPath.
func newGHAPresetHandler(t *testing.T, socketPath string) http.Handler {
	t.Helper()

	cfg, err := config.Load(ghaPresetConfigPath(t))
	if err != nil {
		t.Fatalf("load GHA preset: %v", err)
	}

	policyConfig := cfg.RequestBody.ToFilterOptions()
	policyConfig.DenyResponseVerbosity = filter.DenyResponseVerbosityVerbose

	return newIntegrationProxyHandlerWithOptions(
		t,
		socketPath,
		cfg.Rules,
		filter.Options{PolicyConfig: policyConfig},
		ownership.Options{},
	)
}

// ghaBodyDenied fires a single container-create request and asserts that the
// body inspector (not the catch-all rule) denies it with the given substring.
func ghaBodyDenied(t *testing.T, handler http.Handler, name, body, wantSubstring string) {
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
			t.Fatalf("GHA preset: container create: status = %d, want %d (body: %s)",
				rec.Code, http.StatusForbidden, clipResponseBody(respBody))
		}
		if !strings.Contains(respBody, wantSubstring) {
			t.Fatalf("GHA preset: container create: deny body = %q, want substring %q",
				clipResponseBody(respBody), wantSubstring)
		}
	})
}

// TestGitHubActionsRunner fires a representative request matrix at a sockguard
// chain loaded from the github-actions-runner.yaml preset.
func TestGitHubActionsRunner(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	handler := newGHAPresetHandler(t, socketPath)

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
		// Exec allowed for GHA runner `run:` steps.
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

	// The GHA preset declares its own explicit catch-all rule with reason
	// "not allowed by github-actions-runner preset" (configs/github-actions-runner.yaml),
	// so override the default Tecnativa-compat catch-all substring.
	for _, exp := range ruleExpectations {
		runPresetExpectationWithReason(t, handler, "github-actions-runner", exp, "not allowed by github-actions-runner preset")
	}

	// ── Body-inspection assertions ───────────────────────────────────────────

	// Privileged containers denied.
	ghaBodyDenied(t, handler,
		"privileged-container",
		`{"Image":"scratch","HostConfig":{"Privileged":true}}`,
		"privileged containers are not allowed",
	)

	// Host network denied.
	ghaBodyDenied(t, handler,
		"host-network",
		`{"Image":"scratch","HostConfig":{"NetworkMode":"host"}}`,
		"host network mode is not allowed",
	)

	// Bind mount denied (allowed_bind_mounts is empty — host paths are
	// off-limits for GHA runner workloads).
	ghaBodyDenied(t, handler,
		"bind-mount-host-etc",
		`{"Image":"scratch","HostConfig":{"Binds":["/etc:/etc"]}}`,
		"bind mount source",
	)

	// ── Compliant body → passes body inspector ───────────────────────────────
	// The GHA preset does not require read-only rootfs, memory limits, or
	// CapDrop ALL — so a simple non-privileged create with no-new-privileges
	// should pass. Non-existent image → dockerd returns 404, which is non-403
	// and therefore counts as "allowed."
	t.Run("compliant-body-allowed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		payload := `{
			"Image": "gha-conformance-nonexistent:nosuchtag",
			"HostConfig": {
				"SecurityOpt": ["no-new-privileges:true"]
			}
		}`

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(payload)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		deniedByCatchAll := rec.Code == http.StatusForbidden &&
			strings.Contains(rec.Body.String(), "not allowed by github-actions-runner preset")
		deniedByBodyInspector := rec.Code == http.StatusForbidden &&
			strings.Contains(rec.Body.String(), "container create denied")

		if deniedByCatchAll || deniedByBodyInspector {
			t.Fatalf("GHA preset: compliant container create was denied (status %d, body %s)",
				rec.Code, clipResponseBody(rec.Body.String()))
		}
	})
}
