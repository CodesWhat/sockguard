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

// cisPresetConfigPath returns the absolute path to the CIS Docker Benchmark
// preset YAML regardless of the working directory the test runner uses.
func cisPresetConfigPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate preset config")
	}
	// thisFile is .../app/integration/cis_docker_benchmark_conformance_test.go
	// configs/ sits two levels up from the integration/ directory.
	return filepath.Join(filepath.Dir(filepath.Dir(thisFile)), "configs", "cis-docker-benchmark.yaml")
}

// newCISPresetHandler loads the cis-docker-benchmark.yaml preset and builds the
// full sockguard middleware chain pointing at socketPath. Rules and body
// inspection options both come from the preset file so the test exercises the
// exact policy an operator would deploy.
func newCISPresetHandler(t *testing.T, socketPath string) http.Handler {
	t.Helper()

	cfg, err := config.Load(cisPresetConfigPath(t))
	if err != nil {
		t.Fatalf("load CIS preset: %v", err)
	}

	policyConfig := cfg.RequestBody.ToFilterOptions()
	// Integration tier always uses verbose denials so assertions can read the
	// reason text; the preset default is minimal.
	policyConfig.DenyResponseVerbosity = filter.DenyResponseVerbosityVerbose

	return newIntegrationProxyHandlerWithOptions(
		t,
		socketPath,
		cfg.Rules,
		filter.Options{PolicyConfig: policyConfig},
		ownership.Options{},
	)
}

// cisBodyDenied fires one request through handler, asserts that the response
// status is 403, and confirms the body contains the expected substring — which
// must be part of a body-inspector denial message (i.e. "container create
// denied: …"), not the catch-all rule reason. It fails loudly if the request
// is either allowed or catch-all denied instead.
func cisBodyDenied(t *testing.T, handler http.Handler, name, method, path, body, wantSubstring string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		respBody := rec.Body.String()
		if rec.Code != http.StatusForbidden {
			t.Fatalf("CIS preset: %s %s: status = %d, want %d (body: %s)",
				method, path, rec.Code, http.StatusForbidden, clipResponseBody(respBody))
		}
		if !strings.Contains(respBody, wantSubstring) {
			t.Fatalf("CIS preset: %s %s: deny body = %q, want substring %q",
				method, path, clipResponseBody(respBody), wantSubstring)
		}
	})
}

// TestCISDockerBenchmark fires a representative request matrix at a sockguard
// chain loaded from the cis-docker-benchmark.yaml preset. It asserts both the
// path/method rule layer (catch-all denials) and the body-inspection layer
// (container_create inspector enforcing CIS Section 5 controls).
func TestCISDockerBenchmark(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	handler := newCISPresetHandler(t, socketPath)

	// ── Rule-layer assertions (method + path matching) ──────────────────────
	// These use the shared runPresetExpectation helper from the Tecnativa
	// conformance test. A "catch-all denied" verdict is 403 + "no matching
	// allow rule"; any other status counts as "allowed" at the rule layer.

	ruleExpectations := []presetExpectation{
		// Allowed metadata reads.
		{http.MethodGet, "/containers/json", true},
		{http.MethodGet, "/version", true},
		{http.MethodGet, "/info", true},
		// Build is explicitly denied by the CIS preset catch-all.
		{http.MethodPost, "/build", false},
		// Exec is denied by the catch-all (CIS 5.22/5.23).
		{http.MethodPost, "/containers/abc/exec", false},
		// Swarm management denied.
		{http.MethodPost, "/swarm/init", false},
	}

	for _, exp := range ruleExpectations {
		runPresetExpectation(t, handler, "cis-docker-benchmark", exp)
	}

	// ── Body-inspection assertions (CIS Section 5 controls) ─────────────────
	// Each case sends a POST /containers/create body that trips exactly one
	// CIS control. The body-inspector fires after the rule layer admits the
	// path, so the upstream is never reached — the 403 is inspector-sourced.

	// CIS 5.4 — privileged containers not used.
	cisBodyDenied(t, handler,
		"5.4-privileged-container",
		http.MethodPost, "/containers/create",
		`{"Image":"scratch","HostConfig":{"Privileged":true}}`,
		"privileged containers are not allowed",
	)

	// CIS 5.9 — host network namespace not shared.
	cisBodyDenied(t, handler,
		"5.9-host-network",
		http.MethodPost, "/containers/create",
		`{"Image":"scratch","HostConfig":{"NetworkMode":"host"}}`,
		"host network mode is not allowed",
	)

	// CIS 5.10 / 5.15 — host PID namespace not shared.
	cisBodyDenied(t, handler,
		"5.10-host-pid",
		http.MethodPost, "/containers/create",
		`{"Image":"scratch","HostConfig":{"PidMode":"host"}}`,
		"host PID mode is not allowed",
	)

	// CIS 5.16/5.17 — CapAdd SYS_ADMIN denied (allowed_capabilities is empty).
	cisBodyDenied(t, handler,
		"5.16-cap-add-sys-admin",
		http.MethodPost, "/containers/create",
		`{"Image":"scratch","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
		"capability",
	)

	// CIS 5.25 — no-new-privileges flag required.
	// A body with no SecurityOpt entry for no-new-privileges fails this control.
	cisBodyDenied(t, handler,
		"5.25-no-new-privileges-missing",
		http.MethodPost, "/containers/create",
		`{"Image":"scratch","HostConfig":{"ReadonlyRootfs":true,"Memory":67108864,"NanoCpus":1000000000,"PidsLimit":100,"CapDrop":["ALL"]}}`,
		"no-new-privileges is required",
	)

	// CIS 5.12 — read-only root filesystem required.
	// Body has no-new-privileges but no ReadonlyRootfs.
	cisBodyDenied(t, handler,
		"5.30-readonly-rootfs-missing",
		http.MethodPost, "/containers/create",
		`{"Image":"scratch","HostConfig":{"Memory":67108864,"NanoCpus":1000000000,"PidsLimit":100,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"]}}`,
		"read-only root filesystem is required",
	)

	// ── Compliant body → rule-layer allowed ─────────────────────────────────
	// A fully-compliant container_create body should pass the body inspector.
	// The image is deliberately non-existent so dockerd returns 404 (not
	// created), which is not 403, so the "allowed" assertion holds without
	// creating a real container.
	//
	// Note: CIS preset requires memory + CPU + PIDs limits, CapDrop ALL,
	// no-new-privileges, and read-only rootfs.
	t.Run("compliant-body-allowed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		payload := `{
			"Image": "cis-conformance-nonexistent:nosuchtag",
			"HostConfig": {
				"ReadonlyRootfs": true,
				"Memory": 67108864,
				"NanoCpus": 1000000000,
				"PidsLimit": 100,
				"CapDrop": ["ALL"],
				"SecurityOpt": ["no-new-privileges:true"]
			}
		}`

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(payload)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		deniedByCatchAll := rec.Code == http.StatusForbidden &&
			strings.Contains(rec.Body.String(), "no matching allow rule")
		deniedByBodyInspector := rec.Code == http.StatusForbidden &&
			strings.Contains(rec.Body.String(), "container create denied")

		if deniedByCatchAll || deniedByBodyInspector {
			t.Fatalf("CIS preset: compliant container create was denied (status %d, body %s)",
				rec.Code, clipResponseBody(rec.Body.String()))
		}
	})
}
