//go:build integration

package integration_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/ownership"
)

// portwingPresetConfigPath returns the absolute path to the named Portwing
// preset YAML under app/configs, regardless of the working directory the test
// runner uses.
func portwingPresetConfigPath(t *testing.T, presetFile string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate preset config")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(thisFile)), "configs", presetFile)
}

// newPortwingPresetHandler loads the named Portwing preset and builds the
// full sockguard middleware chain pointing at socketPath.
func newPortwingPresetHandler(t *testing.T, socketPath, presetFile string) http.Handler {
	t.Helper()

	cfg, err := config.Load(portwingPresetConfigPath(t, presetFile))
	if err != nil {
		t.Fatalf("load Portwing preset %s: %v", presetFile, err)
	}

	policyConfig := presetPolicyConfig(cfg)

	return newIntegrationProxyHandlerWithOptions(
		t,
		socketPath,
		cfg.Rules,
		filter.Options{
			PolicyConfig:          policyConfig,
			AllowReadExfiltration: cfg.InsecureAllowReadExfiltration,
		},
		ownership.Options{},
	)
}

// portwingBodyDenied fires one request through handler and asserts that it is
// denied (403) with a decoded reason containing wantSubstring. Unlike
// runPresetExpectationWithReason (tecnativa_preset_conformance_test.go), the
// cases here need bespoke request bodies (exec argv, HostConfig.Runtime,
// network EndpointConfig) that the shared presetExpectation cases do not
// carry, and they assert whichever layer (rule or body inspector) produced
// the denial, matching the scope of the filter-level
// TestPortwingPresetConformance in internal/filter.
//
// The reason is decoded via filter.DenialResponse (rather than a raw
// substring match on the response body, as gitlabBodyDenied/ghaBodyDenied do)
// because several reasons here quote an offending value (e.g. runtime
// "kata") — the JSON wire encoding backslash-escapes those quotes, so a raw
// byte-level Contains would need to match the escaped form instead of the
// human-readable one.
func portwingBodyDenied(t *testing.T, handler http.Handler, presetLabel, name, method, path, body, wantSubstring string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %s %s: status = %d, want %d (body: %s)",
				presetLabel, method, path, rec.Code, http.StatusForbidden, clipResponseBody(rec.Body.String()))
		}

		var denial filter.DenialResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil {
			t.Fatalf("%s: %s %s: decode deny body: %v (body: %s)",
				presetLabel, method, path, err, clipResponseBody(rec.Body.String()))
		}
		if !strings.Contains(denial.Reason, wantSubstring) {
			t.Fatalf("%s: %s %s: deny reason = %q, want substring %q",
				presetLabel, method, path, denial.Reason, wantSubstring)
		}
	})
}

// portwingBodyAllowed fires one request through handler and asserts that it
// is NOT denied (any non-403 status, including an upstream 4xx for a
// nonexistent resource, counts as "allowed" — see runPresetExpectationWithReason's
// doc comment for the same convention).
func portwingBodyAllowed(t *testing.T, handler http.Handler, presetLabel, name, method, path, body string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		if rec.Code == http.StatusForbidden {
			t.Fatalf("%s: %s %s was denied but should be allowed (status %d, body %s)",
				presetLabel, method, path, rec.Code, clipResponseBody(rec.Body.String()))
		}
	})
}

// portwingContainerCreateBodyCases fires the container-create body-inspector
// assertions shared by every Portwing preset variant: allowed_bind_mounts: []
// denies any host bind mount, and allowed_runtimes: [runc] admits only the
// stock runtime Portwing's recreate-from-inspect flow carries.
func portwingContainerCreateBodyCases(t *testing.T, handler http.Handler, presetLabel string) {
	t.Helper()

	portwingBodyAllowed(t, handler, presetLabel, "container-create-runc-allowed",
		http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"runc"}}`)
	portwingBodyDenied(t, handler, presetLabel, "container-create-kata-denied",
		http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"kata"}}`,
		"runtime \"kata\" is not allowlisted")
	portwingBodyDenied(t, handler, presetLabel, "container-create-bind-mount-denied",
		http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/etc:/etc"]}}`,
		"bind mount source")
}

// portwingComposeNetworkVolumeBodyCases fires the network/volume body-inspector
// assertions shared by portwing-with-compose.yaml and portwing-with-build.yaml
// (both add network/volume create + network connect/disconnect on top of
// portwing.yaml's read-only network/volume surface): custom drivers are
// denied, plain creates pass, and the multi-network-connect endpoint-config
// posture matches drydock's — Aliases-only is always allowed (Compose sets it
// on every endpoint), a static IP is denied by default.
func portwingComposeNetworkVolumeBodyCases(t *testing.T, handler http.Handler, presetLabel string) {
	t.Helper()

	portwingBodyAllowed(t, handler, presetLabel, "network-create-default-allowed",
		http.MethodPost, "/networks/create", `{"Name":"qa2-preset-conformance-net"}`)
	portwingBodyDenied(t, handler, presetLabel, "network-create-custom-driver-denied",
		http.MethodPost, "/networks/create", `{"Name":"qa2-preset-conformance-net","Driver":"weave"}`,
		"network create denied: driver")
	portwingBodyAllowed(t, handler, presetLabel, "network-connect-aliases-only-allowed",
		http.MethodPost, "/networks/abc/connect", `{"Container":"abc","EndpointConfig":{"Aliases":["myapp"]}}`)
	portwingBodyDenied(t, handler, presetLabel, "network-connect-static-ip-denied",
		http.MethodPost, "/networks/abc/connect", `{"Container":"abc","EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.20.0.50"}}}`,
		"endpoint static IP configuration is not allowed")

	portwingBodyAllowed(t, handler, presetLabel, "volume-create-default-allowed",
		http.MethodPost, "/volumes/create", `{"Name":"qa2-preset-conformance-vol"}`)
	portwingBodyDenied(t, handler, presetLabel, "volume-create-custom-driver-denied",
		http.MethodPost, "/volumes/create", `{"Name":"qa2-preset-conformance-vol","Driver":"custom"}`,
		"volume create denied: driver")
}

// portwingBuildBodyCases fires the POST /build body/query-inspector
// assertions for portwing-with-build.yaml's classic-builder support: remote
// contexts and host-network builds are denied outright (checked before any
// body is read), a Dockerfile RUN instruction is denied by the RUN-instruction
// scan, and a RUN-free classic build reaches the real daemon.
func portwingBuildBodyCases(t *testing.T, handler http.Handler, presetLabel string) {
	t.Helper()

	portwingBodyDenied(t, handler, presetLabel, "build-remote-context-denied",
		http.MethodPost, "/build?remote=https://example.com/repo.git", "",
		"build denied: remote build context")
	portwingBodyDenied(t, handler, presetLabel, "build-host-network-denied",
		http.MethodPost, "/build?networkmode=host", "",
		"build denied: host network mode is not allowed")

	t.Run("build-run-instruction-denied", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		tarBody := mustPortwingBuildContextTar(t, "Dockerfile", "FROM scratch\nRUN echo hi\n")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(tarBody))).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-tar")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: build with RUN: status = %d, want %d (body: %s)",
				presetLabel, rec.Code, http.StatusForbidden, clipResponseBody(rec.Body.String()))
		}
		if !strings.Contains(rec.Body.String(), "RUN instructions are not allowed") {
			t.Fatalf("%s: build with RUN: deny body = %q, want RUN-instruction substring",
				presetLabel, clipResponseBody(rec.Body.String()))
		}
	})

	t.Run("build-run-free-classic-build-allowed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		tarBody := mustPortwingBuildContextTar(t, "Dockerfile", "FROM scratch\n")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(tarBody))).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-tar")
		handler.ServeHTTP(rec, req)

		if rec.Code == http.StatusForbidden {
			t.Fatalf("%s: RUN-free classic build was denied (status %d, body %s)",
				presetLabel, rec.Code, clipResponseBody(rec.Body.String()))
		}
	})
}

// mustPortwingBuildContextTar builds a minimal single-file tar archive
// containing dockerfilePath, the same way the daemon receives a classic
// `docker build` context.
func mustPortwingBuildContextTar(t *testing.T, dockerfilePath, dockerfile string) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: dockerfilePath,
		Mode: 0o644,
		Size: int64(len(dockerfile)),
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write([]byte(dockerfile)); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestPortwingPresetConformance fires portwing's actual internal/docker/client.go
// call surface (ListContainers, InspectContainer, RemoveContainer,
// GetContainerLogs with follow, ContainerStats, GetEvents, GetDockerInfo,
// GetVersion, Ping, CreateExec/StartExec/ResizeExec) plus the compose/build
// extensions, against a sockguard chain built from each shipped Portwing
// preset, pointed at a real dockerd. It is the integration-tier counterpart of
// TestPortwingPresetConformance in internal/filter (stub upstream, no daemon);
// this version proves the same rule/body-inspector verdicts hold end-to-end.
//
//   - portwing.yaml denies exec entirely and has no network/volume write
//     surface — every such path falls to the default-deny catch-all;
//   - portwing-with-exec.yaml additionally allows all four exec paths, with
//     insecure_allow_body_blind_writes lifting only the empty-allowlist gate
//     (allow_privileged still enforced);
//   - portwing-with-compose.yaml additionally allows network/volume
//     create/connect/disconnect/delete for compose stack lifecycle;
//   - portwing-with-build.yaml layers classic-builder POST /build on top of
//     the compose preset.
//
// POST /exec/{id}/start needs a docker-backed InspectStart lookup wired at
// serve time (internal/cmd/serve.go), not by config; newIntegrationProxyHandlerWithOptions
// does not wire it, so start always denies with "no exec inspection
// configured" independent of preset — excluded from the assertions for the
// same reason the filter-level test excludes it.
func TestPortwingPresetConformance(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)

	// ── portwing.yaml ────────────────────────────────────────────────────────
	t.Run("portwing.yaml", func(t *testing.T) {
		handler := newPortwingPresetHandler(t, socketPath, "portwing.yaml")
		reason := "not allowed by portwing preset"

		for _, exp := range []presetExpectation{
			// Health + metadata.
			{http.MethodGet, "/_ping", true},
			{http.MethodHead, "/_ping", true},
			{http.MethodGet, "/version", true},
			{http.MethodGet, "/info", true},
			{http.MethodGet, "/events?until=0", true},

			// Container reads Portwing's docker client uses, including logs
			// (insecure_allow_read_exfiltration: true acknowledges the tradeoff).
			{http.MethodGet, "/containers/json", true},
			{http.MethodGet, "/containers/abc/json", true},
			{http.MethodGet, "/containers/abc/logs?follow=1", true},
			{http.MethodGet, "/containers/abc/stats?stream=false&one-shot=true", true},
			{http.MethodGet, "/containers/abc/top", false},
			{http.MethodGet, "/containers/abc/changes", true},

			// Container lifecycle + create.
			{http.MethodPost, "/containers/abc/start", true},
			{http.MethodPost, "/containers/abc/stop", true},
			{http.MethodPost, "/containers/abc/restart", true},
			{http.MethodPost, "/containers/abc/kill", true},
			{http.MethodPost, "/containers/abc/rename", true},
			{http.MethodPost, "/containers/abc/update", true},
			{http.MethodPost, "/containers/abc/wait", true},
			{http.MethodDelete, "/containers/abc", true},
			{http.MethodPost, "/containers/create", true},

			// Image reads + pull + delete.
			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/images/busybox/json", true},
			{http.MethodGet, "/images/library/busybox/json", true},
			{http.MethodGet, "/images/busybox/history", true},
			{http.MethodPost, "/images/create", true},
			{http.MethodDelete, "/images/busybox", true},

			// Network + volume reads only.
			{http.MethodGet, "/networks", true},
			{http.MethodGet, "/networks/abc", true},
			{http.MethodGet, "/volumes", true},
			{http.MethodGet, "/volumes/abc", true},

			// Distribution + Swarm service reads.
			{http.MethodGet, "/distribution/busybox/json", true},
			{http.MethodGet, "/services", true},
			{http.MethodGet, "/services/abc", true},

			// Bulk-data exfiltration streams, secrets, and BuildKit's opaque
			// tunnels are denied on every Portwing variant.
			{http.MethodGet, "/containers/abc/archive", false},
			{http.MethodGet, "/containers/abc/export", false},
			{http.MethodPost, "/containers/abc/attach", false},
			{http.MethodPost, "/secrets/create", false},
			{http.MethodPost, "/session", false},
			{http.MethodPost, "/grpc", false},

			// No exec rules at all in the base preset.
			{http.MethodPost, "/containers/abc/exec", false},
			{http.MethodPost, "/exec/abc/resize", false},
			{http.MethodGet, "/exec/abc/json", false},

			// No network/volume write surface, no build.
			{http.MethodPost, "/networks/create", false},
			{http.MethodPost, "/networks/abc/connect", false},
			{http.MethodDelete, "/networks/abc", false},
			{http.MethodPost, "/networks/abc/disconnect", false},
			{http.MethodPost, "/volumes/create", false},
			{http.MethodDelete, "/volumes/abc", false},
			{http.MethodPost, "/build", false},
		} {
			runPresetExpectationWithReason(t, handler, "portwing.yaml", exp, reason)
		}

		portwingContainerCreateBodyCases(t, handler, "portwing.yaml")
	})

	// ── portwing-with-exec.yaml ──────────────────────────────────────────────
	t.Run("portwing-with-exec.yaml", func(t *testing.T) {
		handler := newPortwingPresetHandler(t, socketPath, "portwing-with-exec.yaml")
		reason := "not allowed by portwing-with-exec preset"

		for _, exp := range []presetExpectation{
			{http.MethodGet, "/_ping", true},
			{http.MethodGet, "/containers/json", true},
			{http.MethodGet, "/containers/abc/logs?follow=1", true},
			{http.MethodPost, "/containers/abc/start", true},
			{http.MethodDelete, "/containers/abc", true},
			{http.MethodPost, "/containers/create", true},
			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/networks", true},
			{http.MethodGet, "/volumes", true},
			{http.MethodGet, "/services", true},

			{http.MethodGet, "/containers/abc/archive", false},
			{http.MethodPost, "/secrets/create", false},
			{http.MethodPost, "/build", false},
			// Compose lifecycle still not opened by this preset.
			{http.MethodPost, "/networks/create", false},
			{http.MethodPost, "/volumes/create", false},

			// Resize and inspect carry no exec-specific body inspection
			// (isExecCreatePath/isExecStartPath don't match them), so the rule
			// layer alone governs — both are genuinely allowed here.
			{http.MethodPost, "/exec/abc/resize", true},
			{http.MethodGet, "/exec/abc/json", true},
		} {
			runPresetExpectationWithReason(t, handler, "portwing-with-exec.yaml", exp, reason)
		}

		portwingContainerCreateBodyCases(t, handler, "portwing-with-exec.yaml")

		// insecure_allow_body_blind_writes: true + empty allowed_commands: an
		// otherwise-clean exec is genuinely allowed — the preset's header claim
		// delivers.
		portwingBodyAllowed(t, handler, "portwing-with-exec.yaml", "exec-create-allowed-blind-write-flag",
			http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh","-c","id"]}`)
		// The blind-write flag only lifts the allowlist gate: privileged exec
		// still hits allow_privileged: false and is denied.
		portwingBodyDenied(t, handler, "portwing-with-exec.yaml", "exec-create-privileged-still-denied",
			http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"],"Privileged":true}`,
			"privileged exec is not allowed")
	})

	// ── portwing-with-compose.yaml ───────────────────────────────────────────
	t.Run("portwing-with-compose.yaml", func(t *testing.T) {
		handler := newPortwingPresetHandler(t, socketPath, "portwing-with-compose.yaml")
		reason := "not allowed by portwing-with-compose preset"

		for _, exp := range []presetExpectation{
			{http.MethodGet, "/_ping", true},
			{http.MethodGet, "/containers/json", true},
			{http.MethodGet, "/containers/abc/logs?follow=1", true},
			{http.MethodPost, "/containers/abc/start", true},
			{http.MethodDelete, "/containers/abc", true},
			{http.MethodPost, "/containers/create", true},
			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/services", true},

			{http.MethodGet, "/networks", true},
			{http.MethodGet, "/networks/abc", true},
			{http.MethodGet, "/volumes", true},
			{http.MethodGet, "/volumes/abc", true},
			// New compose lifecycle surface.
			{http.MethodPost, "/networks/create", true},
			{http.MethodPost, "/networks/abc/connect", true},
			{http.MethodDelete, "/networks/abc", true},
			{http.MethodPost, "/networks/abc/disconnect", true},
			{http.MethodPost, "/volumes/create", true},
			{http.MethodDelete, "/volumes/abc", true},

			{http.MethodGet, "/containers/abc/archive", false},
			{http.MethodPost, "/secrets/create", false},
			{http.MethodPost, "/build", false},
			// Exec still denied entirely on the compose preset.
			{http.MethodPost, "/containers/abc/exec", false},
			{http.MethodPost, "/exec/abc/resize", false},
			{http.MethodGet, "/exec/abc/json", false},
		} {
			runPresetExpectationWithReason(t, handler, "portwing-with-compose.yaml", exp, reason)
		}

		portwingContainerCreateBodyCases(t, handler, "portwing-with-compose.yaml")
		portwingComposeNetworkVolumeBodyCases(t, handler, "portwing-with-compose.yaml")
	})

	// ── portwing-with-build.yaml ─────────────────────────────────────────────
	t.Run("portwing-with-build.yaml", func(t *testing.T) {
		handler := newPortwingPresetHandler(t, socketPath, "portwing-with-build.yaml")
		reason := "not allowed by portwing-with-build preset"

		for _, exp := range []presetExpectation{
			{http.MethodGet, "/_ping", true},
			{http.MethodGet, "/containers/json", true},
			{http.MethodPost, "/containers/abc/start", true},
			{http.MethodPost, "/containers/create", true},
			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/services", true},
			// Compose lifecycle surface carried over from portwing-with-compose.yaml.
			{http.MethodPost, "/networks/create", true},
			{http.MethodPost, "/networks/abc/connect", true},
			{http.MethodPost, "/volumes/create", true},
			// Classic builder now allowed.
			{http.MethodPost, "/build", true},

			{http.MethodGet, "/containers/abc/archive", false},
			{http.MethodPost, "/secrets/create", false},
			// BuildKit's opaque tunnels stay denied even though /build opened.
			{http.MethodPost, "/session", false},
			{http.MethodPost, "/grpc", false},
			// Exec still denied entirely.
			{http.MethodPost, "/containers/abc/exec", false},
		} {
			runPresetExpectationWithReason(t, handler, "portwing-with-build.yaml", exp, reason)
		}

		portwingContainerCreateBodyCases(t, handler, "portwing-with-build.yaml")
		portwingComposeNetworkVolumeBodyCases(t, handler, "portwing-with-build.yaml")
		portwingBuildBodyCases(t, handler, "portwing-with-build.yaml")
	})
}
