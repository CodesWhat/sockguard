//go:build integration

package integration_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/ownership"
)

// The finalize exec argv drydock's self-update helper issues. Must match the
// allowed_commands entry in drydock-with-selfupdate.yaml exactly (token count
// + every token). See TestDrydockPresetConformance in internal/filter for the
// full self-update flow rationale; kept in sync with the same constant there.
const drydockIntegrationFinalizeArgvBody = `{"Cmd":["node","dist/triggers/providers/docker/self-update-finalize-entrypoint.js"]}`

// drydockIntegrationFinalizeExecCreateBody is the full exec-create body the
// self-update helper container issues, including the Env array
// buildFinalizeExecEnv assembles. The preset's allowed_env_vars allowlists
// exactly this set, so this body must pass identically to
// drydockIntegrationFinalizeArgvBody.
const drydockIntegrationFinalizeExecCreateBody = `{` +
	`"AttachStdout":true,"AttachStderr":true,` +
	`"Cmd":["node","dist/triggers/providers/docker/self-update-finalize-entrypoint.js"],` +
	`"Env":["DD_SELF_UPDATE_FINALIZE_URL=http://127.0.0.1:3000/api/v1/internal/self-update/finalize",` +
	`"DD_SELF_UPDATE_FINALIZE_SECRET=s3cr3t","DD_SELF_UPDATE_OPERATION_ID=op-1",` +
	`"DD_SELF_UPDATE_STATUS=succeeded","DD_SELF_UPDATE_PHASE=succeeded"]` +
	`}`

// drydockIntegrationFinalizeExecCreateBodyWithNodeOptions is the same body as
// drydockIntegrationFinalizeExecCreateBody with a non-allowlisted Env entry
// (NODE_OPTIONS) appended — proves allowed_env_vars is enforced independently
// of the exact-argv pin.
const drydockIntegrationFinalizeExecCreateBodyWithNodeOptions = `{` +
	`"AttachStdout":true,"AttachStderr":true,` +
	`"Cmd":["node","dist/triggers/providers/docker/self-update-finalize-entrypoint.js"],` +
	`"Env":["DD_SELF_UPDATE_FINALIZE_URL=http://127.0.0.1:3000/api/v1/internal/self-update/finalize",` +
	`"DD_SELF_UPDATE_FINALIZE_SECRET=s3cr3t","DD_SELF_UPDATE_OPERATION_ID=op-1",` +
	`"DD_SELF_UPDATE_STATUS=succeeded","DD_SELF_UPDATE_PHASE=succeeded",` +
	`"NODE_OPTIONS=--require /tmp/evil.js"]` +
	`}`

// drydockIntegrationFinalizeExecCreateBodyWithAttackerURL keeps the exact
// allowed argv and variable names but replaces the trusted loopback callback
// with an attacker-selected internal destination. The preset must reject
// this, and the denial must not reflect the rejected value back to the caller.
const drydockIntegrationFinalizeExecCreateBodyWithAttackerURL = `{` +
	`"AttachStdout":true,"AttachStderr":true,` +
	`"Cmd":["node","dist/triggers/providers/docker/self-update-finalize-entrypoint.js"],` +
	`"Env":["DD_SELF_UPDATE_FINALIZE_URL=http://169.254.169.254/latest/meta-data",` +
	`"DD_SELF_UPDATE_FINALIZE_SECRET=s3cr3t","DD_SELF_UPDATE_OPERATION_ID=op-1",` +
	`"DD_SELF_UPDATE_STATUS=succeeded","DD_SELF_UPDATE_PHASE=succeeded"]` +
	`}`

// newDrydockIntegrationPresetHandler loads the named drydock preset (via
// portwingPresetConfigPath, which locates app/configs independent of which
// preset family calls it) and builds the full sockguard middleware chain
// pointing at socketPath.
func newDrydockIntegrationPresetHandler(t *testing.T, socketPath, presetFile string) http.Handler {
	t.Helper()

	cfg, err := config.Load(portwingPresetConfigPath(t, presetFile))
	if err != nil {
		t.Fatalf("load drydock preset %s: %v", presetFile, err)
	}

	policyConfig := presetPolicyConfig(cfg)

	return newIntegrationProxyHandlerWithOptions(
		t,
		socketPath,
		cfg.Rules,
		filter.Options{PolicyConfig: policyConfig},
		ownership.Options{},
	)
}

// drydockBodyDenied fires one request through handler and asserts that it is
// denied (403) with a decoded reason containing wantSubstring, independent of
// whether the rule layer or a body inspector produced it. The reason is
// decoded via filter.DenialResponse rather than matched as a raw substring of
// the wire body — see portwingBodyDenied's doc comment (portwing_preset_conformance_test.go)
// for why: several reasons here quote an offending value and the JSON
// encoding backslash-escapes those quotes.
func drydockBodyDenied(t *testing.T, handler http.Handler, presetLabel, name, method, path, body, wantSubstring string) {
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

// drydockBodyAllowed fires one request through handler and asserts that it is
// NOT denied (any non-403 status counts as "allowed" — see
// runPresetExpectationWithReason's doc comment for the same convention).
func drydockBodyAllowed(t *testing.T, handler http.Handler, presetLabel, name, method, path, body string) {
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

// drydockContainerCreateBodyCases fires the container-create body-inspector
// assertions shared by every drydock preset variant: allowed_runtimes: [runc]
// admits only the stock runtime a recreate-from-inspect flow carries, and an
// unlistedhost bind mount is denied.
func drydockContainerCreateBodyCases(t *testing.T, handler http.Handler, presetLabel string) {
	t.Helper()

	drydockBodyAllowed(t, handler, presetLabel, "container-create-runc-allowed",
		http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"runc"}}`)
	drydockBodyDenied(t, handler, presetLabel, "container-create-kata-denied",
		http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"kata"}}`,
		"runtime \"kata\" is not allowlisted")
	drydockBodyDenied(t, handler, presetLabel, "container-create-bind-mount-denied",
		http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/etc:/etc"]}}`,
		"bind mount source")
}

// drydockNetworkConnectBodyCases fires the POST /networks/{id}/connect
// body-inspector assertions common to every drydock preset (the connect rule
// itself ships in the base drydock.yaml, unlike Portwing where only the
// compose variant adds it): a Compose-style Aliases-only endpoint is always
// allowed, a static IP is denied by default, and the pre-1.5.3 drydock shape
// (Aliases + a cloned MacAddress) is denied identically. See
// TestDrydockPresetConformance in internal/filter for the full incident
// history these three cases guard against.
func drydockNetworkConnectBodyCases(t *testing.T, handler http.Handler, presetLabel string) {
	t.Helper()

	drydockBodyAllowed(t, handler, presetLabel, "network-connect-aliases-only-allowed",
		http.MethodPost, "/networks/abc/connect", `{"Container":"abc","EndpointConfig":{"Aliases":["myapp"]}}`)
	drydockBodyDenied(t, handler, presetLabel, "network-connect-macvlan-static-ip-denied",
		http.MethodPost, "/networks/abc/connect", `{"Container":"abc","EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.20.0.50"},"Aliases":["myapp"]}}`,
		"endpoint static IP configuration is not allowed")
	drydockBodyDenied(t, handler, presetLabel, "network-connect-aliases-and-macaddress-denied-legacy-drydock",
		http.MethodPost, "/networks/abc/connect", `{"Container":"abc","EndpointConfig":{"Aliases":["myapp"],"MacAddress":"02:42:ac:14:00:0a"}}`,
		"endpoint MAC address is not allowed")
}

// drydockComposeNetworkVolumeBodyCases fires the network/volume create
// body-inspector assertions added by drydock-with-compose.yaml and
// drydock-with-build.yaml on top of drydock.yaml's read-only network/volume
// surface: custom drivers are denied, plain creates pass.
func drydockComposeNetworkVolumeBodyCases(t *testing.T, handler http.Handler, presetLabel string) {
	t.Helper()

	drydockBodyAllowed(t, handler, presetLabel, "network-create-default-allowed",
		http.MethodPost, "/networks/create", `{"Name":"qa2-preset-conformance-net"}`)
	drydockBodyDenied(t, handler, presetLabel, "network-create-custom-driver-denied",
		http.MethodPost, "/networks/create", `{"Name":"qa2-preset-conformance-net","Driver":"weave"}`,
		"network create denied: driver")

	drydockBodyAllowed(t, handler, presetLabel, "volume-create-default-allowed",
		http.MethodPost, "/volumes/create", `{"Name":"qa2-preset-conformance-vol"}`)
	drydockBodyDenied(t, handler, presetLabel, "volume-create-custom-driver-denied",
		http.MethodPost, "/volumes/create", `{"Name":"qa2-preset-conformance-vol","Driver":"custom"}`,
		"volume create denied: driver")
}

// mustDrydockBuildContextTar builds a minimal single-file tar archive
// containing dockerfilePath, the same way the daemon receives a classic
// `docker build` context.
func mustDrydockBuildContextTar(t *testing.T, dockerfilePath, dockerfile string) []byte {
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

// drydockBuildBodyCases fires the POST /build body/query-inspector assertions
// for drydock-with-build.yaml's classic-builder support: remote contexts and
// host-network builds are denied before any body is read, a Dockerfile RUN
// instruction is denied by the RUN-instruction scan, and a RUN-free classic
// build reaches the real daemon.
func drydockBuildBodyCases(t *testing.T, handler http.Handler, presetLabel string) {
	t.Helper()

	drydockBodyDenied(t, handler, presetLabel, "build-remote-context-denied",
		http.MethodPost, "/build?remote=https://example.com/repo.git", "",
		"build denied: remote build context")
	drydockBodyDenied(t, handler, presetLabel, "build-host-network-denied",
		http.MethodPost, "/build?networkmode=host", "",
		"build denied: host network mode is not allowed")

	t.Run("build-run-instruction-denied", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		tarBody := mustDrydockBuildContextTar(t, "Dockerfile", "FROM scratch\nRUN echo hi\n")
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

		tarBody := mustDrydockBuildContextTar(t, "Dockerfile", "FROM scratch\n")
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

// TestDrydockPresetConformance fires drydock's real Docker Engine API surface
// at a sockguard chain built from each shipped drydock preset, pointed at a
// real dockerd. It is the integration-tier counterpart of
// TestDrydockPresetConformance in internal/filter (stub upstream, no daemon);
// this version proves the same rule/body-inspector verdicts hold end-to-end.
//
//   - drydock.yaml enumerates reads path-by-path (no logs/archive/export/attach)
//     and denies exec entirely; container recreate's HostConfig.Runtime "runc"
//     passes allowed_runtimes, and the multi-network connect call is allowed
//     by rule with the same endpoint-config posture as every other variant;
//   - drydock-with-compose.yaml additionally allows network/volume
//     create/delete/disconnect for compose stack lifecycle;
//   - drydock-with-build.yaml layers classic-builder POST /build on top of
//     the compose preset;
//   - drydock-with-selfupdate.yaml instead adds the exact-argv, env-pinned
//     finalize exec on top of the base drydock.yaml surface (no compose/build
//     additions).
//
// The exec *start* path (POST /exec/*/start) needs a daemon round-trip to
// inspect the existing exec; newIntegrationProxyHandlerWithOptions does not
// wire InspectStart (see serve.go), so it always denies with "no exec
// inspection configured" independent of preset — excluded from the
// assertions for the same reason the filter-level test excludes it.
func TestDrydockPresetConformance(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)

	// ── drydock.yaml ─────────────────────────────────────────────────────────
	t.Run("drydock.yaml", func(t *testing.T) {
		handler := newDrydockIntegrationPresetHandler(t, socketPath, "drydock.yaml")
		reason := "not allowed by drydock preset"

		for _, exp := range []presetExpectation{
			{http.MethodGet, "/_ping", true},
			{http.MethodHead, "/_ping", true},
			{http.MethodGet, "/version", true},
			{http.MethodGet, "/info", true},
			{http.MethodGet, "/events?until=0", true},

			// Narrow read set — deliberately omits logs/archive/export/attach.
			{http.MethodGet, "/containers/json", true},
			{http.MethodGet, "/containers/abc/json", true},
			{http.MethodGet, "/containers/abc/stats", true},
			{http.MethodGet, "/containers/abc/top", true},
			{http.MethodGet, "/containers/abc/changes", true},

			{http.MethodPost, "/containers/abc/start", true},
			{http.MethodPost, "/containers/abc/stop", true},
			{http.MethodPost, "/containers/abc/restart", true},
			{http.MethodPost, "/containers/abc/kill", true},
			{http.MethodPost, "/containers/abc/rename", true},
			{http.MethodPost, "/containers/abc/update", true},
			{http.MethodPost, "/containers/abc/wait", true},
			{http.MethodDelete, "/containers/abc", true},
			{http.MethodPost, "/containers/create", true},

			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/images/busybox/json", true},
			{http.MethodGet, "/images/library/busybox/json", true},
			{http.MethodGet, "/images/busybox/history", true},
			{http.MethodPost, "/images/create", true},
			{http.MethodDelete, "/images/busybox", true},

			// Network read + connect (no create/delete/disconnect on the base preset).
			{http.MethodGet, "/networks", true},
			{http.MethodGet, "/networks/abc", true},
			{http.MethodPost, "/networks/abc/connect", true},

			{http.MethodGet, "/volumes", true},
			{http.MethodGet, "/volumes/abc", true},
			{http.MethodGet, "/distribution/busybox/json", true},
			{http.MethodGet, "/services", true},
			{http.MethodGet, "/services/abc", true},

			// Deliberately-omitted exfiltration surface, secrets, BuildKit tunnels.
			{http.MethodGet, "/containers/abc/logs", false},
			{http.MethodGet, "/containers/abc/archive", false},
			{http.MethodGet, "/containers/abc/export", false},
			{http.MethodPost, "/containers/abc/attach", false},
			{http.MethodPost, "/secrets/create", false},
			{http.MethodPost, "/session", false},
			{http.MethodPost, "/grpc", false},

			// The base preset denies exec entirely.
			{http.MethodPost, "/containers/abc/exec", false},
			{http.MethodPost, "/exec/abc/resize", false},
			{http.MethodGet, "/exec/abc/json", false},

			// No compose lifecycle, no build.
			{http.MethodPost, "/networks/create", false},
			{http.MethodDelete, "/networks/abc", false},
			{http.MethodPost, "/networks/abc/disconnect", false},
			{http.MethodPost, "/volumes/create", false},
			{http.MethodDelete, "/volumes/abc", false},
			{http.MethodPost, "/build", false},
		} {
			runPresetExpectationWithReason(t, handler, "drydock.yaml", exp, reason)
		}

		drydockContainerCreateBodyCases(t, handler, "drydock.yaml")
		drydockNetworkConnectBodyCases(t, handler, "drydock.yaml")
	})

	// ── drydock-with-compose.yaml ────────────────────────────────────────────
	t.Run("drydock-with-compose.yaml", func(t *testing.T) {
		handler := newDrydockIntegrationPresetHandler(t, socketPath, "drydock-with-compose.yaml")
		reason := "not allowed by drydock-with-compose preset"

		for _, exp := range []presetExpectation{
			{http.MethodGet, "/_ping", true},
			{http.MethodGet, "/containers/json", true},
			{http.MethodPost, "/containers/abc/start", true},
			{http.MethodDelete, "/containers/abc", true},
			{http.MethodPost, "/containers/create", true},
			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/services", true},

			{http.MethodGet, "/networks", true},
			{http.MethodGet, "/networks/abc", true},
			{http.MethodPost, "/networks/abc/connect", true},
			// New compose lifecycle surface.
			{http.MethodPost, "/networks/create", true},
			{http.MethodDelete, "/networks/abc", true},
			{http.MethodPost, "/networks/abc/disconnect", true},
			{http.MethodPost, "/volumes/create", true},
			{http.MethodDelete, "/volumes/abc", true},

			{http.MethodGet, "/containers/abc/logs", false},
			{http.MethodPost, "/secrets/create", false},
			{http.MethodPost, "/build", false},
			// Exec still denied entirely — self-update finalize needs the
			// dedicated drydock-with-selfupdate.yaml preset.
			{http.MethodPost, "/containers/abc/exec", false},
			{http.MethodGet, "/exec/abc/json", false},
		} {
			runPresetExpectationWithReason(t, handler, "drydock-with-compose.yaml", exp, reason)
		}

		drydockContainerCreateBodyCases(t, handler, "drydock-with-compose.yaml")
		drydockNetworkConnectBodyCases(t, handler, "drydock-with-compose.yaml")
		drydockComposeNetworkVolumeBodyCases(t, handler, "drydock-with-compose.yaml")
	})

	// ── drydock-with-build.yaml ──────────────────────────────────────────────
	t.Run("drydock-with-build.yaml", func(t *testing.T) {
		handler := newDrydockIntegrationPresetHandler(t, socketPath, "drydock-with-build.yaml")
		reason := "not allowed by drydock-with-build preset"

		for _, exp := range []presetExpectation{
			{http.MethodGet, "/_ping", true},
			{http.MethodGet, "/containers/json", true},
			{http.MethodPost, "/containers/create", true},
			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/services", true},
			// Compose lifecycle surface carried over from drydock-with-compose.yaml.
			{http.MethodPost, "/networks/create", true},
			{http.MethodPost, "/networks/abc/connect", true},
			{http.MethodPost, "/volumes/create", true},
			// Classic builder now allowed.
			{http.MethodPost, "/build", true},

			{http.MethodGet, "/containers/abc/logs", false},
			{http.MethodPost, "/secrets/create", false},
			// BuildKit's opaque tunnels stay denied even though /build opened.
			{http.MethodPost, "/session", false},
			{http.MethodPost, "/grpc", false},
			// Exec still denied entirely.
			{http.MethodPost, "/containers/abc/exec", false},
		} {
			runPresetExpectationWithReason(t, handler, "drydock-with-build.yaml", exp, reason)
		}

		drydockContainerCreateBodyCases(t, handler, "drydock-with-build.yaml")
		drydockNetworkConnectBodyCases(t, handler, "drydock-with-build.yaml")
		drydockComposeNetworkVolumeBodyCases(t, handler, "drydock-with-build.yaml")
		drydockBuildBodyCases(t, handler, "drydock-with-build.yaml")
	})

	// ── drydock-with-selfupdate.yaml ─────────────────────────────────────────
	t.Run("drydock-with-selfupdate.yaml", func(t *testing.T) {
		handler := newDrydockIntegrationPresetHandler(t, socketPath, "drydock-with-selfupdate.yaml")
		reason := "not allowed by drydock-with-selfupdate preset"

		for _, exp := range []presetExpectation{
			{http.MethodGet, "/_ping", true},
			{http.MethodGet, "/containers/json", true},
			{http.MethodPost, "/containers/abc/start", true},
			{http.MethodDelete, "/containers/abc", true},
			{http.MethodPost, "/containers/create", true},
			{http.MethodGet, "/images/json", true},
			{http.MethodGet, "/services", true},
			{http.MethodGet, "/networks", true},
			{http.MethodPost, "/networks/abc/connect", true},

			// Expanded exec surface vs. drydock.yaml: create, start-rule (start
			// itself is excluded from assertions, see the doc comment), inspect.
			{http.MethodPost, "/containers/abc/exec", true},
			{http.MethodGet, "/exec/abc/json", true},
			// No resize rule on this preset either.
			{http.MethodPost, "/exec/abc/resize", false},

			{http.MethodGet, "/containers/abc/logs", false},
			{http.MethodPost, "/secrets/create", false},
			{http.MethodPost, "/build", false},
			// No compose lifecycle on this preset.
			{http.MethodPost, "/networks/create", false},
			{http.MethodPost, "/volumes/create", false},
		} {
			runPresetExpectationWithReason(t, handler, "drydock-with-selfupdate.yaml", exp, reason)
		}

		// allowed_bind_mounts here is [/var/run/docker.sock], not [] — verify
		// the positive case in addition to the shared kata/etc-bind-mount
		// denials drydockContainerCreateBodyCases already covers.
		drydockBodyAllowed(t, handler, "drydock-with-selfupdate.yaml", "container-create-docker-socket-bind-allowed",
			http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`)
		drydockContainerCreateBodyCases(t, handler, "drydock-with-selfupdate.yaml")
		drydockNetworkConnectBodyCases(t, handler, "drydock-with-selfupdate.yaml")

		// The finalize exec: exact argv, no User field. Allowed only because
		// allow_root_user is true (empty User reads as root).
		drydockBodyAllowed(t, handler, "drydock-with-selfupdate.yaml", "finalize-exec-allowed",
			http.MethodPost, "/containers/abc/exec", drydockIntegrationFinalizeArgvBody)
		// The real body the helper container sends, Env included — the
		// preset's allowed_env_vars allowlists exactly the DD_SELF_UPDATE_*
		// names it carries, so the verdict is unchanged.
		drydockBodyAllowed(t, handler, "drydock-with-selfupdate.yaml", "finalize-exec-allowed-full-body",
			http.MethodPost, "/containers/abc/exec", drydockIntegrationFinalizeExecCreateBody)
		// Any other exec command stays denied by the exact-argv allowlist.
		drydockBodyDenied(t, handler, "drydock-with-selfupdate.yaml", "exec-shell-denied",
			http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh","-c","id"]}`,
			"is not allowlisted")
		drydockBodyDenied(t, handler, "drydock-with-selfupdate.yaml", "exec-other-node-denied",
			http.MethodPost, "/containers/abc/exec", `{"Cmd":["node","evil.js"]}`,
			"is not allowlisted")
		// Same allowlisted argv, but with an extra non-allowlisted Env entry
		// (NODE_OPTIONS): allowed_env_vars must deny this even though
		// allowed_commands alone would have let it through.
		drydockBodyDenied(t, handler, "drydock-with-selfupdate.yaml", "finalize-exec-denied-node-options-env",
			http.MethodPost, "/containers/abc/exec", drydockIntegrationFinalizeExecCreateBodyWithNodeOptions,
			"environment variable \"NODE_OPTIONS\"")

		// Exact value pinning prevents the finalize callback from becoming an
		// SSRF primitive even when argv and variable names are valid — and the
		// denial must not reflect the rejected value back to the caller.
		t.Run("finalize-exec-denied-attacker-url", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/containers/abc/exec",
				strings.NewReader(drydockIntegrationFinalizeExecCreateBodyWithAttackerURL)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("drydock-with-selfupdate.yaml: attacker-URL finalize exec: status = %d, want %d (body: %s)",
					rec.Code, http.StatusForbidden, clipResponseBody(rec.Body.String()))
			}
			if strings.Contains(rec.Body.String(), "169.254.169.254") {
				t.Fatalf("drydock-with-selfupdate.yaml: denial reflected the rejected environment value: %s", rec.Body.String())
			}
		})
	})
}
