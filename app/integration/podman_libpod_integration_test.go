//go:build podmanintegration

// Package integration_test's podman-tagged suite exercises the libpod
// inspectors added by #148 (see app/internal/filter/libpod_*.go and the
// design doc's "Sequencing" PR6 entry) against a REAL `podman system
// service` socket — rootful and rootless, per
// .github/workflows/quality-integration-podman.yml — the same way
// docker_integration_test.go exercises the Docker-compat inspectors against
// a real dockerd. Handler construction is shared with the Docker suite
// (newIntegrationProxyHandlerWithOptions, helpers_test.go) since the
// middleware chain itself has no daemon-specific behavior; only the request
// paths/bodies and the pinger/cleanup helpers (podman_helpers_test.go) are
// libpod-specific.
package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/ownership"
)

func TestProxyReachesRealPodmanVersion(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	version := fetchLibpodVersion(t, socketPath)

	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/version"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/libpod/version", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body libpodVersionResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Version.APIVersion != version.Version.APIVersion {
		t.Fatalf("APIVersion = %q, want %q", body.Version.APIVersion, version.Version.APIVersion)
	}
}

func TestProxyAllowsPlainLibpodContainerCreateAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	// "systemd":"false" is required: SpecGenerator's own default is "true"
	// (see testdata/libpod/basic_create.json) and sockguard's
	// AllowSystemdMode defaults to false — a "plain" body still has to say
	// systemd=false explicitly to pass the default-deny gate.
	payload := `{"image":"` + busyboxPinnedRef + `","command":["sleep","30"],"systemd":"false"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var body libpodContainerCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Id == "" {
		t.Fatal("expected libpod create response Id")
	}
	removeLibpodContainer(t, socketPath, body.Id)
}

func TestProxyDeniesPrivilegedLibpodContainerCreateAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	payload := `{"image":"` + busyboxPinnedRef + `","privileged":true,"systemd":"false"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "libpod container create denied: privileged containers are not allowed") {
		t.Fatalf("deny body = %q, want libpod-prefixed privileged reason", rec.Body.String())
	}
}

func TestProxyDeniesDangerousLibpodPodCreateBodiesAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)

	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "host network namespace",
			payload: `{"netns":{"nsmode":"host"}}`,
			want:    "libpod pod create denied: host network namespace is not allowed",
		},
		{
			// AllowedInfraImageRegistries defaults empty: ANY explicit
			// infra_image is denied regardless of which registry it names —
			// see LibpodPodCreateOptions.AllowedInfraImageRegistries's doc
			// comment. quay.io is picked here only because it is a
			// registry a Docker Hub-only allowlist would plausibly miss,
			// not because it needs to be "bad" in any other sense.
			name:    "disallowed infra image registry",
			payload: `{"infra_image":"quay.io/podman/pause:5.0"}`,
			want:    `libpod pod create denied: infra image registry "quay.io" is not allowlisted`,
		},
	}

	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/pods/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Fatalf("deny body = %q, want substring %q", rec.Body.String(), tt.want)
			}
		})
	}
}

// TestLibpodExecHonorsSharedRequestBodyExecConfigAgainstRealPodman pins #148
// design decision C3: libpod exec create/start are gated by the SAME
// request_body.exec config (filter.ExecOptions) as the Docker-compat exec
// paths, not a separate libpod_exec block. It creates and starts a real
// container, then drives exec create/start through sockguard against that
// real container: a disallowed command is denied before ever reaching
// Podman, an allowlisted command is forwarded and actually created/started.
func TestLibpodExecHonorsSharedRequestBodyExecConfigAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)

	setupHandler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	createPayload := `{"image":"` + busyboxPinnedRef + `","command":["sleep","30"],"systemd":"false"}`
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(createPayload))
	createReq.Header.Set("Content-Type", "application/json")
	setupHandler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body: %s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}

	var createBody libpodContainerCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&createBody); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createBody.Id == "" {
		t.Fatal("expected libpod create response Id")
	}
	t.Cleanup(func() { removeLibpodContainer(t, socketPath, createBody.Id) })

	startRec := httptest.NewRecorder()
	startReq := httptest.NewRequest(http.MethodPost, "/libpod/containers/"+url.PathEscape(createBody.Id)+"/start", nil)
	setupHandler.ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusNoContent && startRec.Code != http.StatusOK {
		t.Fatalf("start status = %d, want %d or %d; body: %s", startRec.Code, http.StatusNoContent, http.StatusOK, startRec.Body.String())
	}
	waitForLibpodContainerRunning(t, socketPath, createBody.Id)

	execOpts := filter.ExecOptions{
		AllowedCommands:    [][]string{{"echo", "hello"}},
		InspectStartLibpod: filter.NewLibpodExecInspector(socketPath),
	}
	execHandler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/exec"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/exec/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{PolicyConfig: filter.PolicyConfig{Exec: execOpts}}, ownership.Options{})

	// Disallowed command: denied by sockguard before the request ever
	// reaches Podman — no exec instance is created upstream.
	deniedRec := httptest.NewRecorder()
	deniedReq := httptest.NewRequest(http.MethodPost, "/libpod/containers/"+url.PathEscape(createBody.Id)+"/exec", strings.NewReader(`{"Cmd":["cat","/etc/shadow"]}`))
	deniedReq.Header.Set("Content-Type", "application/json")
	execHandler.ServeHTTP(deniedRec, deniedReq)
	if deniedRec.Code != http.StatusForbidden {
		t.Fatalf("exec create status = %d, want %d; body: %s", deniedRec.Code, http.StatusForbidden, deniedRec.Body.String())
	}
	if !strings.Contains(deniedRec.Body.String(), `exec denied: command "cat /etc/shadow" is not allowlisted`) {
		t.Fatalf("deny body = %q, want allowlist reason (no libpod prefix: exec config is shared, #148 C3)", deniedRec.Body.String())
	}

	// Allowed command: forwarded to Podman, which creates a real exec
	// instance against the running container.
	allowedRec := httptest.NewRecorder()
	allowedReq := httptest.NewRequest(http.MethodPost, "/libpod/containers/"+url.PathEscape(createBody.Id)+"/exec", strings.NewReader(`{"Cmd":["echo","hello"]}`))
	allowedReq.Header.Set("Content-Type", "application/json")
	execHandler.ServeHTTP(allowedRec, allowedReq)
	if allowedRec.Code != http.StatusCreated {
		t.Fatalf("exec create status = %d, want %d; body: %s", allowedRec.Code, http.StatusCreated, allowedRec.Body.String())
	}

	var execCreateBody struct {
		Id string `json:"Id"`
	}
	if err := json.NewDecoder(allowedRec.Body).Decode(&execCreateBody); err != nil {
		t.Fatalf("decode exec create response: %v", err)
	}
	if execCreateBody.Id == "" {
		t.Fatal("expected exec create response Id")
	}

	// Start it detached so the response is a plain status code rather than
	// a hijacked stream — the hijack transport itself is out of PR6's scope
	// (see the design doc's "Hijack" section, already covered by
	// TestProxyAllowsDockerAttachEndToEndHijack's Docker-side counterpart).
	startExecRec := httptest.NewRecorder()
	startExecReq := httptest.NewRequest(http.MethodPost, "/libpod/exec/"+url.PathEscape(execCreateBody.Id)+"/start", strings.NewReader(`{"Detach":true}`))
	startExecReq.Header.Set("Content-Type", "application/json")
	execHandler.ServeHTTP(startExecRec, startExecReq)
	if startExecRec.Code != http.StatusOK {
		t.Fatalf("exec start status = %d, want %d; body: %s", startExecRec.Code, http.StatusOK, startExecRec.Body.String())
	}
}

func TestProxyDeniesCustomLibpodVolumeDriverAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/volumes/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(`{"Driver":"custom-driver"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `libpod volume create denied: driver "custom-driver" is not allowed`) {
		t.Fatalf("deny body = %q, want driver reason", rec.Body.String())
	}
}

func TestProxyDeniesCustomLibpodNetworkDriverAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/networks/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/libpod/networks/create", strings.NewReader(`{"driver":"custom-driver"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `libpod network create denied: driver "custom-driver" is not allowed`) {
		t.Fatalf("deny body = %q, want driver reason", rec.Body.String())
	}
}

func TestProxyDeniesLibpodSecretCustomDriverAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/secrets/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	// libpod secret driver/opts are URL query parameters, not a JSON body
	// (see libpod_secret.go's doc comment) — the body here is deliberately
	// opaque secret payload bytes the inspector never reads.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?driver=custom-driver", strings.NewReader("supersecret"))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `libpod secret create denied: driver "custom-driver" is not allowed`) {
		t.Fatalf("deny body = %q, want driver reason", rec.Body.String())
	}
}
