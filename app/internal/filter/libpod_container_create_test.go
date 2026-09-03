package filter

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/imagetrust"
)

// libpod_container_create_test.go tests the POST /libpod/containers/create
// inspector (#148 PR2). Gate coverage tables are driven off the golden
// fixtures in testdata/libpod/*.json wherever a fixture exists for the
// scenario (see that directory's README for capture provenance) — per the
// design doc's C4 decision, hand-written JSON bodies are only used for
// combinatorial variations of an already-confirmed-real field/value that
// don't warrant a dedicated capture (e.g. a synthetic "systemd":"false"
// body built from the confirmed field name and a value Podman's own docs
// define).
//
// IMPORTANT: every captured fixture's "systemd" field defaults to "true"
// (SpecGenerator's own default — see basic_create.json — sent even when
// --systemd was never passed on the CLI), which the systemd-mode gate
// denies by default (see denySystemdModeReason). So any test that expects a
// fixture-driven body to be ALLOWED must set AllowSystemdMode: true in its
// policy, or the assertion fails for the wrong reason. Tests that expect a
// DENY from a gate that runs BEFORE the systemd check in inspect()'s order
// (privileged, host namespaces, namespace sharing, bind mounts, devices,
// capabilities, seccomp/apparmor/selinux, non-root user, read-only rootfs,
// resource limits, sysctls) do not need it — the earlier gate short-circuits
// first regardless.

// loadLibpodFixture reads a captured request body from testdata/libpod.
func loadLibpodFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "libpod", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// makeLibpodInspectRequest builds a POST /libpod/containers/create request
// carrying body, the libpod-path counterpart of makeInspectRequest
// (container_create_test.go), which hardcodes the Docker path.
func makeLibpodInspectRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// inspectLibpod runs policy.inspect against a fresh request built from body
// and fails the test on an unexpected error.
func inspectLibpod(t *testing.T, policy libpodContainerCreatePolicy, body []byte) string {
	t.Helper()
	reason, err := policy.inspect(nil, makeLibpodInspectRequest(t, body), "/libpod/containers/create")
	if err != nil {
		t.Fatalf("inspect() unexpected error: %v", err)
	}
	return reason
}

func TestNewLibpodContainerCreatePolicyNormalizesAndDeduplicatesAllowedBindMounts(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{
		AllowedBindMounts: []string{"", "relative", "/safe", "/safe/", "/safe/../safe", "/other/../allowed"},
	})
	want := []string{"/safe", "/allowed"}
	if len(policy.allowedBindMounts) != len(want) {
		t.Fatalf("allowedBindMounts = %v, want %v", policy.allowedBindMounts, want)
	}
	for i, w := range want {
		if policy.allowedBindMounts[i] != w {
			t.Fatalf("allowedBindMounts[%d] = %q, want %q", i, policy.allowedBindMounts[i], w)
		}
	}
}

// TestInspectorRoutingIsPathExclusive is the #148 design doc's single most
// important test (design doc "Agreed core" item 2): fail-open body-shape
// confusion between the Docker and libpod inspector families is the #1 risk
// this split guards against. One body carries BOTH a Docker-shaped dangerous
// value (HostConfig.Privileged) and a libpod-shaped safe value (top-level
// "privileged"), and vice versa in a second body — a wrong-shape read would
// flip the verdict. Also asserts each inspect() is a structural no-op
// (neither reads nor errors) when called against the OTHER family's path,
// proving routing is done by path predicate, not body sniffing. Both bodies
// carry "systemd":"false" purely so the libpod policy's other default-deny
// gates (see file doc comment) don't mask the privileged-field assertion.
func TestInspectorRoutingIsPathExclusive(t *testing.T) {
	dockerDangerousLibpodSafe := []byte(`{"Image":"x","image":"x","HostConfig":{"Privileged":true},"privileged":false,"systemd":"false"}`)
	dockerSafeLibpodDangerous := []byte(`{"Image":"x","image":"x","HostConfig":{"Privileged":false},"privileged":true,"systemd":"false"}`)

	dockerPolicy := newContainerCreatePolicy(ContainerCreateOptions{})
	libpodPolicy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})

	t.Run("docker inspector reads only HostConfig.Privileged", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(dockerDangerousLibpodSafe))
		reason, err := dockerPolicy.inspect(nil, req, "/containers/create")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reason == "" {
			t.Fatal("want deny: HostConfig.Privileged=true, got allow — Docker inspector ignored its own shape")
		}

		req2 := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(dockerSafeLibpodDangerous))
		reason2, err := dockerPolicy.inspect(nil, req2, "/containers/create")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reason2 != "" {
			t.Fatalf("want allow (HostConfig.Privileged=false): got deny %q — Docker inspector leaked the libpod \"privileged\" field", reason2)
		}
	})

	t.Run("libpod inspector reads only top-level privileged", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", bytes.NewReader(dockerDangerousLibpodSafe))
		reason, err := libpodPolicy.inspect(nil, req, "/libpod/containers/create")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reason != "" {
			t.Fatalf("want allow (privileged=false): got deny %q — libpod inspector leaked HostConfig.Privileged", reason)
		}

		req2 := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", bytes.NewReader(dockerSafeLibpodDangerous))
		reason2, err := libpodPolicy.inspect(nil, req2, "/libpod/containers/create")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reason2 == "" {
			t.Fatal("want deny: privileged=true, got allow — libpod inspector ignored its own shape")
		}
	})

	t.Run("docker inspector is a structural no-op on the libpod path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", bytes.NewReader(dockerSafeLibpodDangerous))
		reason, err := dockerPolicy.inspect(nil, req, "/libpod/containers/create")
		if err != nil || reason != "" {
			t.Fatalf("inspect() = (%q, %v), want (\"\", nil) — Docker inspector must never fire on a libpod path", reason, err)
		}
	})

	t.Run("libpod inspector is a structural no-op on the docker path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(dockerDangerousLibpodSafe))
		reason, err := libpodPolicy.inspect(nil, req, "/containers/create")
		if err != nil || reason != "" {
			t.Fatalf("inspect() = (%q, %v), want (\"\", nil) — libpod inspector must never fire on the Docker path", reason, err)
		}
	})
}

func TestLibpodContainerCreatePrivilegedGate(t *testing.T) {
	deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	if reason := inspectLibpod(t, deny, loadLibpodFixture(t, "privileged.json")); reason == "" {
		t.Fatal("want deny: privileged=true with default policy")
	}

	permissive := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if reason := inspectLibpod(t, permissive, loadLibpodFixture(t, "basic_create.json")); reason != "" {
		t.Fatalf("want allow: basic create, got deny %q", reason)
	}

	allow := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowPrivileged: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allow, loadLibpodFixture(t, "privileged.json")); reason != "" {
		t.Fatalf("want allow: AllowPrivileged=true, got deny %q", reason)
	}
}

func TestLibpodContainerCreateHostNamespaceGates(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		allow   LibpodContainerCreateOptions
	}{
		{"host network", "host_network.json", LibpodContainerCreateOptions{AllowHostNetwork: true}},
		{"host pid", "host_pid.json", LibpodContainerCreateOptions{AllowHostPID: true}},
		{"host ipc", "host_ipc.json", LibpodContainerCreateOptions{AllowHostIPC: true}},
		{"host userns", "host_userns.json", LibpodContainerCreateOptions{AllowHostUserNS: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := loadLibpodFixture(t, tt.fixture)
			deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
			if reason := inspectLibpod(t, deny, body); reason == "" {
				t.Fatalf("want deny with default policy for %s", tt.fixture)
			}
			allowOpts := tt.allow
			allowOpts.AllowSystemdMode = true
			allow := newLibpodContainerCreatePolicy(allowOpts)
			if reason := inspectLibpod(t, allow, body); reason != "" {
				t.Fatalf("want allow with matching opt-in, got deny %q", reason)
			}
		})
	}
}

func TestLibpodContainerCreateNamespaceSharingGate(t *testing.T) {
	body := loadLibpodFixture(t, "namespace_share_container_ref.json")

	t.Run("default pass-through", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
		if reason := inspectLibpod(t, policy, body); reason != "" {
			t.Fatalf("want allow (restrict_namespace_sharing default false): got deny %q", reason)
		}
	})

	t.Run("restricted with empty allowlist denies", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{RestrictNamespaceSharing: true})
		if reason := inspectLibpod(t, policy, body); reason == "" {
			t.Fatal("want deny: restrict_namespace_sharing=true, empty allowlist")
		}
	})

	t.Run("restricted with matching allowlist entry allows", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{
			RestrictNamespaceSharing:          true,
			AllowedNamespaceSharingContainers: []string{"sg-nsshare-target"},
			AllowSystemdMode:                  true,
		})
		if reason := inspectLibpod(t, policy, body); reason != "" {
			t.Fatalf("want allow: target in allowlist, got deny %q", reason)
		}
	})

	t.Run("restricted with non-matching allowlist entry denies", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{
			RestrictNamespaceSharing:          true,
			AllowedNamespaceSharingContainers: []string{"someone-else"},
		})
		if reason := inspectLibpod(t, policy, body); reason == "" {
			t.Fatal("want deny: target not in allowlist")
		}
	})
}

func TestLibpodContainerCreateBindMountGate(t *testing.T) {
	body := loadLibpodFixture(t, "mounts_bind_tmpfs.json")

	deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	if reason := inspectLibpod(t, deny, body); reason == "" {
		t.Fatal("want deny: bind source not allowlisted")
	}

	allow := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedBindMounts: []string{"/tmp/bindsrc"}, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allow, body); reason != "" {
		t.Fatalf("want allow: bind source allowlisted, got deny %q", reason)
	}

	other := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedBindMounts: []string{"/other"}})
	if reason := inspectLibpod(t, other, body); reason == "" {
		t.Fatal("want deny: bind source not in allowlist")
	}
}

// TestLibpodContainerCreateNamedVolumesNeverGatedAsBindMounts confirms the
// "volumes" array (named-volume mounts) is never routed through the bind-mount
// allowlist — it references a volume by name, not a host path, and has a
// different (capitalized) field shape than "mounts". A restrictive bind-mount
// policy must not accidentally deny it.
func TestLibpodContainerCreateNamedVolumesNeverGatedAsBindMounts(t *testing.T) {
	body := loadLibpodFixture(t, "volumes_named.json")
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true}) // no allowed_bind_mounts at all
	if reason := inspectLibpod(t, policy, body); reason != "" {
		t.Fatalf("want allow: named volume mount is not a bind mount, got deny %q", reason)
	}
}

func TestLibpodContainerCreateDeviceGate(t *testing.T) {
	body := loadLibpodFixture(t, "devices.json") // path "/dev/null:/dev/xnull"

	deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	if reason := inspectLibpod(t, deny, body); reason == "" {
		t.Fatal("want deny: device not allowlisted")
	}

	allowAll := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowAllDevices: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allowAll, body); reason != "" {
		t.Fatalf("want allow: allow_all_devices, got deny %q", reason)
	}

	allowed := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedDevices: []string{"/dev/null"}, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allowed, body); reason != "" {
		t.Fatalf("want allow: host device path allowlisted, got deny %q", reason)
	}

	wrong := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedDevices: []string{"/dev/other"}})
	if reason := inspectLibpod(t, wrong, body); reason == "" {
		t.Fatal("want deny: device not in allowlist")
	}
}

func TestSplitLibpodDevicePath(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		wantOK   bool
	}{
		{"/dev/null:/dev/xnull", "/dev/null", true},
		{"/dev/null:/dev/xnull:rwm", "/dev/null", true},
		{"/dev/fuse", "/dev/fuse", true},
		{"", "", false},
		// A leading ':' puts the separator at index 0 — the
		// idx >= 0 boundary in splitLibpodDevicePath (idx must include
		// zero, not just strictly-positive indices) must still split, not
		// fall through to treating the whole raw string as an unsplit
		// single-argument host path.
		{":leading", "", true},
	}
	for _, tt := range tests {
		host, ok := splitLibpodDevicePath(tt.raw)
		if host != tt.wantHost || ok != tt.wantOK {
			t.Errorf("splitLibpodDevicePath(%q) = (%q, %v), want (%q, %v)", tt.raw, host, ok, tt.wantHost, tt.wantOK)
		}
	}
}

// TestLibpodNamespaceContainerRef covers libpodNamespace.containerRef
// (libpod_container_create_types.go line 84), including its ref == ""
// boundary at line 89: a "container:" nsmode with an empty or
// whitespace-only value must report ok=false, not a spurious ref.
func TestLibpodNamespaceContainerRef(t *testing.T) {
	tests := []struct {
		name    string
		ns      libpodNamespace
		wantRef string
		wantOK  bool
	}{
		{name: "joins another container", ns: libpodNamespace{NSMode: "container", Value: "abc123"}, wantRef: "abc123", wantOK: true},
		{name: "trims surrounding whitespace", ns: libpodNamespace{NSMode: "container", Value: "  abc123  "}, wantRef: "abc123", wantOK: true},
		{name: "empty value is not a ref", ns: libpodNamespace{NSMode: "container", Value: ""}, wantRef: "", wantOK: false},
		{name: "whitespace-only value is not a ref", ns: libpodNamespace{NSMode: "container", Value: "   "}, wantRef: "", wantOK: false},
		{name: "non-container nsmode is never a ref", ns: libpodNamespace{NSMode: "host", Value: "abc123"}, wantRef: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, ok := tt.ns.containerRef()
			if ref != tt.wantRef || ok != tt.wantOK {
				t.Errorf("containerRef() = (%q, %v), want (%q, %v)", ref, ok, tt.wantRef, tt.wantOK)
			}
		})
	}
}

func TestLibpodContainerCreateCapabilitiesGate(t *testing.T) {
	body := loadLibpodFixture(t, "capabilities.json") // cap_add: [SYS_ADMIN]

	deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	if reason := inspectLibpod(t, deny, body); reason == "" {
		t.Fatal("want deny: SYS_ADMIN not allowlisted")
	}

	allowAll := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowAllCapabilities: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allowAll, body); reason != "" {
		t.Fatalf("want allow: allow_all_capabilities, got deny %q", reason)
	}

	allowed := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedCapabilities: []string{"SYS_ADMIN"}, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allowed, body); reason != "" {
		t.Fatalf("want allow: SYS_ADMIN allowlisted, got deny %q", reason)
	}

	wrong := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedCapabilities: []string{"NET_ADMIN"}})
	if reason := inspectLibpod(t, wrong, body); reason == "" {
		t.Fatal("want deny: SYS_ADMIN not in allowlist")
	}
}

func TestLibpodContainerCreateSeccompGate(t *testing.T) {
	body := loadLibpodFixture(t, "security_opts_seccomp_apparmor_selinux.json") // seccomp_profile_path: unconfined

	permissive := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if reason := inspectLibpod(t, permissive, body); reason != "" {
		t.Fatalf("want allow: no seccomp gate configured, got deny %q", reason)
	}

	denyUnconfined := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true})
	if reason := inspectLibpod(t, denyUnconfined, body); reason == "" {
		t.Fatal("want deny: deny_unconfined_seccomp with unconfined profile")
	}

	allowedMismatch := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedSeccompProfiles: []string{"default"}})
	if reason := inspectLibpod(t, allowedMismatch, body); reason == "" {
		t.Fatal("want deny: unconfined not in allowed_seccomp_profiles")
	}

	allowedMatch := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedSeccompProfiles: []string{"unconfined"}, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allowedMatch, body); reason != "" {
		t.Fatalf("want allow: unconfined allowlisted, got deny %q", reason)
	}

	// basic_create.json has no explicit seccomp profile path (empty string,
	// SpecGenerator's "default" sentinel) — must satisfy an allowlist
	// containing "default".
	defaultBody := loadLibpodFixture(t, "basic_create.json")
	allowedDefault := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedSeccompProfiles: []string{"default"}, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allowedDefault, defaultBody); reason != "" {
		t.Fatalf("want allow: empty seccomp profile path maps to \"default\", got deny %q", reason)
	}
}

func TestLibpodContainerCreateAppArmorGate(t *testing.T) {
	body := loadLibpodFixture(t, "security_opts_seccomp_apparmor_selinux.json") // apparmor_profile: unconfined

	permissive := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if reason := inspectLibpod(t, permissive, body); reason != "" {
		t.Fatalf("want allow: no apparmor gate configured, got deny %q", reason)
	}

	denyUnconfined := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{DenyUnconfinedAppArmor: true})
	if reason := inspectLibpod(t, denyUnconfined, body); reason == "" {
		t.Fatal("want deny: deny_unconfined_apparmor with unconfined profile")
	}

	allowedMismatch := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedAppArmorProfiles: []string{"default"}})
	if reason := inspectLibpod(t, allowedMismatch, body); reason == "" {
		t.Fatal("want deny: unconfined not in allowed_apparmor_profiles")
	}

	allowedMatch := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedAppArmorProfiles: []string{"unconfined"}, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allowedMatch, body); reason != "" {
		t.Fatalf("want allow: unconfined allowlisted, got deny %q", reason)
	}
}

func TestLibpodContainerCreateSelinuxDisableGate(t *testing.T) {
	body := loadLibpodFixture(t, "security_opts_seccomp_apparmor_selinux.json") // selinux_opts: [disable]

	permissive := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if reason := inspectLibpod(t, permissive, body); reason != "" {
		t.Fatalf("want allow: deny_selinux_disable not set, got deny %q", reason)
	}

	strict := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{DenySelinuxDisable: true})
	if reason := inspectLibpod(t, strict, body); reason == "" {
		t.Fatal("want deny: deny_selinux_disable with selinux_opts=[disable]")
	}
}

func TestLibpodContainerCreateNonRootUserGate(t *testing.T) {
	nonRootBody := loadLibpodFixture(t, "user.json")      // user: "1000:1000"
	rootBody := loadLibpodFixture(t, "basic_create.json") // no user field -> empty

	require := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{RequireNonRootUser: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, require, nonRootBody); reason != "" {
		t.Fatalf("want allow: non-root user, got deny %q", reason)
	}
	if reason := inspectLibpod(t, require, rootBody); reason == "" {
		t.Fatal("want deny: empty user field with require_non_root_user")
	}

	permissive := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if reason := inspectLibpod(t, permissive, rootBody); reason != "" {
		t.Fatalf("want allow: require_non_root_user not set, got deny %q", reason)
	}
}

func TestLibpodContainerCreateResourceLimitGates(t *testing.T) {
	full := loadLibpodFixture(t, "resource_limits.json")                  // memory+cpu(quota/period)+pids
	sharesOnly := loadLibpodFixture(t, "resource_limits_cpu_shares.json") // cpu.shares only
	none := loadLibpodFixture(t, "basic_create.json")                     // no resource_limits at all

	t.Run("require memory limit", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{RequireMemoryLimit: true, AllowSystemdMode: true})
		if reason := inspectLibpod(t, policy, full); reason != "" {
			t.Fatalf("want allow: memory.limit set, got deny %q", reason)
		}
		if reason := inspectLibpod(t, policy, none); reason == "" {
			t.Fatal("want deny: no resource_limits at all")
		}
	})

	t.Run("require cpu limit accepts shares alone", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{RequireCPULimit: true, AllowSystemdMode: true})
		if reason := inspectLibpod(t, policy, full); reason != "" {
			t.Fatalf("want allow: cpu.quota/period set, got deny %q", reason)
		}
		if reason := inspectLibpod(t, policy, sharesOnly); reason != "" {
			t.Fatalf("want allow: cpu.shares counts as evidence of intent, got deny %q", reason)
		}
		if reason := inspectLibpod(t, policy, none); reason == "" {
			t.Fatal("want deny: no CPU limit at all")
		}
	})

	t.Run("require hard cpu limit rejects shares-only", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{RequireCPULimitHard: true, AllowSystemdMode: true})
		if reason := inspectLibpod(t, policy, full); reason != "" {
			t.Fatalf("want allow: cpu.quota is a genuine hard cap, got deny %q", reason)
		}
		if reason := inspectLibpod(t, policy, sharesOnly); reason == "" {
			t.Fatal("want deny: shares alone is not a hard cap")
		}
	})

	t.Run("require pids limit", func(t *testing.T) {
		policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{RequirePidsLimit: true, AllowSystemdMode: true})
		if reason := inspectLibpod(t, policy, full); reason != "" {
			t.Fatalf("want allow: pids.limit set, got deny %q", reason)
		}
		if reason := inspectLibpod(t, policy, none); reason == "" {
			t.Fatal("want deny: no pids limit")
		}
	})
}

func TestLibpodContainerCreateSysctlsGate(t *testing.T) {
	body := loadLibpodFixture(t, "sysctls.json")

	deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	if reason := inspectLibpod(t, deny, body); reason == "" {
		t.Fatal("want deny: sysctls set without allow_sysctls")
	}

	allow := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSysctls: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allow, body); reason != "" {
		t.Fatalf("want allow: allow_sysctls=true, got deny %q", reason)
	}
}

func TestLibpodContainerCreateReadOnlyRootfsGate(t *testing.T) {
	readOnly := loadLibpodFixture(t, "read_only_filesystem.json")
	readWrite := loadLibpodFixture(t, "basic_create.json")

	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{RequireReadonlyRootfs: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, policy, readOnly); reason != "" {
		t.Fatalf("want allow: read_only_filesystem=true, got deny %q", reason)
	}
	if reason := inspectLibpod(t, policy, readWrite); reason == "" {
		t.Fatal("want deny: read_only_filesystem=false with require_readonly_rootfs")
	}
}

func TestLibpodContainerCreateSystemdModeGate(t *testing.T) {
	// SpecGenerator's own default (even with --systemd never passed) is
	// "true" — see basic_create.json — so the default policy denies the
	// common case, the intended deliberately-strict posture.
	defaultBody := loadLibpodFixture(t, "basic_create.json") // systemd: "true"
	alwaysBody := loadLibpodFixture(t, "systemd_mode.json")  // systemd: "always"

	deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	if reason := inspectLibpod(t, deny, defaultBody); reason == "" {
		t.Fatal("want deny: systemd=true denied by default")
	}
	if reason := inspectLibpod(t, deny, alwaysBody); reason == "" {
		t.Fatal("want deny: systemd=always denied by default")
	}

	allow := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if reason := inspectLibpod(t, allow, defaultBody); reason != "" {
		t.Fatalf("want allow: allow_systemd_mode=true, got deny %q", reason)
	}

	// systemd=false is always exempt — built from the field name/value
	// confirmed by basic_create.json's "systemd" key and Podman's documented
	// tri-state values, not a dedicated capture (see file doc comment).
	falseBody := []byte(`{"name":"sg-systemd-false","image":"alpine:latest","systemd":"false"}`)
	if reason := inspectLibpod(t, deny, falseBody); reason != "" {
		t.Fatalf("want allow: systemd=false is always exempt, got deny %q", reason)
	}
}

func TestLibpodContainerCreateIDMappingsGate(t *testing.T) {
	custom := loadLibpodFixture(t, "idmappings.json")
	defaultBody := loadLibpodFixture(t, "basic_create.json")

	// AllowSystemdMode is set on every policy in this test so the systemd
	// gate (which runs before idmappings — see inspect()'s order) never
	// masks the idmappings assertion itself.
	base := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if reason := inspectLibpod(t, base, custom); reason == "" {
		t.Fatal("want deny: custom UID/GID mapping without allow_custom_id_mappings")
	}
	if reason := inspectLibpod(t, base, defaultBody); reason != "" {
		t.Fatalf("want allow: default idmappings, got deny %q", reason)
	}

	allow := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowCustomIDMappings: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, allow, custom); reason != "" {
		t.Fatalf("want allow: allow_custom_id_mappings=true, got deny %q", reason)
	}

	// --userns host must not also require allow_custom_id_mappings: the
	// fixture's idmappings stay at their non-custom default even though
	// userns.nsmode=host.
	hostUserns := loadLibpodFixture(t, "host_userns.json")
	hostAllow := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowHostUserNS: true, AllowSystemdMode: true})
	if reason := inspectLibpod(t, hostAllow, hostUserns); reason != "" {
		t.Fatalf("want allow: host userns doesn't imply custom id mappings, got deny %q", reason)
	}
}

// --- Fail-closed decode / body-handling tests ---

func TestLibpodContainerCreateMalformedJSONDenied(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	reason := inspectLibpod(t, policy, []byte(`{"image":`))
	if reason == "" {
		t.Fatal("want deny: malformed JSON")
	}
	if !containsSubstring(reason, "malformed JSON") {
		t.Fatalf("deny reason %q does not mention malformed JSON", reason)
	}
}

func TestLibpodContainerCreateOversizedBodyRejected(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	body := bytes.Repeat([]byte("a"), maxContainerCreateBodyBytes+1)
	req := makeLibpodInspectRequest(t, body)
	_, err := policy.inspect(nil, req, "/libpod/containers/create")
	if err == nil {
		t.Fatal("want a request-rejection error for oversized body")
	}
	var rejErr *requestRejectionError
	if !errors.As(err, &rejErr) {
		t.Fatalf("error = %v, want *requestRejectionError", err)
	}
	if rejErr.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rejErr.status, http.StatusRequestEntityTooLarge)
	}
}

func TestLibpodContainerCreateEmptyBodyAllowed(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})
	reason := inspectLibpod(t, policy, []byte{})
	if reason != "" {
		t.Fatalf("want allow: empty body passes through (matches container_create.go's own posture), got deny %q", reason)
	}
}

func TestLibpodContainerCreateInspectNoopCases(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{})

	t.Run("nil request", func(t *testing.T) {
		reason, err := policy.inspect(nil, nil, "/libpod/containers/create")
		if reason != "" || err != nil {
			t.Fatalf("inspect(nil request) = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/libpod/containers/create", nil)
		reason, err := policy.inspect(nil, req, "/libpod/containers/create")
		if reason != "" || err != nil {
			t.Fatalf("inspect(GET) = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("wrong path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", bytes.NewReader(loadLibpodFixture(t, "privileged.json")))
		reason, err := policy.inspect(nil, req, "/libpod/pods/create")
		if reason != "" || err != nil {
			t.Fatalf("inspect(wrong path) = (%q, %v), want (\"\", nil)", reason, err)
		}
	})

	t.Run("nil body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", nil)
		req.Body = nil
		reason, err := policy.inspect(nil, req, "/libpod/containers/create")
		if reason != "" || err != nil {
			t.Fatalf("inspect(nil body) = (%q, %v), want (\"\", nil)", reason, err)
		}
	})
}

// --- Image trust ---

func TestLibpodImageTrustInitErrFailsClosed(t *testing.T) {
	opts := LibpodContainerCreateOptions{
		ImageTrust: ImageTrustOptions{
			Mode:               "enforce",
			AllowedSigningKeys: []SigningKeyOptions{{PEM: "not-a-valid-pem"}},
		},
	}
	policy := newLibpodContainerCreatePolicy(opts)
	if policy.imageTrustInitErr == nil {
		t.Fatal("expected imageTrustInitErr for invalid PEM, got nil")
	}
	// The init-error check runs before any other gate (including systemd),
	// so this fixture's default systemd="true" cannot mask the assertion.
	reason := inspectLibpod(t, policy, loadLibpodFixture(t, "basic_create.json"))
	if !containsSubstring(reason, "image trust policy initialization error") {
		t.Fatalf("deny reason = %q, want mention of image trust init error", reason)
	}
}

func TestLibpodImageTrustNilVerifierPassesThrough(t *testing.T) {
	policy := libpodContainerCreatePolicy{allowSystemdMode: true}
	reason := inspectLibpod(t, policy, []byte(`{"image":"docker.io/library/alpine:3.21"}`))
	if reason != "" {
		t.Fatalf("expected empty deny reason, got %q", reason)
	}
}

func TestLibpodImageTrustEnforceDeniesOnVerifierError(t *testing.T) {
	mv := &mockImageVerifier{err: errors.New("no valid signature found")}
	policy := libpodContainerCreatePolicy{
		allowPrivileged:       true,
		allowHostNetwork:      true,
		allowHostPID:          true,
		allowHostIPC:          true,
		allowHostUserNS:       true,
		allowAllDevices:       true,
		allowAllCapabilities:  true,
		allowSystemdMode:      true,
		allowCustomIDMappings: true,
		imageTrustVerifier:    mv,
		imageFetcher:          oneCandidateFetcher(),
		imageTrustCfg:         imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	body := []byte(`{"image":"registry.example.com/unsigned:latest"}`)
	reason := inspectLibpod(t, policy, body)
	if reason == "" {
		t.Fatal("expected a deny reason, got empty string")
	}
	if !containsSubstring(reason, "image trust verification failed") {
		t.Fatalf("deny reason %q missing expected substring", reason)
	}
}

func TestLibpodImageTrustEmptyImageDeniedWhenConfigured(t *testing.T) {
	mv := &mockImageVerifier{err: errors.New("should not be called")}
	policy := libpodContainerCreatePolicy{
		allowPrivileged:       true,
		allowHostNetwork:      true,
		allowHostPID:          true,
		allowHostIPC:          true,
		allowHostUserNS:       true,
		allowAllDevices:       true,
		allowAllCapabilities:  true,
		allowSystemdMode:      true,
		allowCustomIDMappings: true,
		imageTrustVerifier:    mv,
		imageFetcher:          oneCandidateFetcher(),
		imageTrustCfg:         imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	reason := inspectLibpod(t, policy, []byte(`{"image":""}`))
	const want = "libpod container create denied: image field is required when image trust is configured"
	if reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
	if mv.lastCalled != "" {
		t.Fatalf("verifier should not have been called, lastCalled = %q", mv.lastCalled)
	}
}

func TestLibpodImageTrustEnforcePinsVerifiedDigest(t *testing.T) {
	const digest = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" + "cc"
	policy := libpodContainerCreatePolicy{
		allowPrivileged:       true,
		allowHostNetwork:      true,
		allowHostPID:          true,
		allowHostIPC:          true,
		allowHostUserNS:       true,
		allowAllDevices:       true,
		allowAllCapabilities:  true,
		allowSystemdMode:      true,
		allowCustomIDMappings: true,
		imageTrustVerifier:    &mockImageVerifier{},
		imageFetcher:          &mockSignatureFetcher{candidates: []imagetrust.Candidate{{DigestHex: "00", ImageDigest: digest}}},
		imageTrustCfg:         imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	body := []byte(`{"image":"registry.example.com/app:v1","privileged":false}`)
	req := makeLibpodInspectRequest(t, body)
	reason, err := policy.inspect(nil, req, "/libpod/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want allow", reason)
	}
	got := new(bytes.Buffer)
	if _, err := got.ReadFrom(req.Body); err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if !bytes.Contains(got.Bytes(), []byte("registry.example.com/app@"+digest)) {
		t.Fatalf("rewritten body = %s, want pinned digest reference", got.String())
	}
	if bytes.Contains(got.Bytes(), []byte(`"registry.example.com/app:v1"`)) {
		t.Fatalf("rewritten body still contains the mutable tag: %s", got.String())
	}
}

// --- rewriteLibpodJSONImageField / duplicate-key handling ---

func TestRewriteLibpodJSONImageFieldCollapsesToCanonicalKey(t *testing.T) {
	body := []byte(`{"image":"old:tag","privileged":false}`)
	result, err := rewriteLibpodJSONImageField(body, "pinned@sha256:deadbeef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte(`"image":"pinned@sha256:deadbeef"`)) {
		t.Fatalf("result = %s, want pinned image field", result)
	}
}

func TestRewriteLibpodJSONImageFieldRejectsDuplicateCaseVariantKeys(t *testing.T) {
	body := []byte(`{"image":"a","Image":"b"}`)
	_, err := rewriteLibpodJSONImageField(body, "pinned")
	if err == nil {
		t.Fatal("want error for duplicate case-variant top-level keys, got nil")
	}
}

// --- Fuzz ---

// FuzzLibpodContainerCreate fuzzes the full inspect() entrypoint, seeded from
// the golden fixtures plus a handful of malformed/oversized/adversarial
// bodies. Mirrors FuzzContainerCreate's structure (fuzz_parsers_test.go);
// asserts only that inspect never panics.
func FuzzLibpodContainerCreate(f *testing.F) {
	for _, name := range []string{
		"basic_create.json",
		"privileged.json",
		"host_network.json",
		"host_pid.json",
		"host_ipc.json",
		"host_userns.json",
		"namespace_share_container_ref.json",
		"mounts_bind_tmpfs.json",
		"volumes_named.json",
		"devices.json",
		"capabilities.json",
		"security_opts_seccomp_apparmor_selinux.json",
		"resource_limits.json",
		"resource_limits_cpu_shares.json",
		"systemd_mode.json",
		"idmappings.json",
		"labels.json",
		"sysctls.json",
		"read_only_filesystem.json",
		"user.json",
	} {
		data, err := os.ReadFile(filepath.Join("testdata", "libpod", name))
		if err != nil {
			f.Fatalf("read fixture %s: %v", name, err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"image":`))
	f.Add([]byte(`{"image":"a","Image":"b"}`))
	f.Add(bytes.Repeat([]byte("a"), maxContainerCreateBodyBytes+1))
	f.Add([]byte(``))
	f.Add([]byte(`{"netns":{"nsmode":"container","value":""}}`))

	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{
		AllowedBindMounts: []string{"/tmp"},
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxContainerCreateBodyBytes+1024)
		req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", bytes.NewReader(body))
		_, _ = policy.inspect(nil, req, "/libpod/containers/create")
		if req.Body != nil {
			_ = req.Body.Close()
		}
	})
}
