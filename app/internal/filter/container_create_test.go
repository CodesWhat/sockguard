package filter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/imagetrust"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type erroringReadCloser struct {
	io.Reader
	closeErr error
}

func (r *erroringReadCloser) Close() error {
	return r.closeErr
}

type readErrorReadCloser struct {
	readErr  error
	closeErr error
}

func (r *readErrorReadCloser) Read([]byte) (int, error) {
	return 0, r.readErr
}

func (r *readErrorReadCloser) Close() error {
	return r.closeErr
}

type trackingReadCloser struct {
	reader *bytes.Reader
	reads  int
	closed bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	r.reads++
	return r.reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestNewContainerCreatePolicyNormalizesAndDeduplicatesAllowedBindMounts(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts: []string{
			"",
			"relative",
			"/safe",
			"/safe/",
			"/safe/../safe",
			"/other/../allowed",
		},
	})

	want := []string{"/safe", "/allowed"}
	if len(policy.allowedBindMounts) != len(want) {
		t.Fatalf("allowedBindMounts length = %d, want %d (%v)", len(policy.allowedBindMounts), len(want), policy.allowedBindMounts)
	}
	for i, wantValue := range want {
		if policy.allowedBindMounts[i] != wantValue {
			t.Fatalf("allowedBindMounts[%d] = %q, want %q", i, policy.allowedBindMounts[i], wantValue)
		}
	}
}

func TestContainerCreatePolicyInspectAllowsPermissiveBodyWithoutForbiddenFields(t *testing.T) {
	// allowsAllContainerCreateBodies always returns false because several fields
	// (VolumesFrom, UTSMode:host, CgroupParent, GroupAdd, ExtraHosts) are
	// unconditionally denied; the body must always be inspected. A body with
	// none of those fields and a permissive policy must still be allowed.
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowPrivileged:        true,
		AllowHostNetwork:       true,
		AllowHostPID:           true,
		AllowHostIPC:           true,
		AllowHostUserNS:        true,
		AllowSysctls:           true,
		AllowedBindMounts:      []string{"/"},
		AllowAllDevices:        true,
		AllowDeviceRequests:    true,
		AllowDeviceCgroupRules: true,
		AllowAllCapabilities:   true,
	})
	body := []byte(`{"HostConfig":{"Privileged":true,"NetworkMode":"host","Binds":["/var/run:/host/run"]}}`)
	tracker := &trackingReadCloser{reader: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req.Body = tracker

	reason, err := policy.inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}

	gotBody, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll() error = %v", readErr)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body after inspect = %q, want %q", string(gotBody), string(body))
	}
}

func TestContainerCreatePolicyInspectSkipsNonCreateRequests(t *testing.T) {
	policy := containerCreatePolicy{}

	tests := []struct {
		name           string
		request        *http.Request
		normalizedPath string
	}{
		{name: "nil request", request: nil, normalizedPath: "/containers/create"},
		{name: "wrong method", request: httptest.NewRequest(http.MethodGet, "/containers/create", bytes.NewReader([]byte(`{}`))), normalizedPath: "/containers/create"},
		{name: "wrong path", request: httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader([]byte(`{}`))), normalizedPath: "/containers/json"},
		{name: "nil body", request: &http.Request{Method: http.MethodPost}, normalizedPath: "/containers/create"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := policy.inspect(nil, tt.request, tt.normalizedPath)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

func TestContainerCreatePolicyInspectHandlesBodyEdgeCases(t *testing.T) {
	policy := containerCreatePolicy{}

	t.Run("empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", http.NoBody)

		reason, err := policy.inspect(nil, req, "/containers/create")
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		if reason != "" {
			t.Fatalf("inspect() reason = %q, want empty", reason)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString("{"))

		reason, err := policy.inspect(nil, req, "/containers/create")
		if err != nil {
			t.Fatalf("inspect() error = %v", err)
		}
		// Malformed JSON must be denied (fail-closed), not silently passed to Docker.
		const wantReason = "container create denied: malformed JSON request body"
		if reason != wantReason {
			t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
		}

		// Body must still be readable after inspect (readBoundedBody restores it).
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Fatalf("ReadAll() error = %v", readErr)
		}
		if string(body) != "{" {
			t.Fatalf("reset body = %q, want %q", string(body), "{")
		}
	})

	t.Run("close error after read is ignored", func(t *testing.T) {
		req := &http.Request{
			Method: http.MethodPost,
			Body: &erroringReadCloser{
				Reader:   bytes.NewReader([]byte(`{}`)),
				closeErr: errors.New("close failed"),
			},
		}

		reason, err := policy.inspect(nil, req, "/containers/create")
		if reason != "" {
			t.Fatalf("inspect() reason = %q, want empty", reason)
		}
		if err != nil {
			t.Fatalf("inspect() error = %v, want nil", err)
		}

		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Fatalf("ReadAll() error = %v", readErr)
		}
		if string(body) != "{}" {
			t.Fatalf("reset body = %q, want %q", string(body), "{}")
		}
	})
}

func TestContainerCreatePolicyInspectDeniesHostNamespaces(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "pid host",
			body:       `{"HostConfig":{"PidMode":"host"}}`,
			wantReason: "container create denied: host PID mode is not allowed",
		},
		{
			name:       "ipc host",
			body:       `{"HostConfig":{"IpcMode":"host"}}`,
			wantReason: "container create denied: host IPC mode is not allowed",
		},
		{
			name:       "pid host case insensitive",
			body:       `{"HostConfig":{"PidMode":"HOST"}}`,
			wantReason: "container create denied: host PID mode is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))

			reason, err := newContainerCreatePolicy(ContainerCreateOptions{}).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyInspectDeniesNetworkModeHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(`{"HostConfig":{"NetworkMode":"host"}}`))
	reason, err := newContainerCreatePolicy(ContainerCreateOptions{}).inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	const wantReason = "container create denied: host network mode is not allowed"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
	}
}

func TestContainerCreatePolicyInspectDeniesUninspectedHostConfigFields(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "VolumesFrom non-empty",
			body:       `{"HostConfig":{"VolumesFrom":["other-container"]}}`,
			wantReason: "container create denied: VolumesFrom is not allowed",
		},
		{
			name:       "UTSMode host",
			body:       `{"HostConfig":{"UTSMode":"host"}}`,
			wantReason: "container create denied: host UTS mode is not allowed",
		},
		{
			name:       "UTSMode host case insensitive",
			body:       `{"HostConfig":{"UTSMode":"HOST"}}`,
			wantReason: "container create denied: host UTS mode is not allowed",
		},
		{
			name:       "CgroupParent non-empty",
			body:       `{"HostConfig":{"CgroupParent":"/custom/cgroup"}}`,
			wantReason: "container create denied: custom cgroup parent is not allowed",
		},
		{
			name:       "GroupAdd non-empty",
			body:       `{"HostConfig":{"GroupAdd":["docker","wheel"]}}`,
			wantReason: "container create denied: supplemental group IDs are not allowed",
		},
		{
			name:       "ExtraHosts non-empty",
			body:       `{"HostConfig":{"ExtraHosts":["myhost:192.168.1.1"]}}`,
			wantReason: "container create denied: ExtraHosts is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(ContainerCreateOptions{}).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyInspectAllowsHostNamespacesWhenConfigured(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowHostPID: true,
		AllowHostIPC: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(`{"HostConfig":{"PidMode":"host","IpcMode":"host"}}`))

	reason, err := policy.inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestContainerCreatePolicyInspectDeniesNonAllowlistedDevices(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "device path",
			body:       `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/kvm","PathInContainer":"/dev/kvm","CgroupPermissions":"rwm"}]}}`,
			wantReason: `container create denied: device "/dev/kvm" is not allowlisted`,
		},
		{
			name:       "device request",
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}}`,
			wantReason: "container create denied: device requests are not allowed",
		},
		{
			name:       "device cgroup rule",
			body:       `{"HostConfig":{"DeviceCgroupRules":["c 10:* rwm"]}}`,
			wantReason: "container create denied: device cgroup rules are not allowed",
		},
		{
			name:       "relative device path",
			body:       `{"HostConfig":{"Devices":[{"PathOnHost":"dev/kvm"}]}}`,
			wantReason: `container create denied: device "dev/kvm" is not allowlisted`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))

			reason, err := newContainerCreatePolicy(ContainerCreateOptions{}).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestContainerCreatePolicyInspectAllowsConfiguredDevices(t *testing.T) {
	tests := []struct {
		name string
		opts ContainerCreateOptions
		body string
	}{
		{
			name: "allowed device path",
			opts: ContainerCreateOptions{AllowedDevices: []string{"/dev/dri"}},
			body: `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/dri/renderD128"}]}}`,
		},
		{
			name: "allow all devices",
			opts: ContainerCreateOptions{AllowAllDevices: true},
			body: `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/kvm"}]}}`,
		},
		{
			name: "allow device requests",
			opts: ContainerCreateOptions{AllowDeviceRequests: true},
			body: `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}}`,
		},
		{
			name: "allow device cgroup rules",
			opts: ContainerCreateOptions{AllowDeviceCgroupRules: true},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 10:* rwm"]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))

			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != "" {
				t.Fatalf("inspect() reason = %q, want empty", reason)
			}
		})
	}
}

func TestContainerCreatePolicyDenyBindMountReasonRejectsBindMountSource(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts: []string{"/allowed"},
	})

	reason := policy.denyBindMountReason(containerCreateHostConfig{
		Binds: []string{"not-a-bind"},
		Mounts: []containerCreateMount{
			{Type: "volume", Source: "/denied"},
			{Type: "bind", Source: "relative"},
			{Type: "bind", Source: "/denied"},
		},
	})

	if reason != `container create denied: bind mount source "/denied" is not allowlisted` {
		t.Fatalf("denyBindMountReason() = %q", reason)
	}
}

func TestExtractAndValidateBindSource(t *testing.T) {
	tests := []struct {
		name   string
		bind   string
		mount  containerCreateMount
		want   string
		wantOK bool
	}{
		{
			name:   "bind string",
			bind:   "/source:/target:ro",
			want:   "/source",
			wantOK: true,
		},
		{
			name:   "bind string missing separator",
			bind:   "/source",
			wantOK: false,
		},
		{
			name:   "bind mount entry",
			mount:  containerCreateMount{Type: "bind", Source: "/safe/../allowed"},
			want:   "/allowed",
			wantOK: true,
		},
		{
			name:   "non-bind mount entry",
			mount:  containerCreateMount{Type: "volume", Source: "/allowed"},
			wantOK: false,
		},
		{
			name:   "bind mount with relative source",
			mount:  containerCreateMount{Type: "bind", Source: "relative"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractAndValidateBindSource(tt.bind, tt.mount)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("source = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeContainerCreateBindMount(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		want   string
		wantOK bool
	}{
		{name: "clean absolute path", value: "/safe/../allowed", want: "/allowed", wantOK: true},
		{name: "root", value: "/", want: "/", wantOK: true},
		{name: "relative path", value: "relative", wantOK: false},
		{name: "empty path", value: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeBindMount(tt.value)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("normalized = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBindPathAllowed(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		allowed []string
		want    bool
	}{
		{name: "root allows everything", source: "/etc", allowed: []string{"/"}, want: true},
		{name: "exact match allowed", source: "/srv/data", allowed: []string{"/srv/data"}, want: true},
		{name: "child path allowed", source: "/srv/data/cache", allowed: []string{"/srv/data"}, want: true},
		{name: "sibling prefix rejected", source: "/srv/database", allowed: []string{"/srv/data"}, want: false},
		{name: "parent path rejected", source: "/srv", allowed: []string{"/srv/data"}, want: false},
		{name: "empty allowlist rejected", source: "/srv/data", allowed: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindPathAllowed(tt.source, tt.allowed); got != tt.want {
				t.Fatalf("bindPathAllowed(%q, %v) = %v, want %v", tt.source, tt.allowed, got, tt.want)
			}
		})
	}
}

// TestContainerCreatePolicyInspectCapsOversizedBody locks in the OOM guard.
// A malicious client sending a body larger than maxContainerCreateBodyBytes
// must be rejected with 413 and must not cause the proxy to read unbounded
// memory. The LimitReader caps the read at maxBytes+1, so even a body of
// 100 MiB on the wire only costs ~1 MiB of proxy RAM for the check itself
// before the rejection is returned.
func TestContainerCreatePolicyInspectCapsOversizedBody(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})

	oversized := bytes.Repeat([]byte{'x'}, maxContainerCreateBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(oversized))

	reason, err := policy.inspect(nil, req, "/containers/create")
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		t.Fatalf("inspect() error = %v, want request rejection", err)
	}
	if rejection.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("rejection status = %d, want %d", rejection.status, http.StatusRequestEntityTooLarge)
	}
	wantPrefix := "container create denied: request body exceeds"
	if len(rejection.reason) < len(wantPrefix) || rejection.reason[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("rejection reason = %q, want prefix %q", rejection.reason, wantPrefix)
	}
}

// TestCanonicalizeDeviceCgroupRule verifies parsing, normalization, and
// perm-sorting of Docker device cgroup rule strings.
func TestCanonicalizeDeviceCgroupRule(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		want      string
		wantOK    bool
	}{
		{name: "exact char device", raw: "c 1:3 rwm", want: "c 1:3 rwm", wantOK: true},
		// Cover both digit boundaries explicitly so a CONDITIONALS_BOUNDARY
		// mutation on isDeviceCgroupNumber (`< '0'` → `<= '0'` or `> '9'` →
		// `>= '9'`) is caught by the canonicalize path.
		{name: "major minor at digit boundaries", raw: "c 0:9 rwm", want: "c 0:9 rwm", wantOK: true},
		{name: "minor at upper digit boundary", raw: "c 9:0 rwm", want: "c 9:0 rwm", wantOK: true},
		{name: "block device", raw: "b 8:0 rw", want: "b 8:0 rw", wantOK: true},
		{name: "wildcard major", raw: "c *:3 rwm", want: "c *:3 rwm", wantOK: true},
		{name: "wildcard minor", raw: "c 226:* rwm", want: "c 226:* rwm", wantOK: true},
		{name: "both wildcards", raw: "c *:* rwm", want: "c *:* rwm", wantOK: true},
		{name: "perms sorted mrw→rwm", raw: "c 1:3 mrw", want: "c 1:3 rwm", wantOK: true},
		{name: "extra whitespace normalized", raw: "c  1:3  rwm", want: "c 1:3 rwm", wantOK: true},
		{name: "perms out of order wm→mw", raw: "c 1:3 wm", want: "c 1:3 wm", wantOK: true},
		{name: "all type", raw: "a *:* rwm", want: "a *:* rwm", wantOK: true},
		{name: "empty string", raw: "", wantOK: false},
		{name: "missing minor", raw: "c 1 rwm", wantOK: false},
		{name: "bad type", raw: "x 1:3 rwm", wantOK: false},
		{name: "bad perms char", raw: "c 1:3 rwx", wantOK: false},
		{name: "empty perms", raw: "c 1:3 ", wantOK: false},
		{name: "non-numeric major", raw: "c foo:3 rwm", wantOK: false},
		{name: "non-numeric minor", raw: "c 1:bar rwm", wantOK: false},
		{name: "too few fields", raw: "c 1:3", wantOK: false},
		{name: "too many fields", raw: "c 1:3 rwm extra", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := canonicalizeDeviceCgroupRule(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("canonicalizeDeviceCgroupRule(%q) ok = %v, want %v", tt.raw, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Fatalf("canonicalizeDeviceCgroupRule(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestSortDeviceCgroupPerms verifies that perms are sorted into r, w, m order
// and duplicates are removed.
func TestSortDeviceCgroupPerms(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"rwm", "rwm"},
		{"mrw", "rwm"},
		{"wmr", "rwm"},
		{"r", "r"},
		{"w", "w"},
		{"m", "m"},
		{"wm", "wm"},
		{"rr", "r"},
		{"rww", "rw"},
		{"rrmm", "rm"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got := sortDeviceCgroupPerms(tt.raw)
			if got != tt.want {
				t.Fatalf("sortDeviceCgroupPerms(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestDeviceCgroupRuleAllowed verifies the matching logic between request
// rules and allowlist entries, including wildcard handling.
func TestDeviceCgroupRuleAllowed(t *testing.T) {
	tests := []struct {
		name      string
		canonical string
		allowlist []string
		want      bool
	}{
		{
			name:      "exact match allowed",
			canonical: "c 1:3 rwm",
			allowlist: []string{"c 1:3 rwm"},
			want:      true,
		},
		{
			name:      "exact match denied when not in list",
			canonical: "c 1:5 rwm",
			allowlist: []string{"c 1:3 rwm"},
			want:      false,
		},
		{
			name:      "allowlist wildcard minor matches any minor",
			canonical: "c 226:128 rwm",
			allowlist: []string{"c 226:* rwm"},
			want:      true,
		},
		{
			name:      "allowlist wildcard major matches any major",
			canonical: "c 10:200 rwm",
			allowlist: []string{"c *:200 rwm"},
			want:      true,
		},
		{
			name:      "allowlist both wildcards matches numeric request",
			canonical: "c 99:99 rwm",
			allowlist: []string{"c *:* rwm"},
			want:      true,
		},
		{
			name:      "request wildcard minor denied against numeric allowlist",
			canonical: "c 1:* rwm",
			allowlist: []string{"c 1:3 rwm"},
			want:      false,
		},
		{
			name:      "request wildcard major denied against numeric allowlist",
			canonical: "c *:3 rwm",
			allowlist: []string{"c 1:3 rwm"},
			want:      false,
		},
		{
			name:      "request wildcard minor allowed when allowlist also wildcard minor",
			canonical: "c 1:* rwm",
			allowlist: []string{"c 1:* rwm"},
			want:      true,
		},
		{
			name:      "type mismatch denied",
			canonical: "b 1:3 rwm",
			allowlist: []string{"c 1:3 rwm"},
			want:      false,
		},
		{
			name:      "perms mismatch denied",
			canonical: "c 1:3 rw",
			allowlist: []string{"c 1:3 rwm"},
			want:      false,
		},
		{
			name:      "empty allowlist denies all",
			canonical: "c 1:3 rwm",
			allowlist: []string{},
			want:      false,
		},
		{
			name:      "first allowlist entry mismatch second match",
			canonical: "c 1:3 rwm",
			allowlist: []string{"c 226:* rwm", "c 1:3 rwm"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deviceCgroupRuleAllowed(tt.canonical, tt.allowlist)
			if got != tt.want {
				t.Fatalf("deviceCgroupRuleAllowed(%q, %v) = %v, want %v", tt.canonical, tt.allowlist, got, tt.want)
			}
		})
	}
}

// TestContainerCreatePolicyDenyDeviceCgroupRulesReason exercises the full
// end-to-end path from ContainerCreateOptions → inspect() → deny reason.
func TestContainerCreatePolicyDenyDeviceCgroupRulesReason(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			// (a) empty allowlist denies any rule
			name:       "empty allowlist denies any rule",
			opts:       ContainerCreateOptions{},
			body:       `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rwm"]}}`,
			wantReason: "container create denied: device cgroup rules are not allowed",
		},
		{
			// (b) exact-match allow
			name: "exact match allow",
			opts: ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm"}},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rwm"]}}`,
		},
		{
			// (c) major-wildcard allowlist matches any minor
			name: "major-wildcard allowlist allows matching minor",
			opts: ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 226:* rwm"}},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 226:128 rwm"]}}`,
		},
		{
			// (c) non-matching minor is denied
			name:       "major-wildcard allowlist denies non-matching type",
			opts:       ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 226:* rwm"}},
			body:       `{"HostConfig":{"DeviceCgroupRules":["b 226:128 rwm"]}}`,
			wantReason: `container create denied: device cgroup rule "b 226:128 rwm" is not in the allowed list`,
		},
		{
			// (d) wildcard in request denied against non-wildcard allowlist
			name:       "wildcard in request denied against numeric allowlist",
			opts:       ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm"}},
			body:       `{"HostConfig":{"DeviceCgroupRules":["c 1:* rwm"]}}`,
			wantReason: `container create denied: device cgroup rule "c 1:* rwm" is not in the allowed list`,
		},
		{
			// (e) malformed rule in request → deny with malformed message
			name:       "malformed rule in request denied",
			opts:       ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm"}},
			body:       `{"HostConfig":{"DeviceCgroupRules":["z 1 bad"]}}`,
			wantReason: `container create denied: device cgroup rule "z 1 bad" is malformed`,
		},
		{
			// (f) allowlist canonicalization: whitespace normalization
			name: "allowlist entry with extra whitespace canonicalized",
			opts: ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c  1:3  rwm"}},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rwm"]}}`,
		},
		{
			// (f) allowlist canonicalization: perm order
			name: "allowlist entry with unsorted perms canonicalized",
			opts: ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 mrw"}},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rwm"]}}`,
		},
		{
			// allowDeviceCgroupRules true → blanket allow, overrides allowlist check
			name: "allow_device_cgroup_rules true bypasses allowlist",
			opts: ContainerCreateOptions{AllowDeviceCgroupRules: true},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 999:999 rwm"]}}`,
		},
		{
			// Multiple rules: first passes, second fails
			name: "multiple rules first passes second fails",
			opts: ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm"}},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rwm","c 10:200 rwm"]}}`,
			wantReason: `container create denied: device cgroup rule "c 10:200 rwm" is not in the allowed list`,
		},
		{
			// /dev/null = c 1:3, /dev/dri GPU range c 226:* rwm
			name: "dev/null and GPU range both allowed",
			opts: ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm", "c 226:* rwm"}},
			body: `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rwm","c 226:128 rwm"]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestNewContainerCreatePolicyNormalizesDeviceCgroupRules verifies that the
// allowlist is canonicalized and deduplicated during policy construction.
func TestNewContainerCreatePolicyNormalizesDeviceCgroupRules(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedDeviceCgroupRules: []string{
			"c  1:3  rwm",  // extra whitespace
			"c 1:3 mrw",   // unsorted perms (same as above after canon)
			"c 226:* rwm", // unique entry
			"z bad",       // invalid, should be skipped
		},
	})

	// "c  1:3  rwm" and "c 1:3 mrw" both canonicalize to "c 1:3 rwm"
	// "z bad" is invalid and skipped
	// result should be ["c 1:3 rwm", "c 226:* rwm"]
	want := []string{"c 1:3 rwm", "c 226:* rwm"}
	if len(policy.allowedDeviceCgroupRules) != len(want) {
		t.Fatalf("allowedDeviceCgroupRules = %v, want %v", policy.allowedDeviceCgroupRules, want)
	}
	for i, wantEntry := range want {
		if policy.allowedDeviceCgroupRules[i] != wantEntry {
			t.Fatalf("allowedDeviceCgroupRules[%d] = %q, want %q", i, policy.allowedDeviceCgroupRules[i], wantEntry)
		}
	}
}

// TestContainerCreatePolicyDenyDeviceRequestsReason exercises the full
// end-to-end path from ContainerCreateOptions → inspect() → deny reason for
// the allowed_device_requests structured allowlist.
func TestContainerCreatePolicyDenyDeviceRequestsReason(t *testing.T) {
	maxOne := 1
	maxAllDevices := -1

	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			// (a) default-deny: neither flag nor allowlist set
			name:       "default deny when no flag and no allowlist",
			opts:       ContainerCreateOptions{},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}}`,
			wantReason: "container create denied: device requests are not allowed",
		},
		{
			// (b) allow_device_requests: true overrides allowlist entirely
			name: "allow_device_requests true bypasses allowlist",
			opts: ContainerCreateOptions{AllowDeviceRequests: true},
			body: `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu","utility"]]}]}}`,
		},
		{
			// (c) allowlist match: driver + capability subset → allowed
			name: "single entry match allowed",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu", "compute"}}},
				},
			},
			body: `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1,"Capabilities":[["gpu"]]}]}}`,
		},
		{
			// (d) different driver → denied
			name: "different driver denied",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"amd","Count":1,"Capabilities":[["gpu"]]}]}}`,
			wantReason: `container create denied: device request 0 (driver "amd") is not permitted by the allowlist`,
		},
		{
			// (e) capability not in any allowlisted set → denied
			name: "capability not in allowlisted sets denied",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1,"Capabilities":[["gpu","compute"]]}]}}`,
			wantReason: `container create denied: device request 0 (driver "nvidia") is not permitted by the allowlist`,
		},
		{
			// (f) multiple requests, second violates → denied
			name: "multiple requests one violates",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1,"Capabilities":[["gpu"]]},{"Driver":"amd","Count":1,"Capabilities":[["gpu"]]}]}}`,
			wantReason: `container create denied: device request 1 (driver "amd") is not permitted by the allowlist`,
		},
		{
			// (g) max_count enforcement: within cap → allowed
			name: "max_count within cap allowed",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}, MaxCount: &maxOne},
				},
			},
			body: `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1,"Capabilities":[["gpu"]]}]}}`,
		},
		{
			// (h) max_count enforcement: exceeds cap → denied
			name: "max_count exceeded denied",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}, MaxCount: &maxOne},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":4,"Capabilities":[["gpu"]]}]}}`,
			wantReason: `container create denied: device request 0 (driver "nvidia") is not permitted by the allowlist`,
		},
		{
			// (i) max_count -1 allows Count=-1 (all devices)
			name: "max_count -1 allows all devices",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}, MaxCount: &maxAllDevices},
				},
			},
			body: `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}}`,
		},
		{
			// (j) count -1 (all) denied when max_count is a positive cap
			name: "count -1 denied when max_count is positive",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}, MaxCount: &maxOne},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}}`,
			wantReason: `container create denied: device request 0 (driver "nvidia") is not permitted by the allowlist`,
		},
		{
			// (k) malformed request: empty Driver → denied
			name: "empty driver denied",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"","Count":1,"Capabilities":[["gpu"]]}]}}`,
			wantReason: "container create denied: device request 0 has an empty Driver field",
		},
		{
			// (l) driver case-insensitive matching
			name: "driver match is case insensitive",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "NVIDIA", AllowedCapabilities: [][]string{{"gpu"}}},
				},
			},
			body: `{"HostConfig":{"DeviceRequests":[{"Driver":"Nvidia","Count":1,"Capabilities":[["gpu"]]}]}}`,
		},
		{
			// (m) no DeviceRequests in body → always allowed regardless of policy
			name: "no device requests always allowed",
			opts: ContainerCreateOptions{},
			body: `{"HostConfig":{}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestNewContainerCreatePolicyNormalizesDeviceRequests verifies that allowlist
// entries are canonicalized (driver lowercased, caps sorted/deduped) and that
// invalid entries (empty driver) are skipped.
func TestNewContainerCreatePolicyNormalizesDeviceRequests(t *testing.T) {
	maxTwo := 2
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedDeviceRequests: []AllowedDeviceRequestEntry{
			{Driver: "NVIDIA", AllowedCapabilities: [][]string{{"compute", "gpu", "gpu"}}, MaxCount: &maxTwo},
			{Driver: "", AllowedCapabilities: [][]string{{"gpu"}}},                // invalid: empty driver, skipped
			{Driver: "  amd  ", AllowedCapabilities: [][]string{{"gpu", "video"}}}, // whitespace stripped
		},
	})

	if len(policy.allowedDeviceRequests) != 2 {
		t.Fatalf("allowedDeviceRequests len = %d, want 2 (got %v)", len(policy.allowedDeviceRequests), policy.allowedDeviceRequests)
	}

	// First entry: driver lowercased, caps deduped and sorted
	e0 := policy.allowedDeviceRequests[0]
	if e0.driver != "nvidia" {
		t.Fatalf("entry[0].driver = %q, want %q", e0.driver, "nvidia")
	}
	wantCaps0 := []string{"compute", "gpu"} // sorted, deduped
	if len(e0.allowedCapabilities) != 1 || len(e0.allowedCapabilities[0]) != len(wantCaps0) {
		t.Fatalf("entry[0].allowedCapabilities = %v, want [%v]", e0.allowedCapabilities, wantCaps0)
	}
	for i, c := range wantCaps0 {
		if e0.allowedCapabilities[0][i] != c {
			t.Fatalf("entry[0].allowedCapabilities[0][%d] = %q, want %q", i, e0.allowedCapabilities[0][i], c)
		}
	}
	if e0.maxCount == nil || *e0.maxCount != maxTwo {
		t.Fatalf("entry[0].maxCount = %v, want %d", e0.maxCount, maxTwo)
	}

	// Second entry: trimmed driver
	e1 := policy.allowedDeviceRequests[1]
	if e1.driver != "amd" {
		t.Fatalf("entry[1].driver = %q, want %q", e1.driver, "amd")
	}
}

// ---------------------------------------------------------------------------
// Image trust filter tests
// ---------------------------------------------------------------------------

// mockImageVerifier is a test stub for the imageVerifier interface. It returns
// the configured error (or nil) on every Verify call and records the last
// imageRef it was called with.
type mockImageVerifier struct {
	err        error
	lastCalled string
}

func (m *mockImageVerifier) Verify(_ context.Context, imageRef, _ string, _ verify.SignedEntity) error {
	m.lastCalled = imageRef
	return m.err
}

// ctxRecordingImageVerifier records whether the ctx handed to Verify had a
// deadline set. Used to pin the timeout-gate at container_create.go:361
// (`p.imageTrustTimeout > 0`).
type ctxRecordingImageVerifier struct {
	err            error
	sawDeadline    bool
	deadlineRemain time.Duration
}

func (m *ctxRecordingImageVerifier) Verify(ctx context.Context, _, _ string, _ verify.SignedEntity) error {
	if dl, ok := ctx.Deadline(); ok {
		m.sawDeadline = true
		m.deadlineRemain = time.Until(dl)
	}
	return m.err
}

// makeInspectRequest builds a minimal POST /containers/create request with the
// given JSON body string.
func makeInspectRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestImageTrust_NilVerifier_PassesThrough(t *testing.T) {
	// When no verifier is configured the request must always be allowed.
	policy := containerCreatePolicy{}
	reason, err := policy.inspect(nil, makeInspectRequest(t, `{"Image":"docker.io/library/alpine:3.21"}`), "/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != "" {
		t.Fatalf("expected empty deny reason, got %q", reason)
	}
}

func TestImageTrust_Enforce_VerifierCalledWithImageRef(t *testing.T) {
	mv := &mockImageVerifier{}
	cfg := imagetrust.Config{Mode: imagetrust.ModeEnforce}
	policy := containerCreatePolicy{
		allowPrivileged:  true,
		allowHostNetwork: true,
		allowHostPID:     true,
		allowHostIPC:     true,
		allowHostUserNS:  true,
		allowAllDevices:  true,
		allowAllCapabilities: true,
		allowDeviceRequests:  true,
		allowDeviceCgroupRules: true,
		imageTrustVerifier: mv,
		imageTrustCfg:      cfg,
		imageTrustTimeout:  0,
	}

	body := `{"Image":"registry.example.com/myapp:v1.2.3","HostConfig":{}}`
	reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != "" {
		t.Fatalf("expected allow (verifier returns nil), got %q", reason)
	}
	if mv.lastCalled != "registry.example.com/myapp:v1.2.3" {
		t.Fatalf("verifier called with %q, want %q", mv.lastCalled, "registry.example.com/myapp:v1.2.3")
	}
}

func TestImageTrust_Enforce_DeniesOnVerifierError(t *testing.T) {
	mv := &mockImageVerifier{err: errors.New("no valid signature found")}
	cfg := imagetrust.Config{Mode: imagetrust.ModeEnforce}
	policy := containerCreatePolicy{
		allowPrivileged:  true,
		allowHostNetwork: true,
		allowHostPID:     true,
		allowHostIPC:     true,
		allowHostUserNS:  true,
		allowAllDevices:  true,
		allowAllCapabilities: true,
		allowDeviceRequests:  true,
		allowDeviceCgroupRules: true,
		imageTrustVerifier: mv,
		imageTrustCfg:      cfg,
	}

	body := `{"Image":"registry.example.com/unsigned:latest","HostConfig":{}}`
	reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason == "" {
		t.Fatal("expected a deny reason, got empty string")
	}
	const wantSub = "image trust verification failed"
	if !containsSubstring(reason, wantSub) {
		t.Fatalf("deny reason %q does not contain %q", reason, wantSub)
	}
	if !containsSubstring(reason, "registry.example.com/unsigned:latest") {
		t.Fatalf("deny reason %q does not contain image ref", reason)
	}
}

func TestImageTrust_Warn_AllowsOnVerifierError(t *testing.T) {
	mv := &mockImageVerifier{err: errors.New("no valid signature found")}
	cfg := imagetrust.Config{Mode: imagetrust.ModeWarn}
	policy := containerCreatePolicy{
		allowPrivileged:  true,
		allowHostNetwork: true,
		allowHostPID:     true,
		allowHostIPC:     true,
		allowHostUserNS:  true,
		allowAllDevices:  true,
		allowAllCapabilities: true,
		allowDeviceRequests:  true,
		allowDeviceCgroupRules: true,
		imageTrustVerifier: mv,
		imageTrustCfg:      cfg,
	}

	body := `{"Image":"registry.example.com/unsigned:latest","HostConfig":{}}`
	reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != "" {
		t.Fatalf("warn mode: expected allow despite failure, got deny reason %q", reason)
	}
}

func TestImageTrust_EmptyImage_DeniedWhenVerifierConfigured(t *testing.T) {
	// When image trust is configured, an empty Image field must be denied
	// explicitly rather than silently skipping verification (fail-closed).
	mv := &mockImageVerifier{err: errors.New("should not be called")}
	cfg := imagetrust.Config{Mode: imagetrust.ModeEnforce}
	policy := containerCreatePolicy{
		allowPrivileged:  true,
		allowHostNetwork: true,
		allowHostPID:     true,
		allowHostIPC:     true,
		allowHostUserNS:  true,
		allowAllDevices:  true,
		allowAllCapabilities: true,
		allowDeviceRequests:  true,
		allowDeviceCgroupRules: true,
		imageTrustVerifier: mv,
		imageTrustCfg:      cfg,
	}

	body := `{"Image":"","HostConfig":{}}`
	reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const wantReason = "container create denied: image field is required when image trust is configured"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
	}
	if mv.lastCalled != "" {
		t.Fatalf("verifier should not have been called, but lastCalled = %q", mv.lastCalled)
	}
}

func TestImageTrust_BodyInspectedWhenVerifierPresent(t *testing.T) {
	// Even with every flag permissive, a non-nil imageTrustVerifier must cause
	// the request body to be read and the verifier to be called.
	mv := &mockImageVerifier{}
	cfg := imagetrust.Config{Mode: imagetrust.ModeEnforce}
	policy := containerCreatePolicy{
		allowPrivileged:        true,
		allowHostNetwork:       true,
		allowHostPID:           true,
		allowHostIPC:           true,
		allowHostUserNS:        true,
		allowAllDevices:        true,
		allowAllCapabilities:   true,
		allowDeviceRequests:    true,
		allowDeviceCgroupRules: true,
		imageTrustVerifier:     mv,
		imageTrustCfg:          cfg,
	}
	body := `{"Image":"registry.example.com/app:v1","HostConfig":{}}`
	reason, err := policy.inspect(nil, makeInspectRequest(t, body), "/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want allow (verifier returns nil)", reason)
	}
	if mv.lastCalled != "registry.example.com/app:v1" {
		t.Fatalf("verifier lastCalled = %q, want registry.example.com/app:v1 — body was not inspected", mv.lastCalled)
	}
}

// TestImageTrust_TimeoutGateRespectsZero pins both surviving mutants at
// container_create.go:361:26 (CONDITIONALS_BOUNDARY `>` → `>=` and
// CONDITIONALS_NEGATION `>` → `<=`). The guard is `if p.imageTrustTimeout > 0`
// — only wrap the verifier ctx with a deadline when the timeout is meaningful.
//
// At imageTrustTimeout=0 the original skips context.WithTimeout entirely, so
// the verifier sees the request's bare context (no Deadline). Both mutants
// would call context.WithTimeout(ctx, 0) which sets an immediate deadline.
// We assert the verifier saw no deadline.
//
// A companion sub-test pins the positive-timeout path: with imageTrustTimeout=
// 10s the original sets the deadline; the NEGATION mutant (`<= 0`) would NOT
// set it. We assert the verifier sees a deadline that's roughly the configured
// timeout.
func TestImageTrust_TimeoutGateRespectsZero(t *testing.T) {
	t.Run("zero timeout leaves ctx unwrapped", func(t *testing.T) {
		mv := &ctxRecordingImageVerifier{}
		policy := containerCreatePolicy{
			imageTrustVerifier: mv,
			imageTrustCfg:      imagetrust.Config{Mode: imagetrust.ModeEnforce},
			imageTrustTimeout:  0,
		}
		reason, err := policy.inspect(nil, makeInspectRequest(t, `{"Image":"registry.example.com/app:v1","HostConfig":{}}`), "/containers/create")
		if err != nil {
			t.Fatalf("inspect err = %v", err)
		}
		if reason != "" {
			t.Fatalf("inspect reason = %q, want empty (verifier returns nil)", reason)
		}
		if mv.sawDeadline {
			t.Fatalf("verifier ctx had a deadline (remaining=%v) — original `imageTrustTimeout > 0` is false at 0; mutant `>= 0` or `<= 0` would call WithTimeout(0) and stamp a deadline", mv.deadlineRemain)
		}
	})

	t.Run("positive timeout wraps ctx with deadline", func(t *testing.T) {
		mv := &ctxRecordingImageVerifier{}
		policy := containerCreatePolicy{
			imageTrustVerifier: mv,
			imageTrustCfg:      imagetrust.Config{Mode: imagetrust.ModeEnforce},
			imageTrustTimeout:  10 * time.Second,
		}
		reason, err := policy.inspect(nil, makeInspectRequest(t, `{"Image":"registry.example.com/app:v1","HostConfig":{}}`), "/containers/create")
		if err != nil {
			t.Fatalf("inspect err = %v", err)
		}
		if reason != "" {
			t.Fatalf("inspect reason = %q, want empty", reason)
		}
		if !mv.sawDeadline {
			t.Fatalf("verifier ctx had no deadline — original `imageTrustTimeout > 0` is true at 10s; mutant `<= 0` would skip WithTimeout and leave ctx bare")
		}
		// Remaining should be close to 10s (allow generous slack for slow CI).
		if mv.deadlineRemain < time.Second || mv.deadlineRemain > 11*time.Second {
			t.Fatalf("deadline remaining = %v, want ~10s", mv.deadlineRemain)
		}
	})
}

func TestContainerCreatePolicySysctls(t *testing.T) {
	tests := []struct {
		name         string
		opts         ContainerCreateOptions
		body         string
		wantReason   string
	}{
		{
			name:       "sysctls present AllowSysctls=false → deny",
			opts:       ContainerCreateOptions{},
			body:       `{"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`,
			wantReason: "container create denied: setting sysctls is not allowed",
		},
		{
			name: "sysctls present AllowSysctls=true → allow",
			opts: ContainerCreateOptions{AllowSysctls: true},
			body: `{"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`,
		},
		{
			name: "sysctls absent → allow (unaffected)",
			opts: ContainerCreateOptions{},
			body: `{"HostConfig":{}}`,
		},
		{
			name: "empty sysctls map → allow (unaffected)",
			opts: ContainerCreateOptions{},
			body: `{"HostConfig":{"Sysctls":{}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newContainerCreatePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := policy.inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// containsSubstring is a test helper to avoid importing strings in addition to bytes.
func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
