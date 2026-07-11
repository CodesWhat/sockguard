package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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

// TestContainerCreatePolicyInspectBodyReadErrorFailsClosed proves the
// highest-privilege inspector fails closed on a body-read I/O error: inspect
// must surface the error (reason empty, error non-nil with "read body"
// context) rather than return ("", nil), which the middleware treats as allow.
// A swallowed read error here would skip every container-create policy check
// — privileged, host-namespace, capability, device — so it is fail-open.
func TestContainerCreatePolicyInspectBodyReadErrorFailsClosed(t *testing.T) {
	sentinel := errors.New("read failed")
	policy := newContainerCreatePolicy(ContainerCreateOptions{})
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}

	reason, err := policy.inspect(nil, req, "/containers/create")
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("inspect() error = %v, want wrapped %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), "read body") {
		t.Fatalf("inspect() error = %q, want read body context", err)
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

func TestContainerCreatePolicyInspectCgroupNamespaceModeGate(t *testing.T) {
	const denyReason = "container create denied: host cgroup namespace mode is not allowed"

	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			name:       "host denied by default",
			body:       `{"HostConfig":{"CgroupnsMode":"host"}}`,
			wantReason: denyReason,
		},
		{
			name: "host allowed when configured",
			opts: ContainerCreateOptions{AllowHostCgroupNS: true},
			body: `{"HostConfig":{"CgroupnsMode":"host"}}`,
		},
		{
			name:       "host denied case insensitive",
			body:       `{"HostConfig":{"CgroupnsMode":"HOST"}}`,
			wantReason: denyReason,
		},
		{
			name:       "host denied with surrounding spaces",
			body:       `{"HostConfig":{"CgroupnsMode":" host "}}`,
			wantReason: denyReason,
		},
		{
			name: "private allowed by default",
			body: `{"HostConfig":{"CgroupnsMode":"private"}}`,
		},
		{
			name: "private allowed when configured",
			opts: ContainerCreateOptions{AllowHostCgroupNS: true},
			body: `{"HostConfig":{"CgroupnsMode":"private"}}`,
		},
		{
			name: "empty allowed by default",
			body: `{"HostConfig":{"CgroupnsMode":""}}`,
		},
		{
			name: "absent allowed by default",
			body: `{"HostConfig":{}}`,
		},
		{
			name: "other host namespace gates do not allow cgroupns host",
			opts: ContainerCreateOptions{
				AllowHostNetwork: true,
				AllowHostPID:     true,
				AllowHostIPC:     true,
				AllowHostUserNS:  true,
			},
			body:       `{"HostConfig":{"CgroupnsMode":"host"}}`,
			wantReason: denyReason,
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

func TestContainerNamespaceRef(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantRef string
		wantOK  bool
	}{
		{name: "valid id", mode: "container:abc123", wantRef: "abc123", wantOK: true},
		{name: "case insensitive prefix", mode: "Container:web", wantRef: "web", wantOK: true},
		{name: "upper case prefix", mode: "CONTAINER:worker-1", wantRef: "worker-1", wantOK: true},
		{name: "surrounding whitespace", mode: "  container:/service-api  ", wantRef: "/service-api", wantOK: true},
		{name: "empty ref", mode: "container:", wantOK: false},
		{name: "whitespace ref", mode: "container:   ", wantOK: false},
		{name: "non matching bridge", mode: "bridge", wantOK: false},
		{name: "non matching host", mode: "host", wantOK: false},
		{name: "non matching ns path", mode: "ns:/proc/1/ns/net", wantOK: false},
		{name: "prefix only too short", mode: "container", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRef, gotOK := ContainerNamespaceRef(tt.mode)
			if gotOK != tt.wantOK {
				t.Fatalf("ContainerNamespaceRef(%q) ok = %v, want %v", tt.mode, gotOK, tt.wantOK)
			}
			if gotRef != tt.wantRef {
				t.Fatalf("ContainerNamespaceRef(%q) ref = %q, want %q", tt.mode, gotRef, tt.wantRef)
			}
		})
	}
}

func TestIsNamespacePathMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		{name: "lowercase ns", mode: "ns:/proc/1/ns/net", want: true},
		{name: "uppercase ns", mode: "NS:/var/run/netns/build", want: true},
		{name: "surrounding whitespace", mode: "  Ns:/var/run/netns/build  ", want: true},
		{name: "prefix without path still matches", mode: "ns:", want: true},
		{name: "container mode", mode: "container:abc123", want: false},
		{name: "host mode", mode: "host", want: false},
		{name: "empty", mode: "", want: false},
		{name: "not prefix", mode: "xns:/proc/1/ns/net", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNamespacePathMode(tt.mode); got != tt.want {
				t.Fatalf("isNamespacePathMode(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestContainerCreatePolicyInspectNamespaceSharingGate(t *testing.T) {
	fields := []struct {
		name           string
		jsonField      string
		hostDenyReason string
		emptyDenyLabel string
	}{
		{name: "network", jsonField: "NetworkMode", hostDenyReason: "container create denied: host network mode is not allowed", emptyDenyLabel: "network"},
		{name: "pid", jsonField: "PidMode", hostDenyReason: "container create denied: host PID mode is not allowed", emptyDenyLabel: "PID"},
		{name: "ipc", jsonField: "IpcMode", hostDenyReason: "container create denied: host IPC mode is not allowed", emptyDenyLabel: "IPC"},
		{name: "uts", jsonField: "UTSMode", hostDenyReason: "container create denied: host UTS mode is not allowed", emptyDenyLabel: "UTS"},
		{name: "userns", jsonField: "UsernsMode", hostDenyReason: "container create denied: host user namespace mode is not allowed", emptyDenyLabel: "user"},
	}
	values := []struct {
		name  string
		value string
	}{
		{name: "allowed container", value: "container:allowed-id"},
		{name: "other container", value: "container:other-id"},
		{name: "foo container", value: "container:foo"},
		{name: "host", value: "host"},
		{name: "bridge", value: "bridge"},
		{name: "empty", value: ""},
	}
	policies := []struct {
		name      string
		restrict  bool
		allowlist []string
	}{
		{name: "restrict off empty allowlist", restrict: false, allowlist: nil},
		{name: "restrict off populated allowlist", restrict: false, allowlist: []string{"allowed-id"}},
		{name: "restrict on empty allowlist", restrict: true, allowlist: nil},
		{name: "restrict on populated allowlist", restrict: true, allowlist: []string{"allowed-id"}},
		{name: "restrict on foo allowlist", restrict: true, allowlist: []string{"foo"}},
	}

	for _, field := range fields {
		for _, policy := range policies {
			for _, value := range values {
				t.Run(field.name+"/"+policy.name+"/"+value.name, func(t *testing.T) {
					opts := ContainerCreateOptions{
						RestrictNamespaceSharing:          policy.restrict,
						AllowedNamespaceSharingContainers: policy.allowlist,
					}
					body := fmt.Sprintf(`{"HostConfig":{%q:%q}}`, field.jsonField, value.value)
					req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))

					reason, err := newContainerCreatePolicy(opts).inspect(nil, req, "/containers/create")
					if err != nil {
						t.Fatalf("inspect() error = %v", err)
					}

					wantReason := ""
					ref, isContainerRef := ContainerNamespaceRef(value.value)
					switch {
					case value.value == "host":
						wantReason = field.hostDenyReason
					case isContainerRef && policy.restrict && len(policy.allowlist) == 0:
						wantReason = fmt.Sprintf("container create denied: %s namespace sharing with another container is not allowed", field.emptyDenyLabel)
					case isContainerRef && policy.restrict && !slices.Contains(policy.allowlist, ref):
						wantReason = fmt.Sprintf("container create denied: namespace-sharing target %q is not in the allowed list", ref)
					}

					if reason != wantReason {
						t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
					}
					if !policy.restrict && isContainerRef {
						gotBody, readErr := io.ReadAll(req.Body)
						if readErr != nil {
							t.Fatalf("ReadAll() error = %v", readErr)
						}
						if string(gotBody) != body {
							t.Fatalf("body after inspect = %q, want unchanged %q", string(gotBody), body)
						}
					}
				})
			}
		}
	}
}

func TestContainerCreatePolicyInspectDenyNamespacePathMode(t *testing.T) {
	tests := []struct {
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
	}{
		{
			name: "off passes network ns path",
			body: `{"HostConfig":{"NetworkMode":"ns:/proc/1/ns/net"}}`,
		},
		{
			name:       "on denies network ns path",
			opts:       ContainerCreateOptions{DenyNamespacePathMode: true},
			body:       `{"HostConfig":{"NetworkMode":"ns:/proc/1/ns/net"}}`,
			wantReason: "container create denied: ns: namespace path mode is not allowed",
		},
		{
			name: "off passes uppercase network ns path",
			body: `{"HostConfig":{"NetworkMode":"NS:/var/run/netns/build"}}`,
		},
		{
			name:       "on denies uppercase network ns path",
			opts:       ContainerCreateOptions{DenyNamespacePathMode: true},
			body:       `{"HostConfig":{"NetworkMode":"NS:/var/run/netns/build"}}`,
			wantReason: "container create denied: ns: namespace path mode is not allowed",
		},
		{
			name: "on is scoped to NetworkMode only",
			opts: ContainerCreateOptions{DenyNamespacePathMode: true},
			body: `{"HostConfig":{"PidMode":"ns:/proc/1/ns/pid","IpcMode":"ns:/proc/1/ns/ipc","UsernsMode":"ns:/proc/1/ns/user"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.body))
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

// TestContainerCreatePolicyInspectDeniesEndpointConfigByDefault proves
// POST /containers/create's NetworkingConfig.EndpointsConfig carries the same
// endpoint-config gate as POST /networks/*/connect — the create-side policy
// bypass this closes (real incident: drydock recreating a macvlan+static-IP
// container had its POST /networks/*/connect denied by the connect-side gate,
// but the identical config on create's primary network went unchecked).
func TestContainerCreatePolicyInspectDeniesEndpointConfigByDefault(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "static IP via IPAMConfig",
			body:       `{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"macvlan0":{"IPAMConfig":{"IPv4Address":"172.30.0.10"}}}}}`,
			wantReason: "container create denied: endpoint static IP configuration is not allowed",
		},
		{
			name:       "static IP via IPAddress",
			body:       `{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"macvlan0":{"IPAddress":"172.30.0.10"}}}}`,
			wantReason: "container create denied: endpoint static IP configuration is not allowed",
		},
		{
			name:       "MAC address",
			body:       `{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"macvlan0":{"MacAddress":"02:42:ac:1e:00:0a"}}}}`,
			wantReason: "container create denied: endpoint MAC address is not allowed",
		},
		{
			name:       "links",
			body:       `{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"bridge":{"Links":["db:database"]}}}}`,
			wantReason: "container create denied: endpoint links are not allowed",
		},
		{
			name:       "driver options",
			body:       `{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"bridge":{"DriverOpts":{"foo":"bar"}}}}}`,
			wantReason: "container create denied: endpoint driver options are not allowed",
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

// TestContainerCreatePolicyInspectAllowsEndpointConfigWhenConfigured proves
// AllowEndpointConfig lifts every gated field (static IP, MAC, links, driver
// opts) on create's NetworkingConfig, mirroring network.AllowEndpointConfig's
// effect on connect — the same single config knob governs both endpoints.
func TestContainerCreatePolicyInspectAllowsEndpointConfigWhenConfigured(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{AllowEndpointConfig: true})
	body := `{
		"Image": "x",
		"NetworkingConfig": {
			"EndpointsConfig": {
				"macvlan0": {
					"IPAMConfig": {"IPv4Address": "172.30.0.10"},
					"MacAddress": "02:42:ac:1e:00:0a",
					"Links": ["db:database"],
					"DriverOpts": {"foo": "bar"}
				}
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))

	reason, err := policy.inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

// TestContainerCreatePolicyInspectAllowsAliasesOnlyEndpointConfigByDefault
// proves Aliases are never gated on create's NetworkingConfig either — Docker
// Compose sets Aliases: [serviceName] on every endpoint it creates, so a
// multi-network Compose recreate (which drives its secondary networks through
// this exact NetworkingConfig.EndpointsConfig shape) must pass without the
// flag.
func TestContainerCreatePolicyInspectAllowsAliasesOnlyEndpointConfigByDefault(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})
	body := `{"Image":"x","NetworkingConfig":{"EndpointsConfig":{"app-net":{"Aliases":["web"]}}}}`
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))

	reason, err := policy.inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

// TestContainerCreatePolicyInspectDeniesEndpointConfigAcrossMultipleNetworks
// proves every entry of EndpointsConfig is inspected, not just the first map
// key encountered: "backend" (alphabetically first, clean) must not shadow
// "frontend" (alphabetically second, carries a static IP). Iteration is over
// sorted keys, so the denial is deterministic across runs despite Go's
// randomized map order.
func TestContainerCreatePolicyInspectDeniesEndpointConfigAcrossMultipleNetworks(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})
	body := `{
		"Image": "x",
		"NetworkingConfig": {
			"EndpointsConfig": {
				"backend": {"Aliases": ["db"]},
				"frontend": {"IPAddress": "172.30.0.10"}
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))

	reason, err := policy.inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	const wantReason = "container create denied: endpoint static IP configuration is not allowed"
	if reason != wantReason {
		t.Fatalf("inspect() reason = %q, want %q", reason, wantReason)
	}
}

// TestContainerCreatePolicyDenyNetworkingConfigReasonSkipsNilEndpoint proves a
// null EndpointsConfig map value (valid JSON: {"EndpointsConfig":{"net":null}})
// is skipped rather than dereferenced, so a NetworkingConfig entry with no
// EndpointSettings object cannot panic the inspector.
func TestContainerCreatePolicyDenyNetworkingConfigReasonSkipsNilEndpoint(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{})
	reason := policy.denyNetworkingConfigReason(containerCreateNetworkingConfig{
		EndpointsConfig: map[string]*networkEndpointConfig{"app-net": nil},
	})
	if reason != "" {
		t.Fatalf("denyNetworkingConfigReason() = %q, want empty", reason)
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
		name   string
		raw    string
		want   string
		wantOK bool
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
			name:       "multiple rules first passes second fails",
			opts:       ContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm"}},
			body:       `{"HostConfig":{"DeviceCgroupRules":["c 1:3 rwm","c 10:200 rwm"]}}`,
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
			"c  1:3  rwm", // extra whitespace
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
		{
			// (n) empty Capabilities must NOT vacuously satisfy a constraining
			// allowlist: runtimes expand empty caps to a default set, so a request
			// with no capabilities against a capability-constrained entry is denied.
			name: "empty capabilities denied against constrained allowlist",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1,"Capabilities":[]}]}}`,
			wantReason: `container create denied: device request 0 (driver "nvidia") is not permitted by the allowlist`,
		},
		{
			// (o) all-empty capability sets are equivalent to empty → still denied
			name: "all-empty capability sets denied against constrained allowlist",
			opts: ContainerCreateOptions{
				AllowedDeviceRequests: []AllowedDeviceRequestEntry{
					{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}},
				},
			},
			body:       `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":1,"Capabilities":[[""]]}]}}`,
			wantReason: `container create denied: device request 0 (driver "nvidia") is not permitted by the allowlist`,
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
			{Driver: "", AllowedCapabilities: [][]string{{"gpu"}}},                 // invalid: empty driver, skipped
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

// mockSignatureFetcher stands in for internal/imagefetch.Fetcher so inspect()
// tests reach the verifier without registry I/O. By default it returns a single
// dummy candidate so the configured verifier is invoked once.
type mockSignatureFetcher struct {
	candidates []imagetrust.Candidate
	err        error
	lastRef    string
}

func (m *mockSignatureFetcher) FetchCandidates(_ context.Context, _ *slog.Logger, imageRef string) ([]imagetrust.Candidate, error) {
	m.lastRef = imageRef
	return m.candidates, m.err
}

// oneCandidateFetcher returns a fetcher yielding a single dummy candidate; the
// stub verifiers ignore the digest/entity, so a placeholder digest is fine.
func oneCandidateFetcher() *mockSignatureFetcher {
	return &mockSignatureFetcher{candidates: []imagetrust.Candidate{{DigestHex: "00"}}}
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
		imageFetcher:           oneCandidateFetcher(),
		imageTrustCfg:          cfg,
		imageTrustTimeout:      0,
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
		imageFetcher:           oneCandidateFetcher(),
		imageTrustCfg:          cfg,
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
		imageFetcher:           oneCandidateFetcher(),
		imageTrustCfg:          cfg,
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
		imageFetcher:           oneCandidateFetcher(),
		imageTrustCfg:          cfg,
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
		imageFetcher:           oneCandidateFetcher(),
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

func TestImageTrust_Enforce_PinsVerifiedDigest(t *testing.T) {
	// On successful verification the mutable tag in Image is rewritten to the
	// verified manifest digest, closing the verify→pull TOCTOU window. Sibling
	// fields (including large integers) must survive byte-for-byte.
	const digest = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
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
		imageTrustVerifier:     &mockImageVerifier{},
		imageFetcher:           &mockSignatureFetcher{candidates: []imagetrust.Candidate{{DigestHex: "00", ImageDigest: digest}}},
		imageTrustCfg:          imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	body := `{"Image":"registry.example.com/app:v1","HostConfig":{"Memory":9223372036854775807}}`
	req := makeInspectRequest(t, body)
	reason, err := policy.inspect(nil, req, "/containers/create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want allow", reason)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if !strings.Contains(string(got), "registry.example.com/app@"+digest) {
		t.Fatalf("rewritten body = %s, want pinned digest reference", got)
	}
	if strings.Contains(string(got), `"registry.example.com/app:v1"`) {
		t.Fatalf("rewritten body still contains the mutable tag: %s", got)
	}
	if !strings.Contains(string(got), `9223372036854775807`) {
		t.Fatalf("rewritten body corrupted the Memory field: %s", got)
	}
	if req.ContentLength != int64(len(got)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(got))
	}
}

func TestImageTrust_Enforce_DeniesWhenVerifiedDigestCannotBePinned(t *testing.T) {
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
		imageTrustVerifier:     &mockImageVerifier{},
		imageFetcher:           &mockSignatureFetcher{candidates: []imagetrust.Candidate{{DigestHex: "00", ImageDigest: "notadigest"}}},
		imageTrustCfg:          imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	req := makeInspectRequest(t, `{"Image":"registry.example.com/app:v1","HostConfig":{}}`)

	reason, err := policy.inspect(nil, req, "/containers/create")
	if err == nil {
		t.Fatal("inspect() error = nil, want digest pinning error")
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty when returning an error", reason)
	}
	if !strings.Contains(err.Error(), "pin verified image digest") {
		t.Fatalf("inspect() error = %v, want digest pinning error", err)
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
			imageFetcher:       oneCandidateFetcher(),
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
			imageFetcher:       oneCandidateFetcher(),
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
		name       string
		opts       ContainerCreateOptions
		body       string
		wantReason string
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

// TestSplitDeviceCgroupRuleEdgeCases covers the branches not hit by the
// higher-level canonicalize tests: malformed inputs that trip the inner
// splitDeviceCgroupRule directly.
func TestSplitDeviceCgroupRuleEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantOK   bool
		wantType string
		wantMaj  string
		wantMin  string
		wantPerm string
	}{
		{"valid rule", "b 8:0 rw", true, "b", "8", "0", "rw"},
		{"too few fields", "b 8:0", false, "", "", "", ""},
		{"too many fields", "b 8:0 rw extra", false, "", "", "", ""},
		{"empty string", "", false, "", "", "", ""},
		{"missing colon in major:minor", "b 80 rw", false, "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devType, maj, min, perm, ok := splitDeviceCgroupRule(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("splitDeviceCgroupRule(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok {
				if devType != tt.wantType || maj != tt.wantMaj || min != tt.wantMin || perm != tt.wantPerm {
					t.Errorf("splitDeviceCgroupRule(%q) = (%q,%q,%q,%q), want (%q,%q,%q,%q)",
						tt.input, devType, maj, min, perm, tt.wantType, tt.wantMaj, tt.wantMin, tt.wantPerm)
				}
			}
		})
	}
}

func TestIsDeviceCgroupNumber(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"*", true},
		{"0", true},
		{"8", true},
		{"255", true},
		{"", false},
		{"-1", false},
		{"1a", false},
		{"a", false},
		{"1.5", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isDeviceCgroupNumber(tt.input)
			if got != tt.want {
				t.Errorf("isDeviceCgroupNumber(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidDeviceCgroupPerms(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"r", true},
		{"w", true},
		{"m", true},
		{"rw", true},
		{"rwm", true},
		{"mrw", true},
		{"", false},
		{"x", false},
		{"rq", false},
		{"rwx", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidDeviceCgroupPerms(tt.input)
			if got != tt.want {
				t.Errorf("isValidDeviceCgroupPerms(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCgroupPermOrder(t *testing.T) {
	// r < w < m; any other byte maps to 3 (higher than all valid perms).
	if cgroupPermOrder('r') >= cgroupPermOrder('w') {
		t.Error("expected r < w")
	}
	if cgroupPermOrder('w') >= cgroupPermOrder('m') {
		t.Error("expected w < m")
	}
	// Default case: any non-rwm byte returns 3.
	if got := cgroupPermOrder('x'); got != 3 {
		t.Errorf("cgroupPermOrder('x') = %d, want 3", got)
	}
	if got := cgroupPermOrder(0); got != 3 {
		t.Errorf("cgroupPermOrder(0) = %d, want 3", got)
	}
}

func TestDeviceCgroupRuleAllowedWildcardAndMismatch(t *testing.T) {
	tests := []struct {
		name      string
		canonical string
		allowlist []string
		want      bool
	}{
		{
			name:      "exact match",
			canonical: "b 8:0 rw",
			allowlist: []string{"b 8:0 rw"},
			want:      true,
		},
		{
			name:      "allowlist wildcard major matches numeric request",
			canonical: "b 8:0 rw",
			allowlist: []string{"b *:0 rw"},
			want:      true,
		},
		{
			name:      "allowlist wildcard minor matches numeric request",
			canonical: "b 8:0 rw",
			allowlist: []string{"b 8:* rw"},
			want:      true,
		},
		{
			name:      "request wildcard major denied when allowlist is numeric",
			canonical: "b *:0 rw",
			allowlist: []string{"b 8:0 rw"},
			want:      false,
		},
		{
			name:      "type mismatch",
			canonical: "c 8:0 rw",
			allowlist: []string{"b 8:0 rw"},
			want:      false,
		},
		{
			name:      "perms mismatch",
			canonical: "b 8:0 r",
			allowlist: []string{"b 8:0 rw"},
			want:      false,
		},
		{
			name:      "malformed canonical rule rejected",
			canonical: "not-valid",
			allowlist: []string{"b 8:0 rw"},
			want:      false,
		},
		{
			name:      "malformed allowlist entry skipped",
			canonical: "b 8:0 rw",
			allowlist: []string{"bad-entry", "b 8:0 rw"},
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deviceCgroupRuleAllowed(tt.canonical, tt.allowlist)
			if got != tt.want {
				t.Errorf("deviceCgroupRuleAllowed(%q, %v) = %v, want %v", tt.canonical, tt.allowlist, got, tt.want)
			}
		})
	}
}

func TestParseSecurityOptEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantKind  string
		wantValue string
		wantOK    bool
	}{
		{"empty string returns false", "", "", "", false},
		{"whitespace-only returns false", "   ", "", "", false},
		{"bare token no separator returns false", "no-new-privileges", "", "", false},
		{"equals separator", "seccomp=unconfined", "seccomp", "unconfined", true},
		{"colon separator", "apparmor:docker-default", "apparmor", "docker-default", true},
		{"key is lowercased", "Seccomp=default", "seccomp", "default", true},
		{"value whitespace trimmed", "seccomp= default ", "seccomp", "default", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, value, ok := parseSecurityOpt(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("parseSecurityOpt(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && (kind != tt.wantKind || value != tt.wantValue) {
				t.Errorf("parseSecurityOpt(%q) = (%q, %q), want (%q, %q)", tt.input, kind, value, tt.wantKind, tt.wantValue)
			}
		})
	}
}

func TestHasNoNewPrivilegesEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		securityOpt []string
		want        bool
	}{
		{"nil slice returns false", nil, false},
		{"empty slice returns false", []string{}, false},
		{"empty string entry is skipped", []string{""}, false},
		{"whitespace-only entry is skipped", []string{"   "}, false},
		{"bare token true", []string{"no-new-privileges"}, true},
		{"colon true", []string{"no-new-privileges:true"}, true},
		{"equals true", []string{"no-new-privileges=true"}, true},
		{"colon false", []string{"no-new-privileges:false"}, false},
		{"case insensitive key match", []string{"No-New-Privileges:true"}, true},
		{"different key ignored", []string{"seccomp=unconfined"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasNoNewPrivileges(tt.securityOpt)
			if got != tt.want {
				t.Errorf("hasNoNewPrivileges(%v) = %v, want %v", tt.securityOpt, got, tt.want)
			}
		})
	}
}

func TestIsNonRootUserEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		user string
		want bool
	}{
		{"empty is root", "", false},
		{"whitespace only is root", "   ", false},
		{"root by name", "root", false},
		{"ROOT uppercase", "ROOT", false},
		{"uid 0 is root", "0", false},
		{"uid 00 is root (zero-padded)", "00", false},
		{"non-root name", "nobody", true},
		{"non-root uid", "1000", true},
		{"user:group form non-root", "1000:1000", true},
		{"user:group root uid", "0:1000", false},
		{"empty user part colon form", ":1000", false},
		{"root name with group", "root:staff", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNonRootUser(tt.user)
			if got != tt.want {
				t.Errorf("isNonRootUser(%q) = %v, want %v", tt.user, got, tt.want)
			}
		})
	}
}

func TestNormalizeStringListEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"nil input", nil, []string{}},
		{"empty string omitted", []string{""}, []string{}},
		{"whitespace-only omitted", []string{"  "}, []string{}},
		{"duplicates removed", []string{"a", "a", "b"}, []string{"a", "b"}},
		{"whitespace trimmed", []string{"  hello  "}, []string{"hello"}},
		{"whitespace duplicates deduplicated", []string{"a", " a "}, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeStringList(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeStringList(%v) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizeStringList(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCapabilityAddDenyReasonEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		requested      []string
		allowAll       bool
		allowed        []string
		subject        string
		wantDenyReason string
	}{
		{
			name:      "allowAll skips all checks",
			requested: []string{"NET_ADMIN"},
			allowAll:  true,
			allowed:   nil,
			subject:   "container create",
		},
		{
			name:      "empty capability in requested is skipped",
			requested: []string{""},
			allowAll:  false,
			allowed:   nil,
			subject:   "container create",
		},
		{
			name:           "capability not in allowlist denied",
			requested:      []string{"NET_ADMIN"},
			allowAll:       false,
			allowed:        []string{"SYS_PTRACE"},
			subject:        "container create",
			wantDenyReason: `container create denied: capability "NET_ADMIN" is not in the allowed list`,
		},
		{
			name:      "capability in allowlist passes",
			requested: []string{"NET_ADMIN"},
			allowAll:  false,
			allowed:   []string{"NET_ADMIN"},
			subject:   "container create",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := capabilityAddDenyReason(tt.requested, tt.allowAll, tt.allowed, tt.subject)
			if got != tt.wantDenyReason {
				t.Errorf("capabilityAddDenyReason() = %q, want %q", got, tt.wantDenyReason)
			}
		})
	}
}

func assertDockerContainerImage(t *testing.T, body []byte, want string) {
	t.Helper()

	var got struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode rewritten body as Docker would: %v", err)
	}
	if got.Image != want {
		t.Fatalf("Docker-decoded Image = %q, want %q", got.Image, want)
	}
}

func assertSingleCanonicalContainerImageKey(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("decode rewritten body as map: %v", err)
	}

	var variants []string
	for key := range fields {
		if strings.EqualFold(key, "Image") {
			variants = append(variants, key)

		}
	}
	if len(variants) != 1 || variants[0] != "Image" {
		t.Fatalf("rewritten body image keys = %v, want exactly [Image]; body=%s", variants, body)
	}
	return fields
}

func TestRejectDuplicateCaseVariantJSONKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "top-level HostConfig duplicate",
			body:    `{"HostConfig":{"a":1},"hostconfig":{"b":2}}`,
			wantErr: true,
		},
		{
			name:    "nested HostConfig field duplicate",
			body:    `{"HostConfig":{"Privileged":true,"privileged":false}}`,
			wantErr: true,
		},
		{
			name:    "array element object duplicate",
			body:    `{"Env":[{"K":1,"k":2}]}`,
			wantErr: true,
		},
		{
			name:    "label keys are case-sensitive data",
			body:    `{"Labels":{"Foo":"1","foo":"2"}}`,
			wantErr: false,
		},
		{
			name:    "annotation keys are case-sensitive data",
			body:    `{"Annotations":{"A":"1","a":"2"}}`,
			wantErr: false,
		},
		{
			name:    "volumes keys are case-sensitive data",
			body:    `{"Volumes":{"/Data":{},"/data":{}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate Volumes field is still rejected",
			body:    `{"Volumes":{},"volumes":{}}`,
			wantErr: true,
		},
		{
			name:    "exposed ports keys are case-sensitive data",
			body:    `{"ExposedPorts":{"80/TCP":{},"80/tcp":{}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate ExposedPorts field is still rejected",
			body:    `{"ExposedPorts":{},"exposedports":{}}`,
			wantErr: true,
		},
		{
			name:    "sysctls keys are case-sensitive data",
			body:    `{"HostConfig":{"Sysctls":{"net.Core.somaxconn":"1024","net.core.somaxconn":"512"}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate Sysctls field is still rejected",
			body:    `{"HostConfig":{"Sysctls":{"a":"1"},"sysctls":{"b":"2"}}}`,
			wantErr: true,
		},
		{
			name:    "storage opt keys are case-sensitive data",
			body:    `{"HostConfig":{"StorageOpt":{"Size":"10G","size":"20G"}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate StorageOpt field is still rejected",
			body:    `{"HostConfig":{"StorageOpt":{},"storageopt":{}}}`,
			wantErr: true,
		},
		{
			name:    "tmpfs keys are case-sensitive data",
			body:    `{"HostConfig":{"Tmpfs":{"/Run":"","/run":""}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate Tmpfs field is still rejected",
			body:    `{"HostConfig":{"Tmpfs":{},"tmpfs":{}}}`,
			wantErr: true,
		},
		{
			name:    "port bindings keys are case-sensitive data",
			body:    `{"HostConfig":{"PortBindings":{"80/TCP":[{"HostPort":"8080"}],"80/tcp":[{"HostPort":"9090"}]}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate PortBindings field is still rejected",
			body:    `{"HostConfig":{"PortBindings":{},"portbindings":{}}}`,
			wantErr: true,
		},
		{
			name:    "log config options keys are case-sensitive data",
			body:    `{"Image":"nginx","HostConfig":{"LogConfig":{"Type":"json-file","Config":{"max-size":"10m","Max-Size":"20m"}}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate LogConfig.Config field is still rejected",
			body:    `{"HostConfig":{"LogConfig":{"Config":{},"config":{}}}}`,
			wantErr: true,
		},
		{
			name:    "endpoints config keys are case-sensitive data",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"Frontend":{"Aliases":["a"]},"frontend":{"Aliases":["b"]}}}}`,
			wantErr: false,
		},
		{
			name:    "struct inside EndpointsConfig is still fold-checked",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"net1":{"NetworkID":"a","networkid":"b"}}}}`,
			wantErr: true,
		},
		{
			name:    "struct inside EndpointsConfig network named config is still fold-checked",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"config":{"NetworkID":"a","networkid":"b"}}}}`,
			wantErr: true,
		},
		{
			name:    "struct inside EndpointsConfig network named options is still fold-checked",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"options":{"NetworkID":"a","networkid":"b"}}}}`,
			wantErr: true,
		},
		{
			name:    "struct inside EndpointsConfig network named labels is still fold-checked",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"labels":{"NetworkID":"a","networkid":"b"}}}}`,
			wantErr: true,
		},
		{
			name:    "struct inside EndpointsConfig network named opts is still fold-checked",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"opts":{"NetworkID":"a","networkid":"b"}}}}`,
			wantErr: true,
		},
		{
			name:    "struct inside EndpointsConfig network named sysctls is still fold-checked",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"sysctls":{"NetworkID":"a","networkid":"b"}}}}`,
			wantErr: true,
		},
		{
			name:    "EndpointSettings DriverOpts under colliding network name remain case-sensitive data",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{"config":{"DriverOpts":{"Foo":"1","foo":"2"}}}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate EndpointsConfig field is still rejected",
			body:    `{"NetworkingConfig":{"EndpointsConfig":{},"endpointsconfig":{}}}`,
			wantErr: true,
		},
		{
			name:    "network create options keys are case-sensitive data",
			body:    `{"Options":{"Foo":"1","foo":"2"}}`,
			wantErr: false,
		},
		{
			name:    "duplicate network create Options field is still rejected",
			body:    `{"Options":{"Foo":"1"},"options":{"foo":"2"}}`,
			wantErr: true,
		},
		{
			name:    "IPAM options keys are case-sensitive data",
			body:    `{"IPAM":{"Options":{"Bar":"1","bar":"2"}}}`,
			wantErr: false,
		},
		{
			name:    "duplicate IPAM Options field is still rejected",
			body:    `{"IPAM":{"Options":{"Bar":"1"},"options":{"bar":"2"}}}`,
			wantErr: true,
		},
		{
			name:    "struct inside IPAM.Config is still fold-checked",
			body:    `{"IPAM":{"Config":[{"Subnet":"10.0.0.0/24","subnet":"192.168.0.0/24"}]}}`,
			wantErr: true,
		},
		{
			name:    "volume opts keys are case-sensitive data",
			body:    `{"Opts":{"Type":"nfs","type":"tmpfs"}}`,
			wantErr: false,
		},
		{
			name:    "duplicate volume Opts field is still rejected",
			body:    `{"Opts":{},"opts":{}}`,
			wantErr: true,
		},
		{
			name:    "driver opts keys are case-sensitive data",
			body:    `{"DriverOpts":{"Type":"nfs","type":"tmpfs"}}`,
			wantErr: false,
		},
		{
			name:    "duplicate DriverOpts field is still rejected",
			body:    `{"DriverOpts":{},"driveropts":{}}`,
			wantErr: true,
		},
		{
			name:    "auxiliary addresses keys are case-sensitive data",
			body:    `{"IPAM":{"Config":[{"AuxiliaryAddresses":{"Router":"1.2.3.4","router":"5.6.7.8"}}]}}`,
			wantErr: false,
		},
		{
			name:    "duplicate AuxiliaryAddresses field is still rejected",
			body:    `{"IPAM":{"Config":[{"AuxiliaryAddresses":{},"auxiliaryaddresses":{}}]}}`,
			wantErr: true,
		},
		{
			name:    "clean create body",
			body:    `{"Image":"x","HostConfig":{"Privileged":true},"Labels":{"foo":"bar"}}`,
			wantErr: false,
		},
		{
			name:    "duplicate Labels field is still rejected",
			body:    `{"Labels":{"Foo":"1"},"labels":{"foo":"2"}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := RejectDuplicateCaseVariantJSONKeys([]byte(tt.body))
			if tt.wantErr && err == nil {
				t.Fatal("RejectDuplicateCaseVariantJSONKeys() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, want nil", err)
			}
		})
	}
}

func TestRewriteJSONImageField(t *testing.T) {
	const pinned = "nginx@sha256:abc123"

	tests := []struct {
		name    string
		body    string
		wantErr bool
		assert  func(t *testing.T, result []byte)
	}{
		{
			name: "canonical image key pins digest",
			body: `{"Image":"nginx:latest","HostConfig":{"Memory":134217728}}`,
			assert: func(t *testing.T, result []byte) {
				t.Helper()
				assertDockerContainerImage(t, result, pinned)
				assertSingleCanonicalContainerImageKey(t, result)
				if !strings.Contains(string(result), "134217728") {
					t.Errorf("rewriteJSONImageField() corrupted Memory field: %s", result)
				}
			},
		},
		{
			name: "lowercase image key collapsed to canonical",
			body: `{"image":"nginx:latest","HostConfig":{}}`,
			assert: func(t *testing.T, result []byte) {
				t.Helper()
				assertDockerContainerImage(t, result, pinned)
				assertSingleCanonicalContainerImageKey(t, result)
				if strings.Contains(string(result), `"image"`) {
					t.Fatalf("rewriteJSONImageField() left lowercase image key in body: %s", result)
				}
			},
		},
		{
			name:    "duplicate case-variant image keys rejected",
			body:    `{"Image":"nginx:latest","image":"attacker/evil:1","HostConfig":{}}`,
			wantErr: true,
		},
		{
			name: "large numeric sibling preserved byte-for-byte",
			body: `{"Image":"nginx:latest","Memory":9007199254740993}`,
			assert: func(t *testing.T, result []byte) {
				t.Helper()
				assertDockerContainerImage(t, result, pinned)
				fields := assertSingleCanonicalContainerImageKey(t, result)
				if got := string(fields["Memory"]); got != "9007199254740993" {
					t.Fatalf("Memory raw JSON = %q, want byte-for-byte 9007199254740993; body=%s", got, result)
				}
			},
		},
		{
			name:    "invalid JSON returns error",
			body:    `{bad json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := rewriteJSONImageField([]byte(tt.body), pinned)
			if tt.wantErr {
				if err == nil {
					t.Fatal("rewriteJSONImageField() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("rewriteJSONImageField() error = %v", err)
			}
			if tt.assert != nil {
				tt.assert(t, result)
			}
		})
	}
}

func TestBuildImageTrustRawMapping(t *testing.T) {
	opts := ImageTrustOptions{
		Mode: "enforce",
		AllowedSigningKeys: []SigningKeyOptions{
			{PEM: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"},
		},
		AllowedKeyless: []KeylessOptions{
			{Issuer: "https://accounts.google.com", SubjectPattern: ".*@example.com"},
		},
		RequireRekorInclusion: true,
		VerifyTimeout:         "30s",
	}

	raw := buildImageTrustRaw(opts)

	if len(raw.AllowedSigningKeys) != 1 {
		t.Errorf("AllowedSigningKeys len = %d, want 1", len(raw.AllowedSigningKeys))
	}
	if raw.AllowedSigningKeys[0].PEM != opts.AllowedSigningKeys[0].PEM {
		t.Errorf("AllowedSigningKeys[0].PEM mismatch")
	}
	if len(raw.AllowedKeyless) != 1 {
		t.Errorf("AllowedKeyless len = %d, want 1", len(raw.AllowedKeyless))
	}
	if raw.AllowedKeyless[0].Issuer != "https://accounts.google.com" {
		t.Errorf("AllowedKeyless[0].Issuer = %q, want %q", raw.AllowedKeyless[0].Issuer, "https://accounts.google.com")
	}
	if !raw.RequireRekorInclusion {
		t.Error("RequireRekorInclusion not propagated")
	}
	if raw.VerifyTimeoutStr != "30s" {
		t.Errorf("VerifyTimeoutStr = %q, want %q", raw.VerifyTimeoutStr, "30s")
	}
}

func TestBuildImageTrustFieldsOffMode(t *testing.T) {
	// mode="" and mode="off" both return the zero value (inactive).
	for _, mode := range []string{"", "off"} {
		t.Run("mode="+mode, func(t *testing.T) {
			f := buildImageTrustFields(ImageTrustOptions{Mode: mode})
			if f.verifier != nil {
				t.Error("expected nil verifier for off mode")
			}
			if f.fetcher != nil {
				t.Error("expected nil fetcher for off mode")
			}
			if f.initErr != nil {
				t.Errorf("expected nil initErr for off mode, got %v", f.initErr)
			}
		})
	}
}

func TestBuildImageTrustFieldsInvalidKeyFails(t *testing.T) {
	// An enforce mode with an invalid PEM key must produce an initErr (fail-closed).
	f := buildImageTrustFields(ImageTrustOptions{
		Mode: "enforce",
		AllowedSigningKeys: []SigningKeyOptions{
			{PEM: "not-a-valid-pem"},
		},
	})
	if f.initErr == nil {
		t.Fatal("expected initErr for invalid PEM key, got nil")
	}
}
