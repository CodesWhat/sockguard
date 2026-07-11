package filter

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/imagetrust"
)

func TestServiceInspectDeniesBindMountSource(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{
		AllowedBindMounts: []string{"/srv/services"},
	})

	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{
		"TaskTemplate": {
			"ContainerSpec": {
				"Image": "nginx:latest",
				"Mounts": [
					{"Type": "bind", "Source": "/etc", "Target": "/host-etc"}
				]
			}
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason == "" || !strings.Contains(denyReason, `bind mount source "/etc" is not allowlisted`) {
		t.Fatalf("denyReason = %q, want bind mount denial", denyReason)
	}
}

func TestServiceInspectDeniesHostNetwork(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{})

	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{
		"TaskTemplate": {
			"ContainerSpec": {
				"Image": "nginx:latest"
			}
		},
		"Networks": [
			{"Target": "host"}
		]
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "service denied: host network is not allowed" {
		t.Fatalf("denyReason = %q, want host network denial", denyReason)
	}
}

func TestServiceInspectDeniesRegistryNotAllowlisted(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{
		AllowOfficial: false,
	})

	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{
		"TaskTemplate": {
			"ContainerSpec": {
				"Image": "ghcr.io/acme/private:1.0.0"
			}
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != `service denied: registry "ghcr.io" is not allowlisted` {
		t.Fatalf("denyReason = %q, want registry denial", denyReason)
	}
}

func TestServiceInspectUpdateUsesSamePolicy(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{
		AllowOfficial: true,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1.53/services/web/update?version=7", strings.NewReader(`{
		"TaskTemplate": {
			"ContainerSpec": {
				"Image": "nginx:latest"
			}
		}
	}`))

	denyReason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "" {
		t.Fatalf("denyReason = %q, want allow", denyReason)
	}
}

func TestServiceInspectNilRequestReturnsEmpty(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{})
	reason, err := policy.inspect(nil, nil, "/services/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil) = (%q, %v), want empty", reason, err)
	}
}

func TestServiceInspectNilBodyReturnsEmpty(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{})
	req := httptest.NewRequest(http.MethodPost, "/services/create", nil)
	req.Body = nil
	reason, err := policy.inspect(nil, req, "/services/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(nil body) = (%q, %v), want empty", reason, err)
	}
}

func TestServiceInspectEmptyBodyReturnsEmpty(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(""))
	reason, err := policy.inspect(nil, req, "/services/create")
	if err != nil || reason != "" {
		t.Fatalf("inspect(empty body) = (%q, %v), want empty", reason, err)
	}
}

func TestServiceInspectOversizedBodyDenied(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{})
	payload := strings.Repeat("x", maxServiceBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(payload))

	reason, err := policy.inspect(nil, req, "/services/create")
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
	if !strings.HasPrefix(rejection.reason, "service denied: request body exceeds") {
		t.Fatalf("rejection reason = %q, want oversize denial", rejection.reason)
	}
}

func TestNewServicePolicyDeduplicatesBindMounts(t *testing.T) {
	// Duplicate and invalid entries should be deduplicated/dropped.
	policy := newServicePolicy(ServiceOptions{
		AllowedBindMounts: []string{"/safe", "/safe/", "/safe/../safe", ""},
	})
	if len(policy.allowedBindMounts) != 1 || policy.allowedBindMounts[0] != "/safe" {
		t.Fatalf("allowedBindMounts = %v, want [/safe]", policy.allowedBindMounts)
	}
}

func TestServiceInspectIgnoresBodyCloseErrorAfterRead(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{})
	req := httptest.NewRequest(http.MethodPost, "/services/create", nil)
	req.Body = &erroringReadCloser{Reader: strings.NewReader(`{"TaskTemplate":{}}`), closeErr: io.ErrClosedPipe}
	reason, err := policy.inspect(nil, req, "/services/create")
	if err != nil {
		t.Fatalf("inspect() error = %v, want nil", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty", reason)
	}
}

func TestServiceInspectWrapsBodyReadError(t *testing.T) {
	sentinel := errors.New("read failed")
	policy := newServicePolicy(ServiceOptions{})
	req := httptest.NewRequest(http.MethodPost, "/services/create", nil)
	req.Body = &readErrorReadCloser{readErr: sentinel}

	reason, err := policy.inspect(nil, req, "/services/create")
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

func TestServiceInspectMalformedJSONWithLogger(t *testing.T) {
	// Exercises the logger debug branch when JSON decode fails; must deny (fail-closed).
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true})
	logs := &collectingHandler{}
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader("{bad json}"))
	reason, err := policy.inspect(slog.New(logs), req, "/services/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	const wantReason = "service denied: request body could not be inspected"
	if reason != wantReason {
		t.Fatalf("reason = %q, want %q", reason, wantReason)
	}
	if len(logs.snapshot()) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs.snapshot()))
	}
}

func TestServiceInspectNonBindMountIsSkipped(t *testing.T) {
	// Exercises lines 110-111: mount type is "volume" (not bind) → skipped.
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{
		"TaskTemplate": {
			"ContainerSpec": {
				"Image": "nginx:latest",
				"Mounts": [
					{"Type": "volume", "Source": "myvolume", "Target": "/data"}
				]
			}
		}
	}`))
	reason, err := policy.inspect(nil, req, "/services/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (volume mount allowed)", reason)
	}
}

func TestServiceInspectDeniesCapabilityAdd(t *testing.T) {
	// Swarm task ContainerSpec.CapabilityAdd must obey the same allowlist as
	// /containers/create: with no allowlist, any added capability is denied.
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","CapabilityAdd":["SYS_ADMIN"]}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, `capability "SYS_ADMIN" is not in the allowed list`) {
		t.Fatalf("reason = %q, want capability denial", reason)
	}
}

func TestServiceInspectAllowsAllowlistedCapability(t *testing.T) {
	// CAP_-prefixed and lowercase requests normalize to the allowlist entry.
	policy := newServicePolicy(ServiceOptions{
		AllowAllRegistries:  true,
		AllowedCapabilities: []string{"NET_ADMIN"},
	})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"registry.example.com/app:v1","CapabilityAdd":["cap_net_admin"]}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (capability allowlisted)", reason)
	}
}

func TestServiceInspectDeniesSysctls(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Sysctls":{"net.ipv4.ip_forward":"1"}}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "service denied: setting sysctls is not allowed" {
		t.Fatalf("reason = %q, want sysctls denial", reason)
	}
}

func TestServiceInspectAllowsSysctlsWhenPermitted(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowAllRegistries: true, AllowSysctls: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"registry.example.com/app:v1","Sysctls":{"net.ipv4.ip_forward":"1"}}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (sysctls permitted)", reason)
	}
}

func TestServiceInspectDeniesRootUser(t *testing.T) {
	// require_non_root_user parity: an absent ContainerSpec.User defaults to the
	// image's user, which Sockguard treats as root, so the service is denied.
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireNonRootUser: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "non-root user is required") {
		t.Fatalf("reason = %q, want non-root denial", reason)
	}
}

func TestServiceInspectDeniesZeroPaddedRootUID(t *testing.T) {
	// Docker resolves a numeric User with strconv, so "00" and "0:0" both run as
	// root; the parity check must reject them, not just the literal "0".
	for _, user := range []string{"0", "00", "0:0", "root"} {
		policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireNonRootUser: true})
		body := `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","User":"` + user + `"}}}`
		req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(body))

		reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil {
			t.Fatalf("user %q: inspect() error = %v", user, err)
		}
		if !strings.Contains(reason, "non-root user is required") {
			t.Fatalf("user %q: reason = %q, want non-root denial", user, reason)
		}
	}
}

func TestServiceInspectAllowsNonRootUser(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireNonRootUser: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","User":"1000:1000"}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (non-root user)", reason)
	}
}

func TestServiceInspectDeniesMissingNoNewPrivileges(t *testing.T) {
	// A nil Privileges block means NoNewPrivileges is unset → denied.
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireNoNewPrivileges: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "no-new-privileges is required") {
		t.Fatalf("reason = %q, want no-new-privileges denial", reason)
	}
}

func TestServiceInspectDeniesNoNewPrivilegesFalse(t *testing.T) {
	// Privileges present but NoNewPrivileges explicitly false is still denied.
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireNoNewPrivileges: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"NoNewPrivileges":false}}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "no-new-privileges is required") {
		t.Fatalf("reason = %q, want no-new-privileges denial", reason)
	}
}

func TestServiceInspectAllowsNoNewPrivileges(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireNoNewPrivileges: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"NoNewPrivileges":true}}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (no-new-privileges set)", reason)
	}
}

func TestServiceInspectDeniesWritableRootfs(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireReadonlyRootfs: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "read-only root filesystem is required") {
		t.Fatalf("reason = %q, want readonly-rootfs denial", reason)
	}
}

func TestServiceInspectAllowsReadonlyRootfs(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireReadonlyRootfs: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","ReadOnly":true}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (readonly rootfs)", reason)
	}
}

func TestServiceInspectDeniesMissingCapDropAll(t *testing.T) {
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireDropAllCapabilities: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","CapabilityDrop":["NET_RAW"]}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, `CapabilityDrop must include "ALL"`) {
		t.Fatalf("reason = %q, want drop-all denial", reason)
	}
}

func TestServiceInspectAllowsCapDropAll(t *testing.T) {
	// "ALL" is matched case-insensitively, mirroring capDropContainsAll.
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, RequireDropAllCapabilities: true})
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","CapabilityDrop":["all"]}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (CapDrop ALL)", reason)
	}
}

func TestServiceInspectHardeningRailsComposeOnUpdate(t *testing.T) {
	// All four rails satisfied together on the update path must allow.
	policy := newServicePolicy(ServiceOptions{
		AllowOfficial:              true,
		RequireNonRootUser:         true,
		RequireNoNewPrivileges:     true,
		RequireReadonlyRootfs:      true,
		RequireDropAllCapabilities: true,
	})
	body := `{"TaskTemplate":{"ContainerSpec":{` +
		`"Image":"nginx:latest","User":"1000","ReadOnly":true,` +
		`"CapabilityDrop":["ALL"],"Privileges":{"NoNewPrivileges":true}}}}`
	req := httptest.NewRequest(http.MethodPost, "/v1.53/services/web/update?version=7", strings.NewReader(body))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (all rails satisfied)", reason)
	}
}

func TestServiceInspectDenyUnconfinedSeccomp(t *testing.T) {
	tests := []struct {
		name       string
		opts       ServiceOptions
		body       string
		wantDenied bool
		wantSubstr string
	}{
		{
			name:       "unconfined seccomp denied when knob enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"unconfined"}}}}}`,
			wantDenied: true,
			wantSubstr: "unconfined seccomp mode is not allowed",
		},
		{
			name:       "unconfined seccomp case-insensitive (UNCONFINED)",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"UNCONFINED"}}}}}`,
			wantDenied: true,
			wantSubstr: "unconfined seccomp mode is not allowed",
		},
		{
			name:       "unconfined seccomp allowed when knob disabled",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: false},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"unconfined"}}}}}`,
			wantDenied: false,
		},
		{
			name:       "default seccomp always allowed",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"default"}}}}}`,
			wantDenied: false,
		},
		{
			name:       "nil Seccomp block always allowed",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"NoNewPrivileges":true}}}}`,
			wantDenied: false,
		},
		{
			name:       "nil Privileges block always allowed",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}}}`,
			wantDenied: false,
		},
		{
			name:       "custom seccomp NOT denied by deny_unconfined_seccomp alone",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"custom"}}}}}`,
			wantDenied: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := newServicePolicy(tc.opts)
			req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(tc.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tc.wantDenied {
				if reason == "" {
					t.Fatalf("reason = empty, want denial containing %q", tc.wantSubstr)
				}
				if !strings.Contains(reason, tc.wantSubstr) {
					t.Fatalf("reason = %q, want substring %q", reason, tc.wantSubstr)
				}
			} else {
				if reason != "" {
					t.Fatalf("reason = %q, want empty (allowed)", reason)
				}
			}
		})
	}
}

func TestServiceInspectDenyCustomSeccompProfiles(t *testing.T) {
	tests := []struct {
		name       string
		opts       ServiceOptions
		body       string
		wantDenied bool
		wantSubstr string
	}{
		{
			name:       "custom seccomp denied when deny_custom_seccomp_profiles enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenyCustomSeccompProfiles: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"custom"}}}}}`,
			wantDenied: true,
			wantSubstr: "custom seccomp profiles are not allowed",
		},
		{
			name:       "custom seccomp case-insensitive (CUSTOM)",
			opts:       ServiceOptions{AllowOfficial: true, DenyCustomSeccompProfiles: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"CUSTOM"}}}}}`,
			wantDenied: true,
			wantSubstr: "custom seccomp profiles are not allowed",
		},
		{
			name:       "custom seccomp allowed when knob disabled",
			opts:       ServiceOptions{AllowOfficial: true, DenyCustomSeccompProfiles: false},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"custom"}}}}}`,
			wantDenied: false,
		},
		{
			name:       "unconfined not affected by deny_custom_seccomp_profiles alone",
			opts:       ServiceOptions{AllowOfficial: true, DenyCustomSeccompProfiles: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"unconfined"}}}}}`,
			wantDenied: false,
		},
		{
			name:       "both knobs together deny both unconfined and custom",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedSeccomp: true, DenyCustomSeccompProfiles: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"custom"}}}}}`,
			wantDenied: true,
			wantSubstr: "custom seccomp profiles are not allowed",
		},
		{
			name:       "profile without mode treated as implicit custom (fail-closed)",
			opts:       ServiceOptions{AllowOfficial: true, DenyCustomSeccompProfiles: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Profile":"e30K"}}}}}`,
			wantDenied: true,
			wantSubstr: "custom seccomp profiles are not allowed",
		},
		{
			name:       "nil seccomp with empty mode and nil profile allowed",
			opts:       ServiceOptions{AllowOfficial: true, DenyCustomSeccompProfiles: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{}}}}}`,
			wantDenied: false,
		},
		{
			name:       "empty mode with explicit null profile is not a custom profile",
			opts:       ServiceOptions{AllowOfficial: true, DenyCustomSeccompProfiles: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"","Profile":null}}}}}`,
			wantDenied: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := newServicePolicy(tc.opts)
			req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(tc.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tc.wantDenied {
				if reason == "" {
					t.Fatalf("reason = empty, want denial containing %q", tc.wantSubstr)
				}
				if !strings.Contains(reason, tc.wantSubstr) {
					t.Fatalf("reason = %q, want substring %q", reason, tc.wantSubstr)
				}
			} else {
				if reason != "" {
					t.Fatalf("reason = %q, want empty (allowed)", reason)
				}
			}
		})
	}
}

func TestServiceInspectDenyUnconfinedAppArmor(t *testing.T) {
	tests := []struct {
		name       string
		opts       ServiceOptions
		body       string
		wantDenied bool
		wantSubstr string
	}{
		{
			name:       "disabled apparmor denied when knob enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedAppArmor: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"AppArmor":{"Mode":"disabled"}}}}}`,
			wantDenied: true,
			wantSubstr: "disabled apparmor mode is not allowed",
		},
		{
			name:       "disabled apparmor case-insensitive (DISABLED)",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedAppArmor: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"AppArmor":{"Mode":"DISABLED"}}}}}`,
			wantDenied: true,
			wantSubstr: "disabled apparmor mode is not allowed",
		},
		{
			name:       "disabled apparmor allowed when knob off",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedAppArmor: false},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"AppArmor":{"Mode":"disabled"}}}}}`,
			wantDenied: false,
		},
		{
			name:       "default apparmor always allowed",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedAppArmor: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"AppArmor":{"Mode":"default"}}}}}`,
			wantDenied: false,
		},
		{
			name:       "nil AppArmor block always allowed",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedAppArmor: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"NoNewPrivileges":true}}}}`,
			wantDenied: false,
		},
		{
			name:       "nil Privileges block always allowed with apparmor knob enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenyUnconfinedAppArmor: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}}}`,
			wantDenied: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := newServicePolicy(tc.opts)
			req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(tc.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tc.wantDenied {
				if reason == "" {
					t.Fatalf("reason = empty, want denial containing %q", tc.wantSubstr)
				}
				if !strings.Contains(reason, tc.wantSubstr) {
					t.Fatalf("reason = %q, want substring %q", reason, tc.wantSubstr)
				}
			} else {
				if reason != "" {
					t.Fatalf("reason = %q, want empty (allowed)", reason)
				}
			}
		})
	}
}

func TestServiceInspectDenySelinuxContext(t *testing.T) {
	tests := []struct {
		name       string
		opts       ServiceOptions
		body       string
		wantDenied bool
		wantSubstr string
	}{
		{
			name:       "selinux disable denied when deny_selinux_disable enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxDisable: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"SELinuxContext":{"Disable":true}}}}}`,
			wantDenied: true,
			wantSubstr: "SELinux disable is not allowed",
		},
		{
			name:       "selinux disable allowed when knob off",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxDisable: false},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"SELinuxContext":{"Disable":true}}}}}`,
			wantDenied: false,
		},
		{
			name:       "selinux label override denied when deny_selinux_label_override enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxLabelOverride: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"SELinuxContext":{"Type":"spc_t"}}}}}`,
			wantDenied: true,
			wantSubstr: "SELinux context override is not allowed",
		},
		{
			name:       "selinux level override denied when deny_selinux_label_override enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxLabelOverride: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"SELinuxContext":{"Level":"s0"}}}}}`,
			wantDenied: true,
			wantSubstr: "SELinux context override is not allowed",
		},
		{
			name:       "label override knob does not deny a bare disable",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxLabelOverride: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"SELinuxContext":{"Disable":true}}}}}`,
			wantDenied: false,
		},
		{
			name:       "disable knob does not deny a context override",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxDisable: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"SELinuxContext":{"User":"system_u"}}}}}`,
			wantDenied: false,
		},
		{
			name:       "nil SELinuxContext always allowed with both knobs enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxDisable: true, DenySelinuxLabelOverride: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"NoNewPrivileges":true}}}}`,
			wantDenied: false,
		},
		{
			name:       "nil Privileges block always allowed with selinux knobs enabled",
			opts:       ServiceOptions{AllowOfficial: true, DenySelinuxDisable: true, DenySelinuxLabelOverride: true},
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}}}`,
			wantDenied: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := newServicePolicy(tc.opts)
			req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(tc.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tc.wantDenied {
				if reason == "" {
					t.Fatalf("reason = empty, want denial containing %q", tc.wantSubstr)
				}
				if !strings.Contains(reason, tc.wantSubstr) {
					t.Fatalf("reason = %q, want substring %q", reason, tc.wantSubstr)
				}
			} else {
				if reason != "" {
					t.Fatalf("reason = %q, want empty (allowed)", reason)
				}
			}
		})
	}
}

func TestServiceInspectSeccompAndAppArmorRailsCompose(t *testing.T) {
	// All new rails satisfied together must allow.
	policy := newServicePolicy(ServiceOptions{
		AllowOfficial:             true,
		DenyUnconfinedSeccomp:     true,
		DenyCustomSeccompProfiles: true,
		DenyUnconfinedAppArmor:    true,
	})
	body := `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"default"},"AppArmor":{"Mode":"default"}}}}}`
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(body))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow (all confinement rails satisfied)", reason)
	}
}

func TestServiceInspectSeccompDenialOnUpdatePath(t *testing.T) {
	// Seccomp/AppArmor denial must also fire on the /services/{id}/update path,
	// confirming isServiceWritePath routes update requests to policy inspection.
	policy := newServicePolicy(ServiceOptions{
		AllowOfficial:         true,
		DenyUnconfinedSeccomp: true,
	})
	body := `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Privileges":{"Seccomp":{"Mode":"unconfined"}}}}}`
	req := httptest.NewRequest(http.MethodPost, "/v1.53/services/web/update?version=7", strings.NewReader(body))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "unconfined seccomp mode is not allowed") {
		t.Fatalf("reason = %q, want unconfined seccomp denial on update path", reason)
	}
}

func TestServiceInspectImageTrustDeniesUnverified(t *testing.T) {
	// A swarm service whose ContainerSpec.Image fails cosign verification is
	// denied in enforce mode — services must not bypass image trust.
	policy := newServicePolicy(ServiceOptions{AllowAllRegistries: true})
	policy.imageTrust = imageTrustFields{
		verifier: &mockImageVerifier{err: errors.New("no valid signature found")},
		fetcher:  oneCandidateFetcher(),
		cfg:      imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"TaskTemplate":{"ContainerSpec":{"Image":"registry.example.com/app:v1"}}}`))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if !strings.Contains(reason, "image trust verification failed") {
		t.Fatalf("reason = %q, want image-trust denial", reason)
	}
	if !strings.Contains(reason, "registry.example.com/app:v1") {
		t.Fatalf("reason = %q, want image ref in denial", reason)
	}
}

func TestServiceInspectImageTrustPinsVerifiedDigest(t *testing.T) {
	// On successful verification the mutable tag in ContainerSpec.Image is
	// rewritten to the verified digest, closing the verify→pull TOCTOU.
	const digest = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	policy := newServicePolicy(ServiceOptions{AllowAllRegistries: true})
	policy.imageTrust = imageTrustFields{
		verifier: &mockImageVerifier{},
		fetcher:  &mockSignatureFetcher{candidates: []imagetrust.Candidate{{DigestHex: "00", ImageDigest: digest}}},
		cfg:      imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	body := `{"TaskTemplate":{"ContainerSpec":{"Image":"registry.example.com/app:v1"}},"Mode":{"Replicated":{"Replicas":3}}}`
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(body))

	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want allow", reason)
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
	if !strings.Contains(string(got), `"Replicas":3`) {
		t.Fatalf("rewritten body dropped sibling fields: %s", got)
	}
	if req.ContentLength != int64(len(got)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(got))
	}
}

func assertDockerServiceImage(t *testing.T, body []byte, want string) {
	t.Helper()

	var got serviceRequest
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode rewritten service body as Docker would: %v", err)
	}
	if got.TaskTemplate.ContainerSpec.Image != want {
		t.Fatalf("Docker-decoded TaskTemplate.ContainerSpec.Image = %q, want %q", got.TaskTemplate.ContainerSpec.Image, want)
	}
}

func assertSingleCanonicalServiceImageKey(t *testing.T, body []byte) {
	t.Helper()

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("decode rewritten service body as map: %v", err)
	}
	taskTemplateRaw, ok := top["TaskTemplate"]
	if !ok {
		t.Fatalf("rewritten service body missing canonical TaskTemplate: %s", body)
	}

	var taskTemplate map[string]json.RawMessage
	if err := json.Unmarshal(taskTemplateRaw, &taskTemplate); err != nil {
		t.Fatalf("decode rewritten TaskTemplate: %v", err)
	}
	containerSpecRaw, ok := taskTemplate["ContainerSpec"]
	if !ok {
		t.Fatalf("rewritten service body missing canonical ContainerSpec: %s", body)
	}

	var containerSpec map[string]json.RawMessage
	if err := json.Unmarshal(containerSpecRaw, &containerSpec); err != nil {
		t.Fatalf("decode rewritten ContainerSpec: %v", err)
	}
	var variants []string
	for key := range containerSpec {
		if strings.EqualFold(key, "Image") {
			variants = append(variants, key)
		}
	}
	if len(variants) != 1 || variants[0] != "Image" {
		t.Fatalf("rewritten ContainerSpec image keys = %v, want exactly [Image]; body=%s", variants, body)
	}
}

func TestRewriteServiceImage(t *testing.T) {
	const pinned = "nginx@sha256:deadbeef"

	t.Run("canonical nested image key pins digest", func(t *testing.T) {
		body := []byte(`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","User":"nobody"},"Resources":{"Limits":{"MemoryBytes":134217728}}},"Replicas":2}`)
		result, err := rewriteServiceImage(body, pinned)
		if err != nil {
			t.Fatalf("rewriteServiceImage() error = %v", err)
		}
		assertDockerServiceImage(t, result, pinned)
		assertSingleCanonicalServiceImageKey(t, result)
		if !strings.Contains(string(result), `"nobody"`) {
			t.Errorf("rewriteServiceImage() dropped User field: %s", result)
		}
		if !strings.Contains(string(result), "134217728") {
			t.Errorf("rewriteServiceImage() corrupted MemoryBytes: %s", result)
		}
	})

	t.Run("lowercase image leaf collapsed to canonical", func(t *testing.T) {
		body := []byte(`{"TaskTemplate":{"ContainerSpec":{"image":"nginx:latest","User":"nobody"}}}`)
		result, err := rewriteServiceImage(body, pinned)
		if err != nil {
			t.Fatalf("rewriteServiceImage() error = %v", err)
		}
		assertDockerServiceImage(t, result, pinned)
		assertSingleCanonicalServiceImageKey(t, result)
		if strings.Contains(string(result), `"image"`) {
			t.Fatalf("rewriteServiceImage() left lowercase image key in body: %s", result)
		}
	})

	t.Run("duplicate case-variant image leaf rejected", func(t *testing.T) {
		body := []byte(`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","image":"attacker/evil:1"}}}`)
		if _, err := rewriteServiceImage(body, pinned); err == nil {
			t.Fatal("rewriteServiceImage() error = nil, want duplicate image-key rejection")
		}
	})

	t.Run("duplicate case-variant ContainerSpec rejected", func(t *testing.T) {
		body := []byte(`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"},"containerspec":{"Image":"attacker/evil:1"}}}`)
		if _, err := rewriteServiceImage(body, pinned); err == nil {
			t.Fatal("rewriteServiceImage() error = nil, want duplicate ContainerSpec-key rejection")
		}
	})

	t.Run("duplicate case-variant TaskTemplate rejected", func(t *testing.T) {
		body := []byte(`{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest"}},"tasktemplate":{"ContainerSpec":{"Image":"attacker/evil:1"}}}`)
		if _, err := rewriteServiceImage(body, pinned); err == nil {
			t.Fatal("rewriteServiceImage() error = nil, want duplicate TaskTemplate-key rejection")
		}
	})

	t.Run("missing TaskTemplate returns error", func(t *testing.T) {
		body := []byte(`{"Replicas":1}`)
		_, err := rewriteServiceImage(body, pinned)
		if err == nil {
			t.Fatal("expected error for missing TaskTemplate, got nil")
		}
	})

	t.Run("missing ContainerSpec returns error", func(t *testing.T) {
		body := []byte(`{"TaskTemplate":{"Resources":{}}}`)
		_, err := rewriteServiceImage(body, pinned)
		if err == nil {
			t.Fatal("expected error for missing ContainerSpec, got nil")
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		_, err := rewriteServiceImage([]byte("{bad"), pinned)
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}
