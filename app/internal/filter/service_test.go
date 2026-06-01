package filter

import (
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
