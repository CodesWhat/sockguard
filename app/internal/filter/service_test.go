package filter

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason == "" {
		t.Fatal("expected oversized body to be denied")
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

func TestServiceInspectBodyCloseErrorPropagates(t *testing.T) {
	// Exercises the closeErr branch in service inspect (lines 76-78).
	policy := newServicePolicy(ServiceOptions{})
	sentinel := io.ErrClosedPipe
	req := httptest.NewRequest(http.MethodPost, "/services/create", nil)
	req.Body = &erroringReadCloser{Reader: strings.NewReader(`{"TaskTemplate":{}}`), closeErr: sentinel}
	_, err := policy.inspect(nil, req, "/services/create")
	if err == nil {
		t.Fatal("expected close error to propagate")
	}
}

func TestServiceInspectMalformedJSONWithLogger(t *testing.T) {
	// Exercises the logger debug branch when JSON decode fails.
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true})
	logs := &collectingHandler{}
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader("{bad json}"))
	reason, err := policy.inspect(slog.New(logs), req, "/services/create")
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (deferred)", reason)
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
