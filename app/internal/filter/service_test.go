package filter

import (
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
