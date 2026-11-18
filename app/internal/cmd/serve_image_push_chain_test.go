package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/clientacl"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

// imagePushChainConfig loads a config whose rules admit every push route and
// whose request_body.image_push allowlist is set at the top level, in the
// "scoped" profile, or both. The "open" profile carries no image_push block,
// and a profile replaces request_body wholesale, so it is unrestricted even
// though the top level is not.
func imagePushChainConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadBytes([]byte(`
insecure_allow_read_exfiltration: true
insecure_allow_body_blind_writes: true
rules:
  - match: { method: POST, path: "/images/**" }
    action: allow
  - match: { method: POST, path: "/plugins/**/push" }
    action: allow
  - match: { method: POST, path: "/libpod/images/**" }
    action: allow
  - match: { method: POST, path: "/libpod/manifests/*/registry/**" }
    action: allow
  - match: { method: POST, path: "/libpod/manifests/*/push" }
    action: allow
request_body:
  image_push:
    allowed_registries: [ghcr.io]
    registry_aliases:
      - from: mirror.corp.example
        to: ghcr.io
clients:
  profiles:
    - name: scoped
      rules:
        - match: { method: POST, path: "/images/**" }
          action: allow
        - match: { method: POST, path: "/libpod/images/**" }
          action: allow
      request_body:
        image_push:
          allowed_registries: [registry.internal:5000, docker.io]
    - name: open
      rules:
        - match: { method: POST, path: "/images/**" }
          action: allow
        - match: { method: POST, path: "/libpod/images/**" }
          action: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	return cfg
}

func TestServeChainImagePushRegistryAllowlist(t *testing.T) {
	t.Parallel()
	cfg := imagePushChainConfig(t)
	cfg.Response.DenyVerbosity = "verbose"
	rules, err := validateAndCompileRulesStructural(cfg)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := compileClientProfiles(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		profile string
		flavor  upstreamflavor.Flavor
		path    string
		want    int
		reason  string
	}{
		{name: "top level allows the listed registry", path: "/images/ghcr.io/acme/app/push", want: http.StatusNoContent},
		{name: "top level denies another registry", path: "/images/quay.io/acme/app/push", want: http.StatusForbidden, reason: `registry \"quay.io\" is not allowlisted`},
		{name: "top level resolves an alias", path: "/images/mirror.corp.example/acme/app/push", want: http.StatusNoContent},
		{name: "top level version prefix", path: "/v1.45/images/quay.io/acme/app/push", want: http.StatusForbidden, reason: "is not allowlisted"},
		{name: "top level plugin push", path: "/plugins/quay.io/acme/p/push", want: http.StatusForbidden, reason: "is not allowlisted"},
		{name: "top level libpod destination", path: "/libpod/images/img/push?destination=quay.io/acme/app", want: http.StatusForbidden, reason: "is not allowlisted"},
		{name: "top level libpod transport", path: "/libpod/images/img/push?destination=oci:/tmp/x", want: http.StatusForbidden, reason: "destination transport"},
		{name: "top level manifest registry", path: "/libpod/manifests/l/registry/quay.io%2Facme%2Fapp", want: http.StatusForbidden, reason: "is not allowlisted"},
		{name: "top level manifest registry allowed", path: "/libpod/manifests/l/registry/ghcr.io%2Facme%2Fapp", want: http.StatusNoContent},
		{name: "top level unqualified on docker", flavor: upstreamflavor.Docker, path: "/images/acme/app/push", want: http.StatusForbidden, reason: `registry \"docker.io\" is not allowlisted`},
		{name: "top level unqualified on podman", flavor: upstreamflavor.Podman, path: "/images/acme/app/push", want: http.StatusForbidden, reason: "unqualified destination"},
		{name: "profile allowlist replaces the top level", profile: "scoped", path: "/images/ghcr.io/acme/app/push", want: http.StatusForbidden, reason: ""},
		{name: "profile allowlist allows its own registry", profile: "scoped", path: "/images/registry.internal:5000/acme/app/push", want: http.StatusNoContent},
		{name: "profile unqualified is docker hub on docker", profile: "scoped", path: "/images/acme/app/push", want: http.StatusNoContent},
		{name: "profile carries the podman flavor", profile: "scoped", flavor: upstreamflavor.Podman, path: "/images/acme/app/push", want: http.StatusForbidden},
		{name: "profile without image_push is unrestricted", profile: "open", path: "/images/quay.io/acme/app/push", want: http.StatusNoContent},
		{name: "profile without image_push libpod", profile: "open", path: "/libpod/images/img/push?destination=oci:/tmp/x", want: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flavor := tt.flavor
			if flavor == "" {
				flavor = upstreamflavor.Docker
			}
			logger, _ := flavorTestLogger()
			handler := withFilter(cfg, nil, logger, rules, profiles, flavor, nil, flavor == upstreamflavor.Docker)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			if tt.profile != "" {
				handler = clientacl.MiddlewareWithRoundTripper(nil, logger, clientacl.Options{Profiles: clientacl.ProfileOptions{DefaultProfile: tt.profile}})(handler)
			}
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("POST %s = %d, want %d: %s", tt.path, rec.Code, tt.want, rec.Body.String())
			}
			if tt.reason != "" && !strings.Contains(rec.Body.String(), tt.reason) {
				t.Fatalf("denial body = %s, want reason containing %q", rec.Body.String(), tt.reason)
			}
		})
	}
}

// TestServeChainImagePushInactiveWithoutAllowlist pins that a config with no
// image_push block leaves pushes exactly as the exfiltration acknowledgment
// and the rules left them.
func TestServeChainImagePushInactiveWithoutAllowlist(t *testing.T) {
	t.Parallel()
	cfg := imagePushChainConfig(t)
	cfg.RequestBody.ImagePush = config.ImagePushRequestBodyConfig{}
	rules, err := validateAndCompileRulesStructural(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger, _ := flavorTestLogger()
	handler := withFilter(cfg, nil, logger, rules, nil, upstreamflavor.Podman, nil, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, path := range []string{"/images/quay.io/acme/app/push", "/libpod/images/img/push?destination=oci:/tmp/x", "/images/app/push"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("POST %s = %d, want it forwarded: %s", path, rec.Code, rec.Body.String())
		}
	}
}
