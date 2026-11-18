package filter

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func pushTestPolicy(podman bool) imagePushPolicy {
	return newImagePushPolicy(ImagePushOptions{
		AllowedRegistries: []string{"ghcr.io", "Registry.Internal:5000", "docker.io", "localhost:5000", "[::1]:5000"},
		RegistryAliases: map[string]string{
			"mirror.corp.example": "registry.internal:5000",
			"evil.corp.example":   "evil.example",
		},
		PodmanUpstream: podman,
	})
}

// inspectPush sends target through the inspector the way the middleware does:
// the matcher sees the normalized path, the inspector sees the request.
func inspectPush(t *testing.T, p imagePushPolicy, method, target string, headers map[string]string) string {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	normalized := NormalizePath(req.URL.Path)
	if !matchesImagePushInspection(normalized) {
		return "<not matched>"
	}
	reason, err := p.inspect(nil, req, normalized)
	if err != nil {
		t.Fatalf("inspect(%s %s) error = %v", method, target, err)
	}
	return reason
}

func TestImagePushPolicyRoutes(t *testing.T) {
	const (
		notAllowed  = "is not allowlisted"
		unqualified = "unqualified destination"
		transport   = "destination transport"
		invalid     = "invalid destination reference"
		ambiguous   = "ambiguous"
	)
	tests := []struct {
		name   string
		podman bool
		target string
		want   string // "" = allowed, otherwise a reason substring
	}{
		// Docker-compat image push.
		{name: "compat allowlisted", target: "/images/ghcr.io/acme/app/push", want: ""},
		{name: "compat allowlisted with tag query", target: "/images/ghcr.io/acme/app/push?tag=v1", want: ""},
		{name: "compat tag in name", target: "/images/ghcr.io/acme/app:v1/push", want: ""},
		{name: "compat digest in name", target: "/images/ghcr.io/acme/app@sha256:" + strings.Repeat("a", 64) + "/push", want: ""},
		{name: "compat not allowlisted", target: "/images/quay.io/acme/app/push", want: notAllowed},
		{name: "compat version prefix allowlisted", target: "/v1.45/images/ghcr.io/acme/app/push", want: ""},
		{name: "compat version prefix denied", target: "/v1.45/images/quay.io/acme/app/push", want: notAllowed},
		{name: "compat podman-style version prefix denied", target: "/v5.8.1/images/quay.io/acme/app/push", want: notAllowed},
		{name: "compat uppercase host", target: "/images/GHCR.IO/acme/app/push", want: ""},
		{name: "compat uppercase host not allowlisted", target: "/images/QUAY.IO/acme/app/push", want: notAllowed},
		{name: "compat host with port allowlisted", target: "/images/registry.internal:5000/acme/app/push", want: ""},
		{name: "compat host with wrong port", target: "/images/registry.internal:5001/acme/app/push", want: notAllowed},
		{name: "compat host without port", target: "/images/registry.internal/acme/app/push", want: notAllowed},
		{name: "compat ipv6 allowlisted", target: "/images/[::1]:5000/acme/app/push", want: ""},
		{name: "compat ipv6 other port", target: "/images/[::1]:5001/acme/app/push", want: notAllowed},
		{name: "compat ipv6 other host", target: "/images/[::2]:5000/acme/app/push", want: notAllowed},
		{name: "compat localhost allowlisted", target: "/images/localhost:5000/app/push", want: ""},
		{name: "compat bare localhost host not allowlisted", target: "/images/localhost/app/push", want: notAllowed},
		{name: "compat alias to allowlisted", target: "/images/mirror.corp.example/acme/app/push", want: ""},
		{name: "compat alias to non-allowlisted", target: "/images/evil.corp.example/acme/app/push", want: notAllowed},
		{name: "compat builtin docker alias index", target: "/images/index.docker.io/acme/app/push", want: ""},
		{name: "compat builtin docker alias registry-1", target: "/images/registry-1.docker.io/acme/app/push", want: ""},
		{name: "compat builtin docker alias hub", target: "/images/registry.hub.docker.com/acme/app/push", want: ""},
		{name: "compat unqualified is docker hub on docker", target: "/images/acme/app/push", want: ""},
		{name: "compat single component is docker hub on docker", target: "/images/app/push", want: ""},
		{name: "compat unqualified refused on podman", podman: true, target: "/images/acme/app/push", want: unqualified},
		{name: "compat single component refused on podman", podman: true, target: "/images/app/push", want: unqualified},
		{name: "compat qualified fine on podman", podman: true, target: "/images/ghcr.io/acme/app/push", want: ""},
		{name: "compat uppercase first component is a registry", target: "/images/Evil/app/push", want: notAllowed},
		{name: "compat uppercase repo invalid", target: "/images/ghcr.io/Acme/app/push", want: invalid},
		{name: "compat empty segment", target: "/images/ghcr.io//app/push", want: invalid},
		{name: "compat transport in name", target: "/images/oci:/tmp/x/push", want: transport},
		{name: "compat ambiguous tag", target: "/images/ghcr.io/acme/app/push?tag=a&tag=b", want: ambiguous},
		{name: "compat differently spelled tag", target: "/images/ghcr.io/acme/app/push?Tag=a", want: ambiguous},
		{name: "compat destination query held to allowlist", target: "/images/ghcr.io/acme/app/push?destination=quay.io/x/y", want: notAllowed},
		{name: "compat destination query allowlisted", target: "/images/ghcr.io/acme/app/push?destination=ghcr.io/x/y", want: ""},
		{name: "compat ambiguous destination", target: "/images/ghcr.io/acme/app/push?destination=a&destination=b", want: ambiguous},
		{name: "compat escaped slashes in name", target: "/images/ghcr.io%2Facme%2Fapp/push", want: ""},
		{name: "compat escaped slashes not allowlisted", target: "/images/quay.io%2Facme%2Fapp/push", want: notAllowed},
		{name: "compat double-encoded name", target: "/images/ghcr.io%252Facme%252Fapp/push", want: invalid},
		{name: "compat trailing slash is not the push shape", target: "/images/ghcr.io/acme/app/push/", want: invalid},
		{name: "compat malformed query", target: "/images/ghcr.io/acme/app/push?tag=%zz", want: invalid},

		// Plugin push.
		{name: "plugin allowlisted", target: "/plugins/ghcr.io/acme/plug/push", want: ""},
		{name: "plugin not allowlisted", target: "/plugins/quay.io/acme/plug/push", want: notAllowed},
		{name: "plugin unqualified is docker hub", target: "/plugins/acme/plug/push", want: ""},
		{name: "plugin unqualified on podman", podman: true, target: "/plugins/acme/plug/push", want: unqualified},
		{name: "plugin version prefix", target: "/v1.45/plugins/quay.io/acme/plug/push", want: notAllowed},

		// Libpod image push.
		{name: "libpod path name allowlisted", target: "/libpod/images/ghcr.io/acme/app/push", want: ""},
		{name: "libpod path name not allowlisted", target: "/libpod/images/quay.io/acme/app/push", want: notAllowed},
		{name: "libpod unqualified path name", target: "/libpod/images/acme/app/push", want: unqualified},
		{name: "libpod unqualified path name on podman", podman: true, target: "/libpod/images/app/push", want: unqualified},
		{name: "libpod version prefix", target: "/v5.8.1/libpod/images/quay.io/acme/app/push", want: notAllowed},
		{name: "libpod destination allowlisted", target: "/libpod/images/localimg/push?destination=ghcr.io/acme/app:v1", want: ""},
		{name: "libpod destination not allowlisted", target: "/libpod/images/localimg/push?destination=quay.io/acme/app", want: notAllowed},
		{name: "libpod destination overrides an allowlisted name", target: "/libpod/images/ghcr.io/acme/app/push?destination=quay.io/acme/app", want: notAllowed},
		{name: "libpod destination docker transport allowlisted", target: "/libpod/images/localimg/push?destination=docker://ghcr.io/acme/app", want: ""},
		{name: "libpod destination docker transport not allowlisted", target: "/libpod/images/localimg/push?destination=docker://quay.io/acme/app", want: notAllowed},
		{name: "libpod destination DOCKER transport is not the docker transport", target: "/libpod/images/localimg/push?destination=DOCKER://ghcr.io/acme/app", want: transport},
		{name: "libpod destination unqualified", target: "/libpod/images/localimg/push?destination=acme/app", want: unqualified},
		{name: "libpod destination single component", target: "/libpod/images/localimg/push?destination=app", want: unqualified},
		{name: "libpod destination empty falls back to path name", target: "/libpod/images/ghcr.io/acme/app/push?destination=", want: ""},
		{name: "libpod destination empty falls back to denied path name", target: "/libpod/images/quay.io/acme/app/push?destination=", want: notAllowed},
		{name: "libpod destination ambiguous", target: "/libpod/images/localimg/push?destination=ghcr.io/a&destination=quay.io/a", want: ambiguous},
		{name: "libpod destination other case spelling", target: "/libpod/images/localimg/push?Destination=ghcr.io/a", want: ambiguous},
		{name: "libpod destination host with port", target: "/libpod/images/localimg/push?destination=registry.internal:5000/a", want: ""},
		{name: "libpod destination alias", target: "/libpod/images/localimg/push?destination=mirror.corp.example/a", want: ""},
		{name: "libpod destination alias to denied", target: "/libpod/images/localimg/push?destination=evil.corp.example/a", want: notAllowed},
		{name: "libpod destination ipv6", target: "/libpod/images/localimg/push?destination=%5B::1%5D:5000/a", want: ""},
		{name: "libpod destination invalid", target: "/libpod/images/localimg/push?destination=ghcr.io/A", want: invalid},
		{name: "libpod destination oci transport", target: "/libpod/images/localimg/push?destination=oci:/tmp/x", want: transport},
		{name: "libpod destination oci-archive transport", target: "/libpod/images/localimg/push?destination=oci-archive:/tmp/x.tar", want: transport},
		{name: "libpod destination dir transport", target: "/libpod/images/localimg/push?destination=dir:/tmp/x", want: transport},
		{name: "libpod destination docker-archive transport", target: "/libpod/images/localimg/push?destination=docker-archive:/tmp/x.tar", want: transport},
		{name: "libpod destination docker-archive transport no slash", target: "/libpod/images/localimg/push?destination=docker-archive:x.tar", want: transport},
		{name: "libpod destination docker-daemon transport", target: "/libpod/images/localimg/push?destination=docker-daemon:img:tag", want: transport},
		{name: "libpod destination containers-storage transport", target: "/libpod/images/localimg/push?destination=containers-storage:img", want: transport},
		{name: "libpod destination unknown transport", target: "/libpod/images/localimg/push?destination=weird:/x", want: transport},
		{name: "libpod destination transport named like a host with port", target: "/libpod/images/localimg/push?destination=oci:5000/x", want: transport},
		{name: "libpod destination docker:// followed by transport", target: "/libpod/images/localimg/push?destination=docker://oci:/x", want: transport},
		{name: "libpod destination docker:// twice", target: "/libpod/images/localimg/push?destination=docker://docker://ghcr.io/a", want: transport},
		{name: "libpod destination whitespace", target: "/libpod/images/localimg/push?destination=ghcr.io/a%20b", want: invalid},
		{name: "libpod destination percent", target: "/libpod/images/localimg/push?destination=ghcr.io/a%2525", want: invalid},
		{name: "libpod destination nul", target: "/libpod/images/localimg/push?destination=ghcr.io/a%00", want: invalid},
		{name: "libpod destination leading slash", target: "/libpod/images/localimg/push?destination=/ghcr.io/a", want: invalid},
		{name: "libpod destination digest", target: "/libpod/images/localimg/push?destination=ghcr.io/a@sha256:" + strings.Repeat("b", 64), want: ""},
		{name: "libpod destination bad digest", target: "/libpod/images/localimg/push?destination=ghcr.io/a@sha256:zz", want: invalid},
		{name: "libpod destination bad tag", target: "/libpod/images/localimg/push?destination=ghcr.io/a:-x", want: invalid},
		{name: "libpod destination too long", target: "/libpod/images/localimg/push?destination=ghcr.io/" + strings.Repeat("a", 2000), want: invalid},

		// Libpod manifest push, registry form.
		{name: "manifest registry allowlisted", target: "/libpod/manifests/list/registry/ghcr.io%2Facme%2Fapp", want: ""},
		{name: "manifest registry not allowlisted", target: "/libpod/manifests/list/registry/quay.io%2Facme%2Fapp", want: notAllowed},
		{name: "manifest registry unescaped destination", target: "/libpod/manifests/list/registry/quay.io/acme/app", want: notAllowed},
		{name: "manifest registry unescaped allowlisted", target: "/libpod/manifests/list/registry/ghcr.io/acme/app:v1", want: ""},
		{name: "manifest registry version prefix", target: "/v5.8.1/libpod/manifests/list/registry/quay.io%2Facme%2Fapp", want: notAllowed},
		{name: "manifest registry docker transport escaped", target: "/libpod/manifests/list/registry/docker:%2F%2Fghcr.io%2Facme%2Fapp", want: ""},
		{name: "manifest registry docker transport escaped denied", target: "/libpod/manifests/list/registry/docker:%2F%2Fquay.io%2Facme%2Fapp", want: notAllowed},
		{name: "manifest registry unqualified", target: "/libpod/manifests/list/registry/acme%2Fapp", want: unqualified},
		{name: "manifest registry oci transport", target: "/libpod/manifests/list/registry/oci:%2Ftmp%2Fx", want: transport},
		{name: "manifest registry double-encoded slash", target: "/libpod/manifests/list/registry/ghcr.io%252Facme%252Fapp", want: invalid},
		{name: "manifest registry escaped registry segment in name", target: "/libpod/manifests/x%2Fregistry%2Fghcr.io%2Fa/registry/quay.io%2Fa", want: notAllowed},
		{name: "manifest registry name hides an allowlisted decoy", target: "/libpod/manifests/ghcr.io/registry/ghcr.io/a/registry/quay.io/a", want: notAllowed},
		{name: "manifest registry name with decoy first", target: "/libpod/manifests/x/registry/quay.io/a/registry/ghcr.io/a", want: notAllowed},
		{name: "manifest registry alias", target: "/libpod/manifests/list/registry/mirror.corp.example%2Fa", want: ""},

		// Libpod manifest push, query form.
		{name: "manifest push allowlisted", target: "/libpod/manifests/list/push?destination=ghcr.io/acme/app", want: ""},
		{name: "manifest push not allowlisted", target: "/libpod/manifests/list/push?destination=quay.io/acme/app", want: notAllowed},
		{name: "manifest push no destination", target: "/libpod/manifests/list/push", want: invalid},
		{name: "manifest push empty destination", target: "/libpod/manifests/list/push?destination=", want: invalid},
		{name: "manifest push ambiguous destination", target: "/libpod/manifests/list/push?destination=ghcr.io/a&destination=quay.io/a", want: ambiguous},
		{name: "manifest push transport", target: "/libpod/manifests/list/push?destination=dir:/tmp/x", want: transport},
		{name: "manifest push unqualified", target: "/libpod/manifests/list/push?destination=acme/app", want: unqualified},
		{name: "manifest push docker://", target: "/libpod/manifests/list/push?destination=docker://ghcr.io/a", want: ""},
		{name: "manifest push version prefix", target: "/v5.8.1/libpod/manifests/list/push?destination=quay.io/a", want: notAllowed},

		// Paths that are not pushes are left alone.
		{name: "pull is not a push", target: "/images/create?fromImage=quay.io/a", want: "<not matched>"},
		{name: "tag is not a push", target: "/images/ghcr.io/acme/app/tag?repo=quay.io/x", want: "<not matched>"},
		{name: "manifest add is not a push", target: "/libpod/manifests/list/add", want: "<not matched>"},
		{name: "image json is not a push", target: "/images/quay.io/acme/app/json", want: "<not matched>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inspectPush(t, pushTestPolicy(tt.podman), http.MethodPost, tt.target, nil)
			switch tt.want {
			case "":
				if got != "" {
					t.Fatalf("POST %s denied: %q", tt.target, got)
				}
			case "<not matched>":
				if got != tt.want {
					t.Fatalf("POST %s = %q, want the path left unmatched", tt.target, got)
				}
			default:
				if got == "" || !strings.Contains(got, tt.want) || !strings.HasPrefix(got, "image push denied: ") {
					t.Fatalf("POST %s = %q, want an image push denial containing %q", tt.target, got, tt.want)
				}
			}
		})
	}
}

func TestImagePushPolicyInactiveChangesNothing(t *testing.T) {
	for name, opts := range map[string]ImagePushOptions{
		"zero":                {},
		"empty allowlist":     {AllowedRegistries: []string{}},
		"aliases only":        {RegistryAliases: map[string]string{"a.example": "b.example"}},
		"unparseable entries": {AllowedRegistries: []string{"https://ghcr.io/x", " "}},
	} {
		t.Run(name, func(t *testing.T) {
			p := newImagePushPolicy(opts)
			if p.active {
				t.Fatal("policy is active")
			}
			for _, target := range []string{
				"/images/quay.io/a/b/push",
				"/libpod/images/x/push?destination=oci:/tmp/x",
				"/libpod/manifests/l/registry/quay.io%2Fa",
				"/plugins/quay.io/a/push",
			} {
				if got := inspectPush(t, p, http.MethodPost, target, map[string]string{"X-Registry-Auth": "!!"}); got != "" {
					t.Fatalf("inactive policy denied POST %s: %q", target, got)
				}
			}
		})
	}
}

func TestImagePushPolicyOnlyInspectsPost(t *testing.T) {
	p := pushTestPolicy(false)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/images/quay.io/a/b/push", nil)
		if reason, err := p.inspect(nil, req, "/images/quay.io/a/b/push"); reason != "" || err != nil {
			t.Fatalf("%s inspected: (%q, %v)", method, reason, err)
		}
	}
	if reason, err := p.inspect(nil, nil, "/images/quay.io/a/b/push"); reason != "" || err != nil {
		t.Fatalf("nil request inspected: (%q, %v)", reason, err)
	}
}

func registryAuthHeaderFor(t *testing.T, json string) string {
	t.Helper()
	return base64.URLEncoding.EncodeToString([]byte(json))
}

func TestImagePushPolicyRegistryAuthHeader(t *testing.T) {
	const target = "/images/ghcr.io/acme/app/push"
	const secret = "hunter2-do-not-echo"
	tests := []struct {
		name    string
		headers map[string]string
		repeat  []string
		want    string
	}{
		{name: "absent", want: ""},
		{name: "empty", headers: map[string]string{"X-Registry-Auth": ""}, want: ""},
		{name: "empty object", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{}`)}, want: ""},
		{name: "no serveraddress", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"username":"u","password":"`+secret+`"}`)}, want: ""},
		{name: "match", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"ghcr.io","password":"`+secret+`"}`)}, want: ""},
		{name: "match with scheme and path", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"https://ghcr.io/v2/"}`)}, want: ""},
		{name: "match uppercase", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"GHCR.IO"}`)}, want: ""},
		{name: "match through alias", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"mirror.corp.example"}`)}, want: ""},
		{name: "docker hub v1 address", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"https://index.docker.io/v1/"}`)}, want: ""},
		{name: "mismatch", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"quay.io","password":"`+secret+`"}`)}, want: "X-Registry-Auth serveraddress is not allowlisted"},
		{name: "alias to denied", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"evil.corp.example"}`)}, want: "X-Registry-Auth serveraddress is not allowlisted"},
		{name: "userinfo host", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `{"serveraddress":"ghcr.io@evil.example"}`)}, want: "X-Registry-Auth serveraddress is not allowlisted"},
		{name: "garbage", headers: map[string]string{"X-Registry-Auth": "!!not base64!!"}, want: "not valid base64"},
		{name: "not json", headers: map[string]string{"X-Registry-Auth": registryAuthHeaderFor(t, `not json`)}, want: "not valid JSON"},
		{name: "oversize", headers: map[string]string{"X-Registry-Auth": strings.Repeat("A", maxRegistryAuthHeaderBytes+4)}, want: "exceeds"},
		{name: "oversize decoded", headers: map[string]string{"X-Registry-Auth": base64.StdEncoding.EncodeToString([]byte(`{"serveraddress":"ghcr.io","x":"` + strings.Repeat("a", maxRegistryAuthHeaderBytes) + `"}`))}, want: "exceeds"},
		{name: "repeated header", repeat: []string{registryAuthHeaderFor(t, `{"serveraddress":"ghcr.io"}`), registryAuthHeaderFor(t, `{"serveraddress":"quay.io"}`)}, want: "repeated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, target, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			for _, v := range tt.repeat {
				req.Header.Add("X-Registry-Auth", v)
			}
			reason, err := pushTestPolicy(false).inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(reason, secret) {
				t.Fatalf("reason echoes header content: %q", reason)
			}
			if tt.want == "" {
				if reason != "" {
					t.Fatalf("denied: %q", reason)
				}
				return
			}
			if !strings.HasPrefix(reason, "image push denied: ") || !strings.Contains(reason, tt.want) {
				t.Fatalf("reason = %q, want image push denial containing %q", reason, tt.want)
			}
		})
	}
}

func TestImagePushPolicyRegistryAuthCheckedOnEveryRoute(t *testing.T) {
	header := registryAuthHeaderFor(t, `{"serveraddress":"quay.io"}`)
	for _, target := range []string{
		"/images/ghcr.io/a/b/push",
		"/plugins/ghcr.io/a/b/push",
		"/libpod/images/ghcr.io/a/b/push",
		"/libpod/manifests/l/registry/ghcr.io%2Fa",
		"/libpod/manifests/l/push?destination=ghcr.io/a",
	} {
		got := inspectPush(t, pushTestPolicy(false), http.MethodPost, target, map[string]string{"X-Registry-Auth": header})
		if !strings.Contains(got, "X-Registry-Auth serveraddress is not allowlisted") {
			t.Errorf("POST %s = %q, want the registry-auth denial", target, got)
		}
	}
}

func TestNewImagePushPolicyNormalizesOptions(t *testing.T) {
	p := newImagePushPolicy(ImagePushOptions{
		AllowedRegistries: []string{"GHCR.io", "ghcr.io", "index.docker.io", "registry-1.docker.io", "https://bad/x"},
		RegistryAliases: map[string]string{
			"Mirror.Example":       "GHCR.IO",
			"registry-1.docker.io": "evil.example", // built-in, cannot be redefined
			"self.example":         "self.example",
			"bad/host":             "ghcr.io",
		},
	})
	if got, want := strings.Join(p.allowed, ","), "ghcr.io,docker.io"; got != want {
		t.Fatalf("allowed = %q, want %q", got, want)
	}
	if len(p.aliases) != 1 || p.aliases["mirror.example"] != "ghcr.io" {
		t.Fatalf("aliases = %v", p.aliases)
	}
	if got := p.resolveHost("registry-1.docker.io"); got != "docker.io" {
		t.Fatalf("built-in alias resolved to %q", got)
	}
}

func TestImagePushAliasesAreSingleLevel(t *testing.T) {
	p := newImagePushPolicy(ImagePushOptions{
		AllowedRegistries: []string{"c.example"},
		RegistryAliases:   map[string]string{"a.example": "b.example", "b.example": "c.example"},
	})
	if got := p.resolveHost("a.example"); got != "b.example" {
		t.Fatalf("a.example resolved to %q, want one step only", got)
	}
	if got := inspectPush(t, p, http.MethodPost, "/images/a.example/x/push", nil); !strings.Contains(got, "not allowlisted") {
		t.Fatalf("chained alias reached the allowlist: %q", got)
	}
	if got := inspectPush(t, p, http.MethodPost, "/images/b.example/x/push", nil); got != "" {
		t.Fatalf("one-step alias denied: %q", got)
	}
}

func TestImagePushRawPathIsNotCleaned(t *testing.T) {
	// A hand-built URL whose decoded path differs from its escaped path, and a
	// path that cleaning would rewrite: neither may be read more leniently
	// than the daemon reads the raw bytes.
	p := pushTestPolicy(false)
	for _, tc := range []struct{ name, path, want string }{
		{name: "dot segment in name", path: "/images/ghcr.io/./quay.io/a/push", want: "invalid destination reference"},
		{name: "dot-dot segment in name", path: "/images/quay.io/a/../../ghcr.io/a/push", want: "invalid destination reference"},
		{name: "doubled slash after prefix", path: "/images//ghcr.io/a/push", want: "invalid destination reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.URL = &url.URL{Path: tc.path}
			normalized := NormalizePath(req.URL.Path)
			if !matchesImagePushInspection(normalized) {
				t.Fatalf("%q did not match", normalized)
			}
			reason, err := p.inspect(nil, req, normalized)
			if err != nil || !strings.Contains(reason, tc.want) {
				t.Fatalf("inspect = (%q, %v), want %q", reason, err, tc.want)
			}
		})
	}
}

func TestImagePushParserNeverPanicsOnOddInput(t *testing.T) {
	p := pushTestPolicy(false)
	for _, s := range []string{"", "/", "//", ":", "@", "a@", "@a", "[", "[]", "[::1", "a:b:c/d", "a/b/c/d/e/f/g/h", strings.Repeat("a/", 600), "\xff", "docker://", "docker://[::1]:5000/a", "[::1]:5000"} {
		_ = p.denyReasonForDestination(s, false)
		_ = p.denyReasonForDestination(s, true)
	}
}
