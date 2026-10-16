package config

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/filter"
)

const allowedCreateImage = "docker.io/library/alpine:3.22"

func imageAllowlistHandler(t *testing.T, yaml string) http.Handler {
	t.Helper()
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStructural(cfg); err != nil {
		t.Fatal(err)
	}
	rule, err := filter.CompileRule(filter.Rule{Methods: []string{"POST"}, Pattern: "/**", Action: filter.ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	policy := cfg.RequestBody.ToFilterOptions()
	policy.DenyResponseVerbosity = filter.DenyResponseVerbosityVerbose
	return filter.MiddlewareWithOptions([]*filter.CompiledRule{rule}, discardLogger, filter.Options{
		PolicyConfig: policy,
		Mutation:     cfg.Mutations.ToFilterOptions(),
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

func TestCreateImageAllowlistRoutes(t *testing.T) {
	for _, surface := range []struct {
		group string
		paths []string
		body  string
	}{
		{"container_create", []string{"/containers/create", "/v1.56/containers/create"}, `{"Image":%q}`},
		{"libpod_container_create", []string{"/libpod/containers/create", "/v5.8.1/libpod/containers/create"}, `{"image":%q,"systemd":"false"}`},
		{"service", []string{"/services/create", "/v1.56/services/create", "/services/app/update?version=1", "/v1.56/services/app/update?version=1"}, `{"TaskTemplate":{"ContainerSpec":{"Image":%q}}}`},
	} {
		t.Run(surface.group, func(t *testing.T) {
			handler := imageAllowlistHandler(t, fmt.Sprintf("request_body:\n  %s:\n    allowed_images: [%q]\n", surface.group, allowedCreateImage))
			for _, path := range surface.paths {
				for _, image := range []string{allowedCreateImage, "docker.io/library/busybox:1.37", "alpine:3.22", "", " " + allowedCreateImage, allowedCreateImage + "-evil"} {
					body := fmt.Sprintf(surface.body, image)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
					want := http.StatusForbidden
					if image == allowedCreateImage {
						want = http.StatusOK
						if response.Body.String() != body {
							t.Errorf("allowed body changed: %s", response.Body.String())
						}
					}
					if response.Code != want {
						t.Errorf("%s image %q: status %d, want %d: %s", path, image, response.Code, want, response.Body.String())
					}
				}
				for _, invalid := range []struct {
					body   string
					status int
				}{
					{"", http.StatusForbidden},
					{"{}", http.StatusForbidden},
					{"null", http.StatusForbidden},
					{"{", http.StatusForbidden},
					{`{"Image":"docker.io/library/alpine:3.22","image":"docker.io/library/busybox:1.37"}`, http.StatusBadRequest},
				} {
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader(invalid.body)))
					if response.Code != invalid.status {
						t.Errorf("%s body %q: status %d, want %d", path, invalid.body, response.Code, invalid.status)
					}
				}
			}
		})
	}
}

func TestCreateImageAllowlistValidation(t *testing.T) {
	for _, group := range []string{"container_create", "libpod_container_create", "service"} {
		for _, image := range []string{"", " ", "alpine", "alpine:3.22", "docker.io/alpine:3.22", "ghcr.io/acme/app", "ghcr.io/acme/*:v1", "https://ghcr.io/acme/app:v1", allowedCreateImage + " ", "ghcr.io/acme/app@sha256:bad"} {
			t.Run(group+"/"+image, func(t *testing.T) {
				for _, profile := range []bool{false, true} {
					yaml := fmt.Sprintf("request_body:\n  %s:\n    allowed_images: [%q]\n", group, image)
					if profile {
						yaml = "clients:\n  profiles:\n    - name: restricted\n      rules:\n        - match: {method: GET, path: /_ping}\n          action: allow\n      " + strings.ReplaceAll(strings.TrimSuffix(yaml, "\n"), "\n", "\n      ") + "\n"
					}
					cfg, err := LoadBytes([]byte(yaml))
					if err != nil {
						t.Fatal(err)
					}
					err = ValidateStructural(cfg)
					if err == nil || !strings.Contains(err.Error(), group+".allowed_images") {
						t.Errorf("profile=%v: validation error = %v, want allowed_images error", profile, err)
					}
				}
			})
		}
	}
}

func TestCreateImageAllowlistEnvAndProfileLoading(t *testing.T) {
	image := "ghcr.io/acme/app@sha256:" + strings.Repeat("a", 64)
	for _, group := range []string{"CONTAINER_CREATE", "LIBPOD_CONTAINER_CREATE", "SERVICE"} {
		t.Setenv("SOCKGUARD_REQUEST_BODY_"+group+"_ALLOWED_IMAGES", allowedCreateImage+","+image)
	}
	file := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(file, []byte(`clients:
  profiles:
    - name: restricted
      rules:
        - match: {method: GET, path: /_ping}
          action: allow
      request_body:
        container_create:
          allowed_images: ["docker.io/library/busybox:1.37"]
        libpod_container_create:
          allowed_images: ["docker.io/library/busybox:1.37"]
        service:
          allowed_images: ["docker.io/library/busybox:1.37"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStructural(cfg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body RequestBodyConfig
		want []string
	}{
		{cfg.RequestBody, []string{allowedCreateImage, image}},
		{cfg.Clients.Profiles[0].RequestBody, []string{"docker.io/library/busybox:1.37"}},
	} {
		policy := tc.body.ToFilterOptions()
		for _, got := range [][]string{policy.ContainerCreate.AllowedImages, policy.LibpodContainerCreate.AllowedImages, policy.Service.AllowedImages} {
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("allowed_images = %v, want %v", got, tc.want)
			}
		}
	}
}

func TestCreateImageAllowlistDigestAndMutation(t *testing.T) {
	digest := "ghcr.io/acme/app@sha256:" + strings.Repeat("a", 64)
	for _, group := range []string{"container_create", "service"} {
		path, template, surface := "/containers/create", `{"Image":%q}`, "container_create"
		if group == "service" {
			path, template, surface = "/services/app/update?version=1", `{"TaskTemplate":{"ContainerSpec":{"Image":%q}}}`, "service_update"
		}
		yaml := fmt.Sprintf("request_body:\n  %s:\n    allowed_images: [%q]\n", group, digest)
		if group == "service" {
			yaml += "    allowed_registries: [ghcr.io]\n"
		}
		yaml += fmt.Sprintf("mutations:\n  rules:\n    - id: mirror\n      surfaces: [%s]\n      remap_image:\n        match: exact\n        from: %s\n        to: %s\n", surface, allowedCreateImage, digest)
		handler := imageAllowlistHandler(t, yaml)
		for _, image := range []string{allowedCreateImage, digest, strings.Replace(digest, "@sha256:a", "@sha256:b", 1)} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader(fmt.Sprintf(template, image))))
			if image == allowedCreateImage || image == digest {
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), digest) {
					t.Errorf("%s image %s: %d %s", group, image, response.Code, response.Body.String())
				}
			} else if response.Code != http.StatusForbidden {
				t.Errorf("%s wrong digest: %d", group, response.Code)
			}
		}
	}
}

func TestCreateImageAllowlistAlternateFilesystemsAndRollback(t *testing.T) {
	for _, tc := range []struct {
		group string
		path  string
		body  string
	}{
		{"container_create", "/containers/create", `{"Image":"docker.io/library/alpine:3.22","HostConfig":{"Mounts":[{"Type":"image","Source":"docker.io/library/busybox:1.37","Target":"/other"}]}}`},
		{"libpod_container_create", "/libpod/containers/create", `{"image":"docker.io/library/alpine:3.22","systemd":"false","rootfs":"/srv/rootfs"}`},
		{"libpod_container_create", "/libpod/containers/create", `{"image":"docker.io/library/alpine:3.22","systemd":"false","image_volumes":[{"Source":"docker.io/library/busybox:1.37","Destination":"/other"}]}`},
		{"libpod_container_create", "/libpod/containers/create", `{"image":"docker.io/library/alpine:3.22","systemd":"false","mounts":[{"type":"image","source":"docker.io/library/busybox:1.37","destination":"/other"}]}`},
		{"libpod_container_create", "/v5.8.1/libpod/containers/create", `{"image":"docker.io/library/alpine:3.22","systemd":"false","mounts":[{"type":"IMAGE","source":"docker.io/library/busybox:1.37","destination":"/other"}]}`},
		{"service", "/services/app/update?rollback=previous&version=1", `{"TaskTemplate":{"ContainerSpec":{"Image":"docker.io/library/alpine:3.22"}}}`},
		{"service", "/services/app/update?rollback=previous&version=1", ""},
		{"service", "/services/app/update?version=1", `{"TaskTemplate":{"ContainerSpec":{"Image":"docker.io/library/alpine:3.22"}},"UpdateConfig":{"FailureAction":"rollback"}}`},
		{"service", "/services/create", `{"TaskTemplate":{"ContainerSpec":{"Image":"docker.io/library/alpine:3.22","Mounts":[{"Type":"image","Source":"docker.io/library/busybox:1.37","Target":"/other"}]}}}`},
	} {
		t.Run(tc.group+tc.path+tc.body, func(t *testing.T) {
			yaml := fmt.Sprintf("request_body:\n  %s:\n    allowed_images: [%q]\n", tc.group, allowedCreateImage)
			if tc.group == "libpod_container_create" {
				yaml += "    allowed_bind_mounts: [/srv/rootfs]\n"
			}
			handler := imageAllowlistHandler(t, yaml)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if response.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", response.Code, response.Body.String())
			}
		})
	}
}
