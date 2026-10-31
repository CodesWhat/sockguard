package config

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMountSourceMutationConfigRoutes(t *testing.T) {
	for _, native := range []bool{false, true} {
		group, path, body := "container_create", "/containers/create", `{"HostConfig":{"Binds":["/srv/data:/d:U"]}}`
		if native {
			group, path, body = "libpod_container_create", "/libpod/containers/create", `{"systemd":"false","mounts":[{"type":"bind","source":"/srv/data","destination":"/d","options":["U"]}]}`
		}
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", group, allow), func(t *testing.T) {
				handler := imageAllowlistHandler(t, fmt.Sprintf("request_body:\n  %s: {allowed_bind_mounts: [/srv/data], allow_mount_source_mutation: %v}\n", group, allow))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(body)))
				want := 403
				if allow {
					want = 200
				}
				if rec.Code != want {
					t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body)
				}
			})
		}
	}
}

func TestMountSourceMutationProfileAndEnv(t *testing.T) {
	for _, group := range []string{"container_create", "libpod_container_create"} {
		cfg, err := LoadBytes([]byte(fmt.Sprintf("clients:\n  profiles:\n    - name: worker\n      request_body:\n        %s: {allow_mount_source_mutation: true}\n", group)))
		if err != nil {
			t.Fatal(err)
		}
		policy := cfg.Clients.Profiles[0].RequestBody.ToFilterOptions()
		got := policy.ContainerCreate.AllowMountSourceMutation
		if group == "libpod_container_create" {
			got = policy.LibpodContainerCreate.AllowMountSourceMutation
		}
		if !got {
			t.Fatal("profile lost source-mutation grant")
		}
		t.Setenv("SOCKGUARD_REQUEST_BODY_"+strings.ToUpper(group)+"_ALLOW_MOUNT_SOURCE_MUTATION", "true")
		loaded, err := Load("")
		if err != nil {
			t.Fatal(err)
		}
		policy = loaded.RequestBody.ToFilterOptions()
		got = policy.ContainerCreate.AllowMountSourceMutation
		if group == "libpod_container_create" {
			got = policy.LibpodContainerCreate.AllowMountSourceMutation
		}
		if !got {
			t.Fatal("environment lost source-mutation grant")
		}
	}
}
