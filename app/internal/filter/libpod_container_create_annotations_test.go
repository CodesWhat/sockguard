package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLibpodContainerCreateRuntimeAnnotationGate pins that SpecGenerator's
// "annotations" are held to the same refusal as the Docker-compat
// HostConfig.Annotations: run.oci.* and the io.podman.annotations. keys Podman
// acts on are denied unless allow_runtime_annotations is set, and the markers
// podman-remote sends on ordinary creates pass.
func TestLibpodContainerCreateRuntimeAnnotationGate(t *testing.T) {
	deny := func(key string) string {
		return `libpod container create denied: runtime annotation "` + key + `" is not allowed (set allow_runtime_annotations: true)`
	}
	cases := []struct {
		name string
		opts LibpodContainerCreateOptions
		body string
		want string
	}{
		{"run.oci annotation denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"run.oci.keep_original_groups":"1"}}`, deny("run.oci.keep_original_groups")},
		{"run.oci annotation in another case is denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"RUN.OCI.handler":"wasm"}}`, deny("RUN.OCI.handler")},
		{"io.podman.annotations markers pass, podman-remote sends them", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.seccomp":"unconfined","io.podman.annotations.userns":"private","io.podman.annotations.pids-limit":"100"}}`, ""},
		{"first sorted runtime key is reported", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"run.oci.b":"1","run.oci.a":"1","org.example":"x"}}`, deny("run.oci.a")},
		{"cid-file annotation denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.cid-file":"/etc/passwd"}}`, deny("io.podman.annotations.cid-file")},
		{"autoremove annotation denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.autoremove":"TRUE"}}`, deny("io.podman.annotations.autoremove")},
		{"autoremove-image annotation denied in another case", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"IO.Podman.Annotations.Autoremove-Image":"true"}}`, deny("IO.Podman.Annotations.Autoremove-Image")},
		{"acted annotations allowed with opt-in", LibpodContainerCreateOptions{AllowRuntimeAnnotations: true}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.cid-file":"/x","io.podman.annotations.autoremove":"true"}}`, ""},
		{"runtime annotations allowed with opt-in", LibpodContainerCreateOptions{AllowRuntimeAnnotations: true}, `{"image":"alpine","systemd":"false","annotations":{"run.oci.keep_original_groups":"1"}}`, ""},
		{"plain annotation passes", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"org.example.team":"a","io.podman":"x","run.ocix":"y"}}`, ""},
		{"empty annotations pass", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{}}`, ""},
		{"null annotations pass", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":null}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", bytes.NewBufferString(tc.body))
			got, err := newLibpodContainerCreatePolicy(tc.opts).inspect(nil, req, "/libpod/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}
