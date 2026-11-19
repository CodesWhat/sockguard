package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContainerCreateRuntimeAnnotations(t *testing.T) {
	deny := func(key string) string {
		return `container create denied: runtime annotation "` + key + `" is not allowed (set allow_runtime_annotations: true)`
	}
	tests := []struct {
		name string
		opts ContainerCreateOptions
		body string
		want string
	}{
		{"run.oci key", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{"run.oci.keep_original_groups":"1"}}}`, deny("run.oci.keep_original_groups")},
		{"run.oci key in another case", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{"Run.OCI.Handler":"wasm"}}}`, deny("Run.OCI.Handler")},
		{"cid-file", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{"io.podman.annotations.cid-file":"/etc/passwd"}}}`, deny("io.podman.annotations.cid-file")},
		{"cid-file in another case with padding", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{" IO.Podman.Annotations.CID-File":"/etc/passwd"}}}`, deny(" IO.Podman.Annotations.CID-File")},
		{"autoremove", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{"io.podman.annotations.autoremove":"true"}}}`, deny("io.podman.annotations.autoremove")},
		{"autoremove-image", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{"io.podman.annotations.autoremove-image":"true"}}}`, deny("io.podman.annotations.autoremove-image")},
		{"harmless metadata", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{"team":"a","io.podman.annotations.userns":"private"}}}`, ""},
		{"empty map", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":{}}}`, ""},
		{"null map", ContainerCreateOptions{}, `{"HostConfig":{"Annotations":null}}`, ""},
		{"opt-in allows", ContainerCreateOptions{AllowRuntimeAnnotations: true}, `{"HostConfig":{"Annotations":{"io.podman.annotations.cid-file":"/x"}}}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.AllowAllCapabilities = true
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(tt.body))
			reason, err := newContainerCreatePolicy(tt.opts).inspect(nil, req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.want {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.want)
			}
		})
	}
}

// TestContainerCreateAnnotationsDoNotLeakAcrossPooledRequests pins that a
// recycled decode target forgets the previous request's annotations.
func TestContainerCreateAnnotationsDoNotLeakAcrossPooledRequests(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{AllowAllCapabilities: true})
	for _, body := range []string{
		`{"HostConfig":{"Annotations":{"run.oci.handler":"wasm"}}}`,
		`{"HostConfig":{}}`,
		`{"HostConfig":{"Annotations":{"run.oci.handler":"wasm"}}}`,
		`{}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))
		reason, err := policy.inspect(nil, req, "/containers/create")
		if err != nil {
			t.Fatalf("inspect(%s) error = %v", body, err)
		}
		wantDenied := body == `{"HostConfig":{"Annotations":{"run.oci.handler":"wasm"}}}`
		if (reason != "") != wantDenied {
			t.Fatalf("inspect(%s) reason = %q, wantDenied = %v", body, reason, wantDenied)
		}
	}
}
