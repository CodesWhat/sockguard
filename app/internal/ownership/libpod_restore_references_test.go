package ownership

import (
	"net/url"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

func TestIsLibpodContainerRestorePath(t *testing.T) {
	tests := map[string]bool{
		"/libpod/containers/c/restore":      true,
		"/libpod/containers/c/restore/":     false,
		"/libpod/containers//restore":       false,
		"/libpod/containers/a/b/restore":    false,
		"/libpod/containers/c/checkpoint":   false,
		"/containers/c/restore":             false,
		"/libpod/pods/c/restore":            false,
		"/libpod/containers/create/restore": true,
	}
	for path, want := range tests {
		if got := isLibpodContainerRestorePath(path); got != want {
			t.Errorf("isLibpodContainerRestorePath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestLibpodContainerRestoreOwnershipReferences(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantNil  bool
		wantDeny bool
		wantPod  string
	}{
		{"no pod", "keep=true", true, false, ""},
		{"empty pod", "pod=", true, false, ""},
		{"a pod", "pod=web", false, false, "web"},
		{"pod twice", "pod=a&pod=b", false, true, ""},
		{"pod re-cased", "Pod=a", false, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := url.ParseQuery(tt.query)
			if err != nil {
				t.Fatal(err)
			}
			refs := libpodContainerRestoreOwnershipReferences(query)
			if tt.wantNil {
				if refs != nil {
					t.Fatalf("refs = %+v, want nil", refs)
				}
				return
			}
			if (refs.denyReason != "") != tt.wantDeny {
				t.Fatalf("denyReason = %q, want deny=%v", refs.denyReason, tt.wantDeny)
			}
			if tt.wantPod != "" {
				if len(refs.embeddedResources) != 1 || refs.embeddedResources[0].kind != dockerresource.KindLibpodPod || refs.embeddedResources[0].identifier != tt.wantPod {
					t.Errorf("embeddedResources = %+v, want the pod %q", refs.embeddedResources, tt.wantPod)
				}
			}
		})
	}
}

func TestContainerCreatePodmanNetworkNameReferences(t *testing.T) {
	decoded := map[string]any{
		"HostConfig": map[string]any{"NetworkMode": "ingress"},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{
			"bridge": map[string]any{}, "mine": map[string]any{}, "docker_gwbridge": map[string]any{},
		}},
	}
	var got []string
	for _, ref := range containerCreatePodmanNetworkNameReferences(decoded) {
		got = append(got, ref.source+":"+ref.identifier)
	}
	want := []string{
		"container HostConfig.NetworkMode:ingress",
		"container NetworkingConfig.EndpointsConfig:bridge",
		"container NetworkingConfig.EndpointsConfig:docker_gwbridge",
	}
	if len(got) != len(want) {
		t.Fatalf("references = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("references[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if refs := containerCreatePodmanNetworkNameReferences(map[string]any{"HostConfig": map[string]any{"NetworkMode": "bridge"}}); len(refs) != 0 {
		t.Errorf("NetworkMode bridge is Podman's own mode, got references %+v", refs)
	}
}
