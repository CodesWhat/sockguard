package filter

import (
	"net/http"
	"testing"
)

func TestLookupLibpodUnscopeableWriteMatchesPodPrune(t *testing.T) {
	t.Parallel()
	write, ok := LookupLibpodUnscopeableWrite(http.MethodPost, LibpodPodPrunePath)
	if !ok {
		t.Fatalf("LookupLibpodUnscopeableWrite(POST, %q) = no match, want the pod prune entry", LibpodPodPrunePath)
	}
	if write.ReasonCodeStem != "pod_prune" {
		t.Fatalf("ReasonCodeStem = %q, want %q", write.ReasonCodeStem, "pod_prune")
	}
	if write.Reason != LibpodPodPruneDenyReason {
		t.Fatalf("Reason = %q, want the shared deny reason", write.Reason)
	}
}

// TestLookupLibpodUnscopeableWriteMatchesKubeDown pins both spellings of kube
// down. Podman serves DELETE /libpod/play/kube and DELETE /libpod/kube/play
// from one handler (pkg/api/server/register_kube.go:180-181 at v5.8.6), so a
// refusal that covered one would leave the other forwarding the same
// teardown.
func TestLookupLibpodUnscopeableWriteMatchesKubeDown(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/libpod/play/kube", "/libpod/kube/play"} {
		write, ok := LookupLibpodUnscopeableWrite(http.MethodDelete, path)
		if !ok {
			t.Fatalf("LookupLibpodUnscopeableWrite(DELETE, %q) = no match, want the kube down entry", path)
		}
		if write.ReasonCodeStem != "kube_down" {
			t.Fatalf("%s: ReasonCodeStem = %q, want %q", path, write.ReasonCodeStem, "kube_down")
		}
		if write.Reason != LibpodKubeDownDenyReason {
			t.Fatalf("%s: Reason = %q, want the shared deny reason", path, write.Reason)
		}
	}
}

// TestLookupLibpodUnscopeableWriteIsMethodExact pins the method gate. Podman
// serves POST on the prune path and nothing else, so matching another method
// would answer 403 where the daemon answers 405, and matching a neighboring
// prune route would refuse an endpoint the owner-label filter already scopes.
// On the kube paths POST is kube play, a different operation that isn't
// refused here.
func TestLookupLibpodUnscopeableWriteIsMethodExact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: LibpodPodPrunePath},
		{method: http.MethodHead, path: LibpodPodPrunePath},
		{method: http.MethodDelete, path: LibpodPodPrunePath},
		{method: http.MethodPost, path: "/libpod/containers/prune"},
		{method: http.MethodPost, path: "/libpod/images/prune"},
		{method: http.MethodPost, path: "/libpod/networks/prune"},
		{method: http.MethodPost, path: "/libpod/volumes/prune"},
		{method: http.MethodPost, path: "/libpod/pods/create"},
		{method: http.MethodPost, path: "/v5.8.1/libpod/pods/prune"},
		{method: http.MethodPost, path: "/libpod/play/kube"},
		{method: http.MethodPost, path: "/libpod/kube/play"},
		{method: http.MethodGet, path: "/libpod/kube/play"},
		{method: http.MethodDelete, path: "/libpod/kube/apply"},
		{method: http.MethodDelete, path: "/libpod/generate/kube"},
		{method: http.MethodDelete, path: "/v5.8.6/libpod/kube/play"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			if write, ok := LookupLibpodUnscopeableWrite(tt.method, tt.path); ok {
				t.Fatalf("LookupLibpodUnscopeableWrite(%s, %q) = %#v, want no match", tt.method, tt.path, write)
			}
		})
	}
}
