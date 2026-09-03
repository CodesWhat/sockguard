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

// TestLookupLibpodUnscopeableWriteIsMethodExact pins the method gate. Podman
// serves POST on this path and nothing else, so matching another method would
// answer 403 where the daemon answers 405, and matching a neighboring prune
// route would refuse an endpoint the owner-label filter already scopes.
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
