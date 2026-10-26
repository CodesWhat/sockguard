package buildkitproxy

import (
	"net/http"
	"reflect"
	"testing"
)

func TestSessionMethodAdvertisementsMatchBuildkit(t *testing.T) {
	h := http.Header{}
	methods := []string{"/grpc.health.v1.Health/Check", "/moby.filesync.v1.Auth/Credentials", "/moby.filesync.v1.FileSync/DiffCopy", "/moby.filesync.v1.FileSync/TarStream", "/moby.filesync.v1.Auth/Unknown", "/moby.buildkit.v1.frontend.LLBBridge/Solve"}
	for _, method := range methods {
		h.Add(sessionGRPCMethodHeader, method)
	}
	p := Policy{Session: SessionPolicy{Health: true, FileSync: FileSyncPolicy{Allow: true}}}
	rewriteSessionAdvertisement(h, p)
	want := []string{methods[0], methods[2]}
	if got := h.Values(sessionGRPCMethodHeader); !reflect.DeepEqual(got, want) {
		t.Fatalf("advertised=%v want=%v", got, want)
	}
	if !p.Allowed(EndpointSession, "grpc.health.v1.Health", "Check") {
		t.Fatal("daemon health callback denied despite session.health grant")
	}
	if p.Allowed(EndpointSession, "grpc.health.v1.Health", "Watch") {
		t.Fatal("unneeded streaming health callback was granted")
	}
}
