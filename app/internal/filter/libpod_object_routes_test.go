package filter

import (
	"net/http"
	"testing"
)

func TestLibpodObjectReadRouteBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/libpod/quadlets/a.container/file", true},
		{"/libpod/quadlets/a.container/exists", true},
		{"/libpod/quadlets/a/b/file", false},
		{"/libpod/quadlets/a.container/file-extra", false},
		{"/libpod/quadlets//file", false},
		{"/libpod/artifacts/registry.example/a/b:latest/json", true},
		{"/libpod/artifacts/registry.example/a/b:latest/extract", true},
		{"/libpod/artifacts/a/extract-extra", false},
		{"/libpod/artifacts//extract", false},
		{"/libpod/artifacts/a/push", false},
	} {
		if _, got := LookupLibpodUnscopeableRead(tc.path); got != tc.want {
			t.Errorf("read %s = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestLibpodObjectWriteRouteBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodDelete, "/libpod/quadlets/a.container", true},
		{http.MethodDelete, "/libpod/quadlets/a/b", false},
		{http.MethodDelete, "/libpod/quadlets/", false},
		{http.MethodPost, "/libpod/quadlets/a.container", false},
		{http.MethodDelete, "/libpod/artifacts/registry.example/a/b:latest", true},
		{http.MethodPost, "/libpod/artifacts/registry.example/a/b:latest/push", true},
		{http.MethodPost, "/libpod/artifacts/a/push/extra", false},
		{http.MethodPost, "/libpod/artifacts//push", false},
		{http.MethodPut, "/libpod/artifacts/a", false},
	} {
		if _, got := LookupLibpodUnscopeableWrite(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}
