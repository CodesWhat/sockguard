package differential

import (
	"net/http"
	"testing"
)

func TestClassifyDockerRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		want   RouteCategory
	}{
		{"container list", http.MethodGet, "/containers/json", RouteContainerList},
		{"container create", http.MethodPost, "/containers/create", RouteContainerCreate},
		{"container create versioned", http.MethodPost, "/v1.45/containers/create", RouteContainerCreate},
		{"container create multi-dot version", http.MethodPost, "/v1.2.3/containers/create", RouteContainerCreate},
		{"container inspect", http.MethodGet, "/containers/abc123/json", RouteContainerInspect},
		{"container start", http.MethodPost, "/containers/abc123/start", RouteContainerStart},
		{"container delete", http.MethodDelete, "/containers/abc123", RouteContainerDelete},
		{"container stop", http.MethodPost, "/containers/abc/stop", RouteContainerStop},
		{"container stop versioned", http.MethodPost, "/v1.45/containers/abc/stop", RouteContainerStop},
		{"container kill", http.MethodPost, "/containers/abc/kill", RouteContainerKill},
		{"container exec create", http.MethodPost, "/containers/abc/exec", RouteContainerExecCreate},
		{"exec inspect", http.MethodGet, "/exec/abc/json", RouteExecInspect},
		{"version", http.MethodGet, "/version", RouteVersion},
		{"info", http.MethodGet, "/info", RouteInfo},
		{"image list", http.MethodGet, "/images/json", RouteImageList},
		{"exec start", http.MethodPost, "/exec/deadbeef/start", RouteExecStart},
		{"image create", http.MethodPost, "/images/create", RouteImageCreate},
		{"build", http.MethodPost, "/build", RouteBuild},
		{"ping", http.MethodGet, "/_ping", RoutePing},

		// Path cleaning: the oracle resolves dot-segments and doubled slashes.
		{"doubled slash collapses to create", http.MethodPost, "//containers//create", RouteContainerCreate},
		{"dot-dot resolves into create", http.MethodPost, "/containers/json/../create", RouteContainerCreate},
		{"trailing slash trimmed", http.MethodGet, "/containers/json/", RouteContainerList},

		// Method mismatch and unknown shapes route nowhere.
		{"create with GET is not a route", http.MethodGet, "/containers/create", RouteUnknown},
		{"unknown path", http.MethodGet, "/totally/unknown", RouteUnknown},
		{"version prefix without trailing slash is literal", http.MethodPost, "/v1.45", RouteUnknown},
		{"non-numeric version prefix not stripped", http.MethodPost, "/vX/containers/create", RouteUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyDockerRoute(tt.method, tt.path); got != tt.want {
				t.Fatalf("ClassifyDockerRoute(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
