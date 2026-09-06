package differential

import (
	"net/http"
	"testing"
)

// TestClassifyDockerRouteVersionPrefixEdges pins the three edges of the
// dockerd version-prefix oracle that the ordinary "/v1.45/..." rows leave
// free: an empty version segment, and each end of the [0-9.] class dockerd's
// router accepts. Getting any of them wrong makes the oracle strip a prefix
// the daemon would keep (or keep one it would strip), which silently rewrites
// what the differential suite holds sockguard to.
func TestClassifyDockerRouteVersionPrefixEdges(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   RouteCategory
	}{
		{
			name:   "empty version segment is not a version prefix",
			method: http.MethodGet,
			path:   "/v/containers/json",
			want:   RouteUnknown,
		},
		{
			name:   "version digit zero",
			method: http.MethodGet,
			path:   "/v0/containers/json",
			want:   RouteContainerList,
		},
		{
			name:   "version digit nine",
			method: http.MethodGet,
			path:   "/v9/containers/json",
			want:   RouteContainerList,
		},
		{
			name:   "version digits at both class ends",
			method: http.MethodGet,
			path:   "/v0.9/containers/json",
			want:   RouteContainerList,
		},
		{
			name:   "letters are outside dockerd's version class",
			method: http.MethodGet,
			path:   "/v1a/containers/json",
			want:   RouteUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyDockerRoute(tt.method, tt.path); got != tt.want {
				t.Fatalf("ClassifyDockerRoute(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

// TestClassifyDockerRouteNormalizesRelativeAndEmptyPaths covers the two inputs
// that reach the classifier without a leading slash. An empty path is what
// proves the guard tests p before indexing it, and a dot-segment path is what
// proves the leading slash goes on before path.Clean runs, which is the whole
// reason the daemon resolves "/../containers/json" to the container list.
func TestClassifyDockerRouteNormalizesRelativeAndEmptyPaths(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   RouteCategory
	}{
		{name: "empty path", method: http.MethodGet, path: "", want: RouteUnknown},
		{name: "relative dot-dot path", method: http.MethodGet, path: "../containers/json", want: RouteContainerList},
		{name: "relative dot path", method: http.MethodGet, path: "./containers/json", want: RouteContainerList},
		{name: "bare relative path", method: http.MethodGet, path: "containers/json", want: RouteContainerList},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyDockerRoute(tt.method, tt.path); got != tt.want {
				t.Fatalf("ClassifyDockerRoute(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
