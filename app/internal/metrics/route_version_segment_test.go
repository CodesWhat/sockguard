package metrics

import "testing"

// Two mutants in this file's subject stay alive on purpose, both verified by
// hand-applying the mutation and re-running this package:
//
//   - metrics.go appendRouteSegments, `i >= 0` on the IndexByte result: `rest`
//     is taken after every leading slash has been skipped, so IndexByte can
//     never return 0 and `> 0` is the same predicate.
//   - metrics.go ObserveConfigReload, `ts < 0` on time.Now().UnixNano():
//     `<= 0` differs only for a clock reading of exactly the Unix epoch. The
//     guard is there for the 2262 int64 overflow, and killing it would need a
//     clock seam this package does not have.

// TestIsDockerVersionSegmentAcceptsEveryClassBoundary pins each end of the
// [0-9A-Za-z.-] class the Podman VersionedPath mirror accepts, one row per
// boundary character, plus one character just outside the class. Asserting
// only on "v1.45" leaves every boundary free to move a byte in either
// direction without a test noticing.
func TestIsDockerVersionSegmentAcceptsEveryClassBoundary(t *testing.T) {
	tests := []struct {
		name    string
		segment string
		want    bool
	}{
		{name: "leading digit zero", segment: "v0", want: true},
		{name: "leading digit nine", segment: "v9", want: true},
		{name: "tail digit zero", segment: "v10", want: true},
		{name: "tail digit nine", segment: "v19", want: true},
		{name: "tail lowercase a", segment: "v1a", want: true},
		{name: "tail lowercase z", segment: "v1z", want: true},
		{name: "tail uppercase A", segment: "v1A", want: true},
		{name: "tail uppercase Z", segment: "v1Z", want: true},
		{name: "tail dot", segment: "v1.45", want: true},
		{name: "tail hyphen", segment: "v5.8.1-dev", want: true},
		{name: "tail underscore is outside the class", segment: "v1_", want: false},
		{name: "tail slash is outside the class", segment: "v1/", want: false},
		{name: "tail at sign is outside the class", segment: "v1@", want: false},
		{name: "second byte must be a digit", segment: "vx", want: false},
		{name: "second byte punctuation", segment: "v.", want: false},
		{name: "too short", segment: "v", want: false},
		{name: "no v prefix", segment: "1.45", want: false},
		{name: "empty", segment: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDockerVersionSegment(tt.segment); got != tt.want {
				t.Fatalf("isDockerVersionSegment(%q) = %v, want %v", tt.segment, got, tt.want)
			}
		})
	}
}

// TestRouteCategoryHonorsVersionSegmentClassBoundaries walks the same
// boundaries through the exported entry point, so a version prefix that stops
// being recognized shows up as a route label regression and not only as a
// helper-level difference.
func TestRouteCategoryHonorsVersionSegmentClassBoundaries(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "v0 prefix", path: "/v0/containers/json", want: "/containers/json"},
		{name: "v19 prefix", path: "/v19/containers/json", want: "/containers/json"},
		{name: "v1a prefix", path: "/v1a/containers/json", want: "/containers/json"},
		{name: "v1z prefix", path: "/v1z/containers/json", want: "/containers/json"},
		{name: "v1A prefix", path: "/v1A/containers/json", want: "/containers/json"},
		{name: "v1Z prefix", path: "/v1Z/containers/json", want: "/containers/json"},
		{name: "podman dev prefix", path: "/v5.8.1-dev/containers/json", want: "/containers/json"},
		{name: "underscore is not a version prefix", path: "/v1_/containers/json", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RouteCategory(tt.path); got != tt.want {
				t.Fatalf("RouteCategory(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestAppendRouteSegmentsToleratesDegenerateSlashPaths calls the splitter
// directly with the inputs RouteCategory filters out before it ever gets
// there. The trailing-slash trim runs before the start/end sanity check, so
// an empty or all-slash path is what proves the loop's lower bound holds.
func TestAppendRouteSegmentsToleratesDegenerateSlashPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{name: "empty", path: "", want: nil},
		{name: "root", path: "/", want: nil},
		{name: "double slash", path: "//", want: nil},
		{name: "only slashes", path: "/////", want: nil},
		{name: "trailing slash trimmed", path: "/containers/json/", want: []string{"containers", "json"}},
		{name: "interior empty segment kept", path: "/containers//json", want: []string{"containers", "", "json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendRouteSegments(nil, tt.path)
			if len(got) != len(tt.want) {
				t.Fatalf("appendRouteSegments(nil, %q) = %q, want %q", tt.path, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("appendRouteSegments(nil, %q) = %q, want %q", tt.path, got, tt.want)
				}
			}
		})
	}
}
