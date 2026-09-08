package apipath

import "testing"

// Two mutants in normalize.go stay alive on purpose, both verified by
// hand-applying the mutation and re-running this package:
//
//   - pathNeedsClean, `len(p) > 1` before the trailing-slash test: the only
//     one-byte path whose last byte is '/' is "/", and that already returned
//     at the guard above, so `>= 1` decides the same way for every input.
//   - StripVersionPrefix, the `i++` after the first-digit check: p[1] is
//     already known to be 'v', which is inside the [0-9A-Za-z.-] class the
//     loop consumes, so `i--` re-reads it and lands on the same index.

// TestStripVersionPrefixAcceptsEveryClassBoundary pins each end of the
// [0-9A-Za-z.-] class Podman's VersionedPath routing uses, one row per
// boundary byte. Without a row per boundary, either end of any of the four
// ranges can move a byte and every existing case still passes, because the
// versions the other tests use ("v1.45", "v5.8.1-dev") sit in the interior of
// the ranges they exercise.
func TestStripVersionPrefixAcceptsEveryClassBoundary(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "tail digit zero", path: "/v10/containers/json", want: "/containers/json"},
		{name: "tail digit nine", path: "/v19/containers/json", want: "/containers/json"},
		{name: "tail lowercase a", path: "/v1a/containers/json", want: "/containers/json"},
		{name: "tail lowercase z", path: "/v1z/containers/json", want: "/containers/json"},
		{name: "tail uppercase A", path: "/v1A/containers/json", want: "/containers/json"},
		{name: "tail uppercase Z", path: "/v1Z/containers/json", want: "/containers/json"},
		{name: "tail dot", path: "/v1.45/containers/json", want: "/containers/json"},
		{name: "tail hyphen", path: "/v5.8.1-dev/containers/json", want: "/containers/json"},
		{name: "underscore is outside the class", path: "/v1_/containers/json", want: "/v1_/containers/json"},
		{name: "at sign is outside the class", path: "/v1@/containers/json", want: "/v1@/containers/json"},
		{name: "second byte must be a digit", path: "/vx/containers/json", want: "/vx/containers/json"},
		{name: "prefix must end in a slash", path: "/v1.45", want: "/v1.45"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripVersionPrefix(tt.path); got != tt.want {
				t.Fatalf("StripVersionPrefix(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
