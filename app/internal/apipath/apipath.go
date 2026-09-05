// Package apipath holds path-classifier predicates over normalized Docker
// and libpod API paths that internal/filter, internal/ownership,
// internal/visibility, and internal/responsefilter each need independently.
// Every predicate here used to be duplicated verbatim in two or more of
// those packages. apipath has no dependency on any of the four, by design:
// internal/responsefilter and internal/ownership/internal/visibility all
// import internal/filter, so a canonical home inside any of the four would
// create an import cycle for at least one of the others. This package stays
// a leaf so all four can import it.
//
// A path passed to any function here must already have gone through
// normalization (version prefix stripped, path cleaned) — none of these
// functions do their own cleaning, so callers must never pass a raw request
// path straight from the wire.
package apipath

import "strings"

// libpodPathPrefix is the namespace prefix for Podman's native libpod API,
// distinct from the Docker-compatibility surface. It intentionally includes
// the trailing slash so a bare "/libpod" (no trailing segment) never
// matches.
const libpodPathPrefix = "/libpod/"

// IsLibpodPath reports whether normPath falls under Podman's native libpod
// API namespace.
func IsLibpodPath(normPath string) bool {
	return strings.HasPrefix(normPath, libpodPathPrefix)
}

// IsNodeUpdatePath reports whether normPath is /nodes/{id}/update.
func IsNodeUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/nodes/"), "/")
	return ok && identifier != "" && tail == "update"
}
