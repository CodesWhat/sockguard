// Package apipath holds the request classification sockguard's policy,
// ownership, visibility and response-filtering layers all have to agree on:
// the canonical view of a Docker or libpod API path, and the path-shape
// predicates read off that view. internal/filter, internal/ownership,
// internal/visibility, internal/responsefilter, internal/ratelimit,
// internal/proxy and internal/cmd each need some of it.
//
// apipath depends on none of them, by design: internal/ownership,
// internal/visibility and internal/responsefilter all import internal/filter,
// so a canonical home inside any of those four would create an import cycle
// for at least one of the others. This package stays a leaf so every one of
// them can import it, and so the classification a request is judged by is
// read from one definition rather than re-derived per package — a second
// parser that disagrees with the first is the smuggling bug this proxy
// exists to prevent, not a cosmetic duplication.
//
// Nothing here reads configuration or policy state. Every function takes a
// method or a path string and returns a bool or a string.
//
// The functions fall into two groups and the split matters. NormalizePath,
// CanonicalizePath, StripVersionPrefix and NormalizePodmanRoutePath produce
// the canonical view and are the only ones that accept a raw request path.
// Every predicate — IsLibpodPath, IsNodeUpdatePath, the hijack-candidate set
// — consumes that view and does no cleaning of its own, so a caller must
// never hand one a path straight from the wire: a literal
// "/libpod/../containers/create" would falsely satisfy IsLibpodPath, where
// NormalizePath collapses it to "/containers/create" before any predicate
// sees it.
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
