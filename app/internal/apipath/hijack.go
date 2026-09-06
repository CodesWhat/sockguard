package apipath

import (
	"net/http"
	"strings"
)

// IsHijackCandidatePath reports whether method+normPath is one of the
// connection-upgrade endpoints — Docker-compat or libpod — that
// internal/proxy's hijack layer must recognize identically to
// internal/filter's own routing.
//
// It lives here, in the leaf, for the reason the package doc gives: a path
// this reports true for that the hijack layer treats as false (or the
// reverse) is a two-parser-drift smuggling bug, not a cosmetic mismatch, so
// both sides of the filter/proxy package split have to read one definition
// rather than each keep its own. See internal/proxy's TestHijackFilterParity,
// and #148's design doc ("Agreed core" item 3) for why this must hold for the
// libpod namespace too.
func IsHijackCandidatePath(method, normPath string) bool {
	if method != http.MethodPost {
		return false
	}
	return IsContainerAttachPath(normPath) ||
		IsExecStartPath(normPath) ||
		IsLibpodContainerAttachPath(normPath) ||
		IsLibpodExecStartPath(normPath)
}

// IsContainerAttachPath matches POST /containers/{id}/attach, the Docker
// counterpart of IsLibpodContainerAttachPath. Unlike exec create/start,
// container-attach previously had no reusable predicate — the hijack layer
// (internal/proxy) matched it with inline logic instead. This gives that
// inline logic a named, testable counterpart, and lets internal/filter's
// TestLibpodMatchersNeverMatchDockerPathsAndViceVersa assert the
// libpod/Docker attach matchers stay mutually exclusive.
func IsContainerAttachPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/containers/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "attach"
}

// IsExecStartPath matches POST /exec/{id}/start, the Docker counterpart of
// IsLibpodExecStartPath.
func IsExecStartPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/exec/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/exec/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "start"
}

// IsLibpodContainerAttachPath matches POST /libpod/containers/{id}/attach,
// the libpod equivalent of the Docker hijack endpoint
// /containers/{id}/attach (see IsContainerAttachPath). Like every other
// libpod matcher it is exact-prefix-guarded on libpodPathPrefix, so a
// Docker-compat path can never satisfy it.
func IsLibpodContainerAttachPath(normPath string) bool {
	if !strings.HasPrefix(normPath, libpodPathPrefix+"containers/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, libpodPathPrefix+"containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "attach"
}

// IsLibpodExecStartPath matches POST /libpod/exec/{id}/start, the libpod
// equivalent of IsExecStartPath's /exec/{id}/start.
func IsLibpodExecStartPath(normPath string) bool {
	if !strings.HasPrefix(normPath, libpodPathPrefix+"exec/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, libpodPathPrefix+"exec/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "start"
}
