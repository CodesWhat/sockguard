package filter

import "strings"

// libpodPathPrefix is the literal namespace prefix for Podman's native
// libpod API, distinct from the Docker-compatibility surface sockguard
// already filters (see stripVersionPrefix's doc comment for the version-
// prefix handling that makes /v5.0.0/libpod/... normalize the same as
// /libpod/...). Every matcher in this file is exact-prefix-guarded on this
// constant so a crafted Docker-shaped path (e.g. "/containers/create") can
// never satisfy a libpod predicate, and vice versa — see
// TestLibpodMatchersNeverMatchDockerPathsAndViceVersa.
const libpodPathPrefix = "/libpod/"

// isLibpodPath reports whether normalizedPath falls under Podman's native
// libpod API namespace. normalizedPath must already have gone through
// NormalizePath (version prefix stripped, path cleaned) — this function does
// no cleaning of its own, so callers must never pass a raw request path
// straight from the wire (a literal "/libpod/../containers/create" would
// otherwise falsely match; NormalizePath collapses it to "/containers/create"
// before any matcher in this file ever sees it).
func isLibpodPath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, libpodPathPrefix)
}

// isLibpodContainerCreatePath matches POST /libpod/containers/create, the
// libpod equivalent of Docker's POST /containers/create.
func isLibpodContainerCreatePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"containers/create"
}

// isLibpodPodCreatePath matches POST /libpod/pods/create. Pods are a
// libpod-native concept with no Docker-compat equivalent.
func isLibpodPodCreatePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"pods/create"
}

// isLibpodExecCreatePath matches POST /libpod/containers/{id}/exec, the
// libpod equivalent of isExecCreatePath's /containers/{id}/exec.
func isLibpodExecCreatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, libpodPathPrefix+"containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, libpodPathPrefix+"containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "exec"
}

// isLibpodExecStartPath matches POST /libpod/exec/{id}/start, the libpod
// equivalent of isExecStartPath's /exec/{id}/start.
func isLibpodExecStartPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, libpodPathPrefix+"exec/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, libpodPathPrefix+"exec/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "start"
}

// isLibpodContainerAttachPath matches POST /libpod/containers/{id}/attach,
// the libpod equivalent of the Docker hijack endpoint
// /containers/{id}/attach (see isContainerAttachPath).
func isLibpodContainerAttachPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, libpodPathPrefix+"containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, libpodPathPrefix+"containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "attach"
}

// isLibpodPlayKubePath matches POST /libpod/play/kube. It has no Docker
// analog: a single request can create an arbitrary number of privileged
// containers from a Kubernetes-shaped manifest. Full body modeling is
// deferred (see the design doc's play/kube posture); PR2+ routes any allow
// rule for this path through the blind-write acknowledgement gate rather
// than modeling its body.
func isLibpodPlayKubePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"play/kube"
}

// isContainerAttachPath matches POST /containers/{id}/attach, the Docker
// counterpart of isLibpodContainerAttachPath. Unlike exec create/start,
// container-attach previously had no reusable filter-side predicate — the
// hijack layer (internal/proxy) matched it with inline logic instead. This
// gives that inline logic a named, testable counterpart on this side of the
// package split, and lets TestLibpodMatchersNeverMatchDockerPathsAndViceVersa
// assert the libpod/Docker attach matchers stay mutually exclusive.
func isContainerAttachPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, "/containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "attach"
}
