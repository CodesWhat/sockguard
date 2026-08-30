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

// isLibpodImagePullPath matches POST /libpod/images/pull, Podman's native
// image-pull endpoint and the libpod equivalent of Docker's
// POST /images/create. The two are path-exclusive, and their query shapes are
// not interchangeable — see imagePullPolicy.inspectLibpod.
func isLibpodImagePullPath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"images/pull"
}

// isLibpodImageLoadPath matches POST /libpod/images/load, Podman's native
// image-load endpoint. Verified against Podman v5.8.1
// (pkg/api/server/register_images.go registers it on libpod.ImagesLoad;
// pkg/api/handlers/libpod/images.go's ImagesLoad copies the WHOLE request
// body to a temp file and hands it to imageEngine.Load): it takes no query
// parameters at all, and its body is the same docker-archive/oci-archive
// stream Docker's POST /images/load carries. Same input in the same place,
// so the Docker-compat inspector applies to it unchanged rather than needing
// a libpod-specific one — see matchesImageLoadInspection.
func isLibpodImageLoadPath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"images/load"
}

// isLibpodLocalImageLoadPath matches POST /libpod/local/images/load. Despite
// the name it is not a spelling variant of the endpoint above: it carries NO
// request body and names an absolute path on the DAEMON HOST in a required
// `path` query parameter (Podman v5.8.1 pkg/api/handlers/libpod/images.go,
// ImagesLocalLoad, whose only check is internal/localapi's
// ValidatePathForLocalAPI — "is it absolute" and "does it exist", with no
// sandbox root). The archive therefore never crosses the socket, so there is
// no manifest for sockguard to read; see imageLoadPolicy.inspect.
func isLibpodLocalImageLoadPath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"local/images/load"
}

// isLibpodImageImportPath matches POST /libpod/images/import, the libpod
// counterpart of the Docker-compat import that rides on
// POST /images/create?fromSrc= and that request_body.image_pull.allow_imports
// already gates. Podman v5.8.1's ImagesImport takes the tarball from the body
// OR fetches it from a caller-supplied `URL` query parameter; both are the
// same "materialize an image from something that is not a registry pull"
// operation, which is what allow_imports governs. See
// imagePullPolicy.inspectLibpodImport.
func isLibpodImageImportPath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"images/import"
}

// isLibpodLocalBuildPath matches POST /libpod/local/build. It shares Podman's
// build implementation with /libpod/build — both are compat.buildImage in
// v5.8.1's pkg/api/handlers/compat/images_build.go, so both accept the same
// libpod-only build query controls — but takes its build context from a
// required `localcontextdir` query parameter naming an absolute path on the
// DAEMON HOST instead of from a tar in the request body, and resolves the
// Containerfile as a daemon-host path too (handleLocalBuildContexts ->
// localapi.ValidatePathForLocalAPI, the same absolute-and-exists check the
// local image load uses). Nothing to build from ever crosses the socket, so
// request_body.build's Dockerfile scan has no bytes to read.
func isLibpodLocalBuildPath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"local/build"
}

// isLibpodBuildPath matches both of Podman's native build endpoints. They
// differ only in where the build context comes from, and exactly one of them
// puts it in the request body, which is why inspectLibpodBuildControls gates
// both while only /libpod/build can be inspected — see isLibpodLocalBuildPath.
func isLibpodBuildPath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"build" || isLibpodLocalBuildPath(normalizedPath)
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

// containerSubresourcePath reports whether normalizedPath addresses the
// per-container subresource named by subresource on either of Podman's two
// spellings of the same route family — Docker-compat
// "/containers/{id}/<subresource>" and libpod-native
// "/libpod/containers/{id}/<subresource>" — and, when it does, which of the
// two spellings it matched.
//
// It exists so a per-container matcher is written once against both spellings
// instead of twice against one each. A predicate hand-written on the bare
// "/containers/" prefix stops matching the moment a client speaks libpod to
// the same Podman socket, which is exactly how
// PUT /libpod/containers/{name}/archive and
// POST /libpod/containers/{name}/update went uninspected: the drift between
// two hand-maintained path lists IS the bug, so a second list is not the fix.
//
// The tail comparison deliberately does not require a non-empty {id}, which
// preserves the behavior isContainerArchivePath and isContainerUpdatePath had
// before they were rebuilt on this helper — narrowing it would move a path
// out of inspection, not into it.
//
// normalizedPath must already have gone through NormalizePath, for the reason
// isLibpodPath's doc comment gives.
func containerSubresourcePath(normalizedPath string, subresource string) (libpod bool, ok bool) {
	rest, found := strings.CutPrefix(normalizedPath, libpodPathPrefix+"containers/")
	if found {
		libpod = true
	} else {
		rest, found = strings.CutPrefix(normalizedPath, "/containers/")
		if !found {
			return false, false
		}
	}
	_, tail, hasTail := strings.Cut(rest, "/")
	return libpod, hasTail && tail == subresource
}

// isLibpodContainerUpdatePath matches POST /libpod/containers/{name}/update,
// registered on libpod.UpdateContainer in Podman v5.8.1's
// pkg/api/server/register_containers.go. It is deliberately NOT folded into
// isContainerUpdatePath the way archive is: the two endpoints share a name
// and nothing else. Docker's update body is a flat container.UpdateConfig,
// libpod's is handlers.UpdateEntities (an embedded OCI specs.LinuxResources
// plus healthcheck and device-limit blocks), and libpod takes the restart
// policy from the query string rather than the body — so the two need
// separate readers even though they share one ContainerUpdateOptions. See
// containerUpdatePolicy.inspectLibpod.
func isLibpodContainerUpdatePath(normalizedPath string) bool {
	libpod, ok := containerSubresourcePath(normalizedPath, "update")
	return ok && libpod
}
