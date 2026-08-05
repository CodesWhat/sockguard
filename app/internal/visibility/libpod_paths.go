package visibility

import "strings"

// libpod_paths.go is patterns.go/middleware.go's counterpart for Podman's
// native /libpod/ API family (#148 PR5). It reuses the existing generic
// identifier helpers (singleSegmentIdentifier/suffixedIdentifier/
// readSubresourceIdentifier) with libpod-specific prefixes and reserved
// words, rather than duplicating their logic — "the existing
// path-classification mechanism" the design doc names as one of the two
// acceptable approaches (the other being a dedicated LibpodInspectPath,
// which dockerresource.KindLibpodPod/KindLibpodNetwork do use, for the two
// kinds with no Docker-compat inspect path to fall back on).
const libpodPrefix = "/libpod/"

// needsLibpodVisibilityLabelFilter mirrors needsVisibilityLabelFilter for
// libpod's list endpoints. Podman consistently suffixes every /libpod/ list
// endpoint with "/json" (unlike the Docker-compat API's mixed /networks vs
// /containers/json convention).
func needsLibpodVisibilityLabelFilter(normPath string) bool {
	switch normPath {
	case libpodPrefix + "containers/json",
		libpodPrefix + "pods/json",
		libpodPrefix + "networks/json",
		libpodPrefix + "volumes/json",
		libpodPrefix + "secrets/json":
		return true
	default:
		return false
	}
}

// libpodContainerReadIdentifier matches every GET libpod container read
// endpoint that discloses container data, the libpod counterpart of
// containerReadIdentifier. Name/image pattern axes do not apply here — see
// needsPatternResponseFilter's doc comment, which already documents that
// pattern filtering is scoped to exactly two Docker-compat list endpoints;
// this does not regress that, it just does not extend pattern filtering to
// a third route family.
func libpodContainerReadIdentifier(normPath string) (string, bool) {
	return readSubresourceIdentifier(normPath, libpodPrefix+"containers/", "json", "logs", "stats", "top", "changes", "export")
}

// libpodPodReadIdentifier matches GET /libpod/pods/{id}/json. Unlike
// Docker-compat's KindNetwork/KindVolume ("/networks/{id}" bare, no
// suffix), every libpod inspect endpoint is uniformly suffixed "/json" —
// hence suffixedIdentifier rather than singleSegmentIdentifier here and in
// the three inspect identifiers below. The collection endpoint itself
// (GET /libpod/pods/json) never matches: its remainder after the prefix is
// bare "json" with no "/id/json" shape for suffixedIdentifier to find.
func libpodPodReadIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, libpodPrefix+"pods/", "json")
}

// libpodNetworkInspectIdentifier matches GET /libpod/networks/{id}/json.
func libpodNetworkInspectIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, libpodPrefix+"networks/", "json")
}

// libpodVolumeInspectIdentifier matches GET /libpod/volumes/{id}/json.
func libpodVolumeInspectIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, libpodPrefix+"volumes/", "json")
}

// libpodSecretInspectIdentifier matches GET /libpod/secrets/{id}/json.
func libpodSecretInspectIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, libpodPrefix+"secrets/", "json")
}

// isLibpodVisibilityPath reports whether normPath falls under the /libpod/
// route family, for the sole purpose of applying the "libpod " deny-reason
// prefix convention (#148 design doc item 5) to the hidden-resource 404.
func isLibpodVisibilityPath(normPath string) bool {
	return strings.HasPrefix(normPath, libpodPrefix)
}
