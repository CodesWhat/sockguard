package filter

import (
	"slices"
	"strings"
)

// PodmanVolumeListPath and PodmanVolumeLibpodListPath are the normalized
// paths of the Docker-compat and native volume list routes.
const (
	PodmanVolumeListPath       = "/volumes"
	PodmanVolumeLibpodListPath = "/libpod/volumes/json"
)

// IsPodmanVolumeListPath reports whether normPath is a volume list route.
func IsPodmanVolumeListPath(normPath string) bool {
	return normPath == PodmanVolumeListPath || normPath == PodmanVolumeLibpodListPath
}

// IsPodmanVolumePrunePath reports whether normPath is a volume prune route.
func IsPodmanVolumePrunePath(normPath string) bool {
	return normPath == "/volumes/prune" || normPath == libpodPathPrefix+"volumes/prune"
}

// PodmanVolumeFilterDenyReason reports whether a decoded volume filter set
// carries a key other than `label`, and if so the operator-facing reason.
//
// Podman before 6.0 combines volume filters of different keys with OR
// (libpod/runtime_volume.go accumulates `include = include || filter(vol)`),
// so any extra key (driver, name, label!, until, dangling, ...) widens the
// result past an injected `label` selector, and on prune removes other
// owners' unused volumes. Callers apply this to old or unverified Podman
// versions; every endpoint must positively report a released version >=6
// before the volume-filter capability bypasses this refusal.
func PodmanVolumeFilterDenyReason(filters map[string][]string) (string, bool) {
	var unsupported []string
	for key := range filters {
		if key != "label" {
			unsupported = append(unsupported, key)
		}
	}
	if len(unsupported) == 0 {
		return "", false
	}
	slices.Sort(unsupported)
	return "volume filter denied: this Podman upstream has old or unverified volume-filter semantics; different keys may combine disjunctively, so only `label` filters can be scoped to one owner or visibility policy (unsupported: " + strings.Join(unsupported, ", ") + ")", true
}
