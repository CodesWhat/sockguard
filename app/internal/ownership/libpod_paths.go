package ownership

import "strings"

// libpod_paths.go is paths.go's counterpart for Podman's native /libpod/
// API family (#148 PR5). Every matcher here is exact-prefix-guarded on
// libpodPrefix so a Docker-compat path can never satisfy a libpod predicate
// and vice versa, mirroring internal/filter/libpod_normalize.go's own
// exact-prefix-guard convention for the same reason (see that file's doc
// comment on isLibpodPath).
const libpodPrefix = "/libpod/"

const (
	libpodContainerCreatePath = libpodPrefix + "containers/create"
	libpodPodCreatePath       = libpodPrefix + "pods/create"
	libpodNetworkCreatePath   = libpodPrefix + "networks/create"
	libpodVolumeCreatePath    = libpodPrefix + "volumes/create"
	libpodSecretCreatePath    = libpodPrefix + "secrets/create"
)

// isLibpodOwnershipPath reports whether normPath falls under the /libpod/
// route family, for the sole purpose of deciding whether a denial reason
// should carry the "libpod " prefix convention (#148 design doc, item 5) —
// matching the human-readable-reason style internal/filter's libpod_*.go
// inspectors already use ("libpod container create denied: ...").
func isLibpodOwnershipPath(normPath string) bool {
	return strings.HasPrefix(normPath, libpodPrefix)
}

// libpodNeedsOwnerFilter mirrors needsOwnerFilter for libpod's list
// endpoints. Podman consistently suffixes every /libpod/ list endpoint with
// "/json" (unlike the Docker-compat API's mixed /networks vs /containers/json
// convention), so every entry here follows that one shape.
func libpodNeedsOwnerFilter(normPath string) bool {
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

// libpodContainerIdentifier matches any /libpod/containers/{id}/... path,
// returning {id}. Mirrors containerIdentifier's "any action on a specific
// container" breadth (start/stop/kill/exec-create/attach/inspect/...), not
// just inspect — a client acting on another owner's container through the
// libpod route family must be denied the same as through the Docker-compat
// one.
func libpodContainerIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"containers/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"containers/"), "/")
	switch identifier {
	case "", "create", "json", "prune":
		return "", false
	default:
		return identifier, true
	}
}

// libpodExecIdentifier matches /libpod/exec/{id}/..., the libpod
// counterpart of execIdentifier. Podman's exec-session store is shared
// between the Docker-compat and libpod route families (both are a view onto
// the same libpod runtime state), so the existing Docker-compat
// GET /exec/{id}/json upstream inspector correctly resolves a libpod-created
// exec session's owning container too — no separate libpod-path exec
// inspector is needed here.
func libpodExecIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"exec/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"exec/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

// libpodPodIdentifier matches /libpod/pods/{id}/..., the libpod-only
// counterpart of containerIdentifier for KindLibpodPod. "stats" is reserved
// alongside "json"/"create"/"prune" because GET /libpod/pods/stats is a
// collection-level endpoint (all pods' stats), not a per-pod one.
func libpodPodIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"pods/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"pods/"), "/")
	switch identifier {
	case "", "create", "json", "prune", "stats":
		return "", false
	default:
		return identifier, true
	}
}

// libpodNetworkIdentifier matches /libpod/networks/{id}/..., checked against
// the Docker-compat KindNetwork path (see dockerresource.KindLibpodNetwork's
// doc comment on why ownership's write-side check does not need the
// libpod-native inspect path the way visibility's does).
func libpodNetworkIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"networks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"networks/"), "/")
	switch identifier {
	case "", "create", "prune", "json":
		return "", false
	default:
		return identifier, true
	}
}

// libpodVolumeIdentifier matches /libpod/volumes/{id}/....
func libpodVolumeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"volumes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"volumes/"), "/")
	switch identifier {
	case "", "create", "prune", "json":
		return "", false
	default:
		return identifier, true
	}
}

// libpodSecretIdentifier matches /libpod/secrets/{id}/....
func libpodSecretIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"secrets/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"secrets/"), "/")
	switch identifier {
	case "", "create", "json":
		return "", false
	default:
		return identifier, true
	}
}
