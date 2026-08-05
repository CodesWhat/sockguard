// Package dockerresource defines the canonical set of Docker resource kinds
// that ownership and visibility middlewares use to describe inspectable
// objects. Both packages must agree on the wire-format strings, so the
// enumeration lives here to prevent silent divergence.
package dockerresource

import "net/url"

// Kind names a category of Docker resource (container, image, network, etc.)
// in the same form the Docker API uses in URL paths.
type Kind string

const (
	KindContainer Kind = "containers"
	KindImage     Kind = "images"
	KindNetwork   Kind = "networks"
	KindVolume    Kind = "volumes"
	KindService   Kind = "services"
	KindTask      Kind = "tasks"
	KindSecret    Kind = "secrets"
	KindConfig    Kind = "configs"
	KindNode      Kind = "nodes"
	KindSwarm     Kind = "swarm"

	// KindLibpodPod identifies Podman's native pod resource (#148). Pods have
	// no Docker-compat equivalent — there is no "/pods/{id}" endpoint on the
	// Docker Engine API a pod is also reachable through — so, unlike every
	// other kind above, a pod can only ever be inspected via the /libpod/
	// route family. See LibpodInspectPath.
	KindLibpodPod Kind = "libpod-pods"
	// KindLibpodNetwork identifies a libpod-native network *inspect request*
	// specifically — i.e. the inbound client request itself is under
	// /libpod/networks/, not "a network that happens to have been created
	// via the libpod API" (any network, regardless of which API created it,
	// is also reachable through the Docker-compat KindNetwork path, and
	// ownership's write-side checks use that path uniformly). It exists as
	// its own Kind because GET /libpod/networks/{id}/json has two wire-shape
	// differences from the Docker-compat GET /networks/{id} DecodeLabels
	// already reads for KindNetwork: a lowercase top-level "labels" key, and
	// — per #148 design doc C6 — a single-element ARRAY-wrapped response on
	// some Podman versions/endpoints. See DecodeLibpodLabels.
	KindLibpodNetwork Kind = "libpod-networks"
)

// InspectPath returns the Docker API path for fetching a single resource of
// the given kind. The result is a server-side path, ready for
// "http://docker" + InspectPath. Returns ("", false) when the kind is not
// individually inspectable.
//
// Ownership and visibility both build the same URLs to fetch labels for a
// resource; centralizing the mapping ensures they cannot drift apart.
func InspectPath(kind Kind, identifier string) (string, bool) {
	escaped := url.PathEscape(identifier)
	switch kind {
	case KindContainer:
		return "/containers/" + escaped + "/json", true
	case KindImage:
		return "/images/" + escaped + "/json", true
	case KindNetwork:
		return "/networks/" + escaped, true
	case KindVolume:
		return "/volumes/" + escaped, true
	case KindService:
		return "/services/" + escaped, true
	case KindTask:
		return "/tasks/" + escaped, true
	case KindSecret:
		return "/secrets/" + escaped, true
	case KindConfig:
		return "/configs/" + escaped, true
	case KindNode:
		return "/nodes/" + escaped, true
	case KindSwarm:
		return "/swarm", true
	case KindLibpodPod, KindLibpodNetwork:
		return LibpodInspectPath(kind, identifier)
	}
	return "", false
}

// LibpodInspectPath returns the libpod-native inspect path for kind — always
// shaped /libpod/<resource>/<id>/json, unlike the Docker-compat paths
// InspectPath returns for kinds such as KindNetwork/KindVolume (bare
// /networks/{id}, no /json suffix). Centralizing this the same way
// InspectPath is centralized keeps ownership and visibility from drifting
// apart on the libpod route shape, per #148 design doc C6. Returns
// ("", false) for any kind with no libpod-native inspect path of its own
// (e.g. KindVolume/KindSecret/KindContainer reuse their Docker-compat path
// via InspectPath instead, since Podman's compat API is a translation layer
// over the same underlying resource store for those kinds).
func LibpodInspectPath(kind Kind, identifier string) (string, bool) {
	escaped := url.PathEscape(identifier)
	switch kind {
	case KindLibpodPod:
		return "/libpod/pods/" + escaped + "/json", true
	case KindLibpodNetwork:
		return "/libpod/networks/" + escaped + "/json", true
	}
	return "", false
}
