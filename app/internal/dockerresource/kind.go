// Package dockerresource defines the canonical set of Docker resource kinds
// that ownership and visibility middlewares use to describe inspectable
// objects. Both packages must agree on the wire-format strings, so the
// enumeration lives here to prevent silent divergence.
package dockerresource

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
)

// InspectPath returns the Docker API path for fetching a single resource of
// the given kind. The result is a server-side path, ready for
// "http://docker" + InspectPath. Returns ("", false) when the kind is not
// individually inspectable.
//
// Ownership and visibility both build the same URLs to fetch labels for a
// resource; centralizing the mapping ensures they cannot drift apart.
func InspectPath(kind Kind, identifier string) (string, bool) {
	escaped := pathEscape(identifier)
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
	}
	return "", false
}
