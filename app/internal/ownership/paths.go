package ownership

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
)

func needsOwnerFilter(method, normPath string) bool {
	if method == http.MethodPost {
		switch normPath {
		case "/containers/prune", "/images/prune", "/networks/prune", "/volumes/prune":
			return true
		default:
			return false
		}
	}
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	switch normPath {
	case "/events", "/containers/json", "/images/json", "/networks", "/volumes", "/services", "/tasks", "/secrets", "/configs", "/nodes":
		return true
	default:
		return false
	}
}

// resourceIdentifier extracts the identifier segment right after prefix from
// normPath (e.g. "/networks/{id}" -> "{id}"), the pattern shared by every
// per-resource identifier extractor in this file. A bare collection route
// (no identifier), or a single-segment path whose identifier is actually a
// collection-level action name for the given method, is not a resource and
// returns ("", false) — postExcluded lists the action names excluded on
// POST (e.g. "create", "prune"), getExcluded lists the ones excluded on
// GET/HEAD (e.g. "json"). Either may be nil when a family has no such
// collision (exec, tasks, and nodes never register such actions).
func resourceIdentifier(method, normPath, prefix string, postExcluded, getExcluded []string) (string, bool) {
	if !strings.HasPrefix(normPath, prefix) {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, prefix), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail {
		if method == http.MethodPost && identifierExcluded(postExcluded, identifier) {
			return "", false
		}
		if (method == http.MethodGet || method == http.MethodHead) && identifierExcluded(getExcluded, identifier) {
			return "", false
		}
	}
	return identifier, true
}

func identifierExcluded(excluded []string, identifier string) bool {
	for _, candidate := range excluded {
		if candidate == identifier {
			return true
		}
	}
	return false
}

var (
	createPruneExcluded = []string{"create", "prune"}
	createExcluded      = []string{"create"}
)

// containerIdentifier extracts the container name from a Docker-compat path.
// dockerd registers every container route as /containers/{name:.*}/<action>,
// so the name can hold slashes (a legacy link registers "/A/x" as an alias of
// the linked container). The whole name before the registered action suffix is
// authorized, never just the first segment, or a request for "A/x" would be
// checked as "A". Podman's own grammar stays single-segment, see
// libpodContainerIdentifier.
func containerIdentifier(method, normPath string) (string, bool) {
	name, _, ok := apipath.DockerContainerRoute(method, normPath)
	return name, ok
}

func execIdentifier(normPath string) (string, bool) {
	return resourceIdentifier("", normPath, "/exec/", nil, nil)
}

// networkIdentifier extracts the network name from a Docker-compat path.
// dockerd registers the network routes as /networks/{id:.*}, with connect and
// disconnect as /networks/{id:.*}/{action}, so a network named "a/b" is
// addressable and the whole name is authorized, never just its first segment.
// DELETE and GET take the complete remainder; connect and disconnect strip
// only the final action. Podman's native /libpod/networks routes keep their
// single-segment grammar and are handled by the libpod extractors.
func networkIdentifier(method, normPath string) (string, bool) {
	rest, ok := strings.CutPrefix(normPath, "/networks/")
	if !ok || rest == "" {
		return "", false
	}
	if !strings.Contains(rest, "/") {
		return resourceIdentifier(method, normPath, "/networks/", createPruneExcluded, nil)
	}
	if method == http.MethodPost {
		if name, ok := dockerNetworkActionName(rest); ok {
			return name, true
		}
	}
	return rest, true
}

// dockerNetworkActionName returns the network name in "{name}/connect" or
// "{name}/disconnect", where name may itself contain slashes.
func dockerNetworkActionName(rest string) (string, bool) {
	for _, action := range []string{"/connect", "/disconnect"} {
		if name, ok := strings.CutSuffix(rest, action); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

func isNetworkMembershipChangePath(normPath string) bool {
	if rest, ok := strings.CutPrefix(normPath, "/networks/"); ok {
		_, ok := dockerNetworkActionName(rest)
		return ok
	}
	if rest, ok := strings.CutPrefix(normPath, libpodPrefix+"networks/"); ok {
		identifier, action, ok := strings.Cut(rest, "/")
		return ok && identifier != "" && (action == "connect" || action == "disconnect")
	}
	return false
}

// isCommitPath matches both spellings of the container-commit endpoint.
//
// It lives here rather than in libpod_paths.go because the endpoint is not a
// resource route in either family: Docker registers POST /commit (moby's
// container router, versioned and unversioned), Podman registers the same
// compat path onto compat.CommitContainer and its own POST /libpod/commit
// onto libpod.CommitContainer, and none of the three names a container in the
// path. The container is a query parameter, so commit is classified from the
// query rather than from a path identifier — see commitOwnershipReferences.
func isCommitPath(normPath string) bool {
	return normPath == "/commit" || normPath == libpodPrefix+"commit"
}

func volumeIdentifier(method, normPath string) (string, bool) {
	return resourceIdentifier(method, normPath, "/volumes/", createPruneExcluded, nil)
}

func imageIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/images/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/images/")
	if rest == "" {
		return "", false
	}
	if !strings.Contains(rest, "/") {
		if (method == http.MethodGet || method == http.MethodHead) && (rest == "json" || rest == "search" || rest == "get") {
			return "", false
		}
		if method == http.MethodPost && (rest == "create" || rest == "load" || rest == "prune") {
			return "", false
		}
	}

	// "/get" exports a single image as a tarball (GET /images/{name}/get) — a
	// data-exfiltration path that must be owner-checked against {name}. Without
	// it here, imageIdentifier would return "{name}/get", the ownership inspect
	// would 404, and the fail-closed lookup would deny even an owned image instead
	// of authorizing the actual target.
	//
	// "/attestations" (GET /images/{name}/attestations, Engine API 1.55+) lists
	// an image's signer/predicate metadata and must be owner-checked against
	// {name} for the same reason: without it, imageIdentifier would return
	// "{name}/attestations", the ownership inspect would 404, and the request
	// would be denied even when the caller owns the actual image.
	for _, suffix := range []string{"/json", "/history", "/push", "/tag", "/get", "/attestations"} {
		if strings.HasSuffix(rest, suffix) {
			return strings.TrimSuffix(rest, suffix), true
		}
	}
	return rest, true
}

func serviceIdentifier(method, normPath string) (string, bool) {
	return resourceIdentifier(method, normPath, "/services/", createExcluded, nil)
}

func isServiceUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/services/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/services/"), "/")
	return ok && identifier != "" && tail == "update"
}

func taskIdentifier(normPath string) (string, bool) {
	return resourceIdentifier("", normPath, "/tasks/", nil, nil)
}

func secretIdentifier(method, normPath string) (string, bool) {
	return resourceIdentifier(method, normPath, "/secrets/", createExcluded, nil)
}

func configIdentifier(method, normPath string) (string, bool) {
	return resourceIdentifier(method, normPath, "/configs/", createExcluded, nil)
}

func nodeIdentifier(normPath string) (string, bool) {
	return resourceIdentifier("", normPath, "/nodes/", nil, nil)
}

func isNodeUpdatePath(normPath string) bool {
	return apipath.IsNodeUpdatePath(normPath)
}

// isSwarmPath matches the Swarm-state operations that act on the swarm itself:
// inspect, the unlock key read and leave. Leave with force=1 takes a manager
// out of the swarm, so none of them can be left to a path rule alone.
func isSwarmPath(normPath string) bool {
	switch normPath {
	case "/swarm", "/swarm/unlockkey", "/swarm/leave":
		return true
	default:
		return false
	}
}

func isSwarmUpdatePath(normPath string) bool {
	return normPath == "/swarm/update"
}

func ownerFilterKey(normPath string) string {
	if normPath == "/nodes" {
		return "node.label"
	}
	return "label"
}

// enforcedSelectorsOnlyPath reports whether normPath is a path where only the
// enforced label selectors (owner plus injected) may be sent upstream.
//
// Event streams, compat and libpod: Podman ORs repeated `label` values on
// event filters, so a kept client selector would widen the stream.
//
// /libpod/images/prune: Podman's handler flattens the filters with v[0]
// (pkg/api/handlers/libpod/images.go), so only the first `label` value is
// honored. A kept client selector would be silently ignored, so none is sent.
func enforcedSelectorsOnlyPath(normPath string) bool {
	switch normPath {
	case "/events", libpodPrefix + "events", libpodPrefix + "images/prune":
		return true
	default:
		return false
	}
}
