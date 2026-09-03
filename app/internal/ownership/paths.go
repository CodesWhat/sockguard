package ownership

import (
	"net/http"
	"strings"
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

func containerIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/containers/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, "/containers/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && ((method == http.MethodGet || method == http.MethodHead) && identifier == "json" || method == http.MethodPost && (identifier == "create" || identifier == "prune")) {
		return "", false
	}
	return identifier, true
}

func execIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/exec/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/exec/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func networkIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/networks/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, "/networks/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && method == http.MethodPost && (identifier == "create" || identifier == "prune") {
		return "", false
	}
	return identifier, true
}

func isNetworkMembershipChangePath(normPath string) bool {
	for _, prefix := range []string{"/networks/", libpodPrefix + "networks/"} {
		if !strings.HasPrefix(normPath, prefix) {
			continue
		}
		identifier, action, ok := strings.Cut(strings.TrimPrefix(normPath, prefix), "/")
		return ok && identifier != "" && (action == "connect" || action == "disconnect")
	}
	return false
}

func volumeIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/volumes/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, "/volumes/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && method == http.MethodPost && (identifier == "create" || identifier == "prune") {
		return "", false
	}
	return identifier, true
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
	// would 404, and the request would pass through unfiltered, letting a client
	// export another owner's image.
	//
	// "/attestations" (GET /images/{name}/attestations, Engine API 1.53+) lists
	// an image's signer/predicate metadata and must be owner-checked against
	// {name} for the same reason: without it, imageIdentifier would return
	// "{name}/attestations", the ownership inspect would 404, and the request
	// would pass through unfiltered.
	for _, suffix := range []string{"/json", "/history", "/push", "/tag", "/get", "/attestations"} {
		if strings.HasSuffix(rest, suffix) {
			return strings.TrimSuffix(rest, suffix), true
		}
	}
	return rest, true
}

func serviceIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/services/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, "/services/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && method == http.MethodPost && identifier == "create" {
		return "", false
	}
	return identifier, true
}

func isServiceUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/services/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/services/"), "/")
	return ok && identifier != "" && tail == "update"
}

func taskIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/tasks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/tasks/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func secretIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/secrets/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, "/secrets/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && method == http.MethodPost && identifier == "create" {
		return "", false
	}
	return identifier, true
}

func configIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/configs/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, "/configs/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && method == http.MethodPost && identifier == "create" {
		return "", false
	}
	return identifier, true
}

func nodeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/nodes/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func isNodeUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/nodes/"), "/")
	return ok && identifier != "" && tail == "update"
}

func isSwarmPath(normPath string) bool {
	return normPath == "/swarm"
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
