package apipath

import (
	"net/http"
	"strings"
)

// dockerContainerPrefix is the Docker-compat container route family. Podman's
// native /libpod/containers routes are a separate grammar with a
// single-segment {name}, and are not parsed here.
const dockerContainerPrefix = "/containers/"

// dockerContainerActions lists, per method, the action suffixes dockerd
// registers after a container name. It mirrors moby's container router
// (api/server/router/container/container.go) and the checkpoint router.
//
// dockerd registers every one of these as /containers/{name:.*}/<action>, so a
// name may itself contain slashes: legacy links register "/A/x" as an alias of
// the linked container, and POST /containers/A/x/stop acts on it. gorilla/mux
// compiles {name:.*} greedily, so the name is everything before the last
// action suffix, not the first path segment.
var dockerContainerActions = map[string][]string{
	http.MethodGet:  {"json", "top", "logs", "stats", "changes", "export", "archive", "checkpoints", "attach/ws"},
	http.MethodHead: {"archive"},
	http.MethodPost: {"wait", "stop", "kill", "pause", "unpause", "restart", "start", "rename", "resize", "attach", "update", "exec", "copy", "checkpoints"},
	http.MethodPut:  {"archive"},
}

// DockerContainerRoute parses a normalized Docker-compat container path into
// the full container name and the registered action suffix that follows it
// (empty when the whole remainder is the name).
//
// ok is false for anything that is not a per-container route: other
// families, the bare "/containers/" prefix, and the collection routes
// GET /containers/json, POST /containers/create and POST /containers/prune.
//
// DELETE takes the complete remainder as the name, the way dockerd's
// DELETE /containers/{name:.*} does. A path whose last segment is not a
// registered action for the method also takes the whole remainder as the
// name, so a slash-bearing name is looked up as itself and fails closed
// instead of being cut to its first segment.
func DockerContainerRoute(method, normPath string) (name, action string, ok bool) {
	rest, found := strings.CutPrefix(normPath, dockerContainerPrefix)
	if !found || rest == "" {
		return "", "", false
	}
	if !strings.Contains(rest, "/") {
		switch {
		case method == http.MethodPost && (rest == "create" || rest == "prune"):
			return "", "", false
		case (method == http.MethodGet || method == http.MethodHead) && rest == "json":
			return "", "", false
		}
		return rest, "", true
	}
	if method == http.MethodDelete {
		return rest, "", true
	}
	actions, known := dockerContainerActions[method]
	if !known {
		actions = dockerContainerActions[http.MethodGet]
	}
	for _, candidate := range actions {
		if name, found := strings.CutSuffix(rest, "/"+candidate); found && name != "" {
			return name, candidate, true
		}
	}
	return rest, "", true
}

// DockerContainerAction reports the container name when normPath ends in
// "/<action>" after the "/containers/" prefix, whatever the method. The name
// may be empty: the hijack and inspection matchers deliberately match the
// shape rather than a valid name, so narrowing it would move a path out of
// inspection. It is the
// method-less form of DockerContainerRoute for the matchers that classify a
// path before the method is known to apply: the name is everything before the
// suffix, so a slash-bearing name matches the same as a single-segment one.
func DockerContainerAction(normPath, action string) (name string, ok bool) {
	rest, found := strings.CutPrefix(normPath, dockerContainerPrefix)
	if !found {
		return "", false
	}
	name, found = strings.CutSuffix(rest, "/"+action)
	if !found {
		return "", false
	}
	return name, true
}
