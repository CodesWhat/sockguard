package ownership

import (
	"net/http"
	"strings"
)

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
// convention), so every list entry here follows that one shape.
//
// /libpod/events is the exception to that shape and belongs here all the
// same, as the libpod spelling of the "/events" entry in needsOwnerFilter.
// Podman registers /events and /libpod/events on ONE handler
// (pkg/api/server/register_events.go at v5.8.1 wires both to
// compat.GetEvents), so both accept the identical JSON-encoded
// map[string][]string `filters` parameter, and both match a `label=` filter
// against the labels Podman stamps onto each container event
// (libpod/events.go sets Details.Attributes = c.Labels(), and events.Event
// embeds Details, so the LABEL filter's e.Attributes is that map). No other
// event type carries a container label: pod, volume, secret and system
// events set no attributes at all, and a network create/remove event sets
// only {"driver": ...}, so every one of them fails an owner-label filter and
// is dropped — the fail-closed direction.
//
// addOwnerLabelFilter's unconditional replacement is what makes this safe on
// the event endpoint specifically. Podman's event filter is disjunctive within
// a key (libpod/events/filters.go: "Filters under the same key are disjunctive
// while each key must match"), so a client-supplied `label` value left beside
// the injected one would OR with it; replacement leaves exactly one value, for
// which disjunctive and conjunctive evaluation are the same thing. Every other
// filter key the endpoint accepts is ANDed, so a client can only narrow the
// stream further.
func libpodNeedsOwnerFilter(normPath string) bool {
	switch normPath {
	case libpodPrefix + "events",
		libpodPrefix + "containers/json",
		libpodPrefix + "images/json",
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
func libpodContainerIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"containers/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"containers/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && ((method == http.MethodGet || method == http.MethodHead) && (identifier == "json" || identifier == "showmounted" || identifier == "stats") || method == http.MethodPost && (identifier == "create" || identifier == "prune")) {
		return "", false
	}
	return identifier, true
}

// libpodImageIdentifier matches any /libpod/images/{name}/... path plus the
// bare DELETE /libpod/images/{name}, returning {name}. It is imageIdentifier's
// libpod counterpart and follows its shape exactly: reserve the collection
// keywords for the method that actually routes them, then trim a known
// per-image action suffix from the END so a namespaced reference such as
// "registry.io/team/app" survives intact — Podman routes its per-image
// libpod paths with `{name:.*}`, so an identifier here legitimately contains
// "/". (The one exception is /changes, routed `{name}`, which cannot span a
// "/"; trimming it here is a superset of what the daemon will route, which
// costs an inspect the daemon would have 404'd anyway.)
//
// The reserved words are Podman's libpod image collection routes at v5.8.1
// (pkg/api/server/register_images.go): GET json/search/export, POST
// load/import/pull/prune, DELETE remove. The trimmed suffixes are its
// per-image ones: json, history, tree, exists, changes, resolve, get, push,
// tag, untag.
//
// POST /libpod/images/scp/{name:.*} copies an image to another host, which is
// the same exfiltration shape as a push and has to be owner-checked against
// the same {name}. "scp" is a route segment rather than part of the
// reference, so it is stripped — but only after the suffix trimming above,
// because gorilla/mux resolves the per-image action routes first and Podman
// registers them earlier: POST /libpod/images/scp/app/push is an image named
// "scp/app" being pushed, not an scp of "app".
//
// Two batch image endpoints are not matched here, because they name their
// images in the query string rather than the path and need a different
// mechanism than a path identifier:
// DELETE /libpod/images/remove?images=…&all= and
// GET /libpod/images/export?references=…. They remain reserved above, while
// image_batch.go parses and owner-checks their query subjects before the
// request is forwarded. The Docker-compat GET /images/get?names=… route uses
// that same batch path.
func libpodImageIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"images/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, libpodPrefix+"images/")
	if rest == "" {
		return "", false
	}
	if !strings.Contains(rest, "/") {
		switch {
		case (method == http.MethodGet || method == http.MethodHead) && (rest == "json" || rest == "search" || rest == "export"):
			return "", false
		case method == http.MethodPost && (rest == "load" || rest == "import" || rest == "pull" || rest == "prune"):
			return "", false
		case method == http.MethodDelete && rest == "remove":
			return "", false
		}
	}
	for _, suffix := range []string{"/json", "/history", "/tree", "/exists", "/changes", "/resolve", "/get", "/push", "/tag", "/untag"} {
		if trimmed := strings.TrimSuffix(rest, suffix); trimmed != rest && trimmed != "" {
			return trimmed, true
		}
	}
	if method == http.MethodPost {
		if reference, ok := strings.CutPrefix(rest, "scp/"); ok && reference != "" {
			return reference, true
		}
	}
	return rest, true
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
func libpodPodIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"pods/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"pods/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && ((method == http.MethodGet || method == http.MethodHead) && (identifier == "json" || identifier == "stats") || method == http.MethodPost && (identifier == "create" || identifier == "prune")) {
		return "", false
	}
	return identifier, true
}

// libpodNetworkIdentifier matches /libpod/networks/{id}/..., checked against
// the Docker-compat KindNetwork path (see dockerresource.KindLibpodNetwork's
// doc comment on why ownership's write-side check does not need the
// libpod-native inspect path the way visibility's does).
func libpodNetworkIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"networks/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"networks/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && ((method == http.MethodGet || method == http.MethodHead) && identifier == "json" || method == http.MethodPost && (identifier == "create" || identifier == "prune")) {
		return "", false
	}
	return identifier, true
}

// libpodVolumeIdentifier matches /libpod/volumes/{id}/....
func libpodVolumeIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"volumes/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"volumes/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && ((method == http.MethodGet || method == http.MethodHead) && identifier == "json" || method == http.MethodPost && (identifier == "create" || identifier == "prune")) {
		return "", false
	}
	return identifier, true
}

// libpodSecretIdentifier matches /libpod/secrets/{id}/....
func libpodSecretIdentifier(method, normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"secrets/") {
		return "", false
	}
	identifier, _, hasTail := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"secrets/"), "/")
	if identifier == "" {
		return "", false
	}
	if !hasTail && ((method == http.MethodGet || method == http.MethodHead) && identifier == "json" || method == http.MethodPost && identifier == "create") {
		return "", false
	}
	return identifier, true
}
