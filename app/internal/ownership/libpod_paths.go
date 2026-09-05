package ownership

import (
	"net/http"
	"net/url"
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

// libpodNeedsOwnerFilter mirrors needsOwnerFilter for libpod's list and prune
// endpoints, and takes the method for the same reason its Docker-compat
// counterpart does: the two families are reached by different methods and a
// path alone cannot say which.
//
// The POST half is the prune family. Podman documents a JSON-encoded
// `filters` query parameter taking `label` on all four routes and reads it
// through util.PrepareFilters in each handler at v5.8.1:
// POST /libpod/containers/prune is registered onto compat.PruneContainers —
// literally the same handler as the Docker-compat route (register_containers.go),
// POST /libpod/networks/prune onto libpod.Prune, POST /libpod/volumes/prune
// onto libpod.PruneVolumes, and POST /libpod/images/prune onto
// libpod.PruneImages. Without the injection each one deletes every prunable
// resource on the host, which is the same host-wide write the Docker-compat
// entries in needsOwnerFilter have been scoped against since owner isolation
// shipped.
//
// libpod.PruneImages is the one that constrains how the filter is written: it
// flattens the decoded filter map with `fmt.Sprintf("%s=%s", k, v[0])`, so
// only the FIRST value under `label` reaches libimage. addOwnerLabelFilter
// writes the owner label first and appends proxy-injected visibility
// selectors after it, so the owner selector is the one that survives that
// truncation. Nothing injects visibility selectors into a prune today —
// needsVisibilityLabelFilter covers lists and events only — so the case is
// hypothetical, and the ordering keeps it fail-closed for the owner boundary
// if it stops being.
//
// POST /libpod/pods/prune is deliberately absent: it takes no parameters at
// all, so there is nothing to inject. It is refused instead, through
// filter.LookupLibpodUnscopeableWrite.
//
// Podman consistently suffixes every /libpod/ list endpoint with
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
//
// GET /libpod/secrets/json was in this list until v2.1 and is now refused
// instead. Podman filters that endpoint with utils.IfPassesSecretsFilter
// (pkg/domain/utils/secrets_filters.go at v5.8.1), whose switch accepts only
// "name" and "id" and returns an error on any other key, and
// compat.ListSecrets turns that error into a 500, so the injected owner label
// did not narrow the list, it broke every request. See
// filter.LibpodSecretListDenyReason for why the path is refused rather than
// forwarded unfiltered.
func libpodNeedsOwnerFilter(method, normPath string) bool {
	if method == http.MethodPost {
		switch normPath {
		case libpodPrefix + "containers/prune", libpodPrefix + "images/prune", libpodPrefix + "networks/prune", libpodPrefix + "volumes/prune":
			return true
		default:
			return false
		}
	}
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	switch normPath {
	case libpodPrefix + "events",
		libpodPrefix + "containers/json",
		libpodPrefix + "images/json",
		libpodPrefix + "pods/json",
		libpodPrefix + "networks/json",
		libpodPrefix + "volumes/json":
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
// per-image action suffix for the method that routes it from the END so a
// namespaced reference such as "registry.io/team/app" survives intact —
// Podman routes its per-image
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
// reference, so libpodImageScpSource classifies it before the generic suffix
// handling can mistake a source ending in "/json" or another GET-only action
// for an ordinary per-image route. The only collisions are POST push/tag/
// untag: gorilla/mux resolves those per-image handlers first because Podman
// registers them earlier, so POST /libpod/images/scp/app/push is an image
// named "scp/app" being pushed, not an scp of "app".
//
// Two batch image endpoints are not matched here, because they name their
// images in the query string rather than the path and need a different
// mechanism than a path identifier:
// DELETE /libpod/images/remove?images=…&all= and
// GET /libpod/images/export?references=…. They remain reserved above, while
// image_batch.go parses and owner-checks their query subjects before the
// request is forwarded. The Docker-compat GET /images/get?names=… route uses
// that same batch path but is refused under ownership because one selector can
// export a multi-platform index that the ordinary image inspect cannot fully
// authorize.
func libpodImageIdentifier(method, normPath string) (string, bool) {
	return libpodImageIdentifierForRoute(method, normPath, normPath)
}

// libpodImageIdentifierForRoute classifies the resource from normPath while
// resolving route collisions against routePath. They differ when the client
// percent-encodes a slash: net/http decodes URL.Path, but Podman's gorilla/mux
// router uses URL.EscapedPath and therefore keeps that slash inside {name}.
func libpodImageIdentifierForRoute(method, normPath, routePath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"images/") {
		return "", false
	}
	if identifier, remote, ok := libpodImageScpSource(method, routePath); ok {
		if remote || identifier == "" {
			return "", false
		}
		return identifier, true
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
	var suffixes []string
	switch method {
	case http.MethodGet, http.MethodHead:
		suffixes = []string{"/json", "/history", "/tree", "/exists", "/changes", "/resolve", "/get"}
	case http.MethodPost:
		suffixes = []string{"/push", "/tag", "/untag"}
	}
	for _, suffix := range suffixes {
		if trimmed := strings.TrimSuffix(rest, suffix); trimmed != rest && trimmed != "" {
			return trimmed, true
		}
	}
	return rest, true
}

// libpodImageScpSource reports whether normPath is Podman's native image-SCP
// route and parses the source using ParseImageSCPArg's v5.8.1 semantics.
// `user@localhost::image` names a local image and returns the image portion;
// any other source containing "::" is remote. A remote source names an image
// in another daemon's store, so the local image inspect used by ownership
// cannot classify it. A malformed local-user source returns an empty local
// identifier so the caller can fail closed without issuing an invalid inspect.
// The bare route, /libpod/images/scp/ with no source at all, is an SCP route
// for the same reason: {name:.*} matches the empty string, so mux dispatches it
// to the SCP handler. It reports an empty local identifier rather than "not an
// SCP route", which is what keeps the caller from handing the leftover "scp/"
// to the generic image classifier and inspecting an image name no daemon has.
//
// The push/tag/untag exclusions preserve Podman's route order: those handlers
// are registered before /images/scp/{name:.*}, so a path such as
// /images/scp/app/push pushes the local image named "scp/app" rather than
// invoking image SCP.
//
// routePath is normalized from URL.EscapedPath, matching Podman's
// mux.Router.UseEncodedPath. Once the route is known to be SCP, its variable is
// unescaped exactly once, matching handlers/utils.GetName. This keeps an
// encoded slash inside the source instead of mistaking it for an action-route
// separator.
func libpodImageScpSource(method, routePath string) (identifier string, remote, ok bool) {
	if method != http.MethodPost {
		return "", false, false
	}
	rest, ok := strings.CutPrefix(routePath, libpodPrefix+"images/scp/")
	if !ok {
		return "", false, false
	}
	for _, action := range []string{"push", "tag", "untag"} {
		if rest == action || strings.HasSuffix(rest, "/"+action) {
			return "", false, false
		}
	}
	if decoded, err := url.PathUnescape(rest); err == nil {
		rest = decoded
	}
	if strings.Contains(rest, "@localhost::") {
		return strings.Split(rest, "::")[1], false, true
	}
	if strings.Contains(rest, "::") {
		return "", true, true
	}
	return rest, false, true
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
