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
//
// GET /libpod/events is deliberately absent even though it is the libpod
// spelling of the Docker-compat /events entry in needsVisibilityLabelFilter:
// Podman evaluates several values under one event filter key disjunctively,
// so the append-style injection addVisibilityLabelFilters performs would
// widen the response rather than narrow it. It is handled by
// libpod_events.go instead — see libpodEventsDenyReason.
//
// GET /libpod/secrets/json is absent for a harder reason: Podman's secret
// filter grammar (utils.IfPassesSecretsFilter at v5.8.1) accepts only "name"
// and "id" and errors on any other key, which compat.ListSecrets turns into a
// 500, so injecting a `label` selector here broke the endpoint rather than
// scoping it. It is refused as filter.LibpodSecretListPath instead; see
// filter.LibpodSecretListDenyReason.
func needsLibpodVisibilityLabelFilter(normPath string) bool {
	switch normPath {
	case libpodPrefix + "containers/json",
		libpodPrefix + "images/json",
		libpodPrefix + "pods/json",
		libpodPrefix + "networks/json",
		libpodPrefix + "volumes/json":
		return true
	default:
		return false
	}
}

// suffixedIdentifierAny is suffixedIdentifier over several suffixes, returning
// the first that matches. It exists rather than a readSubresourceIdentifier
// call because Podman routes pods, networks, volumes and secrets with a
// gorilla/mux `{name}` variable, which never spans a "/" — so splitting on the
// FIRST "/" is the faithful classification for those four kinds, and
// readSubresourceIdentifier's trim-from-the-end behavior (which exists for
// image references, routed `{name:.*}`) would accept identifiers those routes
// cannot produce.
func suffixedIdentifierAny(normPath, prefix string, suffixes ...string) (string, bool) {
	for _, suffix := range suffixes {
		if identifier, ok := suffixedIdentifier(normPath, prefix, suffix); ok {
			return identifier, true
		}
	}
	return "", false
}

// libpodContainerReadIdentifier matches every GET/HEAD libpod container read
// endpoint that discloses container data, the libpod counterpart of
// containerReadIdentifier. The suffix list is Podman's complete GET/HEAD
// per-container route set at v5.8.1 (pkg/api/server/register_containers.go,
// register_archive.go and register_healthcheck.go), the same way
// containerReadIdentifier's is dockerd's:
//
//	json logs stats top changes export archive exists healthcheck
//
// "archive" is the read half of GET|PUT|HEAD /libpod/containers/{name}/archive
// (the write half never reaches here — the visibility middleware only runs on
// GET/HEAD), and "exists" is GET /libpod/containers/{name}/exists, which
// answers 204/404 and is therefore precisely the existence oracle this
// package's 404-on-hidden behavior exists to deny. libpod has no /attach/ws:
// Podman registers container attach as a POST.
//
// Name/image pattern axes use the same Docker-compatible container inspect
// metadata as the corresponding /containers/{name}/... reads. This matcher
// only classifies the target; requestVisibleWithPolicy applies every configured
// axis before forwarding the native read.
func libpodContainerReadIdentifier(normPath string) (string, bool) {
	return readSubresourceIdentifier(normPath, libpodPrefix+"containers/",
		"json", "logs", "stats", "top", "changes", "export", "archive", "exists", "healthcheck")
}

// libpodImageReadIdentifier matches every GET libpod image read endpoint that
// discloses or exfiltrates image data — inspect (/json), history, layer tree,
// filesystem changes, single-image export (/get), and the /exists existence
// oracle — the libpod counterpart of imageReadIdentifier.
//
// It uses readSubresourceIdentifier rather than suffixedIdentifierAny because
// Podman routes its per-image libpod paths with `{name:.*}`, so an identifier
// here legitimately contains "/" for a namespaced reference such as
// "registry.io/team/app"; trimming the suffix from the END preserves it.
// (/changes is the one route in this list Podman declares `{name}` instead,
// so it cannot carry a namespaced reference — matching one here is a superset
// of what the daemon routes, which costs a hidden-check the daemon would have
// 404'd anyway.)
//
// The identifier is resolved against dockerresource.KindImage, i.e. the
// Docker-compat GET /images/{name}/json inspect, for the same reason libpod
// containers, volumes and secrets are: Podman's compat API is a translation
// layer over the same image store, and unlike libpod network inspect its
// response needs no shape-specific decoding.
//
// GET /libpod/images/{name}/resolve is deliberately absent. It resolves a
// short name against registries.conf and answers for names that identify no
// local image at all, so it discloses nothing about a stored image and has no
// resource for a selector to be matched against.
func libpodImageReadIdentifier(normPath string) (string, bool) {
	return readSubresourceIdentifier(normPath, libpodPrefix+"images/",
		"json", "history", "get", "tree", "changes", "exists")
}

// libpodPodReadIdentifier matches the GET pod reads Podman registers per pod:
// inspect (/json), the /exists existence oracle, and /top, which lists the
// processes running in another owner's pod. Unlike Docker-compat's
// KindNetwork/KindVolume ("/networks/{id}" bare, no suffix), every libpod
// inspect endpoint is uniformly suffixed "/json" — hence suffixedIdentifierAny
// rather than singleSegmentIdentifier here and in the three inspect
// identifiers below. The collection endpoints themselves (GET
// /libpod/pods/json, GET /libpod/pods/stats) never match: their remainder
// after the prefix is a bare word with no "/id/suffix" shape to find.
func libpodPodReadIdentifier(normPath string) (string, bool) {
	return suffixedIdentifierAny(normPath, libpodPrefix+"pods/", "json", "exists", "top")
}

// libpodNetworkInspectIdentifier matches GET /libpod/networks/{id}/json, its
// /exists sibling, and the bare GET /libpod/networks/{id} spelling Podman
// registers on the very same libpod.InspectNetwork handler
// (pkg/api/server/register_networks.go at v5.8.1 wires both). The bare form is
// neither the Docker-compat "/networks/{id}" path networkInspectIdentifier
// covers nor the "/json" form suffixedIdentifier finds, so without it a
// hidden network stayed readable under one of its two libpod spellings.
//
// The list route GET /libpod/networks/json is excluded explicitly, because
// singleSegmentIdentifier — written for Docker-compat, where "json" is only
// ever a write-side collection keyword — would otherwise classify it as a
// network named "json".
func libpodNetworkInspectIdentifier(normPath string) (string, bool) {
	if identifier, ok := suffixedIdentifierAny(normPath, libpodPrefix+"networks/", "json", "exists"); ok {
		return identifier, true
	}
	identifier, ok := singleSegmentIdentifier(normPath, libpodPrefix+"networks/")
	if !ok || identifier == "json" {
		return "", false
	}
	return identifier, true
}

// libpodVolumeInspectIdentifier matches GET /libpod/volumes/{id}/json, its
// /exists sibling, and GET /libpod/volumes/{id}/export, which streams the
// volume's contents as a tar archive and is the volume equivalent of a
// container export.
func libpodVolumeInspectIdentifier(normPath string) (string, bool) {
	return suffixedIdentifierAny(normPath, libpodPrefix+"volumes/", "json", "exists", "export")
}

// libpodExecInspectIdentifier matches GET /libpod/exec/{id}/json, Podman's
// native spelling of the Docker-compat GET /exec/{id}/json that
// execInspectIdentifier covers. Podman registers both on ONE handler
// (pkg/api/server/register_exec.go at v5.8.1 wires /exec/{id}/json at line 179
// and /libpod/exec/{id}/json at line 350, both to compat.ExecInspectHandler),
// so the two return the identical InspectExecSession: ContainerID,
// ProcessConfig and Pid for the container the session belongs to. Forwarding
// the native spelling for a container the policy hides discloses all three,
// which is why requestVisibleWithPolicy routes this matcher into the same
// deps.inspectExec branch rather than letting it fall through to the closing
// "no matcher claimed this path" pass-through.
//
// Only the VersionedPath spelling of the libpod route is registered, so a
// Podman binding issues /v5.8.1/libpod/exec/{id}/json; NormalizePath strips
// the version prefix but not the /libpod segment, so that spelling normalizes
// here. suffixedIdentifier is the faithful shape because Podman routes the
// session with a gorilla/mux {id} variable, which never spans a "/".
//
// Ownership's counterpart is libpodExecIdentifier, which is broader on purpose
// (every /libpod/exec/{id}/... action, not just the inspect) because a write
// to another owner's session has to be denied as well as a read of it.
func libpodExecInspectIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, libpodPrefix+"exec/", "json")
}

// libpodSecretInspectIdentifier matches GET /libpod/secrets/{id}/json and its
// /exists sibling.
func libpodSecretInspectIdentifier(normPath string) (string, bool) {
	return suffixedIdentifierAny(normPath, libpodPrefix+"secrets/", "json", "exists")
}

// isLibpodVisibilityPath reports whether normPath falls under the /libpod/
// route family, for the sole purpose of applying the "libpod " deny-reason
// prefix convention (#148 design doc item 5) to the hidden-resource 404.
func isLibpodVisibilityPath(normPath string) bool {
	return strings.HasPrefix(normPath, libpodPrefix)
}
