package differential

import (
	"net/http"
	"path"
	"strings"
)

// RouteCategory names a Docker Engine API endpoint.
//
// ClassifyDockerRoute is a test oracle: it models how a Docker daemon routes a
// request method+path to an endpoint, letting the differential suite assert
// that sockguard evaluated its policy against the same endpoint the daemon
// would actually execute. The oracle is deliberately small — it covers only
// the routes the differential corpus exercises. The build-tagged real-dockerd
// tier in app/integration/ replays the same corpus against a live daemon and
// validates this oracle; if real daemon routing ever diverges from the model,
// that tier fails first.
type RouteCategory string

const (
	// RouteUnknown is any method+path that matches no modeled route. On a
	// real daemon this is a 404/405 — harmless, the daemon executes nothing.
	RouteUnknown RouteCategory = "unknown"

	RoutePing    RouteCategory = "system.ping"
	RouteVersion RouteCategory = "system.version"
	RouteInfo    RouteCategory = "system.info"

	RouteContainerList       RouteCategory = "container.list"
	RouteContainerCreate     RouteCategory = "container.create"
	RouteContainerInspect    RouteCategory = "container.inspect"
	RouteContainerStart      RouteCategory = "container.start"
	RouteContainerStop       RouteCategory = "container.stop"
	RouteContainerKill       RouteCategory = "container.kill"
	RouteContainerDelete     RouteCategory = "container.delete"
	RouteContainerExecCreate RouteCategory = "container.exec_create"

	RouteExecInspect RouteCategory = "exec.inspect"
	RouteExecStart   RouteCategory = "exec.start"

	RouteImageList   RouteCategory = "image.list"
	RouteImageCreate RouteCategory = "image.create"

	RouteBuild RouteCategory = "build"
)

// ClassifyDockerRoute models a Docker daemon's routing of method+rawPath to an
// endpoint.
//
// Model assumptions, each validated against a real dockerd by the integration
// tier:
//   - The daemon strips an API-version prefix /v{version}/ where version is
//     [0-9.]+ (see stripDaemonVersionPrefix) — broader than sockguard's own
//     stripVersionPrefix, by design: the oracle must mirror the daemon.
//   - The daemon's router resolves dot-segments and collapses duplicate
//     slashes (path.Clean) before matching. This is the pessimistic choice:
//     it assumes the daemon *will* route a path like //containers//create to
//     container.create, so the differential demands sockguard agree.
//   - Path segments are matched case-sensitively.
func ClassifyDockerRoute(method, rawPath string) RouteCategory {
	p := stripDaemonVersionPrefix(rawPath)
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	p = path.Clean(p)

	segs := splitPathSegments(p)
	m := strings.ToUpper(method)

	switch {
	case len(segs) == 1 && segs[0] == "_ping" && m == http.MethodGet:
		return RoutePing
	case len(segs) == 1 && segs[0] == "version" && m == http.MethodGet:
		return RouteVersion
	case len(segs) == 1 && segs[0] == "info" && m == http.MethodGet:
		return RouteInfo
	case len(segs) == 1 && segs[0] == "build" && m == http.MethodPost:
		return RouteBuild

	case len(segs) == 2 && segs[0] == "containers" && segs[1] == "json" && m == http.MethodGet:
		return RouteContainerList
	case len(segs) == 2 && segs[0] == "containers" && segs[1] == "create" && m == http.MethodPost:
		return RouteContainerCreate
	case len(segs) == 2 && segs[0] == "containers" && m == http.MethodDelete:
		return RouteContainerDelete

	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "json" && m == http.MethodGet:
		return RouteContainerInspect
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "start" && m == http.MethodPost:
		return RouteContainerStart
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "stop" && m == http.MethodPost:
		return RouteContainerStop
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "kill" && m == http.MethodPost:
		return RouteContainerKill
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "exec" && m == http.MethodPost:
		return RouteContainerExecCreate

	case len(segs) == 2 && segs[0] == "images" && segs[1] == "json" && m == http.MethodGet:
		return RouteImageList
	case len(segs) == 2 && segs[0] == "images" && segs[1] == "create" && m == http.MethodPost:
		return RouteImageCreate

	case len(segs) == 3 && segs[0] == "exec" && segs[2] == "json" && m == http.MethodGet:
		return RouteExecInspect
	case len(segs) == 3 && segs[0] == "exec" && segs[2] == "start" && m == http.MethodPost:
		return RouteExecStart

	default:
		return RouteUnknown
	}
}

// stripDaemonVersionPrefix models the daemon's API-version prefix handling:
// dockerd routes /v{version}/... where version matches [0-9.]+. This is
// intentionally broader than sockguard's stripVersionPrefix (which accepts
// only vN / vN.N) — the oracle mirrors the daemon, not sockguard. The prefix
// must be terminated by a slash, so /v1.45 (no trailing slash) is not a
// version prefix.
func stripDaemonVersionPrefix(p string) string {
	if !strings.HasPrefix(p, "/v") {
		return p
	}
	rest := p[2:]
	end := strings.IndexByte(rest, '/')
	if end <= 0 {
		return p
	}
	version := rest[:end]
	for _, c := range version {
		if (c < '0' || c > '9') && c != '.' {
			return p
		}
	}
	return rest[end:]
}

// splitPathSegments returns the non-empty slash-separated segments of p.
func splitPathSegments(p string) []string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
