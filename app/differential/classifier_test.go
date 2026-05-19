package differential

import (
	"net/http"
	"path"
	"strings"
	"testing"
)

// routeCategory names a Docker Engine API endpoint.
//
// classifyDockerRoute is a test oracle: it models how a Docker daemon routes a
// request method+path to an endpoint, letting the differential suite assert
// that sockguard evaluated its policy against the same endpoint the daemon
// would actually execute. The oracle is deliberately small — it covers only
// the routes the differential corpus exercises. QA-1f replays the same corpus
// against a real dockerd and validates this oracle; if real daemon routing
// ever diverges from the model, that suite fails first.
type routeCategory string

const (
	// routeUnknown is any method+path that matches no modeled route. On a
	// real daemon this is a 404/405 — harmless, the daemon executes nothing.
	routeUnknown routeCategory = "unknown"

	routePing    routeCategory = "system.ping"
	routeVersion routeCategory = "system.version"
	routeInfo    routeCategory = "system.info"

	routeContainerList       routeCategory = "container.list"
	routeContainerCreate     routeCategory = "container.create"
	routeContainerInspect    routeCategory = "container.inspect"
	routeContainerStart      routeCategory = "container.start"
	routeContainerStop       routeCategory = "container.stop"
	routeContainerKill       routeCategory = "container.kill"
	routeContainerDelete     routeCategory = "container.delete"
	routeContainerExecCreate routeCategory = "container.exec_create"

	routeExecInspect routeCategory = "exec.inspect"
	routeExecStart   routeCategory = "exec.start"

	routeImageList   routeCategory = "image.list"
	routeImageCreate routeCategory = "image.create"

	routeBuild routeCategory = "build"
)

// classifyDockerRoute models a Docker daemon's routing of method+rawPath to an
// endpoint.
//
// Model assumptions, each validated against a real dockerd by QA-1f:
//   - The daemon strips an API-version prefix /v{version}/ where version is
//     [0-9.]+ (see stripDaemonVersionPrefix) — broader than sockguard's own
//     stripVersionPrefix, by design: the oracle must mirror the daemon.
//   - The daemon's router resolves dot-segments and collapses duplicate
//     slashes (path.Clean) before matching. This is the pessimistic choice:
//     it assumes the daemon *will* route a path like //containers//create to
//     container.create, so the differential demands sockguard agree.
//   - Path segments are matched case-sensitively.
func classifyDockerRoute(method, rawPath string) routeCategory {
	p := stripDaemonVersionPrefix(rawPath)
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	p = path.Clean(p)

	segs := splitPathSegments(p)
	m := strings.ToUpper(method)

	switch {
	case len(segs) == 1 && segs[0] == "_ping" && m == http.MethodGet:
		return routePing
	case len(segs) == 1 && segs[0] == "version" && m == http.MethodGet:
		return routeVersion
	case len(segs) == 1 && segs[0] == "info" && m == http.MethodGet:
		return routeInfo
	case len(segs) == 1 && segs[0] == "build" && m == http.MethodPost:
		return routeBuild

	case len(segs) == 2 && segs[0] == "containers" && segs[1] == "json" && m == http.MethodGet:
		return routeContainerList
	case len(segs) == 2 && segs[0] == "containers" && segs[1] == "create" && m == http.MethodPost:
		return routeContainerCreate
	case len(segs) == 2 && segs[0] == "containers" && m == http.MethodDelete:
		return routeContainerDelete

	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "json" && m == http.MethodGet:
		return routeContainerInspect
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "start" && m == http.MethodPost:
		return routeContainerStart
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "stop" && m == http.MethodPost:
		return routeContainerStop
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "kill" && m == http.MethodPost:
		return routeContainerKill
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "exec" && m == http.MethodPost:
		return routeContainerExecCreate

	case len(segs) == 2 && segs[0] == "images" && segs[1] == "json" && m == http.MethodGet:
		return routeImageList
	case len(segs) == 2 && segs[0] == "images" && segs[1] == "create" && m == http.MethodPost:
		return routeImageCreate

	case len(segs) == 3 && segs[0] == "exec" && segs[2] == "json" && m == http.MethodGet:
		return routeExecInspect
	case len(segs) == 3 && segs[0] == "exec" && segs[2] == "start" && m == http.MethodPost:
		return routeExecStart

	default:
		return routeUnknown
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

func TestClassifyDockerRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		want   routeCategory
	}{
		{"container list", http.MethodGet, "/containers/json", routeContainerList},
		{"container create", http.MethodPost, "/containers/create", routeContainerCreate},
		{"container create versioned", http.MethodPost, "/v1.45/containers/create", routeContainerCreate},
		{"container create multi-dot version", http.MethodPost, "/v1.2.3/containers/create", routeContainerCreate},
		{"container inspect", http.MethodGet, "/containers/abc123/json", routeContainerInspect},
		{"container start", http.MethodPost, "/containers/abc123/start", routeContainerStart},
		{"container delete", http.MethodDelete, "/containers/abc123", routeContainerDelete},
		{"exec start", http.MethodPost, "/exec/deadbeef/start", routeExecStart},
		{"image create", http.MethodPost, "/images/create", routeImageCreate},
		{"build", http.MethodPost, "/build", routeBuild},
		{"ping", http.MethodGet, "/_ping", routePing},

		// Path cleaning: the oracle resolves dot-segments and doubled slashes.
		{"doubled slash collapses to create", http.MethodPost, "//containers//create", routeContainerCreate},
		{"dot-dot resolves into create", http.MethodPost, "/containers/json/../create", routeContainerCreate},
		{"trailing slash trimmed", http.MethodGet, "/containers/json/", routeContainerList},

		// Method mismatch and unknown shapes route nowhere.
		{"create with GET is not a route", http.MethodGet, "/containers/create", routeUnknown},
		{"unknown path", http.MethodGet, "/totally/unknown", routeUnknown},
		{"version prefix without trailing slash is literal", http.MethodPost, "/v1.45", routeUnknown},
		{"non-numeric version prefix not stripped", http.MethodPost, "/vX/containers/create", routeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyDockerRoute(tt.method, tt.path); got != tt.want {
				t.Fatalf("classifyDockerRoute(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
