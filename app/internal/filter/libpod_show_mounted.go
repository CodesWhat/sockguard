package filter

// LibpodShowMountedPath is the normalized path of Podman's native
// GET /libpod/containers/showmounted endpoint.
//
// It has no Docker-compat counterpart at all — dockerd serves nothing at
// /containers/showmounted — so unlike /libpod/system/df there is no compat
// spelling of it that gets filtered normally instead. Only the versioned
// route is registered (pkg/api/server/register_containers.go at v5.8.1 wires
// VersionedPath("/libpod/containers/showmounted") to
// libpod.ShowMountedContainers), so a Podman binding issues
// /v5.8.1/libpod/containers/showmounted; NormalizePath strips the version
// prefix but not the /libpod segment, so that spelling normalizes here.
const LibpodShowMountedPath = "/libpod/containers/showmounted"

// LibpodShowMountedDenyReason is the operator-facing reason the ownership and
// visibility middlewares report when they refuse
// GET /libpod/containers/showmounted. Both share this string so the two
// layers cannot drift into explaining the same refusal differently, the same
// way they share responsefilter.LibpodSystemDataUsageDenyReason.
//
// The endpoint is refused for the same reason /libpod/system/df is: the body
// cannot be classified per caller, not merely that filtering it was
// unimplemented. libpod.ShowMountedContainers at v5.8.1 walks
// runtime.GetAllContainers() and answers with a bare map[string]string of
// container ID to host mount point — no labels, no owner field, and no
// per-item envelope a selector could read. It accepts no query parameters at
// all, so the label-filter injection that scopes /libpod/containers/json has
// nothing to attach to either.
//
// Two disclosures ride in that one body, and dropping either alone leaves the
// other. The values are absolute paths on the DAEMON HOST's filesystem (the
// container's storage mount point), which is the same class of detail
// redact_mount_paths exists to strip from an inspect response. The keys are
// the full container ID set of every mounted container on the host,
// regardless of owner, which is the enumeration owner isolation exists to
// deny. Redacting the values would still hand over the enumeration, and there
// is no field left to decide an entry by.
//
// Emptying the map was rejected for the same reason an emptied
// /libpod/system/df report was: "no containers are mounted" is a legitimate
// answer from this endpoint, so a rewritten body is indistinguishable from
// the truthful one and would sell an isolation guarantee the shape cannot
// support. A refusal names the endpoint that could not be scoped.
const LibpodShowMountedDenyReason = "libpod show mounted denied: " +
	"GET /libpod/containers/showmounted returns every mounted container on the host keyed by ID with the " +
	"daemon host's mount path as the value, carries no labels, and accepts no filters, so it cannot be " +
	"scoped to one caller"
