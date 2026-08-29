package filter

// libpod_unscopeable_reads.go names the Podman-native GET endpoints that
// neither owner isolation nor a visibility policy can scope to one caller, so
// both middlewares refuse them outright instead of forwarding or filtering.
//
// Membership is a claim about the endpoint's SHAPE, not about what sockguard
// has got round to implementing. Each entry has to fail all three ways in:
// the response carries no label or owner field a selector could read, the
// request accepts no `filters` parameter for addOwnerLabelFilter to attach to,
// and an emptied or redacted body would be indistinguishable from a truthful
// one. An endpoint that fails only the last two is filtered on the response
// instead, the way GET /system/df is.
//
// The reason strings live here rather than in either middleware so the two
// layers cannot drift into explaining the same refusal differently, the same
// way they share responsefilter.LibpodSystemDataUsageDenyReason.

import "slices"

// LibpodUnscopeableRead describes one refused endpoint.
type LibpodUnscopeableRead struct {
	// Path is the normalized request path, i.e. what NormalizePath returns.
	// It strips the API version prefix but not the /libpod segment, so a
	// Podman binding's /v5.8.1/libpod/... spelling normalizes to this.
	Path string
	// ReasonCodeStem is the middle of the structured reason code each
	// middleware logs: ownership logs "owner_libpod_" + stem +
	// "_unscopeable", visibility logs "visibility_libpod_" + stem +
	// "_unscopeable". Both packages assert the assembled strings as literals
	// in their own tests, so adding an entry here without deciding what its
	// two codes are fails those tests rather than inventing a code silently.
	ReasonCodeStem string
	// Reason is the operator-facing explanation both layers report in the 403
	// body and the access log.
	Reason string
}

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

// LibpodContainerStatsPath is the normalized path of Podman's native
// collection-level GET /libpod/containers/stats endpoint. Registered at
// pkg/api/server/register_containers.go:1190 (v5.8.1) as
// VersionedPath("/libpod/containers/stats") → libpod.StatsContainer, versioned
// spelling only.
//
// It is the collection endpoint, not the per-container one: with no
// `containers` parameter and all=false, abi.ContainerEngine.ContainerStats
// takes its `default:` branch and calls GetRunningContainers, so the plain
// request streams every running container on the host; all=true swaps that for
// GetAllContainers.
//
// The per-container GET /libpod/containers/{name}/stats is a different route
// (register_containers.go:1157) and stays allowed, because {name} is an
// identifier the ownership and visibility layers already check. Podman's own
// swagger marks that route "DEPRECATED. This endpoint will be removed with the
// next major release. Please use /libpod/containers/stats instead." — so the
// only owner-scopeable spelling of a stats read is the one upstream intends to
// delete, which is worth knowing before building on it.
const LibpodContainerStatsPath = "/libpod/containers/stats"

// LibpodPodStatsPath is the normalized path of Podman's native
// GET /libpod/pods/stats endpoint. Registered at
// pkg/api/server/register_pods.go:351 (v5.8.1) as
// VersionedPath("/libpod/pods/stats") → libpod.PodStats, versioned spelling
// only.
//
// A request that names nothing enumerates the whole host by design rather than
// by omission: entities.ValidatePodStatsOptions sets options.All = true when
// neither namesOrIDs, all nor latest is given, commented "Podman v1 compat: if
// nothing's specified get all running pods".
//
// There is no per-pod counterpart to fall back to. Podman registers no
// /libpod/pods/{name}/stats route at all, which is why libpodPodIdentifier
// reserves "stats" alongside "json": the only spelling of a pod stats read is
// the collection one.
const LibpodPodStatsPath = "/libpod/pods/stats"

// LibpodShowMountedDenyReason is reported when either middleware refuses
// GET /libpod/containers/showmounted.
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
// answer from this endpoint, so a rewritten body is indistinguishable from the
// truthful one and would sell an isolation guarantee the shape cannot support.
// A refusal names the endpoint that could not be scoped.
const LibpodShowMountedDenyReason = "libpod show mounted denied: " +
	"GET /libpod/containers/showmounted returns every mounted container on the host keyed by ID with the " +
	"daemon host's mount path as the value, carries no labels, and accepts no filters, so it cannot be " +
	"scoped to one caller"

// LibpodContainerStatsDenyReason is reported when either middleware refuses
// GET /libpod/containers/stats.
//
// The query struct in pkg/api/handlers/libpod/containers_stats.go at v5.8.1 is
// {Containers []string `schema:"containers"`; Stream bool; Interval int;
// All bool}. There is no `filters` member, so the label-filter injection that
// scopes /libpod/containers/json has nothing to attach to, and the report
// items are libpod/define.ContainerStats — AvgCPU, ContainerID, Name, PerCPU,
// CPU, CPUNano, CPUSystemNano, SystemNano, MemUsage, MemLimit, MemPerc,
// Network, BlockInput, BlockOutput, PIDs, UpTime, Duration — with no Labels
// field and no owner field, so neither the selector axes nor the name/image
// pattern axes have anything to read. Every entry does carry ContainerID and
// Name, so the stream is a live cross-owner enumeration on top of being a
// resource-usage disclosure.
//
// The refusal covers the `containers=` spelling too, not just the bare
// enumeration. Checking each named container against the owner would be
// possible in principle — ownership already inspects a named container on
// every other libpod route — but nothing here does it, and half a check is
// worse than none: a request that named one owned container and one that was
// not would still be forwarded whole. Refusing the path is the honest shape
// until a per-name check exists. GET /libpod/containers/{name}/stats is the
// route that has one.
const LibpodContainerStatsDenyReason = "libpod container stats denied: " +
	"GET /libpod/containers/stats streams live resource usage keyed by container ID for every running " +
	"container on the host, carries no labels, and accepts no filters, so it cannot be scoped to one caller"

// LibpodPodStatsDenyReason is reported when either middleware refuses
// GET /libpod/pods/stats.
//
// The query struct in pkg/api/handlers/libpod/pods.go at v5.8.1 is
// {NamesOrIDs []string `schema:"namesOrIDs"`; All bool; Stream bool;
// Delay int} — again no `filters` member. The report items are
// pkg/domain/entities/types.PodStatsReport (CPU, MemUsage, MemUsageBytes, Mem,
// NetIO, BlockIO, PIDS, Pod, CID, Name), which carries no labels and no owner
// field; Pod, CID and Name identify the resource without saying whose it is,
// so filtering has nothing to decide on and the body is an enumeration.
//
// Pods are the case where the gap is widest. A pod's labels live on the pod,
// not on this report, and libpodNeedsOwnerFilter can scope GET /libpod/pods/json
// because that endpoint does take `filters`. This one does not, so the same
// deployment that gets a correctly scoped pod LIST gets an unscoped pod STATS
// unless it is refused.
const LibpodPodStatsDenyReason = "libpod pod stats denied: " +
	"GET /libpod/pods/stats reports resource usage for every running pod on the host by default, carries no " +
	"labels, and accepts no filters, so it cannot be scoped to one caller"

var libpodUnscopeableReads = []LibpodUnscopeableRead{
	{Path: LibpodShowMountedPath, ReasonCodeStem: "show_mounted", Reason: LibpodShowMountedDenyReason},
	{Path: LibpodContainerStatsPath, ReasonCodeStem: "container_stats", Reason: LibpodContainerStatsDenyReason},
	{Path: LibpodPodStatsPath, ReasonCodeStem: "pod_stats", Reason: LibpodPodStatsDenyReason},
}

var libpodUnscopeableReadsByPath = func() map[string]LibpodUnscopeableRead {
	byPath := make(map[string]LibpodUnscopeableRead, len(libpodUnscopeableReads))
	for _, read := range libpodUnscopeableReads {
		byPath[read.Path] = read
	}
	return byPath
}()

// LookupLibpodUnscopeableRead reports whether normPath is a libpod read both
// isolation layers refuse. Callers must have already established the method is
// GET: every entry is a GET-only route, and refusing another method here would
// answer 403 where the daemon answers 405.
func LookupLibpodUnscopeableRead(normPath string) (LibpodUnscopeableRead, bool) {
	read, ok := libpodUnscopeableReadsByPath[normPath]
	return read, ok
}

// LibpodUnscopeableReads returns the whole set, for tests that need to assert
// both middlewares cover every entry and that no shipped preset admits one.
func LibpodUnscopeableReads() []LibpodUnscopeableRead {
	return slices.Clone(libpodUnscopeableReads)
}
