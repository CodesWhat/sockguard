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
// LibpodSecretListPath is the one entry that does not meet the first
// condition, and it is the only one allowed not to. Its items carry
// Spec.Labels, so a response-side filter of the /system/df kind could scope
// it; none exists, and the alternative to refusing it is forwarding the whole
// host's secret inventory. That reasoning is written out in its own deny
// reason and has to be for any future entry claiming the same exemption:
// naming the response filter that would replace the refusal is the bar,
// because "unimplemented" is otherwise a license to add anything here.
//
// The reason strings live here rather than in either middleware so the two
// layers cannot drift into explaining the same refusal differently, the same
// way they share responsefilter.LibpodSystemDataUsageDenyReason.

import (
	"slices"
	"strings"
)

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

// LibpodSecretListPath is the normalized path of Podman's native
// GET /libpod/secrets/json endpoint. Registered at
// pkg/api/server/register_secrets.go:72 (v5.8.1) as
// VersionedPath("/libpod/secrets/json") -> compat.ListSecrets, versioned
// spelling only.
//
//nolint:gosec // G101: a URL path, not a credential; "secrets" is Podman's route segment.
const LibpodSecretListPath = "/libpod/secrets/json" // #nosec G101 -- a URL path, not a credential; "secrets" is Podman's route segment.

// LibpodManifestExistsPath and LibpodManifestJSONPath are representative
// normalized paths for Podman's two dynamic manifest-read route families.
// Podman routes both with `{name:.*}`, so LookupLibpodUnscopeableRead matches
// every non-empty name, including namespaced references, while these stable
// values name the families in the shared catalog and its policy tests.
const (
	LibpodManifestExistsPath = "/libpod/manifests/sockguard-test/exists"
	LibpodManifestJSONPath   = "/libpod/manifests/sockguard-test/json"
)

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

// LibpodManifestExistsDenyReason is reported when either middleware refuses
// GET /libpod/manifests/{name}/exists. The endpoint reveals whether a manifest
// list exists in local storage but exposes no label or owner metadata and
// accepts no filter that could constrain the lookup.
const LibpodManifestExistsDenyReason = "libpod manifest exists denied: " +
	"GET /libpod/manifests/{name}/exists reveals whether a manifest list exists in local storage, carries no " +
	"labels, and accepts no filters, so it cannot be scoped to one caller"

// LibpodManifestJSONDenyReason is reported when either middleware refuses
// GET /libpod/manifests/{name}/json. Podman inspects a local manifest list when
// one exists, but falls back to fetching the caller-named reference from a
// registry when it does not. Neither response carries policy labels and the
// endpoint accepts no filter, so there is no narrower truthful response the
// ownership or visibility middleware can produce.
const LibpodManifestJSONDenyReason = "libpod manifest inspect denied: " +
	"GET /libpod/manifests/{name}/json returns local manifest content or fetches a caller-named remote " +
	"manifest, carries no labels, and accepts no filters, so it cannot be scoped to one caller"

// LibpodSecretListDenyReason is reported when either middleware refuses
// GET /libpod/secrets/json.
//
// This entry is the exception the membership note at the top of this file
// names, and it is worth being precise about why. The report items are
// entities.SecretInfoReport (pkg/domain/entities/types/secrets.go at v5.8.1:
// ID, CreatedAt, UpdatedAt, Spec, SecretData), and Spec is a SecretSpec that
// DOES carry a Labels map. So unlike showmounted or either stats collection,
// a selector has a field it could read here, and a response-side filter of the
// GET /system/df kind could in principle scope this list.
//
// What it cannot be is scoped UPSTREAM, which is what both isolation layers do
// for every other libpod list. Podman evaluates this endpoint's filters with
// utils.IfPassesSecretsFilter (pkg/domain/utils/secrets_filters.go at v5.8.1),
// whose switch accepts "name" and "id" and returns
// fmt.Errorf("invalid filter %q", key) on anything else. compat.ListSecrets
// turns that error into utils.InternalServerError, so the injected `label`
// key that scopes GET /libpod/containers/json does not merely fail to narrow
// this list, it turns every request into a 500. Injecting it was the behavior
// this refusal replaces.
//
// That leaves forward-unfiltered or refuse, and forwarding is a cross-owner
// enumeration of every secret ID and name on the host. Refusing is the honest
// shape until a response-side filter over Spec.Labels exists, the same call
// LibpodContainerStatsDenyReason makes about the `containers=` spelling: half
// a check is worse than none. Implementing that filter is what would move this
// entry back out of the table.
const LibpodSecretListDenyReason = "libpod secret list denied: " +
	"GET /libpod/secrets/json accepts only name and id filters and answers 500 for any other key, so the label " +
	"filter that scopes every other libpod list cannot be pushed upstream, and no response-side owner filter " +
	"exists for its shape, so it cannot be scoped to one caller"

var (
	libpodManifestExistsRead = LibpodUnscopeableRead{
		Path: LibpodManifestExistsPath, ReasonCodeStem: "manifest_exists", Reason: LibpodManifestExistsDenyReason,
	}
	libpodManifestJSONRead = LibpodUnscopeableRead{
		Path: LibpodManifestJSONPath, ReasonCodeStem: "manifest_json", Reason: LibpodManifestJSONDenyReason,
	}
)

var libpodUnscopeableReads = []LibpodUnscopeableRead{
	{Path: LibpodShowMountedPath, ReasonCodeStem: "show_mounted", Reason: LibpodShowMountedDenyReason},
	{Path: LibpodContainerStatsPath, ReasonCodeStem: "container_stats", Reason: LibpodContainerStatsDenyReason},
	{Path: LibpodPodStatsPath, ReasonCodeStem: "pod_stats", Reason: LibpodPodStatsDenyReason},
	{Path: LibpodSecretListPath, ReasonCodeStem: "secret_list", Reason: LibpodSecretListDenyReason},
	libpodManifestExistsRead,
	libpodManifestJSONRead,
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
// GET or HEAD. Every entry is a GET-only route, so refusing anything else here
// would answer 403 where the daemon answers 405; HEAD is the exception because
// there is no body-filtering step it could legitimately need, and forwarding it
// is the same unscoped disclosure the GET refusal exists to prevent.
func LookupLibpodUnscopeableRead(normPath string) (LibpodUnscopeableRead, bool) {
	if read, ok := libpodUnscopeableReadsByPath[normPath]; ok {
		return read, true
	}

	rest, ok := strings.CutPrefix(normPath, "/libpod/manifests/")
	if !ok {
		return LibpodUnscopeableRead{}, false
	}
	if name := strings.TrimSuffix(rest, "/exists"); name != rest && name != "" {
		return libpodManifestExistsRead, true
	}
	if name := strings.TrimSuffix(rest, "/json"); name != rest && name != "" {
		return libpodManifestJSONRead, true
	}
	return LibpodUnscopeableRead{}, false
}

// LibpodUnscopeableReads returns the whole set, for tests that need to assert
// both middlewares cover every entry and that no shipped preset admits one.
func LibpodUnscopeableReads() []LibpodUnscopeableRead {
	return slices.Clone(libpodUnscopeableReads)
}
