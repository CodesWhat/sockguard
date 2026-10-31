package filter

// libpod_unscopeable_writes.go is libpod_unscopeable_reads.go's write-side
// counterpart: a Podman-native endpoint that CHANGES state across the whole
// host and hands owner isolation nothing to scope the change with.
//
// Membership is the same claim about the endpoint's SHAPE, asked of a write.
// Each entry has to fail all three ways in: the request accepts no `filters`
// parameter for the owner-label injection to attach to, the URL names no
// resource the ownership layer could inspect before the write, and there is
// no response step that could undo what the daemon already did. A write that
// takes `filters` is scoped by injection instead — every other libpod prune
// route is; see libpodNeedsOwnerFilter in internal/ownership.
//
// Only owner isolation consumes this catalog. The visibility layer refuses
// every entry in the READ catalog alongside ownership because both layers
// answer reads, but neither of its axes decides a write, so it has no verdict
// to give here.

import (
	"net/http"
	"slices"
)

// LibpodUnscopeableWrite describes one refused endpoint.
type LibpodUnscopeableWrite struct {
	// Method is the HTTP method Podman routes the refused operation on.
	// Matching it exactly matters: refusing another method would answer 403
	// where the daemon answers 405, or refuse a different operation Podman
	// serves on the same path, as kube play is on the kube down paths.
	Method string
	// Path is the normalized request path, i.e. what NormalizePath returns.
	// It strips the API version prefix but not the /libpod segment, so a
	// Podman binding's /v5.8.1/libpod/... spelling normalizes to this.
	Path string
	// ReasonCodeStem is the middle of the structured reason code ownership
	// logs: "owner_libpod_" + stem + "_unscopeable", the same assembly the
	// read catalog uses.
	ReasonCodeStem string
	// Reason is the operator-facing explanation reported in the 403 body and
	// the access log.
	Reason string
}

// LibpodPodPrunePath is the normalized path of Podman's native
// POST /libpod/pods/prune endpoint. Registered at
// pkg/api/server/register_pods.go:81 (v5.8.1) as
// VersionedPath("/libpod/pods/prune") -> libpod.PodPrune, versioned spelling
// only.
const LibpodPodPrunePath = "/libpod/pods/prune"

// LibpodPodPruneDenyReason is reported when owner isolation refuses
// POST /libpod/pods/prune.
//
// It is the one prune route in the libpod family with nothing to scope it by.
// The other four — containers, images, networks and volumes — document a
// `filters` query parameter that takes `label`, and Podman reads it through
// util.PrepareFilters in each handler, so the owner label is injected into
// them the same way it is into their Docker-compat twins. This endpoint
// documents no parameters at all, and pkg/api/handlers/libpod/pods.go's
// PodPruneHelper at v5.8.1 is two lines: it calls
// runtime.PrunePods(r.Context()) with no options and turns the result map
// into a report. There is no argument to narrow it with.
//
// Forwarding it under owner isolation would delete every prunable pod on the
// host regardless of owner, so the refusal is unconditional and does not
// honor RequestMeta.AllowsPassThrough the way a request-side owner verdict
// does. Warn mode buys an operator a measurement of what enforcement would
// cost; there is no measurement to take after another tenant's pods are
// gone. A deployment that wants host-wide pod pruning runs it without owner
// isolation, or removes pods one at a time through
// DELETE /libpod/pods/{name}, which names a pod the ownership layer checks.
const LibpodPodPruneDenyReason = "libpod pod prune denied: " +
	"POST /libpod/pods/prune removes every prunable pod on the host, accepts no filters at all, and reports " +
	"what it removed only after removing it, so it cannot be scoped to one caller"

// LibpodSystemPrunePath is the normalized path of Podman's native
// POST /libpod/system/prune endpoint.
const LibpodSystemPrunePath = "/libpod/system/prune"

// LibpodSystemPruneDenyReason is reported when owner isolation refuses
// POST /libpod/system/prune.
//
// It prunes pods, containers and images in one call, and volumes too when the
// client asks for them. That is several resource types behind one handler, so
// the single optional `filters` parameter cannot be shown to scope every one
// of them to an owner label, and the removal has happened by the time the
// report comes back. The refusal is unconditional for the reason the pod
// prune one is. A caller under owner isolation prunes with the per-type
// routes (containers, images, networks, volumes), which the ownership layer
// scopes by injecting the owner label.
const LibpodSystemPruneDenyReason = "libpod system prune denied: " +
	"POST /libpod/system/prune removes unused pods, containers, images and optionally volumes across the whole host in one call, " +
	"so it cannot be scoped to one caller"

// LibpodSystemCheckPath is the normalized path of Podman's native
// POST /libpod/system/check endpoint.
const LibpodSystemCheckPath = "/libpod/system/check"

// LibpodSystemCheckDenyReason is reported when owner isolation refuses
// POST /libpod/system/check.
//
// It runs a storage consistency check over the whole host and can repair it,
// removing damaged containers and images whoever owns them, so it names no
// resource an owner check could inspect and cannot be scoped to one caller.
// The refusal is unconditional for the reason the pod prune one is.
const LibpodSystemCheckDenyReason = "libpod system check denied: " +
	"POST /libpod/system/check checks the host's storage and can repair it by removing damaged containers and images " +
	"whoever owns them, so it cannot be scoped to one caller"

// LibpodKubeDownDenyReason is reported when owner isolation refuses kube
// down, DELETE /libpod/play/kube and its DELETE /libpod/kube/play alias.
//
// Podman 5.8.6 serves both from one handler (pkg/api/server/register_kube.go:180-181),
// whose only query parameter is `force`. What it removes is named in the
// request body: the pods, secrets and volumes of a Kubernetes YAML
// (pkg/domain/infra/abi/play.go:1678-1819), which nothing in sockguard
// parses. So the request takes no `filters`, the URL names no resource to
// check an owner on, and a client can name another owner's pod, secret or
// volume in the YAML and have it removed.
//
// The refusal is unconditional for the reason the pod prune one is. A caller
// under owner isolation removes its pods through DELETE /libpod/pods/{name},
// which names a pod the ownership layer checks.
const LibpodKubeDownDenyReason = "libpod kube down denied: " +
	"DELETE /libpod/play/kube and /libpod/kube/play remove the pods, secrets and volumes named in a YAML body " +
	"that is not parsed, so the request cannot be scoped to one caller"

// LibpodQuadletsPath and LibpodArtifactRemovePath are native batch writes
// registered by Podman v6.0.0's register_quadlets.go and register_artifacts.go.
const (
	LibpodQuadletsPath             = "/libpod/quadlets"
	LibpodArtifactRemovePath       = "/libpod/artifacts/remove"
	LibpodQuadletRemovePath        = "/libpod/quadlets/sockguard-test.container"
	LibpodArtifactSingleRemovePath = "/libpod/artifacts/sockguard-test"
	LibpodArtifactPushPath         = "/libpod/artifacts/sockguard-test/push"
	LibpodQuadletWriteDenyReason   = "libpod quadlet write denied: installation and removal can replace or remove other callers' unit files, with no owner-label scope or per-file ownership check"
	LibpodArtifactRemoveDenyReason = "libpod artifact batch removal denied: the endpoint can remove all artifacts, accepts no owner-label filter and has no per-artifact ownership check"
	LibpodArtifactWriteDenyReason  = "libpod artifact write denied: artifacts have no owner-label scope or per-artifact ownership check"
)

var libpodUnscopeableWrites = []LibpodUnscopeableWrite{
	{Method: http.MethodDelete, Path: LibpodQuadletRemovePath, ReasonCodeStem: "quadlet_remove", Reason: LibpodQuadletWriteDenyReason},
	{Method: http.MethodDelete, Path: LibpodArtifactSingleRemovePath, ReasonCodeStem: "artifact_remove_one", Reason: LibpodArtifactWriteDenyReason},
	{Method: http.MethodPost, Path: "/libpod/artifacts/add", ReasonCodeStem: "artifact_add", Reason: LibpodArtifactWriteDenyReason},
	{Method: http.MethodPost, Path: "/libpod/artifacts/local/add", ReasonCodeStem: "artifact_local_add", Reason: LibpodArtifactWriteDenyReason},
	{Method: http.MethodPost, Path: "/libpod/artifacts/pull", ReasonCodeStem: "artifact_pull", Reason: LibpodArtifactWriteDenyReason},
	{Method: http.MethodPost, Path: LibpodArtifactPushPath, ReasonCodeStem: "artifact_push", Reason: LibpodArtifactWriteDenyReason},
	{Method: http.MethodPost, Path: LibpodQuadletsPath, ReasonCodeStem: "quadlet_write", Reason: LibpodQuadletWriteDenyReason},
	{Method: http.MethodDelete, Path: LibpodQuadletsPath, ReasonCodeStem: "quadlet_write", Reason: LibpodQuadletWriteDenyReason},
	{Method: http.MethodDelete, Path: LibpodArtifactRemovePath, ReasonCodeStem: "artifact_remove", Reason: LibpodArtifactRemoveDenyReason},
	{Method: http.MethodPost, Path: LibpodPodPrunePath, ReasonCodeStem: "pod_prune", Reason: LibpodPodPruneDenyReason},
	{Method: http.MethodPost, Path: LibpodSystemPrunePath, ReasonCodeStem: "system_prune", Reason: LibpodSystemPruneDenyReason},
	{Method: http.MethodPost, Path: LibpodSystemCheckPath, ReasonCodeStem: "system_check", Reason: LibpodSystemCheckDenyReason},
	{Method: http.MethodDelete, Path: libpodPathPrefix + "play/kube", ReasonCodeStem: "kube_down", Reason: LibpodKubeDownDenyReason},
	{Method: http.MethodDelete, Path: libpodPathPrefix + "kube/play", ReasonCodeStem: "kube_down", Reason: LibpodKubeDownDenyReason},
}

// LookupLibpodUnscopeableWrite reports whether method and normPath name a
// libpod write owner isolation refuses. Unlike the read lookup it takes the
// method itself rather than trusting the caller to have checked it, because
// these paths are not GET-family routes an unconditional refusal could be
// safe on: POST /libpod/pods/prune is a write and GET on the same path is a
// route Podman does not serve, and POST on the kube down paths is kube play,
// a different operation.
func LookupLibpodUnscopeableWrite(method, normPath string) (LibpodUnscopeableWrite, bool) {
	for _, write := range libpodUnscopeableWrites {
		if write.Method == method && libpodUnscopeableWritePathMatches(write.Path, normPath) {
			return write, true
		}
	}
	return LibpodUnscopeableWrite{}, false
}

func libpodUnscopeableWritePathMatches(representative, normPath string) bool {
	if representative == normPath {
		return true
	}
	switch representative {
	case LibpodQuadletRemovePath:
		return libpodNamedPathMatches(normPath, "/libpod/quadlets/", "", false)
	case LibpodArtifactSingleRemovePath:
		return normPath != LibpodArtifactRemovePath && libpodNamedPathMatches(normPath, "/libpod/artifacts/", "", true)
	case LibpodArtifactPushPath:
		return libpodNamedPathMatches(normPath, "/libpod/artifacts/", "/push", true)
	default:
		return false
	}
}

// LibpodUnscopeableWrites returns the whole set, for tests that need to
// assert the ownership middleware covers every entry.
func LibpodUnscopeableWrites() []LibpodUnscopeableWrite {
	return slices.Clone(libpodUnscopeableWrites)
}
