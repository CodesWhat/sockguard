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
	// Method is the single HTTP method Podman routes the endpoint on.
	// Matching it exactly matters: refusing another method would answer 403
	// where the daemon answers 405.
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

var libpodUnscopeableWrites = []LibpodUnscopeableWrite{
	{Method: http.MethodPost, Path: LibpodPodPrunePath, ReasonCodeStem: "pod_prune", Reason: LibpodPodPruneDenyReason},
}

// LookupLibpodUnscopeableWrite reports whether method and normPath name a
// libpod write owner isolation refuses. Unlike the read lookup it takes the
// method itself rather than trusting the caller to have checked it, because
// these paths are not GET-family routes an unconditional refusal could be
// safe on: POST /libpod/pods/prune is a write and GET on the same path is a
// route Podman does not serve.
func LookupLibpodUnscopeableWrite(method, normPath string) (LibpodUnscopeableWrite, bool) {
	for _, write := range libpodUnscopeableWrites {
		if write.Method == method && write.Path == normPath {
			return write, true
		}
	}
	return LibpodUnscopeableWrite{}, false
}

// LibpodUnscopeableWrites returns the whole set, for tests that need to
// assert the ownership middleware covers every entry.
func LibpodUnscopeableWrites() []LibpodUnscopeableWrite {
	return slices.Clone(libpodUnscopeableWrites)
}
