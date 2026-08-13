package filter

// resource_limit_guard.go implements #152: revalidating configured
// require_memory_limit / require_cpu_limit / require_cpu_limit_hard /
// require_pids_limit guarantees across POST /containers/{id}/update and
// service create/update/rollback, closing the gap where allow_resource_updates
// (container) and swarm's replace-the-whole-spec update model let a later
// write silently clear a limit that was enforced at create time.
//
// ResourceLimitGuard is a SEPARATE middleware layer from the request-body
// inspectors in middleware.go/container_update.go/service.go, and it runs
// POST-ownership (see internal/cmd/serve.go's buildServeHandlerLayersWithRuntime,
// which inserts it between withHijack and withOwnership in append order — later
// appends wrap earlier ones, so the runtime order is
// ...filter -> visibility -> ownership -> ResourceLimitGuard -> hijack -> proxy).
// Two reasons this cannot live inside containerUpdatePolicy.inspect /
// servicePolicy.inspect, which run BEFORE ownership:
//
//  1. Resolving "what does an omitted container-update field mean" requires a
//     daemon GET of the target's current state. Doing that GET before ownership
//     has decided whether the caller may even see this resource turns
//     resource-deny-vs-ownership-deny into a compliance oracle for containers
//     the caller doesn't own, and wastes a daemon round-trip on every request
//     ownership was always going to deny anyway.
//  2. Swarm rollback (manual ?rollback=previous, or an automatic
//     UpdateConfig.FailureAction: rollback) needs to inspect the target
//     service's current Version/Spec/PreviousSpec — again, only safe to fetch
//     once ownership has cleared the caller for this specific service.
//
// Everything the guard enforces is a PRESENCE predicate over the effective
// state Docker's own merge semantics will produce, never a numeric floor —
// see resourceLimitDenyReason in container_create.go, shared verbatim by the
// container-update path here so update can never drift from create's
// semantics. The guard forwards the original request body byte-for-byte; it
// never rewrites it, so there is no TOCTOU between "what we validated" and
// "what Docker applies" — Docker's own merge (for update) or the request body
// itself (for service, which has no partial-merge concept) determines the
// applied state, and it is exactly what was validated.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

const (
	reasonCodeResourceLimitRequestInvalid     = "resource_limit_request_invalid"
	reasonCodeResourceLimitPolicyDenied       = "resource_limit_policy_denied"
	reasonCodeResourceLimitPolicyLookupFailed = "resource_limit_policy_lookup_failed"
	reasonCodeResourceLimitPolicyStateChanged = "resource_limit_policy_state_changed"
)

const (
	resourcePolicyKindContainer = "container"
	resourcePolicyKindService   = "service"
)

// ResourceLimitGuardOptions configures ResourceLimitGuardWithOptions. It
// mirrors filter.Options' shape (PolicyConfig + Profiles + ResolveProfile) so
// the guard selects the same per-client policy the request-body inspectors
// and rule evaluator already resolved, plus the runtime daemon inspectors
// only this layer needs.
type ResourceLimitGuardOptions struct {
	PolicyConfig
	// Profiles mirrors filter.Options.Profiles — the same compiled per-client
	// policy map the filter/ownership/visibility layers use, so a profile's
	// require_* flags apply identically here.
	Profiles map[string]Policy
	// ResolveProfile mirrors filter.Options.ResolveProfile (typically
	// clientacl.RequestProfile).
	ResolveProfile func(*http.Request) (string, bool)
	// InspectContainer resolves a container's current HostConfig resource
	// fields for the update-omission merge. Required for
	// require_{memory,cpu,cpu_hard,pids}_limit on container update; a nil
	// value with an active requirement fails closed (does not panic).
	InspectContainer ContainerUpdateInspectFunc
	// InspectService resolves a service's current Version/Spec/PreviousSpec
	// for rollback validation. Required for require_cpu_limit(_hard) on
	// ?rollback=previous or an automatic-rollback-capable update; a nil value
	// with an active requirement fails closed (does not panic).
	InspectService ServiceInspectFunc
}

// ResourceLimitGuardWithOptions returns the #152 resource-limit guard
// middleware. See the package-level doc comment above for placement and
// rationale.
func ResourceLimitGuardWithOptions(logger *slog.Logger, opts ResourceLimitGuardOptions) func(http.Handler) http.Handler {
	g := &resourceLimitGuard{
		defaultPolicy:    opts.normalized(),
		profiles:         opts.Profiles,
		resolveProfile:   opts.ResolveProfile,
		inspectContainer: opts.InspectContainer,
		inspectService:   opts.InspectService,
		logger:           logger,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.serve(w, r, next)
		})
	}
}

type resourceLimitGuard struct {
	defaultPolicy    PolicyConfig
	profiles         map[string]Policy
	resolveProfile   func(*http.Request) (string, bool)
	inspectContainer ContainerUpdateInspectFunc
	inspectService   ServiceInspectFunc
	logger           *slog.Logger
}

func (g *resourceLimitGuard) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if r.Method != http.MethodPost {
		next.ServeHTTP(w, r)
		return
	}

	normPath := resolveNormalizedPath(logging.MetaForRequest(w, r), r)

	policy, ok := g.policyForRequest(w, r)
	if !ok {
		// Mirrors filter's unresolved-profile denial (already written to w by
		// policyForRequest). In the production chain filter's own resolution
		// runs first and would have denied this request long before it
		// reached the guard; this branch only matters if the guard is ever
		// wired without filter ahead of it (e.g. isolated tests).
		return
	}

	switch {
	case isContainerUpdatePath(normPath):
		g.guardContainerUpdate(w, r, normPath, policy, next)
	case isServiceWritePath(normPath):
		g.guardServiceWrite(w, r, normPath, policy, next)
	default:
		next.ServeHTTP(w, r)
	}
}

// policyForRequest resolves the PolicyConfig for this request using the same
// profile-selection contract filter.MiddlewareWithOptions uses. ok=false
// means a response was already written (unresolved named profile).
func (g *resourceLimitGuard) policyForRequest(w http.ResponseWriter, r *http.Request) (PolicyConfig, bool) {
	if g.resolveProfile == nil {
		return g.defaultPolicy, true
	}
	name, ok := g.resolveProfile(r)
	if !ok {
		return g.defaultPolicy, true
	}
	profile, found := g.profiles[name]
	if !found {
		denyWithReasonCode(w, r, g.logger, reasonCodeClientPolicyProfileUnresolved, "client policy profile could not be resolved", g.defaultPolicy.DenyResponseVerbosity)
		return PolicyConfig{}, false
	}
	return profile.normalized(), true
}

// ---------------------------------------------------------------------------
// Container update
// ---------------------------------------------------------------------------

// containerUpdateResourcePatch decodes ONLY the root-level Docker
// update-resource fields. Nested "HostConfig"/"Resources" wrappers are
// deliberately NOT part of this type: Docker's real
// POST /containers/{id}/update schema is flat at the request root, so a value
// nested under a decoy wrapper is never applied by the daemon. Reading it here
// would let a request satisfy the floor check using a number Docker will
// never actually use — a hole, not a false positive — so this type silently
// ignores anything outside the root object, exactly matching what the daemon
// itself honors.
//
// Scalars are plain int64 (not pointers): Docker's own merge treats an
// explicit 0 identically to an omitted field ("unchanged" — see the overlay in
// guardContainerUpdateResources), so sockguard does not need to distinguish
// "absent" from "present and zero" for these five fields. PidsLimit is the
// one exception — Docker uses a pointer there specifically so 0/-1 CAN be an
// explicit clear — so it stays a pointer here too.
type containerUpdateResourcePatch struct {
	Memory    int64  `json:"Memory"`
	NanoCpus  int64  `json:"NanoCpus"`
	CpuQuota  int64  `json:"CpuQuota"`
	CpuPeriod int64  `json:"CpuPeriod"`
	CpuShares int64  `json:"CpuShares"`
	PidsLimit *int64 `json:"PidsLimit"`
}

// containerUpdateIdentifier extracts the {id} path segment from a normalized
// POST /containers/{id}/update path. Assumes isContainerUpdatePath(normPath)
// already holds.
func containerUpdateIdentifier(normalizedPath string) (string, bool) {
	id, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/containers/"), "/")
	if !ok || id == "" || tail != "update" {
		return "", false
	}
	return id, true
}

func (g *resourceLimitGuard) guardContainerUpdate(w http.ResponseWriter, r *http.Request, normPath string, policy PolicyConfig, next http.Handler) {
	cu := policy.ContainerUpdate
	// §0.1: require_* is only ever consulted when AllowResourceUpdates is
	// true. When false, the existing blanket deny of every resource-control
	// field (containerUpdatePolicy.inspect, container_update.go) already
	// preserves the create-time guarantee — enforcing a ratchet check on
	// non-resource updates on top of that adds rollout pain for zero
	// additional bypass closed. No reads, no lookups, no logging.
	if !cu.AllowResourceUpdates {
		next.ServeHTTP(w, r)
		return
	}
	requirements := containerUpdateRequirementsList(cu)
	if requirements == "" {
		next.ServeHTTP(w, r)
		return
	}

	id, ok := containerUpdateIdentifier(normPath)
	if !ok {
		next.ServeHTTP(w, r)
		return
	}

	rp := logging.GetResourcePolicyMeta()
	rp.Evaluated = true
	rp.Kind = resourcePolicyKindContainer
	rp.Operation = "update"
	rp.StateSource = "effective_state"
	rp.Requirements = requirements

	body, err := readBoundedBody(r, maxContainerUpdateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.respondHardDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("container update denied: request body exceeds %d byte limit", maxContainerUpdateBodyBytes),
				policy.DenyResponseVerbosity, rp)
			return
		}
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: request body could not be read", policy.DenyResponseVerbosity, rp)
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: a request body is required to verify resource requirements", policy.DenyResponseVerbosity, rp)
		return
	}
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: request body contains ambiguous duplicate keys", policy.DenyResponseVerbosity, rp)
		return
	}

	var patch containerUpdateResourcePatch
	if err := json.Unmarshal(body, &patch); err != nil {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: request body could not be inspected", policy.DenyResponseVerbosity, rp)
		return
	}

	if g.inspectContainer == nil {
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"container update denied: resource requirement verification unavailable", policy.DenyResponseVerbosity, rp)
		return
	}
	rp.StateLookup = true
	current, found, err := g.inspectContainer(r.Context(), id)
	if err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to inspect container for resource-limit guard", err)
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"container update denied: resource requirement verification unavailable", policy.DenyResponseVerbosity, rp)
		return
	}
	if !found {
		// The target container does not exist; the forwarded update will
		// itself 404 at the daemon. Matches exec's and ownership's existing
		// not-found convention — this sub-check simply doesn't apply.
		g.respondAllow(w, r, next, rp)
		return
	}

	effective := containerCreateHostConfig{
		Memory:    current.Memory,
		NanoCpus:  current.NanoCpus,
		CpuQuota:  current.CpuQuota,
		CpuPeriod: current.CpuPeriod,
		CpuShares: current.CpuShares,
		PidsLimit: current.PidsLimit,
	}
	// Moby-faithful overlay (daemon/container_unix.go Container.UpdateContainer):
	// scalar fields apply ONLY when explicitly nonzero — an explicit 0 is the
	// same "unchanged" the daemon reports for an omitted field, never a clear.
	// PidsLimit is a pointer at the daemon too, so ANY non-nil value applies,
	// including 0/-1, which ARE explicit clears there.
	if patch.Memory != 0 {
		effective.Memory = patch.Memory
	}
	if patch.NanoCpus != 0 {
		effective.NanoCpus = patch.NanoCpus
	}
	if patch.CpuQuota != 0 {
		effective.CpuQuota = patch.CpuQuota
	}
	if patch.CpuPeriod != 0 {
		effective.CpuPeriod = patch.CpuPeriod
	}
	if patch.CpuShares != 0 {
		effective.CpuShares = patch.CpuShares
	}
	if patch.PidsLimit != nil {
		effective.PidsLimit = patch.PidsLimit
	}

	reason, violation := resourceLimitDenyReason(effective, cu.RequireMemoryLimit, cu.RequireCPULimit, cu.RequireCPULimitHard, cu.RequirePidsLimit, "container update")
	if reason != "" {
		rp.Violation = violation
		g.respondPolicyDenied(w, r, next, reason, policy.DenyResponseVerbosity, rp)
		return
	}
	g.respondAllow(w, r, next, rp)
}

func containerUpdateRequirementsList(cu ContainerUpdateOptions) string {
	var parts []string
	if cu.RequireMemoryLimit {
		parts = append(parts, "memory")
	}
	if cu.RequireCPULimit {
		parts = append(parts, "cpu")
	}
	if cu.RequireCPULimitHard {
		parts = append(parts, "hard_cpu")
	}
	if cu.RequirePidsLimit {
		parts = append(parts, "pids")
	}
	return strings.Join(parts, ",")
}

// ContainerUpdateInspectResult carries the container-update-relevant subset of
// GET /containers/{id}/json's HostConfig.
type ContainerUpdateInspectResult struct {
	Memory    int64
	NanoCpus  int64
	CpuQuota  int64
	CpuPeriod int64
	CpuShares int64
	PidsLimit *int64
}

// ContainerUpdateInspectFunc looks up a container's current resource state by
// ID. found=false with err=nil means the container does not exist (404).
type ContainerUpdateInspectFunc func(ctx context.Context, id string) (ContainerUpdateInspectResult, bool, error)

// NewDockerContainerUpdateInspectorWithRoundTripper returns a container
// resource-state inspector that issues its GET through the shared upstream
// RoundTripper (typically an *upstream.Resolver), so it follows the same
// active endpoint as the update request it guards under failover. Mirrors
// NewDockerExecInspectorWithRoundTripper's shape (exec.go).
func NewDockerContainerUpdateInspectorWithRoundTripper(rt http.RoundTripper) ContainerUpdateInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, id string) (ContainerUpdateInspectResult, bool, error) {
		requestPath, ok := dockerresource.InspectPath(dockerresource.KindContainer, id)
		if !ok {
			return ContainerUpdateInspectResult{}, false, fmt.Errorf("no inspect path for container %q", id)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil) // #nosec G704 -- InspectPath accepts only a validated engine resource identifier.
		if err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}
		resp, err := client.Do(req) // #nosec G704 -- the injected transport targets the local container-engine socket, not the URL host.
		if err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}
		defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return ContainerUpdateInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ContainerUpdateInspectResult{}, false, fmt.Errorf("inspect container %q returned status %d", id, resp.StatusCode)
		}

		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}

		var decoded struct {
			HostConfig struct {
				Memory    int64  `json:"Memory"`
				NanoCpus  int64  `json:"NanoCpus"`
				CpuQuota  int64  `json:"CpuQuota"`
				CpuPeriod int64  `json:"CpuPeriod"`
				CpuShares int64  `json:"CpuShares"`
				PidsLimit *int64 `json:"PidsLimit"`
			} `json:"HostConfig"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}
		return ContainerUpdateInspectResult{
			Memory:    decoded.HostConfig.Memory,
			NanoCpus:  decoded.HostConfig.NanoCpus,
			CpuQuota:  decoded.HostConfig.CpuQuota,
			CpuPeriod: decoded.HostConfig.CpuPeriod,
			CpuShares: decoded.HostConfig.CpuShares,
			PidsLimit: decoded.HostConfig.PidsLimit,
		}, true, nil
	}
}

// ---------------------------------------------------------------------------
// Service create / update / rollback
// ---------------------------------------------------------------------------

type serviceResourceGuardRequest struct {
	TaskTemplate struct {
		Resources *struct {
			Limits *struct {
				NanoCPUs int64 `json:"NanoCPUs"`
			} `json:"Limits"`
		} `json:"Resources"`
	} `json:"TaskTemplate"`
	UpdateConfig *struct {
		FailureAction string `json:"FailureAction"`
	} `json:"UpdateConfig"`
}

func (req serviceResourceGuardRequest) nanoCPUs() int64 {
	if req.TaskTemplate.Resources == nil || req.TaskTemplate.Resources.Limits == nil {
		return 0
	}
	return req.TaskTemplate.Resources.Limits.NanoCPUs
}

func (req serviceResourceGuardRequest) failureActionIsRollback() bool {
	return req.UpdateConfig != nil && strings.EqualFold(req.UpdateConfig.FailureAction, "rollback")
}

// serviceUpdateIdentifier extracts the {id} path segment from a normalized
// POST /services/{id}/update path.
func serviceUpdateIdentifier(normalizedPath string) (string, bool) {
	if !strings.HasPrefix(normalizedPath, "/services/") {
		return "", false
	}
	id, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/services/"), "/")
	if !ok || id == "" || tail != "update" {
		return "", false
	}
	return id, true
}

// serviceVersionQuery parses the exactly-one-value, strictly-numeric
// ?version= query parameter Docker requires on every service update. Multiple
// values or a non-numeric value is treated as invalid rather than guessed at.
func serviceVersionQuery(r *http.Request) (uint64, bool) {
	values := r.URL.Query()["version"]
	if len(values) != 1 {
		return 0, false
	}
	v, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// serviceManualRollbackQuery distinguishes an ordinary service update from a
// manual rollback request while rejecting ambiguous duplicate query values.
// Docker's request parser may choose one of multiple values, but the guard
// must never guess which daemon behavior it is validating.
func serviceManualRollbackQuery(r *http.Request) (manualRollback, valid bool) {
	values, present := r.URL.Query()["rollback"]
	if !present {
		return false, true
	}
	if len(values) != 1 {
		return false, false
	}
	return strings.EqualFold(values[0], "previous"), true
}

func serviceRequirementsList(svc ServiceOptions) string {
	var parts []string
	if svc.RequireCPULimit {
		parts = append(parts, "cpu")
	}
	if svc.RequireCPULimitHard {
		parts = append(parts, "hard_cpu")
	}
	return strings.Join(parts, ",")
}

// denyServiceCPULimitReason applies the single presence predicate shared by
// RequireCPULimit and RequireCPULimitHard (see ServiceOptions doc comment:
// Swarm's TaskTemplate.Resources.Limits has no soft/hard split the way
// container CpuShares vs NanoCpus/CpuQuota does, so both flags reduce to the
// same NanoCPUs>0 check). subject prefixes the message.
func denyServiceCPULimitReason(nanoCPUs int64, requireCPU, requireCPUHard bool, subject string) (reason, violation string) {
	if (requireCPU || requireCPUHard) && nanoCPUs <= 0 {
		return fmt.Sprintf("%s denied: a CPU limit is required (set TaskTemplate.Resources.Limits.NanoCPUs)", subject), "cpu"
	}
	return "", ""
}

func (g *resourceLimitGuard) guardServiceWrite(w http.ResponseWriter, r *http.Request, normPath string, policy PolicyConfig, next http.Handler) {
	svc := policy.Service
	requirements := serviceRequirementsList(svc)
	if requirements == "" {
		next.ServeHTTP(w, r)
		return
	}

	isCreate := normPath == "/services/create"
	updateID, isUpdate := serviceUpdateIdentifier(normPath)

	rp := logging.GetResourcePolicyMeta()
	rp.Evaluated = true
	rp.Kind = resourcePolicyKindService
	rp.Requirements = requirements
	switch {
	case isCreate:
		rp.Operation = "create"
	default:
		rp.Operation = "update"
	}
	rp.StateSource = "request"
	manualRollback := false
	if isUpdate {
		var rollbackQueryValid bool
		manualRollback, rollbackQueryValid = serviceManualRollbackQuery(r)
		if !rollbackQueryValid {
			rp.Operation = "manual_rollback"
			g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
				"service update denied: rollback query parameter must have exactly one value", policy.DenyResponseVerbosity, rp)
			return
		}
	}

	body, err := readBoundedBody(r, maxServiceBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.respondHardDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("service denied: request body exceeds %d byte limit", maxServiceBodyBytes),
				policy.DenyResponseVerbosity, rp)
			return
		}
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service denied: request body could not be read", policy.DenyResponseVerbosity, rp)
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service denied: a request body is required to verify resource requirements", policy.DenyResponseVerbosity, rp)
		return
	}
	var req serviceResourceGuardRequest
	if err := json.Unmarshal(body, &req); err != nil {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service denied: request body could not be inspected", policy.DenyResponseVerbosity, rp)
		return
	}

	// REAL BYPASS this closes: ?rollback=previous makes the daemon ignore the
	// request body entirely and apply the target's stored PreviousSpec — so
	// validating the submitted body (which is what the switch below would
	// otherwise do) proves nothing about what actually becomes active.
	if manualRollback {
		g.guardServiceManualRollback(w, r, updateID, svc, policy.DenyResponseVerbosity, rp, next)
		return
	}

	reason, violation := denyServiceCPULimitReason(req.nanoCPUs(), svc.RequireCPULimit, svc.RequireCPULimitHard, "service")
	if reason != "" {
		rp.Violation = violation
		g.respondPolicyDenied(w, r, next, reason, policy.DenyResponseVerbosity, rp)
		return
	}

	if isUpdate && req.failureActionIsRollback() {
		// The proposed spec passed above; it may ALSO become the rollback
		// target's predecessor if remediation-in-place is not what happens —
		// what matters here is the daemon's own automatic rollback, which
		// reactivates the CURRENT (pre-update) Spec on failure. That spec was
		// never re-validated at the time it was originally admitted under a
		// weaker (or no) policy, so it must be checked now, before an
		// enabled requirement can be silently defeated by a failed update
		// rolling back to a non-compliant predecessor.
		rp.Operation = "automatic_rollback"
		if !g.guardServiceRollbackTarget(w, r, updateID, svc, policy.DenyResponseVerbosity, rp, next, "current_spec", func(res ServiceInspectResult) int64 {
			return res.SpecNanoCPUs
		}) {
			return
		}
	}

	g.respondAllow(w, r, next, rp)
}

func (g *resourceLimitGuard) guardServiceManualRollback(w http.ResponseWriter, r *http.Request, id string, svc ServiceOptions, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta, next http.Handler) {
	rp.Operation = "manual_rollback"
	if g.guardServiceRollbackTarget(w, r, id, svc, verbosity, rp, next, "previous_spec", func(res ServiceInspectResult) int64 {
		return res.PreviousSpecNanoCPUs
	}) {
		g.respondAllow(w, r, next, rp)
	}
}

// guardServiceRollbackTarget validates the version+extract(current) against
// the requirement, denying (409) on a version mismatch and (403) on a
// noncompliant target. selectNanoCPUs picks which inspected document
// (PreviousSpec for manual rollback, Spec for the automatic-rollback current-
// state check) is being validated. Returns false when a response was already
// written (deny/error) so callers must not also call respondAllow.
func (g *resourceLimitGuard) guardServiceRollbackTarget(w http.ResponseWriter, r *http.Request, id string, svc ServiceOptions, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta, next http.Handler, stateSource string, selectNanoCPUs func(ServiceInspectResult) int64) bool {
	rp.StateSource = stateSource
	version, ok := serviceVersionQuery(r)
	if !ok {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service update denied: a single numeric version query parameter is required", verbosity, rp)
		return false
	}
	if g.inspectService == nil {
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"service update denied: resource requirement verification unavailable", verbosity, rp)
		return false
	}
	rp.StateLookup = true
	current, found, err := g.inspectService(r.Context(), id)
	if err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to inspect service for resource-limit guard", err)
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"service update denied: resource requirement verification unavailable", verbosity, rp)
		return false
	}
	if !found {
		// Target does not exist; the forwarded request will itself 404.
		g.respondAllow(w, r, next, rp)
		return false
	}
	if version != current.Version {
		// The daemon's own version CAS will reject a stale version anyway,
		// but we must not forward a request we validated against a
		// since-superseded document — what we checked would no longer be
		// what applies.
		g.respondHardDeny(w, r, http.StatusConflict, reasonCodeResourceLimitPolicyStateChanged,
			"service update denied: the service state changed since it was inspected; retry with the current version", verbosity, rp)
		return false
	}

	nanoCPUs := selectNanoCPUs(current)
	if stateSource == "previous_spec" && !current.HasPreviousSpec {
		nanoCPUs = 0
	}
	reason, violation := "", ""
	if (svc.RequireCPULimit || svc.RequireCPULimitHard) && nanoCPUs <= 0 {
		reason = "service update denied: rollback target does not satisfy the required CPU limit"
		violation = "cpu"
	}
	if reason != "" {
		rp.Violation = violation
		g.respondPolicyDenied(w, r, next, reason, verbosity, rp)
		return false
	}
	return true
}

// ServiceInspectResult carries the resource-limit-relevant subset of
// GET /services/{id}: the optimistic-concurrency version plus the current and
// (if any) previous spec's TaskTemplate.Resources.Limits.NanoCPUs.
type ServiceInspectResult struct {
	Version              uint64
	SpecNanoCPUs         int64
	HasPreviousSpec      bool
	PreviousSpecNanoCPUs int64
}

// ServiceInspectFunc looks up a service's current version/spec/previous-spec
// resource state by ID. found=false with err=nil means the service does not
// exist (404).
type ServiceInspectFunc func(ctx context.Context, id string) (ServiceInspectResult, bool, error)

// NewDockerServiceInspectorWithRoundTripper returns a service resource-state
// inspector that issues its GET through the shared upstream RoundTripper.
func NewDockerServiceInspectorWithRoundTripper(rt http.RoundTripper) ServiceInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, id string) (ServiceInspectResult, bool, error) {
		requestPath, ok := dockerresource.InspectPath(dockerresource.KindService, id)
		if !ok {
			return ServiceInspectResult{}, false, fmt.Errorf("no inspect path for service %q", id)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil) // #nosec G704 -- InspectPath accepts only a validated engine resource identifier.
		if err != nil {
			return ServiceInspectResult{}, false, err
		}
		resp, err := client.Do(req) // #nosec G704 -- the injected transport targets the local container-engine socket, not the URL host.
		if err != nil {
			return ServiceInspectResult{}, false, err
		}
		defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return ServiceInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ServiceInspectResult{}, false, fmt.Errorf("inspect service %q returned status %d", id, resp.StatusCode)
		}

		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ServiceInspectResult{}, false, err
		}

		type resourceLimits struct {
			TaskTemplate struct {
				Resources struct {
					Limits struct {
						NanoCPUs int64 `json:"NanoCPUs"`
					} `json:"Limits"`
				} `json:"Resources"`
			} `json:"TaskTemplate"`
		}
		var decoded struct {
			Version struct {
				Index uint64 `json:"Index"`
			} `json:"Version"`
			Spec         resourceLimits  `json:"Spec"`
			PreviousSpec *resourceLimits `json:"PreviousSpec"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return ServiceInspectResult{}, false, err
		}

		result := ServiceInspectResult{
			Version:      decoded.Version.Index,
			SpecNanoCPUs: decoded.Spec.TaskTemplate.Resources.Limits.NanoCPUs,
		}
		if decoded.PreviousSpec != nil {
			result.HasPreviousSpec = true
			result.PreviousSpecNanoCPUs = decoded.PreviousSpec.TaskTemplate.Resources.Limits.NanoCPUs
		}
		return result, true, nil
	}
}

// ---------------------------------------------------------------------------
// Shared response helpers
// ---------------------------------------------------------------------------

// readBoundedResponseBody reads a daemon inspect response up to
// MaxResponseBodyBytes+1, rejecting oversized payloads rather than risking
// unbounded memory use on an inspect response.
func readBoundedResponseBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > MaxResponseBodyBytes {
		return nil, fmt.Errorf("inspect response exceeds %d byte limit", MaxResponseBodyBytes)
	}
	return body, nil
}

// respondAllow records an evaluated-allow outcome and forwards the request.
func (g *resourceLimitGuard) respondAllow(w http.ResponseWriter, r *http.Request, next http.Handler, rp *logging.ResourcePolicyMeta) {
	rp.Result = "allow"
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.ResourcePolicy = rp
	}
	next.ServeHTTP(w, r)
}

// respondPolicyDenied handles the one reason code (resource_limit_policy_denied)
// that honors the resolved profile's warn/audit rollout posture — a genuine
// policy violation on an otherwise well-formed, successfully-inspected
// request.
func (g *resourceLimitGuard) respondPolicyDenied(w http.ResponseWriter, r *http.Request, next http.Handler, reason string, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta) {
	meta := logging.MetaForRequest(w, r)
	if meta.AllowsPassThrough() {
		rp.Result = "would_deny"
		if meta != nil {
			meta.ResourcePolicy = rp
		}
		logging.SetWouldDenyWithCode(w, r, reasonCodeResourceLimitPolicyDenied, reason, nil)
		next.ServeHTTP(w, r)
		return
	}
	rp.Result = "deny"
	if meta != nil {
		meta.ResourcePolicy = rp
	}
	logging.SetDeniedWithCode(w, r, reasonCodeResourceLimitPolicyDenied, reason, nil)
	if err := httpjson.Write(w, http.StatusForbidden, denyResponse(r, reason, verbosity)); err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to encode resource-limit denial response", err)
	}
}

// respondHardDeny handles every OTHER reason code (invalid request, lookup
// failure, stale-state conflict) — these never honor warn/audit pass-through
// in any rollout mode: a corrupt request or an unreliable state lookup must
// not silently forward just because the profile is in warn/audit mode.
func (g *resourceLimitGuard) respondHardDeny(w http.ResponseWriter, r *http.Request, status int, reasonCode, reason string, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta) {
	rp.Result = resourcePolicyResultForReasonCode(reasonCode)
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.ResourcePolicy = rp
	}
	logging.SetDeniedWithCode(w, r, reasonCode, reason, nil)
	if err := httpjson.Write(w, status, denyResponse(r, reason, verbosity)); err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to encode resource-limit denial response", err)
	}
}

// resourcePolicyResultForReasonCode maps a hard-deny reason code to its
// ResourcePolicyMeta.Result class. Everything that isn't a lookup failure or
// a stale-state conflict (request-invalid, body-too-large) is "invalid".
func resourcePolicyResultForReasonCode(reasonCode string) string {
	switch reasonCode {
	case reasonCodeResourceLimitPolicyLookupFailed:
		return "lookup_failed"
	case reasonCodeResourceLimitPolicyStateChanged:
		return "state_changed"
	default:
		return "invalid"
	}
}
