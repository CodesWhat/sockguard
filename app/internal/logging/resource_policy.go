package logging

import (
	"log/slog"
	"sync"
)

// ResourcePolicyMeta records the outcome of #152's post-ownership
// resource-limit guard (internal/filter/resource_limit_guard.go) for a single
// request. It is deliberately bounded to classification fields — never raw
// current/effective resource values, full inspect JSON, PreviousSpec content,
// labels, or identifiers beyond the normalized path RequestMeta already
// carries — so access and audit logs stay safe to ship off-box.
type ResourcePolicyMeta struct {
	// Evaluated is true once the guard actually consulted require_* policy
	// for this request (i.e. at least one applicable flag was active). When
	// false, RequestMeta.ResourcePolicy is nil instead of an evaluated-false
	// value — Evaluated exists mainly for callers that already hold a
	// non-nil pointer.
	Evaluated bool
	// Kind is "container" or "service".
	Kind string
	// Operation is "create", "update", "manual_rollback", or
	// "automatic_rollback".
	Operation string
	// StateSource is "request", "effective_state", "previous_spec", or
	// "current_spec" — which document supplied the values that were
	// validated.
	StateSource string
	// Requirements is a stable, comma-joined list of the requirement classes
	// that were active for this request (e.g. "memory,cpu,pids").
	Requirements string
	// Result is "allow", "deny", "would_deny", "invalid", "lookup_failed", or
	// "state_changed".
	Result string
	// Violation is the requirement class that failed ("memory"|"cpu"|
	// "hard_cpu"|"pids"), empty when Result is not a policy denial.
	Violation string
	// StateLookup is true when the guard issued a daemon GET to resolve
	// omitted/rollback state for this request.
	StateLookup bool
}

var resourcePolicyMetaPool = sync.Pool{
	New: func() any {
		return &ResourcePolicyMeta{}
	},
}

// GetResourcePolicyMeta returns a pooled, zeroed ResourcePolicyMeta for the
// caller to populate and attach to RequestMeta.ResourcePolicy. Only called by
// filter.ResourceLimitGuard when at least one applicable require_* flag is
// active, so unrelated requests never pay for this allocation.
func GetResourcePolicyMeta() *ResourcePolicyMeta {
	m, _ := resourcePolicyMetaPool.Get().(*ResourcePolicyMeta)
	if m == nil {
		return &ResourcePolicyMeta{}
	}
	return m
}

func putResourcePolicyMeta(m *ResourcePolicyMeta) {
	if m == nil {
		return
	}
	*m = ResourcePolicyMeta{}
	resourcePolicyMetaPool.Put(m)
}

// appendResourcePolicyAttrs appends resource_policy_* access-log fields when
// the guard evaluated policy for this request. Nil (the common case: no
// applicable require_* flag) appends nothing.
func appendResourcePolicyAttrs(attrs []slog.Attr, rp *ResourcePolicyMeta) []slog.Attr {
	if rp == nil || !rp.Evaluated {
		return attrs
	}
	attrs = append(attrs,
		slog.Bool("resource_policy_evaluated", rp.Evaluated),
		slog.String("resource_policy_kind", SafeString(rp.Kind)),
		slog.String("resource_policy_operation", SafeString(rp.Operation)),
		slog.String("resource_policy_source", SafeString(rp.StateSource)),
		slog.String("resource_policy_requirements", SafeString(rp.Requirements)),
		slog.String("resource_policy_result", SafeString(rp.Result)),
		slog.Bool("resource_policy_state_lookup", rp.StateLookup),
	)
	if rp.Violation != "" {
		attrs = append(attrs, slog.String("resource_policy_violation", SafeString(rp.Violation)))
	}
	return attrs
}
