package config

import "strings"

// RolloutMode controls how a profile's deny decisions are applied. It is the
// operator-facing knob behind a staged policy rollout: a new policy can be
// configured with mode=audit to collect "what would have been blocked" data
// without affecting consumers, promoted to mode=warn so denied requests are
// loudly logged but still pass through, and finally moved to mode=enforce
// once the operator is confident no legitimate traffic is being caught.
type RolloutMode string

const (
	// RolloutEnforce is the default. Deny decisions block the request and the
	// proxy writes a 4xx response.
	RolloutEnforce RolloutMode = "enforce"
	// RolloutWarn lets the request pass through to the upstream Docker
	// daemon, emits a WARN-level audit record carrying the would-be deny
	// reason, and increments the deny / throttle counters with mode=warn so
	// operators can compare warn volume against historical enforce volume.
	RolloutWarn RolloutMode = "warn"
	// RolloutAudit is identical to warn except the audit record is emitted at
	// INFO level. Use it during silent dry-runs where warn-level log volume
	// would page on-call.
	RolloutAudit RolloutMode = "audit"
)

// String returns the canonical lowercase form of the mode.
func (m RolloutMode) String() string { return string(m) }

// AllowsPassThrough reports whether a deny decision under this mode should let
// the request continue to the upstream rather than write a deny response.
func (m RolloutMode) AllowsPassThrough() bool {
	return m == RolloutWarn || m == RolloutAudit
}

// ParseRolloutMode normalizes the operator-supplied value. An empty string is
// treated as RolloutEnforce so omitting the field in YAML is equivalent to
// configuring mode=enforce. Unknown values return (RolloutEnforce, false) so
// the validator can surface a clear error.
func ParseRolloutMode(s string) (RolloutMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "enforce":
		return RolloutEnforce, true
	case "warn":
		return RolloutWarn, true
	case "audit":
		return RolloutAudit, true
	default:
		return RolloutEnforce, false
	}
}
