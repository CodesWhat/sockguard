package ratelimit

import (
	"math"
	"strings"
	"sync/atomic"
)

// Priority is the per-profile priority tier used by the global-concurrency
// fairness gate. Higher tiers reserve more of the global concurrency budget
// so that admin or otherwise latency-sensitive profiles cannot be starved by
// noisy low-priority callers under contention.
type Priority int

const (
	// PriorityNormal is the default tier. Equivalent to no priority field set.
	PriorityNormal Priority = iota
	// PriorityLow tier yields the most under contention.
	PriorityLow
	// PriorityHigh tier reserves the full global budget for its requests.
	PriorityHigh
)

// String returns the lowercase config-form name of the priority.
func (p Priority) String() string {
	switch p {
	case PriorityLow:
		return "low"
	case PriorityHigh:
		return "high"
	default:
		return "normal"
	}
}

// ParsePriority resolves a config string to a Priority value. Empty input
// returns PriorityNormal so omitting the field preserves prior behavior.
// Unknown values return (PriorityNormal, false) so the validator can flag them.
func ParsePriority(s string) (Priority, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "normal":
		return PriorityNormal, true
	case "low":
		return PriorityLow, true
	case "high":
		return PriorityHigh, true
	default:
		return PriorityNormal, false
	}
}

// priorityShare returns the fraction of the global concurrency budget a
// priority tier may consume. Soft preemption: a higher tier's floor sits
// above the lower tier's floor, so when total inflight exceeds the lower
// tier's threshold the lower tier 429s while higher tiers keep going.
//
// Shares are hardcoded for v0.7.0 to keep the public config surface minimal.
// Operators have asked for configurable shares before we expose them.
func priorityShare(p Priority) float64 {
	switch p {
	case PriorityLow:
		return 0.5
	case PriorityHigh:
		return 1.0
	default:
		return 0.8
	}
}

// priorityThreshold computes the integer in-flight ceiling for a priority
// tier against a global cap. Rounded down so a profile cannot exceed its
// share by even one request.
func priorityThreshold(p Priority, globalMax int64) int64 {
	if globalMax <= 0 {
		return 0
	}
	share := priorityShare(p)
	t := int64(math.Floor(float64(globalMax) * share))
	if t < 1 {
		// A non-zero global cap should always admit at least one high-tier
		// request; floor() can return 0 for a very small cap × small share.
		// Forcing a 1-floor for high keeps the budget useful at the edges.
		if p == PriorityHigh {
			return 1
		}
		return 0
	}
	return t
}

// GlobalInflightTracker tracks the system-wide in-flight request count
// across all profiles and gates admission on a priority-aware threshold.
//
// Acquire is non-blocking: requests above their priority's threshold are
// denied immediately. The caller must call Release exactly once per
// successful Acquire, via defer immediately after checking the return value.
type GlobalInflightTracker struct {
	current atomic.Int64
}

// Acquire admits the request when global inflight is below the priority's
// threshold. Returns (ok=true, current=incremented value, threshold) on
// success; (ok=false, current=unchanged, threshold) on denial.
//
// globalMax <= 0 disables the gate (always admits, current still tracked).
//
// CAS loop bounds the increment so the gate never over-admits under
// concurrent Acquire calls.
func (t *GlobalInflightTracker) Acquire(p Priority, globalMax int64) (ok bool, current int64, threshold int64) {
	if globalMax <= 0 {
		next := t.current.Add(1)
		return true, next, 0
	}
	threshold = priorityThreshold(p, globalMax)
	for {
		curr := t.current.Load()
		if curr >= threshold {
			return false, curr, threshold
		}
		if t.current.CompareAndSwap(curr, curr+1) {
			return true, curr + 1, threshold
		}
		// Another goroutine incremented between Load and CAS; retry.
	}
}

// AcquirePassThrough unconditionally increments the global in-flight counter.
// It is used for requests that were denied by the priority gate but are allowed
// to pass through under warn / audit rollout mode. The gauge must reflect real
// concurrency during staged rollouts so operators can correctly size the global
// cap from dashboard data.
//
// The caller is responsible for calling Release exactly once after the request
// completes. AcquirePassThrough does not return a release function to avoid the
// heap allocation a method-value closure would incur; the caller holds a direct
// reference to the tracker and calls Release() itself.
func (t *GlobalInflightTracker) AcquirePassThrough() {
	t.current.Add(1)
}

// Release decrements the global in-flight counter. Safe to call multiple
// times only as paired releases for successful Acquire calls; underflow is
// clamped at zero to guard against bookkeeping errors.
func (t *GlobalInflightTracker) Release() {
	for {
		curr := t.current.Load()
		if curr <= 0 {
			return
		}
		if t.current.CompareAndSwap(curr, curr-1) {
			return
		}
	}
}

// Current returns the current global in-flight count without modifying it.
func (t *GlobalInflightTracker) Current() int64 {
	return t.current.Load()
}
