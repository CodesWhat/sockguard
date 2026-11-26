package health

import (
	"sync"
	"time"
)

// DownTracker turns a stream of watchdog observations into a single verdict:
// has the upstream been continuously unreachable for at least threshold? It
// backs health.watchdog.exit_after, where the process exits non-zero so its
// orchestrator restarts it. A single reachable observation resets the clock,
// so a flapping upstream that keeps recovering never trips it.
type DownTracker struct {
	threshold time.Duration

	mu        sync.Mutex
	downSince time.Time
	tripped   bool
}

// NewDownTracker returns a tracker that trips after threshold of continuous
// unreachability. A non-positive threshold never trips.
func NewDownTracker(threshold time.Duration) *DownTracker {
	return &DownTracker{threshold: threshold}
}

// Observe records one watchdog observation and returns the length of the
// current outage and whether this call is the one that tripped the tracker.
// It reports tripped at most once: later down observations return false so the
// caller signals the process exactly once.
func (t *DownTracker) Observe(state WatchdogState) (down time.Duration, tripped bool) {
	if t == nil || t.threshold <= 0 {
		return 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if state.Up {
		t.downSince = time.Time{}
		return 0, false
	}
	if t.downSince.IsZero() {
		t.downSince = state.CheckedAt
	}
	down = state.CheckedAt.Sub(t.downSince)
	if t.tripped || down < t.threshold {
		return down, false
	}
	t.tripped = true
	return down, true
}
