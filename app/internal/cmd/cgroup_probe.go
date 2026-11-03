package cmd

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/upstream"
)

// cgroupV1RefreshInterval is how often the cgroup version probe is re-run
// while allow_host_cgroupns_on_cgroup_v1 is set anywhere. A daemon migrated
// between cgroup v1 and v2 without restarting sockguard is picked up within
// this window; health changes and hot reloads trigger an earlier re-probe.
const cgroupV1RefreshInterval = 5 * time.Minute

// cgroupV1Tracker owns the live "every upstream endpoint is cgroup v1" answer
// the container-create policy reads per request. It is process-scoped, shared
// by every handler chain generation, and fails closed: the answer is true only
// right after a full probe in which every endpoint reported CgroupVersion "1".
// A nil tracker always answers false.
type cgroupV1Tracker struct {
	deps   *serveDeps
	logger *slog.Logger
	res    *upstream.Resolver

	v1     atomic.Bool
	wanted atomic.Bool
	// mu serializes refreshes so a slow periodic probe cannot overwrite the
	// result of a later one.
	mu     sync.Mutex
	kickCh chan struct{}
}

func newCgroupV1Tracker(deps *serveDeps, res *upstream.Resolver, logger *slog.Logger) *cgroupV1Tracker {
	return &cgroupV1Tracker{deps: deps, res: res, logger: logger, kickCh: make(chan struct{}, 1)}
}

// isV1 is the per-request read.
func (t *cgroupV1Tracker) isV1() bool {
	return t != nil && t.v1.Load()
}

// isV1Func returns the reader for the filter options, or nil for a nil
// tracker (the filter then falls back to its static false).
func (t *cgroupV1Tracker) isV1Func() func() bool {
	if t == nil {
		return nil
	}
	return t.isV1
}

// seed records the startup result and whether the option is set.
func (t *cgroupV1Tracker) seed(wanted, v1 bool) {
	if t == nil {
		return
	}
	t.wanted.Store(wanted)
	t.v1.Store(wanted && v1)
}

// setWanted records whether any policy sets the option and reports whether it
// was just switched on. Turning it on closes the gate until refresh completes;
// turning it off closes it for good.
func (t *cgroupV1Tracker) setWanted(wanted bool) (enabled bool) {
	if t == nil {
		return false
	}
	was := t.wanted.Swap(wanted)
	if !wanted || !was {
		t.v1.Store(false)
	}
	return wanted && !was
}

// kick asks the refresh loop for an immediate re-probe without blocking. It is
// wired to the resolver's endpoint health transitions.
func (t *cgroupV1Tracker) kick() {
	if t == nil {
		return
	}
	select {
	case t.kickCh <- struct{}{}:
	default:
	}
}

// refresh re-probes every endpoint's GET /info and stores the result. It does
// nothing (and sends the daemon nothing) while the option is unset. Any probe
// failure, or any endpoint that is not v1, closes the gate.
func (t *cgroupV1Tracker) refresh(ctx context.Context) {
	if t == nil || !t.wanted.Load() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.wanted.Load() {
		return
	}
	endpoints := t.res.Endpoints()
	v1 := len(endpoints) > 0
	for i, ep := range endpoints {
		rt, err := t.res.EndpointRoundTripper(i)
		if err != nil {
			t.logger.Warn("cgroup version re-probe failed; allow_host_cgroupns_on_cgroup_v1 stays closed", "error", err, "endpoint", ep.String())
			v1 = false
			break
		}
		if !endpointIsCgroupV1(ctx, t.deps, rt, ep, t.logger) {
			v1 = false
			break
		}
	}
	// A reload may have switched the option off while the probes ran.
	v1 = v1 && t.wanted.Load()
	if prev := t.v1.Swap(v1); prev != v1 {
		t.logger.Warn("upstream cgroup version result changed", "upstream_cgroup_v1", v1, "was", prev)
	}
}

// run re-probes every interval and on every kick until ctx ends.
func (t *cgroupV1Tracker) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-t.kickCh:
		}
		t.refresh(ctx)
	}
}

// startCgroupV1Refresh launches the refresh loop and returns its stop func.
func (r *serveRuntime) startCgroupV1Refresh(ctx context.Context) func() {
	if r == nil || r.cgroupV1 == nil {
		return func() {}
	}
	loopCtx, cancel := context.WithCancel(ctx)
	go r.cgroupV1.run(loopCtx, cgroupV1RefreshInterval)
	return cancel
}
