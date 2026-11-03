package cmd

import (
	"context"
	"log/slog"
	"net/http"
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

	// state packs the wanted and v1 bits into one word so a probe result is
	// published only if the option is still wanted, in a single CAS.
	state atomic.Uint32
	// mu serializes refreshes so a slow periodic probe cannot overwrite the
	// result of a later one.
	mu     sync.Mutex
	kickCh chan struct{}

	// probe and the retry bounds are fields so tests can drive them.
	probe     cgroupEndpointProber
	retryBase time.Duration
	retryMax  time.Duration
}

const (
	cgroupStateWanted uint32 = 1 << iota
	cgroupStateV1
)

const (
	// cgroupV1RetryBase and cgroupV1RetryMax bound the backoff retry run after
	// a probe error: 1s, 2s, 4s, 8s, then every 30s until the next tick.
	cgroupV1RetryBase = time.Second
	cgroupV1RetryMax  = 30 * time.Second
)

// cgroupEndpointProber probes one endpoint's cgroup version.
type cgroupEndpointProber func(ctx context.Context, rt http.RoundTripper, ep upstream.Endpoint) cgroupProbeOutcome

func newCgroupV1Tracker(deps *serveDeps, res *upstream.Resolver, logger *slog.Logger) *cgroupV1Tracker {
	t := &cgroupV1Tracker{deps: deps, res: res, logger: logger, kickCh: make(chan struct{}, 1), retryBase: cgroupV1RetryBase, retryMax: cgroupV1RetryMax}
	t.probe = func(ctx context.Context, rt http.RoundTripper, ep upstream.Endpoint) cgroupProbeOutcome {
		return probeEndpointCgroup(ctx, deps, rt, ep, logger)
	}
	return t
}

// isV1 is the per-request read.
func (t *cgroupV1Tracker) isV1() bool {
	return t != nil && t.state.Load()&cgroupStateV1 != 0
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
	var st uint32
	if wanted {
		st |= cgroupStateWanted
		if v1 {
			st |= cgroupStateV1
		}
	}
	t.state.Store(st)
}

// setWanted records whether any policy sets the option and reports whether it
// was just switched on. Turning it on closes the gate until refresh completes;
// turning it off closes it for good.
func (t *cgroupV1Tracker) setWanted(wanted bool) (enabled bool) {
	if t == nil {
		return false
	}
	for {
		old := t.state.Load()
		was := old&cgroupStateWanted != 0
		var next uint32
		if wanted {
			next = cgroupStateWanted
			if was {
				next |= old & cgroupStateV1
			}
		}
		if t.state.CompareAndSwap(old, next) {
			return wanted && !was
		}
	}
}

func (t *cgroupV1Tracker) isWanted() bool {
	return t.state.Load()&cgroupStateWanted != 0
}

// publish stores a probe result only while the option is still wanted, so a
// result that lands after a reload switched the option off cannot reopen the
// gate. It returns the previous v1 bit and whether the result was stored.
func (t *cgroupV1Tracker) publish(v1 bool) (prev bool, ok bool) {
	for {
		old := t.state.Load()
		if old&cgroupStateWanted == 0 {
			return false, false
		}
		next := old &^ cgroupStateV1
		if v1 {
			next |= cgroupStateV1
		}
		if t.state.CompareAndSwap(old, next) {
			return old&cgroupStateV1 != 0, true
		}
	}
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
// failure, or any endpoint that is not v1, closes the gate. It reports whether
// the gate is closed because a probe errored, which is the only case worth a
// short retry; a clean "not v1" answer is final until the next tick.
func (t *cgroupV1Tracker) refresh(ctx context.Context) (retry bool) {
	if t == nil || !t.isWanted() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.isWanted() {
		return false
	}
	endpoints := t.res.Endpoints()
	v1 := len(endpoints) > 0
	failed := false
	for i, ep := range endpoints {
		rt, err := t.res.EndpointRoundTripper(i)
		if err != nil {
			t.logger.Warn("cgroup version re-probe failed; allow_host_cgroupns_on_cgroup_v1 stays closed", "error", err, "endpoint", ep.String())
			v1, failed = false, true
			break
		}
		outcome := t.probe(ctx, rt, ep)
		if outcome != cgroupProbeV1 {
			v1, failed = false, outcome == cgroupProbeFailed
			break
		}
	}
	// A reload may have switched the option off while the probes ran; publish
	// refuses the result in that case.
	prev, ok := t.publish(v1)
	if !ok {
		return false
	}
	if prev != v1 {
		t.logger.Warn("upstream cgroup version result changed", "upstream_cgroup_v1", v1, "was", prev)
	}
	return failed && ctx.Err() == nil
}

// nextCgroupRetryDelay returns the next backoff delay (doubling from base,
// capped at max) and false when that retry would land at or after the next
// regular tick, which re-probes anyway.
func nextCgroupRetryDelay(prev, base, max time.Duration, now, nextTick time.Time) (time.Duration, bool) {
	delay := base
	if prev > 0 {
		delay = min(prev*2, max)
	}
	if !now.Add(delay).Before(nextTick) {
		return 0, false
	}
	return delay, true
}

// run re-probes every interval and on every kick until ctx ends. A probe that
// errors is retried on a short bounded backoff until the next tick.
func (t *cgroupV1Tracker) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	nextTick := time.Now().Add(interval)
	var (
		timer  *time.Timer
		retryC <-chan time.Time
		delay  time.Duration
	)
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer = nil
		}
		retryC = nil
	}
	defer stopTimer()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nextTick = time.Now().Add(interval)
			stopTimer()
			delay = 0
		case <-t.kickCh:
			stopTimer()
			delay = 0
		case <-retryC:
			retryC = nil
			timer = nil
		}
		if !t.refresh(ctx) {
			delay = 0
			continue
		}
		d, ok := nextCgroupRetryDelay(delay, t.retryBase, t.retryMax, time.Now(), nextTick)
		if !ok {
			delay = 0
			continue
		}
		delay = d
		timer = time.NewTimer(d)
		retryC = timer.C
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
