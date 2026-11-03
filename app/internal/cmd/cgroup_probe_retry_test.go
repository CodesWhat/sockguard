package cmd

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/upstream"
)

// fakeCgroupProber answers from a script: outcomes[i] for the i-th call, the
// last entry repeating. onCall, when set, runs before the answer returns.
type fakeCgroupProber struct {
	outcomes []cgroupProbeOutcome
	calls    atomic.Int64
	onCall   func(n int64)
}

func (f *fakeCgroupProber) probe(_ context.Context, _ http.RoundTripper, _ upstream.Endpoint) cgroupProbeOutcome {
	n := f.calls.Add(1)
	if f.onCall != nil {
		f.onCall(n)
	}
	i := int(n) - 1
	if i >= len(f.outcomes) {
		i = len(f.outcomes) - 1
	}
	return f.outcomes[i]
}

func newFakeProbeTracker(t *testing.T, f *fakeCgroupProber) *cgroupV1Tracker {
	t.Helper()
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	tracker := newTestCgroupTracker(t, d)
	tracker.probe = f.probe
	tracker.retryBase = 5 * time.Millisecond
	tracker.retryMax = 20 * time.Millisecond
	tracker.seed(true, false)
	return tracker
}

func TestNextCgroupRetryDelay(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tests := []struct {
		name     string
		prev     time.Duration
		nextTick time.Time
		want     time.Duration
		wantOK   bool
	}{
		{"first retry uses base", 0, now.Add(time.Hour), time.Second, true},
		{"doubles", time.Second, now.Add(time.Hour), 2 * time.Second, true},
		{"doubles again", 4 * time.Second, now.Add(time.Hour), 8 * time.Second, true},
		{"caps at max", 20 * time.Second, now.Add(time.Hour), 30 * time.Second, true},
		{"stays at cap", 30 * time.Second, now.Add(time.Hour), 30 * time.Second, true},
		{"stops when retry would land on the tick", 4 * time.Second, now.Add(8 * time.Second), 0, false},
		{"stops when retry would land after the tick", 0, now.Add(500 * time.Millisecond), 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := nextCgroupRetryDelay(tt.prev, time.Second, 30*time.Second, now, tt.nextTick)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("nextCgroupRetryDelay = (%v, %v), want (%v, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestCgroupV1TrackerRefreshRetryVerdict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		outcome   cgroupProbeOutcome
		wantRetry bool
		wantV1    bool
	}{
		{"probe error asks for retry", cgroupProbeFailed, true, false},
		{"clean not-v1 is final", cgroupProbeNotV1, false, false},
		{"v1 opens the gate", cgroupProbeV1, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeCgroupProber{outcomes: []cgroupProbeOutcome{tt.outcome}}
			tracker := newFakeProbeTracker(t, f)
			if got := tracker.refresh(t.Context()); got != tt.wantRetry {
				t.Fatalf("refresh retry = %v, want %v", got, tt.wantRetry)
			}
			if tracker.isV1() != tt.wantV1 {
				t.Fatalf("isV1 = %v, want %v", tracker.isV1(), tt.wantV1)
			}
		})
	}
}

// A transient /info failure opens the gate on a short retry, long before the
// next regular tick.
func TestCgroupV1TrackerTransientFailureRecoversBeforeTick(t *testing.T) {
	t.Parallel()
	f := &fakeCgroupProber{outcomes: []cgroupProbeOutcome{cgroupProbeFailed, cgroupProbeFailed, cgroupProbeV1}}
	tracker := newFakeProbeTracker(t, f)
	go tracker.run(t.Context(), time.Hour)
	tracker.kick()
	waitForCgroup(t, "retry to open the gate", tracker.isV1)
	if n := f.calls.Load(); n != 3 {
		t.Fatalf("probe calls = %d, want 3", n)
	}
	time.Sleep(60 * time.Millisecond)
	if n := f.calls.Load(); n != 3 {
		t.Fatalf("probing continued after success: %d calls", n)
	}
}

// A clean "not v1" answer is not retried.
func TestCgroupV1TrackerNotV1IsNotRetried(t *testing.T) {
	t.Parallel()
	f := &fakeCgroupProber{outcomes: []cgroupProbeOutcome{cgroupProbeNotV1}}
	tracker := newFakeProbeTracker(t, f)
	go tracker.run(t.Context(), time.Hour)
	tracker.kick()
	waitForCgroup(t, "first probe", func() bool { return f.calls.Load() >= 1 })
	time.Sleep(80 * time.Millisecond)
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("probe calls = %d, want 1", n)
	}
	if tracker.isV1() {
		t.Fatal("gate must stay closed on not-v1")
	}
}

// With a persistent failure the gate stays closed and retries stop at the
// next tick instead of running forever.
func TestCgroupV1TrackerPersistentFailureStopsRetrying(t *testing.T) {
	t.Parallel()
	f := &fakeCgroupProber{outcomes: []cgroupProbeOutcome{cgroupProbeFailed}}
	tracker := newFakeProbeTracker(t, f)
	tracker.retryBase = 10 * time.Millisecond
	tracker.retryMax = 10 * time.Millisecond
	const interval = 100 * time.Millisecond
	go tracker.run(t.Context(), interval)
	tracker.kick()
	time.Sleep(3*interval + 50*time.Millisecond)
	// At most ~interval/base retries per window plus the tick probe itself.
	if n, max := f.calls.Load(), int64(4*(interval/tracker.retryBase+2)); n < 3 || n > max {
		t.Fatalf("probe calls = %d, want between 3 and %d", n, max)
	}
	if tracker.isV1() {
		t.Fatal("gate must stay closed while probes keep failing")
	}
}

// The option turned off while a probe is in flight must not be reopened by
// that probe's late v1 answer, and no retry follows.
func TestCgroupV1TrackerUnwantedMidProbeStaysClosed(t *testing.T) {
	t.Parallel()
	f := &fakeCgroupProber{outcomes: []cgroupProbeOutcome{cgroupProbeV1}}
	tracker := newFakeProbeTracker(t, f)
	f.onCall = func(int64) { tracker.setWanted(false) }
	if retry := tracker.refresh(t.Context()); retry {
		t.Fatal("refresh must not ask for a retry once the option is off")
	}
	if tracker.isV1() {
		t.Fatal("a result landing after the option was turned off reopened the gate")
	}
	if tracker.isWanted() {
		t.Fatal("publish must not resurrect the wanted bit")
	}

	// Same race on the error path: no retry loop for an unwanted option.
	f2 := &fakeCgroupProber{outcomes: []cgroupProbeOutcome{cgroupProbeFailed}}
	tracker2 := newFakeProbeTracker(t, f2)
	f2.onCall = func(int64) { tracker2.setWanted(false) }
	if retry := tracker2.refresh(t.Context()); retry {
		t.Fatal("a failed probe for an unwanted option must not retry")
	}
}

// Canceling the context stops the loop, including a pending retry.
func TestCgroupV1TrackerCancelStopsRetry(t *testing.T) {
	t.Parallel()
	f := &fakeCgroupProber{outcomes: []cgroupProbeOutcome{cgroupProbeFailed}}
	tracker := newFakeProbeTracker(t, f)
	tracker.retryBase = 10 * time.Millisecond
	tracker.retryMax = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		tracker.run(ctx, time.Hour)
		close(done)
	}()
	tracker.kick()
	waitForCgroup(t, "a retry", func() bool { return f.calls.Load() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	n := f.calls.Load()
	time.Sleep(60 * time.Millisecond)
	if got := f.calls.Load(); got != n {
		t.Fatalf("probing continued after cancel: %d -> %d", n, got)
	}
}
