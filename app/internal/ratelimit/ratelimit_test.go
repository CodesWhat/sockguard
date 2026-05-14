package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixedClock returns a nowFn that can be advanced manually.
type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFixedClock(t time.Time) *fixedClock { return &fixedClock{now: t} }

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ---------------------------------------------------------------------------
// bucket: token math
// ---------------------------------------------------------------------------

func TestBucket_AllowConsumeAndDeny(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(10, 10, clk.Now) // 10 tokens/s, burst 10

	// Consume all 10 tokens immediately.
	for i := range 10 {
		ok, _ := b.Allow()
		if !ok {
			t.Fatalf("expected Allow() = true on token %d", i+1)
		}
	}

	// 11th should be denied.
	ok, retryAfter := b.Allow()
	if ok {
		t.Fatal("expected Allow() = false when bucket empty")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected retryAfter > 0, got %d", retryAfter)
	}
}

func TestBucket_RefillPartial(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(10, 10, clk.Now) // 10 tokens/s, burst 10

	// Drain the bucket.
	for range 10 {
		b.Allow() //nolint:errcheck
	}

	// Advance 500ms → should refill 5 tokens.
	clk.Advance(500 * time.Millisecond)
	for i := range 5 {
		ok, _ := b.Allow()
		if !ok {
			t.Fatalf("expected Allow() = true on refilled token %d", i+1)
		}
	}
	ok, _ := b.Allow()
	if ok {
		t.Fatal("expected Allow() = false after consuming refilled tokens")
	}
}

func TestBucket_RefillCapAtBurst(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(10, 5, clk.Now) // 10 tokens/s, burst 5

	// Advance 10 seconds: without capping this would yield 100 tokens.
	clk.Advance(10 * time.Second)

	// Should still be capped at burst=5.
	for i := range 5 {
		ok, _ := b.Allow()
		if !ok {
			t.Fatalf("expected Allow() = true on token %d", i+1)
		}
	}
	ok, _ := b.Allow()
	if ok {
		t.Fatal("expected Allow() = false after burst capacity exhausted")
	}
}

func TestBucket_RefillAcrossMultipleSeconds(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(2, 10, clk.Now) // 2 tokens/s, burst 10

	// Drain completely.
	for range 10 {
		b.Allow() //nolint:errcheck
	}

	// Advance 3 seconds → +6 tokens.
	clk.Advance(3 * time.Second)
	for i := range 6 {
		ok, _ := b.Allow()
		if !ok {
			t.Fatalf("expected Allow() = true on token %d after 3s refill", i+1)
		}
	}
	ok, _ := b.Allow()
	if ok {
		t.Fatal("expected Allow() = false after consuming 3s worth of tokens")
	}
}

func TestBucket_RetryAfterCalculation(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(1, 1, clk.Now) // 1 token/s, burst 1

	// Consume the single token.
	ok, _ := b.Allow()
	if !ok {
		t.Fatal("first Allow() should succeed")
	}

	// Next call should be denied with retryAfter = 1s (ceiling of ~1.0).
	ok, retryAfter := b.Allow()
	if ok {
		t.Fatal("second Allow() should fail")
	}
	if retryAfter != 1 {
		t.Fatalf("expected retryAfter = 1, got %d", retryAfter)
	}
}

func TestBucket_JustRefilled(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(10, 10, clk.Now)

	// Drain completely.
	for range 10 {
		b.Allow() //nolint:errcheck
	}
	ok, _ := b.Allow()
	if ok {
		t.Fatal("should be denied after drain")
	}

	// Advance exactly 100ms → 1 token refilled.
	clk.Advance(100 * time.Millisecond)
	ok, _ = b.Allow()
	if !ok {
		t.Fatal("should be allowed after 100ms refill at 10t/s")
	}
}

// ---------------------------------------------------------------------------
// Limiter
// ---------------------------------------------------------------------------

func TestLimiter_AnonymousBucketing(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	l := newLimiterWithClock(1, 1, clk.Now)

	// Consume the single token with an explicit empty clientID.
	ok, _ := l.Allow("")
	if !ok {
		t.Fatal("Allow() should succeed on first call")
	}
	// Second call with empty clientID hits the same _anonymous bucket.
	ok, _ = l.Allow("")
	if ok {
		t.Fatal("Allow() should fail; _anonymous bucket exhausted")
	}
}

func TestLimiter_SeparateBucketsPerClient(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	l := newLimiterWithClock(1, 1, clk.Now)

	ok1, _ := l.Allow("alice")
	ok2, _ := l.Allow("bob")
	if !ok1 || !ok2 {
		t.Fatal("separate clients should get independent buckets")
	}

	// Both buckets now empty.
	ok1, _ = l.Allow("alice")
	ok2, _ = l.Allow("bob")
	if ok1 || ok2 {
		t.Fatal("both buckets should be exhausted")
	}
}

// ---------------------------------------------------------------------------
// InflightTracker
// ---------------------------------------------------------------------------

func TestInflightTracker_BasicAdmitAndRelease(t *testing.T) {
	var tr InflightTracker

	ok, count := tr.Acquire("alice", 2)
	if !ok || count != 1 {
		t.Fatalf("Acquire 1/2: ok=%v count=%d", ok, count)
	}

	ok, count = tr.Acquire("alice", 2)
	if !ok || count != 2 {
		t.Fatalf("Acquire 2/2: ok=%v count=%d", ok, count)
	}

	// 3rd request should be denied.
	ok, count = tr.Acquire("alice", 2)
	if ok {
		t.Fatalf("Acquire 3/2: expected deny, got count=%d", count)
	}

	// Release one → should admit again.
	tr.Release("alice")
	ok, count = tr.Acquire("alice", 2)
	if !ok || count != 2 {
		t.Fatalf("Acquire after Release: ok=%v count=%d", ok, count)
	}
}

func TestInflightTracker_AnonymousBucketing(t *testing.T) {
	var tr InflightTracker

	ok, _ := tr.Acquire("", 1)
	if !ok {
		t.Fatal("first acquire of anonymous should succeed")
	}
	ok, _ = tr.Acquire("", 1)
	if ok {
		t.Fatal("second acquire of anonymous should fail at cap=1")
	}
}

func TestInflightTracker_ReleaseNoOp(t *testing.T) {
	var tr InflightTracker
	// Should not panic.
	tr.Release("nobody")
}

func TestInflightTracker_SeparateCountsPerClient(t *testing.T) {
	var tr InflightTracker

	tr.Acquire("a", 1) //nolint:errcheck
	tr.Acquire("b", 1) //nolint:errcheck

	if tr.Current("a") != 1 {
		t.Fatalf("expected 1 inflight for a, got %d", tr.Current("a"))
	}
	if tr.Current("b") != 1 {
		t.Fatalf("expected 1 inflight for b, got %d", tr.Current("b"))
	}

	tr.Release("a")
	if tr.Current("a") != 0 {
		t.Fatalf("expected 0 inflight for a after release, got %d", tr.Current("a"))
	}
}

// TestInflightTracker_Race exercises the tracker under -race for 100
// concurrent goroutines simultaneously acquiring and releasing.
func TestInflightTracker_Race(t *testing.T) {
	const cap = 10
	const goroutines = 100
	var tr InflightTracker
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			ok, _ := tr.Acquire("shared", cap)
			if ok {
				defer tr.Release("shared")
				// Simulate some work.
				time.Sleep(time.Microsecond)
			}
		}()
	}
	wg.Wait()

	if got := tr.Current("shared"); got != 0 {
		t.Fatalf("expected all counters released, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// AuditSampler
// ---------------------------------------------------------------------------

func TestAuditSampler_FirstEmitAlways(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	s, stop := newAuditSamplerWithClock(clk.Now)
	defer stop()

	if !s.ShouldEmit("alice", ReasonRateLimit) {
		t.Fatal("first emit for new (client,reason) should always be true")
	}
}

func TestAuditSampler_SuppressesWithin1s(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	s, stop := newAuditSamplerWithClock(clk.Now)
	defer stop()

	s.ShouldEmit("alice", ReasonRateLimit)

	// Advance 999ms — still within the 1s window.
	clk.Advance(999 * time.Millisecond)
	if s.ShouldEmit("alice", ReasonRateLimit) {
		t.Fatal("second emit within 1s window should be suppressed")
	}
}

func TestAuditSampler_AllowsAfter1s(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	s, stop := newAuditSamplerWithClock(clk.Now)
	defer stop()

	s.ShouldEmit("alice", ReasonRateLimit)
	clk.Advance(time.Second)

	if !s.ShouldEmit("alice", ReasonRateLimit) {
		t.Fatal("emit at exactly 1s boundary should be allowed")
	}
}

func TestAuditSampler_IndependentPerClientAndReason(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	s, stop := newAuditSamplerWithClock(clk.Now)
	defer stop()

	// Both should emit immediately since they are different keys.
	if !s.ShouldEmit("alice", ReasonRateLimit) {
		t.Fatal("alice/rate should emit on first call")
	}
	if !s.ShouldEmit("bob", ReasonRateLimit) {
		t.Fatal("bob/rate should emit on first call — different client")
	}
	if !s.ShouldEmit("alice", ReasonConcurrency) {
		t.Fatal("alice/concurrency should emit on first call — different reason")
	}
}

func TestAuditSampler_Eviction(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	s, stop := newAuditSamplerWithClock(clk.Now)
	defer stop()

	s.ShouldEmit("alice", ReasonRateLimit)

	// Advance past the 60s eviction TTL.
	clk.Advance(61 * time.Second)
	s.evict(60 * time.Second)

	// After eviction the entry is gone, so the next emit should be true again.
	if !s.ShouldEmit("alice", ReasonRateLimit) {
		t.Fatal("after eviction the entry should be gone and emit should be allowed")
	}
}

// ---------------------------------------------------------------------------
// bucket: cost-weighted withdrawals via AllowN
// ---------------------------------------------------------------------------

func TestBucket_AllowN_ConsumesNTokens(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(100, 10, clk.Now) // burst 10

	// Cost-5 withdrawals should succeed twice and deny the third.
	for i := range 2 {
		ok, _ := b.AllowN(5)
		if !ok {
			t.Fatalf("expected AllowN(5) = true on call %d (burst=10)", i+1)
		}
	}
	ok, retryAfter := b.AllowN(5)
	if ok {
		t.Fatal("expected AllowN(5) = false after 2 cost-5 withdrawals from burst=10")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected retryAfter > 0 on denial, got %d", retryAfter)
	}
}

func TestBucket_AllowN_RetryAfterScalesWithCost(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(1, 10, clk.Now) // 1 token/s, burst 10

	// Drain completely.
	for range 10 {
		b.Allow() //nolint:errcheck
	}

	// Cost-5 denial should compute retryAfter = ceil(5 / 1) = 5s.
	ok, retryAfter := b.AllowN(5)
	if ok {
		t.Fatal("expected AllowN(5) = false on empty bucket")
	}
	if retryAfter != 5 {
		t.Fatalf("expected retryAfter = 5 for cost=5 at 1 token/s, got %d", retryAfter)
	}
}

func TestBucket_AllowN_ClampsCostBelowOne(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	b := newBucket(10, 10, clk.Now)

	// cost=0 should behave like cost=1 (otherwise a misconfig could bypass).
	for range 10 {
		ok, _ := b.AllowN(0)
		if !ok {
			t.Fatal("AllowN(0) should clamp to AllowN(1) and succeed within burst")
		}
	}
	ok, _ := b.AllowN(0)
	if ok {
		t.Fatal("AllowN(0) should be denied after the bucket is empty")
	}
}

// Clock going backwards (e.g., NTP step) must not over-refill the bucket. The
// elapsed > 0 guard in AllowN skips refill when now.Sub(lastRefill) <= 0; this
// test exercises that branch directly.
func TestBucket_TimeBackwardsDoesNotRefill(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0).Add(10 * time.Second))
	b := newBucket(10, 10, clk.Now)

	// Drain to zero.
	for range 10 {
		b.Allow() //nolint:errcheck
	}
	if ok, _ := b.Allow(); ok {
		t.Fatal("bucket should be empty before clock step")
	}

	// Step clock backwards by 5 seconds. Refill must NOT happen.
	clk.Advance(-5 * time.Second)
	if ok, _ := b.Allow(); ok {
		t.Fatal("Allow() must remain denied after clock step backwards")
	}
}

// Empty clientID flows through ShouldEmit's anonymous fallback. The result
// should be identical to passing AnonymousClientID explicitly.
func TestAuditSampler_EmptyClientIDFallsBackToAnonymous(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	s, stop := newAuditSamplerWithClock(clk.Now)
	defer stop()

	if !s.ShouldEmit("", ReasonRateLimit) {
		t.Fatal("first emit for empty clientID should be true")
	}
	// Second call with explicit AnonymousClientID hits the same bucket and is
	// suppressed within the 1s window.
	if s.ShouldEmit(AnonymousClientID, ReasonRateLimit) {
		t.Fatal("empty clientID and AnonymousClientID must share the same bucket")
	}
}

// Zero-cap concurrency must always deny. The validator rejects this at
// startup, but the InflightTracker contract is part of the security model
// (denied-by-cap means denied, not admitted) and is tested directly.
func TestInflightTracker_ZeroCapAlwaysDenies(t *testing.T) {
	var tr InflightTracker
	for i := range 3 {
		ok, curr := tr.Acquire("anyone", 0)
		if ok {
			t.Fatalf("acquire %d: cap=0 must deny, got admit (curr=%d)", i, curr)
		}
	}
}

// Concurrent Release on a counter at zero must clamp without panic or
// underflow. Exercises the CAS-loop guard in Release.
func TestInflightTracker_ConcurrentReleaseClampsAtZero(t *testing.T) {
	var tr InflightTracker
	ok, _ := tr.Acquire("x", 1)
	if !ok {
		t.Fatal("setup acquire should admit")
	}
	const releasers = 50
	var wg sync.WaitGroup
	wg.Add(releasers)
	for range releasers {
		go func() {
			defer wg.Done()
			tr.Release("x")
		}()
	}
	wg.Wait()
	if got := tr.Current("x"); got != 0 {
		t.Fatalf("expected current=0 after concurrent releases, got %d", got)
	}
}

// Idle buckets are evicted by Limiter.evict after the configured TTL.
func TestLimiter_EvictsIdleBuckets(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	l := newLimiterWithClock(10, 10, clk.Now)
	defer l.Stop()

	l.Allow("alice") //nolint:errcheck
	l.Allow("bob")   //nolint:errcheck

	// Use alice again, but leave bob idle.
	clk.Advance(5 * time.Minute)
	l.Allow("alice") //nolint:errcheck

	// Advance past TTL relative to bob's last access.
	clk.Advance(8 * time.Minute) // alice accessed 8 min ago, bob 13 min ago
	l.evict(10 * time.Minute)    // only bob exceeds 10-minute idle TTL

	_, aliceExists := l.buckets.Load("alice")
	_, bobExists := l.buckets.Load("bob")

	if !aliceExists {
		t.Fatal("alice's bucket should still exist after evict (recently accessed)")
	}
	if bobExists {
		t.Fatal("bob's bucket should have been evicted after exceeding TTL")
	}
}

// Calling Stop multiple times must be safe (idempotent close).
func TestLimiter_StopIsIdempotent(t *testing.T) {
	l := NewLimiter(10, 10)
	l.Stop()
	l.Stop() // must not panic on double-close
}

// compileEndpointCosts must accept any user-influenced glob string without
// regex-compile failure. globToRegex is constructed so every input character
// is either an explicit glob token or regexp.QuoteMeta'd; this test pins that
// invariant so a future change to globToRegex that breaks it gets caught.
func TestCompileEndpointCosts_AllInputsCompile(t *testing.T) {
	weirdGlobs := []string{
		"",
		"[",
		"(",
		"]",
		")",
		"\\",
		"$",
		"^",
		"|",
		"+",
		"?(",
		"foo[bar",
		"foo)bar",
		"foo$bar",
		"foo\\bar",
		"/**/*.go",
		"/v1.45/containers/**",
		"with\nnewline",
		"with\x00null",
	}
	costs := make([]EndpointCost, 0, len(weirdGlobs))
	for _, g := range weirdGlobs {
		costs = append(costs, EndpointCost{PathGlob: g, Cost: 1})
	}
	// Must not panic — every glob must produce valid regex.
	got := compileEndpointCosts(costs)
	if len(got) != len(weirdGlobs) {
		t.Fatalf("expected %d compiled costs, got %d", len(weirdGlobs), len(got))
	}
}

// TestBucket_CASStress runs 32 goroutines hammering AllowN on a single bucket
// for 100 ms and asserts that total tokens granted ≈ initialBurst +
// (elapsed × rate). It exercises the CAS loop under real contention and checks
// that the lock-free implementation neither over-grants nor under-grants by
// more than a small absolute tolerance.
func TestBucket_CASStress(t *testing.T) {
	const (
		goroutines   = 32
		rate         = 500.0  // tokens/s — high enough to keep up with 32 workers
		burst        = 100.0  // initial bucket fill
		runDuration  = 100 * time.Millisecond
		tolerancePct = 0.10 // ±10 % of expected total
	)

	b := newBucket(rate, burst, time.Now)

	var (
		wg      sync.WaitGroup
		granted atomic.Int64
		start   = time.Now()
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for time.Since(start) < runDuration {
				if ok, _ := b.AllowN(1); ok {
					granted.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	elapsed := time.Since(start).Seconds()
	expected := burst + elapsed*rate
	got := float64(granted.Load())

	// got must be ≤ expected (never over-grant) and within tolerance below it.
	if got > expected*(1+tolerancePct) {
		t.Fatalf("over-granted: expected ≤ %.1f, got %.1f (elapsed=%.3fs)", expected, got, elapsed)
	}
	if got < expected*(1-tolerancePct) {
		t.Fatalf("under-granted: expected ≥ %.1f, got %.1f (elapsed=%.3fs)", expected*(1-tolerancePct), got, elapsed)
	}
}

// TestAuditSampler_Race verifies the sampler is safe under concurrent access.
func TestAuditSampler_Race(t *testing.T) {
	clk := newFixedClock(time.Unix(0, 0))
	s, stop := newAuditSamplerWithClock(clk.Now)
	defer stop()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			// Mix of same-key and different-key access.
			clientID := "shared"
			if i%5 == 0 {
				clientID = "varied"
			}
			s.ShouldEmit(clientID, ReasonRateLimit)
		}(i)
	}
	wg.Wait()
}
