package ratelimit

import (
	"sync"
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
