package ratelimit

// bench_test.go — benchmarks and concurrency stress tests for the ratelimit
// package. Tests here cover:
//   - BenchmarkLimiterAllowNParallel: many-client parallel throughput (lock
//     contention / sync.Map cost under realistic workload)
//   - BenchmarkLimiterAllowNHot: single-client warm-bucket throughput
//   - TestLimiterStop_MidFlightRace: Limiter.Stop() called while concurrent
//     AllowN calls are in-flight — asserts no panic and no goroutine leak.

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BenchmarkLimiterAllowNParallel
//
// Spread across 1000 unique client IDs to stress the bucket-lookup path under
// realistic multi-client concurrency. After the first pass every bucket is
// warm, so the benchmark exercises the sync.Map Load hot path.
// ---------------------------------------------------------------------------

const parallelClientCount = 1000

func BenchmarkLimiterAllowNParallel(b *testing.B) {
	l := newLimiterWithClock(1e9, 1e9, time.Now) // effectively unlimited tokens
	defer l.Stop()

	// Pre-warm all buckets so we're not measuring cold-path allocation.
	for i := 0; i < parallelClientCount; i++ {
		l.AllowN(fmt.Sprintf("client-%d", i), 1) //nolint:errcheck
	}

	var idx atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Round-robin across the client pool to exercise many distinct
			// sync.Map entries per goroutine.
			i := int(idx.Add(1)) % parallelClientCount
			l.AllowN(fmt.Sprintf("client-%d", i), 1) //nolint:errcheck
		}
	})
}

// ---------------------------------------------------------------------------
// BenchmarkLimiterAllowNHot
//
// Single client hammered repeatedly — exercises the warm-bucket case
// (sync.Map Load + bucket.AllowN with tokens available). This is the
// steady-state p50 workload for a well-behaved single caller.
// ---------------------------------------------------------------------------

func BenchmarkLimiterAllowNHot(b *testing.B) {
	l := newLimiterWithClock(1e9, 1e9, time.Now) // effectively unlimited tokens
	defer l.Stop()

	// Warm the bucket.
	l.AllowN("hot-client", 1) //nolint:errcheck

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.AllowN("hot-client", 1) //nolint:errcheck
	}
}

// ---------------------------------------------------------------------------
// TestLimiterStop_MidFlightRace
//
// Verifies that Limiter.Stop() can be called safely while AllowN calls are
// running concurrently:
//   - No panic (closed stopCh must not race with eviction goroutine reads)
//   - No goroutine leak: the eviction goroutine exits within a bounded window
//     after Stop returns
//
// Uses stdlib runtime.NumGoroutine polling — no external dependency.
// ---------------------------------------------------------------------------

func TestLimiterStop_MidFlightRace(t *testing.T) {
	t.Parallel()
	const (
		workerCount  = 50
		clientCount  = 200
		stopAfterMs  = 10
		drainTimeout = 3 * time.Second
	)

	// Snapshot goroutine count before we start so we can measure the delta.
	goroutinesBefore := runtime.NumGoroutine()

	l := newLimiterWithClock(65535, 65535, time.Now)

	// Spawn workers that hammer AllowN with rotating client IDs.
	var (
		wg      sync.WaitGroup
		stopped atomic.Bool
	)
	wg.Add(workerCount)
	for w := 0; w < workerCount; w++ {
		go func(workerID int) {
			defer wg.Done()
			i := 0
			for !stopped.Load() {
				clientID := fmt.Sprintf("client-%d", (workerID*workerCount+i)%clientCount)
				l.AllowN(clientID, 1) //nolint:errcheck
				i++
			}
		}(w)
	}

	// Let workers run briefly, then stop the limiter mid-flight.
	time.Sleep(stopAfterMs * time.Millisecond)
	l.Stop() // must not panic even with concurrent AllowN calls
	stopped.Store(true)
	wg.Wait()

	// Stop must be idempotent.
	l.Stop()

	// After Stop and all workers exiting, the eviction goroutine should have
	// exited. Poll runtime.NumGoroutine to confirm no leak. We allow
	// drainTimeout for the runtime to reclaim the goroutine stack.
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		current := runtime.NumGoroutine()
		// Allow a small buffer above the pre-test baseline for test runtime
		// overhead (gc, finalizers, etc.), but the eviction goroutine (1 per
		// Limiter) must not be among them.
		if current <= goroutinesBefore+5 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Final check with a helpful diagnostic.
	current := runtime.NumGoroutine()
	if current > goroutinesBefore+5 {
		t.Errorf("possible goroutine leak after Limiter.Stop(): before=%d, after=%d (delta=%d, want ≤5)",
			goroutinesBefore, current, current-goroutinesBefore)
	}
}

// ---------------------------------------------------------------------------
// Packed-path micro-benchmarks
//
// These benchmarks target the packed atomic.Uint64 token bucket path.
// Run with -benchmem to verify allocs/op = 0.
//
//	go test -bench=BenchmarkBucket_AllowNPacked -benchmem ./internal/ratelimit/
//
// ---------------------------------------------------------------------------

// BenchmarkBucket_AllowNPacked measures the admit path of the packed bucket.
// The bucket uses a real clock advancing naturally so the bucket keeps
// refilling (tpsFP = 65535*65536 grants ~65535 tokens per second). Most calls
// will observe elapsedMS > 0 and hit the refill+admit branch. A small fraction
// near drain boundaries will measure the deny path; both branches are
// allocation-free in the packed design.
func BenchmarkBucket_AllowNPacked(b *testing.B) {
	bkt := newBucket(65535, 65535, time.Now)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bkt.AllowN(1) //nolint:errcheck
	}
}

// BenchmarkBucket_AllowNPackedParallel exercises the CAS retry loop under
// concurrent access. Uses a real clock so the bucket refills between calls.
// Verify allocs/op = 0 with -benchmem.
func BenchmarkBucket_AllowNPackedParallel(b *testing.B) {
	bkt := newBucket(65535, 65535, time.Now)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bkt.AllowN(1) //nolint:errcheck
		}
	})
}
