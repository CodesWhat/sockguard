package health

import (
	"context"
	"net"
	"testing"
	"time"
)

// primedChecker returns a checker holding one fresh successful probe, which is
// what every /health request sees while the TTL runs.
func primedChecker(tb testing.TB) *upstreamHealthChecker {
	tb.Helper()
	checker := newUpstreamHealthChecker(
		time.Hour,
		healthDialTimeout,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) { return noopConn{}, nil },
	)
	if _, err := checker.check(context.Background(), "/tmp/upstream.sock"); err != nil {
		tb.Fatalf("priming check: %v", err)
	}
	return checker
}

// BenchmarkHealthCacheHit measures the path /health takes while the cached
// verdict is still fresh. The parallel arms are the ones that matter: /health
// sits ahead of the rate limiter, so concurrent callers used to serialize on
// the checker mutex for a read of four fields.
func BenchmarkHealthCacheHit(b *testing.B) {
	b.Run("snapshot", func(b *testing.B) {
		checker := primedChecker(b)
		b.ReportAllocs()
		var last verdict
		for b.Loop() {
			last = checker.snapshot()
		}
		if !last.fresh {
			b.Fatal("cached verdict went stale during the benchmark")
		}
	})

	b.Run("snapshot_parallel", func(b *testing.B) {
		checker := primedChecker(b)
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			var last verdict
			iterations := 0
			for pb.Next() {
				last = checker.snapshot()
				iterations++
			}
			// RunParallel hands some goroutines no iterations at all on the
			// calibration run, so only a goroutine that read something can
			// say anything about what it read.
			if iterations > 0 && !last.fresh {
				b.Error("cached verdict went stale during the benchmark")
			}
		})
	})

	b.Run("check_parallel", func(b *testing.B) {
		checker := primedChecker(b)
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			var status string
			iterations := 0
			for pb.Next() {
				status, _ = checker.check(context.Background(), "/tmp/upstream.sock")
				iterations++
			}
			if iterations > 0 && status != "connected" {
				b.Errorf("check status = %q, want connected", status)
			}
		})
	})
}
