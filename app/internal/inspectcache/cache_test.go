package inspectcache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/testhelp"
)

func TestCacheHitsWithinTTL(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var calls atomic.Int32

	cache := New(
		10*time.Second,
		4,
		func() time.Time { return baseNow.Add(time.Duration(nowOffset.Load())) },
		func(context.Context, string, string) (map[string]string, bool, error) {
			calls.Add(1)
			return map[string]string{"com.sockguard.owner": "job-123"}, true, nil
		},
	)

	if _, _, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	nowOffset.Store(int64(5 * time.Second))
	if _, _, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil {
		t.Fatalf("cached lookup: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls within TTL = %d, want 1", got)
	}

	nowOffset.Store(int64(11 * time.Second))
	if _, _, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil {
		t.Fatalf("post-TTL lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls after TTL = %d, want 2", got)
	}
}

func TestCacheCoalescesConcurrentMissesPerResource(t *testing.T) {
	const callers = 16

	release := make(chan struct{})
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(callers)

	var calls atomic.Int32
	cache := New(
		10*time.Second,
		8,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			calls.Add(1)
			<-release
			return map[string]string{"com.sockguard.owner": "job-123"}, true, nil
		},
	)

	results := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			_, _, err := cache.Lookup(context.Background(), "containers", "abc123")
			results <- err
		}()
	}

	ready.Wait()
	close(start)
	// Wait until at least one goroutine has entered the resolver (leader is
	// blocked on <-release), then release so all waiters can unblock.
	testhelp.Eventually(t, func() bool { return calls.Load() >= 1 })
	close(release)

	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("lookup error: %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls for concurrent burst = %d, want 1", got)
	}
}

func TestCacheDifferentResourcesIndependent(t *testing.T) {
	var calls atomic.Int32
	cache := New(
		10*time.Second,
		8,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			calls.Add(1)
			return map[string]string{"com.sockguard.owner": "job-123"}, true, nil
		},
	)

	ctx := context.Background()
	for _, resource := range []struct {
		kind       string
		identifier string
	}{
		{kind: "containers", identifier: "one"},
		{kind: "containers", identifier: "two"},
		{kind: "images", identifier: "one"},
	} {
		if _, _, err := cache.Lookup(ctx, resource.kind, resource.identifier); err != nil {
			t.Fatalf("lookup %s/%s: %v", resource.kind, resource.identifier, err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("resolver calls for 3 distinct resources = %d, want 3", got)
	}
}

func TestCacheDoesNotCacheErrors(t *testing.T) {
	var calls atomic.Int32
	cache := New(
		10*time.Second,
		4,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			calls.Add(1)
			return nil, false, errors.New("upstream flake")
		},
	)

	if _, _, err := cache.Lookup(context.Background(), "containers", "abc123"); err == nil {
		t.Fatal("expected error on first lookup")
	}
	if _, _, err := cache.Lookup(context.Background(), "containers", "abc123"); err == nil {
		t.Fatal("expected error on second lookup")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls for two errored lookups = %d, want 2", got)
	}
}

func TestCacheCachesNotFound(t *testing.T) {
	var calls atomic.Int32
	cache := New(
		10*time.Second,
		4,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			calls.Add(1)
			return nil, false, nil
		},
	)

	if _, found, err := cache.Lookup(context.Background(), "containers", "missing"); err != nil || found {
		t.Fatalf("first lookup = (%v, found=%v), want (nil, found=false)", err, found)
	}
	if _, found, err := cache.Lookup(context.Background(), "containers", "missing"); err != nil || found {
		t.Fatalf("second lookup = (%v, found=%v), want (nil, found=false)", err, found)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls for cached not-found = %d, want 1", got)
	}
}

func TestCacheReturnsDefensiveLabelCopies(t *testing.T) {
	var calls atomic.Int32
	cache := New(
		10*time.Second,
		4,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			calls.Add(1)
			return map[string]string{
				"com.sockguard.owner":   "job-123",
				"com.sockguard.visible": "true",
			}, true, nil
		},
	)

	first, found, err := cache.Lookup(context.Background(), "containers", "abc123")
	if err != nil || !found {
		t.Fatalf("first lookup = (%v, found=%v), want (nil, found=true)", err, found)
	}
	first["com.sockguard.owner"] = "mutated"
	first["com.sockguard.extra"] = "leak"

	second, found, err := cache.Lookup(context.Background(), "containers", "abc123")
	if err != nil || !found {
		t.Fatalf("second lookup = (%v, found=%v), want (nil, found=true)", err, found)
	}
	if got := second["com.sockguard.owner"]; got != "job-123" {
		t.Fatalf("cached owner label = %q, want job-123", got)
	}
	if _, ok := second["com.sockguard.extra"]; ok {
		t.Fatalf("cached labels unexpectedly retained caller mutation: %#v", second)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls for defensive-copy hit = %d, want 1", got)
	}
}

// TestStoreLocked_EvictsStaleEntries exercises the scrub-stale branch of
// storeLocked: when the cache is full and at least one entry is past its TTL,
// those entries are deleted without touching the live ones.
func TestStoreLocked_EvictsStaleEntries(t *testing.T) {
	const maxSize = 2
	ttl := 10 * time.Second

	// epoch is our controllable clock.
	epoch := time.Unix(1_700_000_000, 0)
	now := epoch

	cache := New(
		ttl,
		maxSize,
		func() time.Time { return now },
		func(context.Context, string, string) (map[string]string, bool, error) {
			return map[string]string{"k": "v"}, true, nil
		},
	)

	// Fill to capacity at t=0.
	if _, _, err := cache.Lookup(context.Background(), "containers", "a"); err != nil {
		t.Fatalf("lookup a: %v", err)
	}
	if _, _, err := cache.Lookup(context.Background(), "containers", "b"); err != nil {
		t.Fatalf("lookup b: %v", err)
	}

	// Advance time past TTL so both existing entries are stale.
	now = epoch.Add(ttl + time.Second)

	// A third lookup triggers storeLocked at capacity — stale scrub removes
	// "a" and "b", so "c" fits without evicting a live entry.
	if _, _, err := cache.Lookup(context.Background(), "containers", "c"); err != nil {
		t.Fatalf("lookup c: %v", err)
	}

	cache.mu.Lock()
	_, aPresent := cache.entries[key{kind: "containers", identifier: "a"}]
	_, bPresent := cache.entries[key{kind: "containers", identifier: "b"}]
	_, cPresent := cache.entries[key{kind: "containers", identifier: "c"}]
	size := len(cache.entries)
	cache.mu.Unlock()

	if aPresent || bPresent {
		t.Fatalf("stale entries a/b should have been evicted (a=%v b=%v)", aPresent, bPresent)
	}
	if !cPresent {
		t.Fatal("new entry c should be present after stale scrub")
	}
	if size != 1 {
		t.Fatalf("cache size = %d, want 1", size)
	}
}

// TestStoreLocked_EvictsOldestWhenAllLive exercises the oldest-eviction branch:
// when the cache is full and no entry is stale, the oldest live entry is deleted.
func TestStoreLocked_EvictsOldestWhenAllLive(t *testing.T) {
	const maxSize = 2
	ttl := 10 * time.Second

	epoch := time.Unix(1_700_000_000, 0)
	tick := int64(0) // monotonic tick in nanoseconds

	cache := New(
		ttl,
		maxSize,
		func() time.Time { return epoch.Add(time.Duration(tick)) },
		func(context.Context, string, string) (map[string]string, bool, error) {
			return map[string]string{"k": "v"}, true, nil
		},
	)

	// Insert "a" at t=0, "b" at t=1ns — both well within TTL.
	if _, _, err := cache.Lookup(context.Background(), "containers", "a"); err != nil {
		t.Fatalf("lookup a: %v", err)
	}
	tick = 1
	if _, _, err := cache.Lookup(context.Background(), "containers", "b"); err != nil {
		t.Fatalf("lookup b: %v", err)
	}

	// Advance to t=2ns — still within TTL — then insert "c" to trigger eviction.
	tick = 2
	if _, _, err := cache.Lookup(context.Background(), "containers", "c"); err != nil {
		t.Fatalf("lookup c: %v", err)
	}

	cache.mu.Lock()
	_, aPresent := cache.entries[key{kind: "containers", identifier: "a"}]
	_, bPresent := cache.entries[key{kind: "containers", identifier: "b"}]
	_, cPresent := cache.entries[key{kind: "containers", identifier: "c"}]
	size := len(cache.entries)
	cache.mu.Unlock()

	// "a" is oldest and should have been evicted.
	if aPresent {
		t.Fatal("oldest entry a should have been evicted")
	}
	if !bPresent || !cPresent {
		t.Fatalf("live entries b/c should be present (b=%v c=%v)", bPresent, cPresent)
	}
	if size != maxSize {
		t.Fatalf("cache size = %d, want %d", size, maxSize)
	}
}

func BenchmarkCacheLookupHitClonesLabels(b *testing.B) {
	for _, labelCount := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("labels_%d", labelCount), func(b *testing.B) {
			labels := benchmarkLabels(labelCount)
			cache := New(
				10*time.Second,
				4,
				time.Now,
				func(context.Context, string, string) (map[string]string, bool, error) {
					return labels, true, nil
				},
			)

			if _, _, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil {
				b.Fatalf("warm lookup: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, found, err := cache.Lookup(context.Background(), "containers", "abc123")
				if err != nil || !found {
					b.Fatalf("cached lookup = (%v, found=%v), want (nil, found=true)", err, found)
				}
				benchmarkLookupLabels = got
			}
		})
	}
}

var benchmarkLookupLabels map[string]string

func benchmarkLabels(n int) map[string]string {
	labels := make(map[string]string, n)
	for i := 0; i < n; i++ {
		labels[fmt.Sprintf("com.sockguard.label.%d", i)] = fmt.Sprintf("value-%d", i)
	}
	return labels
}
