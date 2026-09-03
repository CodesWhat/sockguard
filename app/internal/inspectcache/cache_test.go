package inspectcache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

func TestCacheHitsWithinTTL(t *testing.T) {
	t.Parallel()
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

// TestCacheExpiresExactlyAtTTLBoundary pins the freshness check's boundary:
// an entry aged exactly equal to the TTL (age == ttl, not age > ttl) must be
// treated as expired. "< ttl" is fresh; "== ttl" is not. A lookup landing
// precisely on that edge must re-resolve rather than serve the stale value.
func TestCacheExpiresExactlyAtTTLBoundary(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var calls atomic.Int32
	const ttl = 10 * time.Second

	cache := New(
		ttl,
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

	// Age the entry to exactly the TTL — the boundary itself, not past it.
	nowOffset.Store(int64(ttl))
	if _, _, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil {
		t.Fatalf("at-boundary lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls at age==ttl = %d, want 2 (entry must be treated as expired at the exact boundary)", got)
	}
}

func TestCacheCoalescesConcurrentMissesPerResource(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestCacheDoesNotCacheNotFound pins the owner-isolation fix: not-found
// verdicts must NOT be memoized. Caching found=false would let an attacker
// inspect a not-yet-existing name (pass-through), then within the TTL a victim
// creates a resource with that name and the attacker's later operations would
// hit the stale negative entry and bypass ownership. Each sequential lookup of
// a missing resource therefore re-resolves upstream.
func TestCacheDoesNotCacheNotFound(t *testing.T) {
	t.Parallel()
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
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls for uncached not-found = %d, want 2 (negatives not memoized)", got)
	}
}

// TestCacheResolvesAfterMissThenCreate is the regression test for the
// isolation window itself: a not-found lookup followed by the resource coming
// into existence within the TTL must reflect the new (found) state, not a
// stale negative.
func TestCacheResolvesAfterMissThenCreate(t *testing.T) {
	t.Parallel()
	var exists atomic.Bool
	cache := New(
		10*time.Second,
		4,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			if exists.Load() {
				return map[string]string{"owner": "victim"}, true, nil
			}
			return nil, false, nil
		},
	)

	if _, found, err := cache.Lookup(context.Background(), "containers", "shared-name"); err != nil || found {
		t.Fatalf("pre-create lookup = (%v, found=%v), want (nil, found=false)", err, found)
	}
	exists.Store(true)
	labels, found, err := cache.Lookup(context.Background(), "containers", "shared-name")
	if err != nil || !found {
		t.Fatalf("post-create lookup = (%v, found=%v), want (nil, found=true)", err, found)
	}
	if labels["owner"] != "victim" {
		t.Fatalf("post-create labels = %v, want owner=victim (no stale negative)", labels)
	}
}

// TestCacheZeroTTLDisablesMemoizationOfPositiveResults locks in the ttl<=0
// contract that newVisibilityDepsClient relies on (see
// TestNewVisibilityDepsClientResolvesFreshAfterNameReuse in the visibility
// package for the actual stale-cache-content-leak regression test): a cache
// constructed with a non-positive TTL must re-resolve on every sequential
// call instead of memoizing a found=true result.
func TestCacheZeroTTLDisablesMemoizationOfPositiveResults(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	cache := New(
		0,
		4,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			calls.Add(1)
			return map[string]string{"owner": "job-123"}, true, nil
		},
	)

	if _, found, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil || !found {
		t.Fatalf("first lookup = (%v, found=%v), want (nil, found=true)", err, found)
	}
	if _, found, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil || !found {
		t.Fatalf("second lookup = (%v, found=%v), want (nil, found=true)", err, found)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls with ttl<=0 = %d, want 2 (positive results must not be memoized)", got)
	}
}

// TestCacheZeroTTLDoesNotStoreEntry pins the memoization guard's boundary
// directly (c.ttl > 0), rather than through the resolver-call count in
// TestCacheZeroTTLDisablesMemoizationOfPositiveResults above. That test can't
// distinguish "> 0" from ">= 0" at ttl == 0: even if storeLocked ran and
// memoized the entry, the separate freshness check in Lookup
// (now.Sub(at) < c.ttl) can never be true when ttl == 0, so a stored entry
// would still be treated as a miss on the next call and the resolver-call
// count would be identical either way. Assert directly on the map instead:
// at ttl == 0 nothing should ever be written to c.entries.
func TestCacheZeroTTLDoesNotStoreEntry(t *testing.T) {
	t.Parallel()
	cache := New(
		0,
		4,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			return map[string]string{"owner": "job-123"}, true, nil
		},
	)

	if _, found, err := cache.Lookup(context.Background(), "containers", "abc123"); err != nil || !found {
		t.Fatalf("lookup = (%v, found=%v), want (nil, found=true)", err, found)
	}

	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size != 0 {
		t.Fatalf("cache.entries size = %d, want 0 (ttl<=0 must never memoize)", size)
	}
}

// TestCacheReturnsSameMapAcrossLookups locks in the read-only contract of
// Lookup: the returned map is shared with the cache and concurrent waiters,
// so callers must not mutate it. Verified by asserting two consecutive
// lookups for the same key return the same map pointer (no defensive copy).
// If a future change re-introduces a defensive clone, this assertion fails
// and the alloc regression is caught before merge.
func TestCacheReturnsSameMapAcrossLookups(t *testing.T) {
	t.Parallel()
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

	second, found, err := cache.Lookup(context.Background(), "containers", "abc123")
	if err != nil || !found {
		t.Fatalf("second lookup = (%v, found=%v), want (nil, found=true)", err, found)
	}
	if &first == &second {
		t.Fatal("returned map headers compared by address — test bug")
	}
	// Verify both lookups returned the same underlying map (no defensive clone).
	first["__sentinel__"] = "marker"
	if got := second["__sentinel__"]; got != "marker" {
		t.Fatalf("second lookup did not return the cached map; mutation to first not visible in second")
	}
	delete(first, "__sentinel__")

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls for second hit = %d, want 1 (cached)", got)
	}
}

// TestStoreLocked_EvictsStaleEntries exercises the scrub-stale branch of
// storeLocked: when the cache is full and at least one entry is past its TTL,
// those entries are deleted without touching the live ones.
func TestStoreLocked_EvictsStaleEntries(t *testing.T) {
	t.Parallel()
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

// TestStoreLocked_ScrubsEntryExactlyAtTTLBoundary pins the stale-scrub
// comparison's boundary: an entry aged exactly equal to the TTL (age == ttl)
// must be scrubbed as stale, not just entries strictly older than the TTL.
// TestStoreLocked_EvictsStaleEntries above ages entries to ttl+1s, which
// doesn't distinguish ">= ttl" from "> ttl"; this test ages to exactly ttl.
func TestStoreLocked_ScrubsEntryExactlyAtTTLBoundary(t *testing.T) {
	t.Parallel()
	const maxSize = 2
	ttl := 10 * time.Second

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

	if _, _, err := cache.Lookup(context.Background(), "containers", "a"); err != nil {
		t.Fatalf("lookup a: %v", err)
	}
	if _, _, err := cache.Lookup(context.Background(), "containers", "b"); err != nil {
		t.Fatalf("lookup b: %v", err)
	}

	// Advance time to exactly the TTL — the boundary itself, not past it.
	now = epoch.Add(ttl)

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
		t.Fatalf("entries aged exactly to the TTL should have been scrubbed as stale (a=%v b=%v)", aPresent, bPresent)
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
	t.Parallel()
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

// TestStoreLocked_MaxSizeZeroDoesNotPanic pins the tail-eviction loop guard
// at order.Len() == 0. New(...) does not validate maxSize, so a cache can be
// constructed with maxSize <= 0. The very first store then sees
// len(c.entries) (0) >= c.maxSize (0), so storeLocked enters its "at
// capacity" branch on an empty cache: the stale-scrub walk over an empty
// list is a no-op, then the tail-eviction loop's first clause
// (order.Len() > 0) must be false to keep the loop from executing — because
// its body unconditionally calls c.order.Back() and dereferences the result,
// which is nil on an empty list. If that clause is ever widened to include
// zero, the second clause (already true at 0 entries / 0 capacity) lets the
// loop body run and the nil dereference panics.
func TestStoreLocked_MaxSizeZeroDoesNotPanic(t *testing.T) {
	t.Parallel()
	cache := New(
		10*time.Second,
		0,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			return map[string]string{"k": "v"}, true, nil
		},
	)

	_, found, err := cache.Lookup(context.Background(), "containers", "a")
	if err != nil {
		t.Fatalf("lookup with maxSize=0: %v", err)
	}
	if !found {
		t.Fatal("lookup with maxSize=0: want found=true")
	}
}

// BenchmarkCacheLookupHit measures the cache-hit fast path. After the
// defensive-clone removal this should be 0 alloc/op regardless of label count.
func BenchmarkCacheLookupHit(b *testing.B) {
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

// BenchmarkCacheLookupMiss measures the cold-miss path: resolver call plus
// storeLocked into a non-full cache. The resolver is trivial here so overhead
// is dominated by Lookup's map insert, list push, and label clone.
func BenchmarkCacheLookupMiss(b *testing.B) {
	labels := benchmarkLabels(4)
	cache := New(
		10*time.Second,
		1<<20,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			return labels, true, nil
		},
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, found, err := cache.Lookup(context.Background(), "containers", fmt.Sprintf("id-%d", i))
		if err != nil || !found {
			b.Fatalf("lookup err=%v found=%v", err, found)
		}
		benchmarkLookupLabels = got
	}
}

// BenchmarkCacheLookupEviction cycles distinct keys past maxSize so every
// Lookup triggers the LRU tail eviction. Cost floor for a working-set larger
// than the cache.
func BenchmarkCacheLookupEviction(b *testing.B) {
	const maxSize = 64
	labels := benchmarkLabels(4)
	cache := New(
		10*time.Second,
		maxSize,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			return labels, true, nil
		},
	)
	for i := 0; i < maxSize; i++ {
		if _, _, err := cache.Lookup(context.Background(), "containers", fmt.Sprintf("warm-%d", i)); err != nil {
			b.Fatalf("warmup: %v", err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, _, err := cache.Lookup(context.Background(), "containers", fmt.Sprintf("evict-%d", i))
		if err != nil {
			b.Fatalf("lookup: %v", err)
		}
		benchmarkLookupLabels = got
	}
}

// BenchmarkCacheLookupHitParallel runs concurrent hits on the same hot key,
// surfacing contention on the cache mutex.
func BenchmarkCacheLookupHitParallel(b *testing.B) {
	labels := benchmarkLabels(8)
	cache := New(
		10*time.Second,
		4,
		time.Now,
		func(context.Context, string, string) (map[string]string, bool, error) {
			return labels, true, nil
		},
	)
	if _, _, err := cache.Lookup(context.Background(), "containers", "hot"); err != nil {
		b.Fatalf("warmup: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, err := cache.Lookup(context.Background(), "containers", "hot"); err != nil {
				b.Fatalf("lookup: %v", err)
			}
		}
	})
}
