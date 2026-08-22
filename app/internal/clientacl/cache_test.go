package clientacl

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return addr
}

func TestClientCacheHitsWithinTTL(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var calls atomic.Int32

	resolver := func(_ context.Context, addr netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		return resolvedClient{ID: "c-" + addr.String(), Name: "a", Labels: nil}, true, nil
	}

	cache := newClientCache(
		10*time.Second,
		4,
		func() time.Time { return baseNow.Add(time.Duration(nowOffset.Load())) },
		resolver,
	)

	ip := mustAddr(t, "10.0.0.1")

	if _, _, err := cache.Lookup(context.Background(), ip); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	nowOffset.Store(int64(5 * time.Second))
	if _, _, err := cache.Lookup(context.Background(), ip); err != nil {
		t.Fatalf("cached lookup: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls within TTL = %d, want 1", got)
	}

	nowOffset.Store(int64(11 * time.Second))
	if _, _, err := cache.Lookup(context.Background(), ip); err != nil {
		t.Fatalf("post-TTL lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls after TTL = %d, want 2", got)
	}
}

// TestClientCacheReResolvesWhenCachedContainerNoLongerLive is the regression
// test for the stale-identity finding: within the cache TTL, if the
// container backing a cached found=true entry is torn down (verifyLive
// starts returning false — e.g. Docker reassigned the IP to a brand-new
// container), the next Lookup for the same IP must re-resolve instead of
// applying the stale container's cached identity/labels to the new owner.
func TestClientCacheReResolvesWhenCachedContainerNoLongerLive(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var calls atomic.Int32
	var live atomic.Bool
	live.Store(true)

	resolver := func(_ context.Context, addr netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		return resolvedClient{ID: "container-x", Name: "x", Labels: map[string]string{"team": "x-owner"}}, true, nil
	}

	cache := newClientCache(
		10*time.Second,
		4,
		func() time.Time { return baseNow.Add(time.Duration(nowOffset.Load())) },
		resolver,
	)
	cache.verifyLive = func(_ context.Context, id string) bool {
		if id != "container-x" {
			t.Fatalf("verifyLive called with unexpected id %q", id)
		}
		return live.Load()
	}

	ip := mustAddr(t, "10.0.0.5")

	client, found, err := cache.Lookup(context.Background(), ip)
	if err != nil || !found || client.ID != "container-x" {
		t.Fatalf("first lookup = (%+v, found=%v, err=%v), want container-x", client, found, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls after first lookup = %d, want 1", got)
	}

	// Container X is torn down; its IP is about to be reassigned. Still well
	// within the 10s TTL.
	live.Store(false)
	nowOffset.Store(int64(2 * time.Second))

	// A new container Y (with different labels) now answers at the same IP.
	resolver2Called := atomic.Bool{}
	cache.resolve = func(_ context.Context, addr netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		resolver2Called.Store(true)
		return resolvedClient{ID: "container-y", Name: "y", Labels: map[string]string{"team": "y-owner"}}, true, nil
	}

	client, found, err = cache.Lookup(context.Background(), ip)
	if err != nil || !found {
		t.Fatalf("second lookup = (%+v, found=%v, err=%v)", client, found, err)
	}
	if !resolver2Called.Load() {
		t.Fatal("expected a fresh resolve after the cached container stopped being live")
	}
	if client.ID != "container-y" {
		t.Fatalf("second lookup resolved to %q, want container-y (stale container-x identity served instead)", client.ID)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls after cached container died = %d, want 2", got)
	}
}

func TestClientCacheCoalescesConcurrentMissesPerIP(t *testing.T) {
	const callers = 16

	release := make(chan struct{})
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(callers)

	var calls atomic.Int32
	resolver := func(_ context.Context, _ netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		<-release
		return resolvedClient{ID: "c1"}, true, nil
	}

	cache := newClientCache(10*time.Second, 8, time.Now, resolver)
	ip := mustAddr(t, "10.0.0.7")

	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			_, _, err := cache.Lookup(context.Background(), ip)
			results <- err
		}()
	}

	ready.Wait()
	close(start)

	// Wait until the leader goroutine has entered the resolver (it is now
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

func TestClientCacheDifferentIPsIndependent(t *testing.T) {
	var calls atomic.Int32
	resolver := func(_ context.Context, _ netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		return resolvedClient{ID: "x"}, true, nil
	}

	cache := newClientCache(10*time.Second, 8, time.Now, resolver)
	ctx := context.Background()

	for _, s := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, _, err := cache.Lookup(ctx, mustAddr(t, s)); err != nil {
			t.Fatalf("lookup %s: %v", s, err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("resolver calls for 3 distinct IPs = %d, want 3", got)
	}

	// Repeat — all three should now hit the cache.
	for _, s := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, _, err := cache.Lookup(ctx, mustAddr(t, s)); err != nil {
			t.Fatalf("cached lookup %s: %v", s, err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("resolver calls after cache hits = %d, want 3", got)
	}
}

func TestClientCacheDoesNotCacheErrors(t *testing.T) {
	var calls atomic.Int32
	resolver := func(_ context.Context, _ netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		return resolvedClient{}, false, errors.New("upstream flake")
	}

	cache := newClientCache(10*time.Second, 4, time.Now, resolver)
	ip := mustAddr(t, "10.0.0.9")

	if _, _, err := cache.Lookup(context.Background(), ip); err == nil {
		t.Fatal("expected error on first lookup")
	}
	if _, _, err := cache.Lookup(context.Background(), ip); err == nil {
		t.Fatal("expected error on second lookup")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls for two errored lookups = %d, want 2 (errors must not cache)", got)
	}
}

func TestClientCacheCachesNotFound(t *testing.T) {
	var calls atomic.Int32
	resolver := func(_ context.Context, _ netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		return resolvedClient{}, false, nil
	}

	cache := newClientCache(10*time.Second, 4, time.Now, resolver)
	ip := mustAddr(t, "10.0.0.99")

	if _, found, err := cache.Lookup(context.Background(), ip); err != nil || found {
		t.Fatalf("first lookup = (%v, found=%v), want (nil, found=false)", err, found)
	}
	if _, found, err := cache.Lookup(context.Background(), ip); err != nil || found {
		t.Fatalf("second lookup = (%v, found=%v), want (nil, found=false)", err, found)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls for cached not-found = %d, want 1", got)
	}
}

// TestClientCacheEvictsByInsertionOrderUnderCap pins approximate-LRU
// semantics: cache hits do NOT promote, so eviction follows insertion
// order. Re-accessing an older entry does not save it from eviction.
// This trade reduces hit-path lock contention; see clientCache.Lookup
// for the rationale.
func TestClientCacheEvictsByInsertionOrderUnderCap(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var calls atomic.Int32
	resolver := func(_ context.Context, _ netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		return resolvedClient{ID: "x"}, true, nil
	}

	cache := newClientCache(
		10*time.Second,
		2,
		func() time.Time { return baseNow.Add(time.Duration(nowOffset.Load())) },
		resolver,
	)
	ctx := context.Background()

	a := mustAddr(t, "10.1.0.1")
	b := mustAddr(t, "10.1.0.2")
	c := mustAddr(t, "10.1.0.3")

	if _, _, err := cache.Lookup(ctx, a); err != nil {
		t.Fatal(err)
	}
	nowOffset.Store(int64(time.Millisecond))
	if _, _, err := cache.Lookup(ctx, b); err != nil {
		t.Fatal(err)
	}
	// Re-accessing a is a pure cache hit — no promotion, no resolver call.
	nowOffset.Store(int64(2 * time.Millisecond))
	if _, _, err := cache.Lookup(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("re-access of a triggered a resolver call: got %d, want 2", got)
	}

	// Insert c — at cap=2, the LRU tail (a, the older insertion) is evicted.
	nowOffset.Store(int64(3 * time.Millisecond))
	if _, _, err := cache.Lookup(ctx, c); err != nil {
		t.Fatal(err)
	}

	// b should still be cached (younger insertion).
	callsBefore := calls.Load()
	if _, _, err := cache.Lookup(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != callsBefore {
		t.Fatalf("b should have hit cache after c displaced a; resolver was called %d times", got-callsBefore)
	}

	// a should have been evicted — next lookup re-resolves.
	callsBefore = calls.Load()
	if _, _, err := cache.Lookup(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != callsBefore+1 {
		t.Fatalf("a should have been evicted by c (older insertion); want 1 extra resolver call, got %d", got-callsBefore)
	}
}

func TestClientCacheEvictsBeyondMaxSize(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var calls atomic.Int32
	resolver := func(_ context.Context, _ netip.Addr) (resolvedClient, bool, error) {
		calls.Add(1)
		return resolvedClient{ID: "x"}, true, nil
	}

	cache := newClientCache(
		10*time.Second,
		2,
		func() time.Time { return baseNow.Add(time.Duration(nowOffset.Load())) },
		resolver,
	)
	ctx := context.Background()

	a := mustAddr(t, "10.0.0.1")
	b := mustAddr(t, "10.0.0.2")
	c := mustAddr(t, "10.0.0.3")

	if _, _, err := cache.Lookup(ctx, a); err != nil {
		t.Fatal(err)
	}
	nowOffset.Store(int64(time.Millisecond))
	if _, _, err := cache.Lookup(ctx, b); err != nil {
		t.Fatal(err)
	}
	nowOffset.Store(int64(2 * time.Millisecond))
	// Inserting c at cap=2 should evict the oldest surviving entry (a).
	if _, _, err := cache.Lookup(ctx, c); err != nil {
		t.Fatal(err)
	}

	callsBefore := calls.Load()
	// b and c should still be cached; a should have been evicted.
	if _, _, err := cache.Lookup(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Lookup(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != callsBefore {
		t.Fatalf("resolver called %d extra times for b/c after eviction; both should still be cached", got-callsBefore)
	}
	if _, _, err := cache.Lookup(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != callsBefore+1 {
		t.Fatalf("expected one extra resolver call for evicted a, got %d", got-callsBefore)
	}
}
