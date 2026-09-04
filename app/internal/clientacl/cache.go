package clientacl

import (
	"container/list"
	"context"
	"net/netip"
	"sync"
	"time"
)

// Each inbound request from an allowed CIDR used to fire one upstream
// /containers/json call so we could map source IP → caller container. A
// burst of N requests from one IP amplified into N upstream calls, which
// is both a DoS vector against the Docker daemon and a steady background
// load for normal traffic. The cache below coalesces those lookups via
// singleflight (concurrent callers share one in-flight request) and
// short-term TTL caching (repeated callers within the window share the
// last result). Both knobs are kept small so dynamic IP reassignment
// still works — the goal is to flatten amplification, not to memoize
// forever.
const (
	clientCacheTTL     = 10 * time.Second
	clientCacheMaxSize = 256
)

type clientCacheEntry struct {
	client resolvedClient
	found  bool
	at     time.Time
}

type clientCacheNode struct {
	addr  netip.Addr
	entry clientCacheEntry
}

type clientLookup struct {
	done   chan struct{}
	client resolvedClient
	found  bool
	err    error
}

type clientCache struct {
	ttl     time.Duration
	maxSize int
	now     func() time.Time
	resolve func(context.Context, netip.Addr) (resolvedClient, bool, error)
	// augment runs after a successful resolve (on cache miss). It is the
	// hook the middleware uses to pre-compile label ACL rules so repeated
	// callers from the same IP skip the expensive re-compile path. May be
	// nil when label ACLs are disabled.
	augment func(resolvedClient) resolvedClient
	// verifyLive re-checks a cached client against current daemon state before
	// trusting a found=true cache HIT. It asks whether that container ID still
	// holds this very address — existence alone is not enough. Docker releases
	// a container's IP back to IPAM the moment it stops, while the stopped
	// container stays inspectable, so an existence-only check would still let
	// container X's memoized labels/ACL rules be applied to a request that
	// actually came from a brand-new container Y that reused X's IP within
	// ttl. Checking ownership closes both halves: `docker rm` (X is gone) and
	// `docker stop` (X is still there but no longer answers at addr).
	//
	// A single-container inspect costs the same as the liveness check
	// resolve() already performs on every cache MISS, so this closes the gap
	// without reintroducing the O(n) /containers/json listing the cache exists
	// to avoid. Returning false is not an error: the caller drops the entry
	// and falls back to a full re-resolve, so a false negative costs a lookup,
	// never a wrong verdict. Nil disables the check (e.g. in tests that don't
	// wire it up).
	verifyLive func(ctx context.Context, id string, addr netip.Addr) bool

	mu       sync.Mutex
	entries  map[netip.Addr]*list.Element // value: *clientCacheNode
	order    *list.List
	inFlight map[netip.Addr]*clientLookup
}

func newClientCache(
	ttl time.Duration,
	maxSize int,
	now func() time.Time,
	resolve func(context.Context, netip.Addr) (resolvedClient, bool, error),
) *clientCache {
	return &clientCache{
		ttl:      ttl,
		maxSize:  maxSize,
		now:      now,
		resolve:  resolve,
		entries:  make(map[netip.Addr]*list.Element),
		order:    list.New(),
		inFlight: make(map[netip.Addr]*clientLookup),
	}
}

// Lookup returns the resolvedClient for addr, using cached state when fresh
// and verifyLive-confirmed (see clientCache.verifyLive), and coalescing
// concurrent misses into one upstream call. Errors are never cached — a
// transient upstream blip should recover on the next caller instead of being
// pinned to a stale failure verdict.
//
// Cache hits do NOT promote the entry to the LRU front: the hit-path
// critical section is map-lookup + two scalar reads, no list write.
// LRU ordering is maintained on store (insert/refresh), which keeps the
// bounded-size invariant intact and lets bursts of cache hits run
// without serializing on the list head. The TTL drain in storeLocked
// also pulls stale tail entries first, so missing per-hit promotions
// only degrade the eviction order under sustained pressure — a
// trade we accept given the small (256/1024) cap.
func (c *clientCache) Lookup(ctx context.Context, addr netip.Addr) (resolvedClient, bool, error) {
	for {
		now := c.now()

		c.mu.Lock()
		if elem, ok := c.entries[addr]; ok {
			node := elem.Value.(*clientCacheNode)
			if now.Sub(node.entry.at) < c.ttl {
				entry := node.entry
				c.mu.Unlock()
				// Re-verify a found=true hit against current daemon state before
				// trusting it — see the verifyLive doc comment on clientCache.
				if !entry.found || c.verifyLive == nil || c.verifyLive(ctx, entry.client.ID, addr) {
					return entry.client, entry.found, nil
				}

				// The cached container no longer answers at addr — it was removed,
				// or it stopped and released the address back to IPAM. Either way
				// the address may already belong to a different container. Remove
				// the stale entry only if another caller has not refreshed it while
				// verification was in progress.
				c.mu.Lock()
				current, exists := c.entries[addr]
				if !exists {
					return c.resolveAndStoreLocked(ctx, addr)
				}
				currentEntry := current.Value.(*clientCacheNode).entry
				if current != elem || currentEntry.at != entry.at || currentEntry.client.ID != entry.client.ID || currentEntry.found != entry.found {
					c.mu.Unlock()
					continue
				}
				delete(c.entries, addr)
				c.order.Remove(current)
				return c.resolveAndStoreLocked(ctx, addr)
			}
		}

		return c.resolveAndStoreLocked(ctx, addr)
	}
}

// resolveAndStoreLocked joins or creates the in-flight lookup for addr. The
// caller must hold c.mu so the cache miss and in-flight registration are one
// atomic decision; the helper always releases the lock before returning.
func (c *clientCache) resolveAndStoreLocked(ctx context.Context, addr netip.Addr) (resolvedClient, bool, error) {
	if call, ok := c.inFlight[addr]; ok {
		c.mu.Unlock()
		<-call.done
		return call.client, call.found, call.err
	}
	call := &clientLookup{done: make(chan struct{})}
	c.inFlight[addr] = call
	c.mu.Unlock()

	client, found, err := c.resolve(ctx, addr)
	if err == nil && found && c.augment != nil {
		client = c.augment(client)
	}

	c.mu.Lock()
	if err == nil {
		c.storeLocked(addr, client, found, c.now())
	}
	delete(c.inFlight, addr)
	call.client = client
	call.found = found
	call.err = err
	close(call.done)
	c.mu.Unlock()

	return client, found, err
}

func (c *clientCache) storeLocked(addr netip.Addr, client resolvedClient, found bool, at time.Time) {
	entry := clientCacheEntry{client: client, found: found, at: at}
	if elem, ok := c.entries[addr]; ok {
		elem.Value.(*clientCacheNode).entry = entry
		c.order.MoveToFront(elem)
		return
	}
	if len(c.entries) >= c.maxSize {
		// Drain TTL-expired entries first; older nodes cluster at the back.
		for e := c.order.Back(); e != nil; {
			node := e.Value.(*clientCacheNode)
			prev := e.Prev()
			if at.Sub(node.entry.at) >= c.ttl {
				delete(c.entries, node.addr)
				c.order.Remove(e)
			}
			e = prev
		}
		// If still at capacity, evict the LRU tail.
		for c.order.Len() > 0 && len(c.entries) >= c.maxSize {
			tail := c.order.Back()
			tailNode := tail.Value.(*clientCacheNode)
			delete(c.entries, tailNode.addr)
			c.order.Remove(tail)
		}
	}
	node := &clientCacheNode{addr: addr, entry: entry}
	c.entries[addr] = c.order.PushFront(node)
}
