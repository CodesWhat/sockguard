package clientacl

import (
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

	mu       sync.Mutex
	entries  map[netip.Addr]clientCacheEntry
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
		entries:  make(map[netip.Addr]clientCacheEntry),
		inFlight: make(map[netip.Addr]*clientLookup),
	}
}

// Lookup returns the resolvedClient for addr, using cached state when
// fresh and coalescing concurrent misses into one upstream call. Errors
// are never cached — a transient upstream blip should recover on the
// next caller instead of being pinned to a stale failure verdict.
func (c *clientCache) Lookup(ctx context.Context, addr netip.Addr) (resolvedClient, bool, error) {
	now := c.now()

	c.mu.Lock()
	if entry, ok := c.entries[addr]; ok && now.Sub(entry.at) < c.ttl {
		c.mu.Unlock()
		return entry.client, entry.found, nil
	}
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
	if len(c.entries) >= c.maxSize {
		// Scrub anything past TTL first; that usually clears room cheaply.
		var oldestKey netip.Addr
		var oldestAt time.Time
		havingOldest := false
		for k, e := range c.entries {
			if at.Sub(e.at) >= c.ttl {
				delete(c.entries, k)
				continue
			}
			if !havingOldest || e.at.Before(oldestAt) {
				oldestKey = k
				oldestAt = e.at
				havingOldest = true
			}
		}
		// If the scrub didn't open a slot, evict the oldest surviving entry.
		// A 256-entry cap with 10s TTL doesn't justify a proper LRU list.
		if havingOldest && len(c.entries) >= c.maxSize {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[addr] = clientCacheEntry{client: client, found: found, at: at}
}
