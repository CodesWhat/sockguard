package inspectcache

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// DefaultTTL and DefaultMaxSize match the small, burst-flattening cache
// profile used elsewhere in Sockguard: short-lived entries, bounded size,
// and no attempt to memoize long-term daemon state.
const (
	DefaultTTL     = 10 * time.Second
	DefaultMaxSize = 256
)

type entry[V any] struct {
	value V
	found bool
	at    time.Time
}

type entryNode[V any] struct {
	key   key
	entry entry[V]
}

type lookup[V any] struct {
	done  chan struct{}
	value V
	found bool
	err   error
}

type key struct {
	kind       string
	identifier string
}

// Cache coalesces concurrent upstream inspect calls for the same resource
// and memoizes successful (found) results for a short TTL. Not-found results
// are intentionally never memoized — see Lookup — to avoid an owner-isolation
// window where a name created within the TTL is still treated as nonexistent.
//
// V is the resolved value type (label maps, inspect metadata, ...). The cache
// itself never inspects V; freshness and coalescing semantics are identical
// for every instantiation.
//
// Eviction is approximate LRU: storeLocked drops the tail when the map hits
// maxSize and re-promotes refreshed entries, but cache hits do NOT promote.
// That trade keeps the hot-path critical section to a map lookup + scalar
// reads — no list write — so bursts of hits run without serializing on the
// list head. TTL-drained tail entries are evicted first on store, so a
// burst-then-quiet pattern still reclaims stale state correctly.
type Cache[V any] struct {
	ttl     time.Duration
	maxSize int
	now     func() time.Time
	resolve func(context.Context, string, string) (V, bool, error)

	mu       sync.Mutex
	entries  map[key]*list.Element // value: *entryNode[V]
	order    *list.List
	inFlight map[key]*lookup[V]
}

func New[V any](
	ttl time.Duration,
	maxSize int,
	now func() time.Time,
	resolve func(context.Context, string, string) (V, bool, error),
) *Cache[V] {
	return &Cache[V]{
		ttl:      ttl,
		maxSize:  maxSize,
		now:      now,
		resolve:  resolve,
		entries:  make(map[key]*list.Element),
		order:    list.New(),
		inFlight: make(map[key]*lookup[V]),
	}
}

// Lookup returns the cached value for a resource when it is still fresh and
// shares any in-flight miss with concurrent callers. Errors and not-found
// results are never cached (only found results are memoized).
//
// Reference-typed values (maps, pointers) are shared with the cache and any
// concurrent waiter — they MUST NOT be mutated by the caller. Each lookup is
// invariably followed by a read-only match check, so the read-only contract
// has held since the cache was introduced; dropping the defensive clones
// trades 1–2 allocs per call for that invariant.
func (c *Cache[V]) Lookup(ctx context.Context, kind, identifier string) (V, bool, error) {
	now := c.now()
	cacheKey := key{kind: kind, identifier: identifier}

	c.mu.Lock()
	if elem, ok := c.entries[cacheKey]; ok {
		node := elem.Value.(*entryNode[V])
		if now.Sub(node.entry.at) < c.ttl {
			value, found := node.entry.value, node.entry.found
			c.mu.Unlock()
			return value, found, nil
		}
	}
	if call, ok := c.inFlight[cacheKey]; ok {
		c.mu.Unlock()
		<-call.done
		return call.value, call.found, call.err
	}
	call := &lookup[V]{done: make(chan struct{})}
	c.inFlight[cacheKey] = call
	c.mu.Unlock()

	value, found, err := c.resolve(ctx, kind, identifier)

	c.mu.Lock()
	// Only memoize positive (found) results. Caching a not-found verdict would
	// open an owner-isolation window: an attacker could inspect a not-yet-
	// existing name (caching found=false → pass-through), then within the TTL a
	// victim creates a resource with that name, and the attacker's subsequent
	// operations would hit the stale negative entry and bypass the ownership
	// check. Concurrent identical misses are still coalesced via inFlight; they
	// just are not persisted past that in-flight window.
	if err == nil && found {
		c.storeLocked(cacheKey, value, found, c.now())
	}
	delete(c.inFlight, cacheKey)
	call.value = value
	call.found = found
	call.err = err
	close(call.done)
	c.mu.Unlock()

	return value, found, err
}

func (c *Cache[V]) storeLocked(cacheKey key, value V, found bool, at time.Time) {
	if elem, ok := c.entries[cacheKey]; ok {
		node := elem.Value.(*entryNode[V])
		node.entry = entry[V]{value: value, found: found, at: at}
		c.order.MoveToFront(elem)
		return
	}
	if len(c.entries) >= c.maxSize {
		// At capacity. First drain TTL-expired entries — the LRU tail is the
		// most likely candidate but any stale entry anywhere in the list
		// should go. Walk from back to front since older nodes cluster there.
		for e := c.order.Back(); e != nil; {
			node := e.Value.(*entryNode[V])
			prev := e.Prev()
			if at.Sub(node.entry.at) >= c.ttl {
				delete(c.entries, node.key)
				c.order.Remove(e)
			}
			e = prev
		}
		// If still over capacity, evict from the LRU tail.
		for c.order.Len() > 0 && len(c.entries) >= c.maxSize {
			tail := c.order.Back()
			tailNode := tail.Value.(*entryNode[V])
			delete(c.entries, tailNode.key)
			c.order.Remove(tail)
		}
	}
	node := &entryNode[V]{key: cacheKey, entry: entry[V]{value: value, found: found, at: at}}
	c.entries[cacheKey] = c.order.PushFront(node)
}
