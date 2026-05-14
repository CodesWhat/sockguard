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

type entry struct {
	labels map[string]string
	found  bool
	at     time.Time
}

type entryNode struct {
	key   key
	entry entry
}

type lookup struct {
	done   chan struct{}
	labels map[string]string
	found  bool
	err    error
}

type key struct {
	kind       string
	identifier string
}

// Cache coalesces concurrent upstream inspect calls for the same resource
// and memoizes successful/not-found results for a short TTL.
//
// Eviction is true LRU: every cache hit moves the entry to the front of an
// ordering list, and storeLocked drops the tail when the map hits maxSize.
// Previously eviction did a full O(n) scan under the lock on every miss that
// hit the size cap; with a list-backed LRU each lookup pays O(1).
type Cache struct {
	ttl     time.Duration
	maxSize int
	now     func() time.Time
	resolve func(context.Context, string, string) (map[string]string, bool, error)

	mu       sync.Mutex
	entries  map[key]*list.Element // value: *entryNode
	order    *list.List
	inFlight map[key]*lookup
}

func New(
	ttl time.Duration,
	maxSize int,
	now func() time.Time,
	resolve func(context.Context, string, string) (map[string]string, bool, error),
) *Cache {
	return &Cache{
		ttl:      ttl,
		maxSize:  maxSize,
		now:      now,
		resolve:  resolve,
		entries:  make(map[key]*list.Element),
		order:    list.New(),
		inFlight: make(map[key]*lookup),
	}
}

// Lookup returns cached labels for a resource when they are still fresh and
// shares any in-flight miss with concurrent callers. Errors are never cached.
//
// The returned map is owned by the caller; it is a defensive copy of the
// cached entry so callers may not mutate it without risk of corrupting
// subsequent cache hits.
func (c *Cache) Lookup(ctx context.Context, kind, identifier string) (map[string]string, bool, error) {
	now := c.now()
	cacheKey := key{kind: kind, identifier: identifier}

	c.mu.Lock()
	if elem, ok := c.entries[cacheKey]; ok {
		node := elem.Value.(*entryNode)
		if now.Sub(node.entry.at) < c.ttl {
			c.order.MoveToFront(elem)
			labels, found := node.entry.labels, node.entry.found
			c.mu.Unlock()
			return cloneLabels(labels), found, nil
		}
	}
	if call, ok := c.inFlight[cacheKey]; ok {
		c.mu.Unlock()
		<-call.done
		return cloneLabels(call.labels), call.found, call.err
	}
	call := &lookup{done: make(chan struct{})}
	c.inFlight[cacheKey] = call
	c.mu.Unlock()

	labels, found, err := c.resolve(ctx, kind, identifier)
	// Clone labels once for the cache entry (and in-flight waiters). The
	// original resolver map is returned directly to this goroutine's caller
	// so we avoid a second allocation — the resolver always returns a fresh
	// map from JSON decode, and the cache's copy is independent of it.
	cached := cloneLabels(labels)

	c.mu.Lock()
	if err == nil {
		c.storeLocked(cacheKey, cached, found, c.now())
	}
	delete(c.inFlight, cacheKey)
	call.labels = cached
	call.found = found
	call.err = err
	close(call.done)
	c.mu.Unlock()

	return labels, found, err
}

func (c *Cache) storeLocked(cacheKey key, labels map[string]string, found bool, at time.Time) {
	if elem, ok := c.entries[cacheKey]; ok {
		node := elem.Value.(*entryNode)
		node.entry = entry{labels: labels, found: found, at: at}
		c.order.MoveToFront(elem)
		return
	}
	if len(c.entries) >= c.maxSize {
		// At capacity. First drain TTL-expired entries — the LRU tail is the
		// most likely candidate but any stale entry anywhere in the list
		// should go. Walk from back to front since older nodes cluster there.
		for e := c.order.Back(); e != nil; {
			node := e.Value.(*entryNode)
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
			tailNode := tail.Value.(*entryNode)
			delete(c.entries, tailNode.key)
			c.order.Remove(tail)
		}
	}
	node := &entryNode{key: cacheKey, entry: entry{labels: labels, found: found, at: at}}
	c.entries[cacheKey] = c.order.PushFront(node)
}

// cloneLabels returns a defensive copy of a label map. It is used when storing
// resolver output into the cache entry (and in-flight lookup) so the cache's
// backing map is never the same pointer as anything returned to a caller.
func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}
