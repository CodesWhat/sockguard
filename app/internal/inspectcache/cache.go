package inspectcache

import (
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
type Cache struct {
	ttl     time.Duration
	maxSize int
	now     func() time.Time
	resolve func(context.Context, string, string) (map[string]string, bool, error)

	mu       sync.Mutex
	entries  map[key]entry
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
		entries:  make(map[key]entry),
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
	if entry, ok := c.entries[cacheKey]; ok && now.Sub(entry.at) < c.ttl {
		c.mu.Unlock()
		return cloneLabels(entry.labels), entry.found, nil
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
	if len(c.entries) >= c.maxSize {
		var oldestKey key
		var oldestAt time.Time
		haveOldest := false
		for k, e := range c.entries {
			if at.Sub(e.at) >= c.ttl {
				delete(c.entries, k)
				continue
			}
			if !haveOldest || e.at.Before(oldestAt) {
				oldestKey = k
				oldestAt = e.at
				haveOldest = true
			}
		}
		if haveOldest && len(c.entries) >= c.maxSize {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[cacheKey] = entry{labels: labels, found: found, at: at}
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
