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

	return cloneLabels(cached), found, err
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

// cloneLabels intentionally returns a defensive copy before exposing cached
// resolver output to callers. The ownership and visibility paths treat label
// maps as ordinary mutable Go maps, so sharing the cached backing map across
// requests would let one caller corrupt later cache hits.
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
