// Package ratelimit provides per-client token-bucket rate limiting and
// concurrency capping for the sockguard proxy. All state is in-memory; there
// is no pluggable backend.
//
// Identity key: requests are keyed by the profile name resolved by the
// clientacl middleware. Requests with no resolved profile (anonymous callers)
// are bucketed under [AnonymousClientID] so they cannot bypass limits by
// skipping identification.
package ratelimit

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// AnonymousClientID is the bucket key used for requests with no resolved
// profile. This ensures anonymous callers cannot bypass limits by skipping
// identification.
const AnonymousClientID = "_anonymous"

const (
	// auditEmitWindow is the per-(client, reason) suppression window for the
	// slog throttle audit record. The Prometheus counter still fires
	// unconditionally — sampling only bounds log volume.
	auditEmitWindow = time.Second

	// auditEvictInterval is the period of the background eviction tick on
	// AuditSampler and Limiter.
	auditEvictInterval = 30 * time.Second

	// auditEvictTTL is the lifetime of an unaccessed sampler entry before
	// eviction. Must be >= auditEmitWindow so the suppression decision is
	// preserved across at least one window.
	auditEvictTTL = 60 * time.Second

	// limiterEvictTTL is the lifetime of an unaccessed token bucket before
	// eviction. Buckets are keyed today by configured profile name (low
	// cardinality), but eviction is wired in as defense-in-depth so future
	// changes to the key space cannot create an OOM vector.
	limiterEvictTTL = 10 * time.Minute
)

// nowFn is the time source used by token buckets. It can be replaced in tests
// via newBucketWithClock.
type nowFn func() time.Time

// bucket is a single per-client token bucket. It is safe for concurrent use.
//
// lastAccess tracks the wall-clock of the last AllowN call and is read by the
// owning Limiter's eviction loop to drop buckets that have gone idle for
// longer than limiterEvictTTL.
type bucket struct {
	mu              sync.Mutex
	tokens          float64
	tokensPerSecond float64
	burst           float64
	lastRefill      time.Time
	lastAccess      time.Time
	now             nowFn
}

func newBucket(tokensPerSecond, burst float64, now nowFn) *bucket {
	t := now()
	return &bucket{
		tokens:          burst,
		tokensPerSecond: tokensPerSecond,
		burst:           burst,
		lastRefill:      t,
		lastAccess:      t,
		now:             now,
	}
}

// Allow is shorthand for AllowN(1) — withdraws a single token.
func (b *bucket) Allow() (ok bool, retryAfter int) {
	return b.AllowN(1)
}

// AllowN withdraws cost tokens from the bucket. cost < 1 is clamped to 1 so a
// misconfigured zero cost cannot let a client bypass the limiter entirely.
// Returns (true, 0) on success. On failure returns (false, retry-after seconds)
// computed as the ceiling of (cost − current_tokens) / tokensPerSecond.
//
// cost greater than burst is permanently un-satisfiable; the validator in
// internal/config rejects that configuration at startup. AllowN does not
// re-check it here — defensive logic in a hot path would just hide config bugs.
func (b *bucket) AllowN(cost float64) (ok bool, retryAfter int) {
	if cost < 1 {
		cost = 1
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.lastAccess = now
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(b.tokens+elapsed*b.tokensPerSecond, b.burst)
		b.lastRefill = now
	}

	if b.tokens >= cost {
		b.tokens -= cost
		return true, 0
	}

	deficit := cost - b.tokens
	waitSeconds := deficit / b.tokensPerSecond
	return false, int(math.Ceil(waitSeconds))
}

// idleSince returns how long since the last AllowN call. Read under the
// bucket mutex so the value is consistent with concurrent AllowN updates.
func (b *bucket) idleSince(now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.Sub(b.lastAccess)
}

// Limiter maintains per-client token buckets, lazily created on first use.
//
// Buckets that go idle for longer than limiterEvictTTL are dropped by a
// background eviction goroutine started in NewLimiter. The key space today
// is bounded by configured profile names (low cardinality), but eviction is
// wired in as defense-in-depth so future changes to the key space cannot
// create an OOM vector via attacker-influenced identities.
type Limiter struct {
	mu              sync.Mutex
	buckets         map[string]*bucket
	tokensPerSecond float64
	burst           float64
	now             nowFn

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewLimiter creates a Limiter with the given rate parameters and real-clock
// time source. It starts a background eviction goroutine; the caller MUST
// invoke (*Limiter).Stop on shutdown to halt it.
func NewLimiter(tokensPerSecond, burst float64) *Limiter {
	return newLimiterWithClock(tokensPerSecond, burst, time.Now)
}

func newLimiterWithClock(tokensPerSecond, burst float64, now nowFn) *Limiter {
	l := &Limiter{
		buckets:         make(map[string]*bucket),
		tokensPerSecond: tokensPerSecond,
		burst:           burst,
		now:             now,
		stopCh:          make(chan struct{}),
	}
	l.wg.Add(1)
	go l.evictionLoop()
	return l
}

func (l *Limiter) evictionLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(auditEvictInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.evict(limiterEvictTTL)
		case <-l.stopCh:
			return
		}
	}
}

// Stop halts the background eviction goroutine. Safe to call multiple times;
// subsequent calls are no-ops via the closed stopCh.
func (l *Limiter) Stop() {
	select {
	case <-l.stopCh:
		// already stopped
	default:
		close(l.stopCh)
	}
	l.wg.Wait()
}

// evict removes buckets idle for longer than ttl. Exposed for tests.
func (l *Limiter) evict(ttl time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		if b.idleSince(now) > ttl {
			delete(l.buckets, key)
		}
	}
}

// Allow is shorthand for AllowN(clientID, 1) — withdraws a single token.
func (l *Limiter) Allow(clientID string) (ok bool, retryAfter int) {
	return l.AllowN(clientID, 1)
}

// AllowN checks whether clientID may proceed at the given token cost.
// If clientID is empty the request is bucketed under AnonymousClientID.
func (l *Limiter) AllowN(clientID string, cost float64) (ok bool, retryAfter int) {
	if clientID == "" {
		clientID = AnonymousClientID
	}

	l.mu.Lock()
	b, exists := l.buckets[clientID]
	if !exists {
		b = newBucket(l.tokensPerSecond, l.burst, l.now)
		l.buckets[clientID] = b
	}
	l.mu.Unlock()

	return b.AllowN(cost)
}

// InflightTracker maintains per-client in-flight request counts. It is safe
// for concurrent use.
type InflightTracker struct {
	counters sync.Map // map[string]*atomic.Int64
}

// Acquire increments the in-flight counter for clientID and checks it against
// maxInflight. Returns (true, currentCount) when the request is admitted,
// (false, currentCount) when the cap is exceeded. The caller must call
// Release exactly once per successful Acquire, via defer immediately after
// checking the return value.
//
// Important: Acquire does NOT pre-increment before the cap check to avoid
// over-counting denied requests. The sequence is: load current → compare →
// if admitted, increment → return.
func (t *InflightTracker) Acquire(clientID string, maxInflight int64) (ok bool, current int64) {
	if clientID == "" {
		clientID = AnonymousClientID
	}

	// Load or create the counter for this client.
	val, _ := t.counters.LoadOrStore(clientID, &atomic.Int64{})
	counter := val.(*atomic.Int64)

	// CAS loop: check cap, then increment only if within cap.
	for {
		curr := counter.Load()
		if curr >= maxInflight {
			return false, curr
		}
		if counter.CompareAndSwap(curr, curr+1) {
			return true, curr + 1
		}
		// Another goroutine incremented between Load and CAS; retry.
	}
}

// Release decrements the in-flight counter for clientID. It is safe to call
// Release with an empty clientID (same bucketing as Acquire). Release is a
// no-op if no counter exists for the client.
func (t *InflightTracker) Release(clientID string) {
	if clientID == "" {
		clientID = AnonymousClientID
	}
	val, ok := t.counters.Load(clientID)
	if !ok {
		return
	}
	counter := val.(*atomic.Int64)
	// Clamp at zero to prevent underflow from programming errors.
	for {
		curr := counter.Load()
		if curr <= 0 {
			return
		}
		if counter.CompareAndSwap(curr, curr-1) {
			return
		}
	}
}

// Current returns the current in-flight count for clientID without modifying it.
func (t *InflightTracker) Current(clientID string) int64 {
	if clientID == "" {
		clientID = AnonymousClientID
	}
	val, ok := t.counters.Load(clientID)
	if !ok {
		return 0
	}
	return val.(*atomic.Int64).Load()
}

// ThrottleReason is the stable string reason code emitted on throttle events.
type ThrottleReason string

const (
	// ReasonRateLimit is emitted when a token-bucket limit is exceeded.
	ReasonRateLimit ThrottleReason = "rate_limit_exceeded"
	// ReasonConcurrency is emitted when a per-profile concurrency cap is exceeded.
	ReasonConcurrency ThrottleReason = "concurrency_cap"
	// ReasonPriorityFloor is emitted when the global priority-aware floor is
	// exceeded — total inflight crossed this profile's priority share of the
	// global concurrency cap. Distinguished from ReasonConcurrency so operators
	// can tune the global cap and per-profile caps independently.
	ReasonPriorityFloor ThrottleReason = "priority_floor"
)

// clientReasonKey is the deduplication key for audit-event sampling.
type clientReasonKey struct {
	clientID string
	reason   ThrottleReason
}

// AuditSampler enforces the 1-per-second-per-(client,reason) audit-emit
// policy. Prometheus counters always fire; the slog audit record is gated
// through this sampler to avoid log-volume blowout under attack.
//
// AuditSampler also runs a background eviction goroutine to prevent unbounded
// memory growth from many unique client IDs.
type AuditSampler struct {
	mu      sync.Mutex
	lastHit map[clientReasonKey]time.Time
	now     nowFn
}

// NewAuditSampler creates a sampler with a real-clock time source and starts
// the background eviction goroutine. The goroutine exits when the returned
// stop function is called.
func NewAuditSampler() (s *AuditSampler, stop func()) {
	return newAuditSamplerWithClock(time.Now)
}

func newAuditSamplerWithClock(now nowFn) (*AuditSampler, func()) {
	s := &AuditSampler{
		lastHit: make(map[clientReasonKey]time.Time),
		now:     now,
	}
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(auditEvictInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.evict(auditEvictTTL)
			case <-stopCh:
				return
			}
		}
	}()
	return s, func() {
		close(stopCh)
		wg.Wait()
	}
}

// ShouldEmit returns true if an audit record should be emitted for the given
// (client, reason) pair. It advances the last-emit time when returning true.
// The Prometheus counter should always increment regardless of this return value.
func (s *AuditSampler) ShouldEmit(clientID string, reason ThrottleReason) bool {
	if clientID == "" {
		clientID = AnonymousClientID
	}
	key := clientReasonKey{clientID: clientID, reason: reason}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	last, exists := s.lastHit[key]
	if !exists || now.Sub(last) >= auditEmitWindow {
		s.lastHit[key] = now
		return true
	}
	return false
}

// evict removes entries older than ttl from the sampler map.
func (s *AuditSampler) evict(ttl time.Duration) {
	cutoff := s.now().Add(-ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, t := range s.lastHit {
		if t.Before(cutoff) {
			delete(s.lastHit, key)
		}
	}
}
