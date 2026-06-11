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

// Packed-state constants for the atomic.Uint64 token bucket.
// Encoding:
//
//	bits [63:32]  uint32  millisecond timestamp mod 2^32 (wraps every ~49.7 days)
//	bits [31:0]   uint32  16.16 fixed-point token count
//	  bits [31:16]  uint16  integer part  (0..65535 tokens)
//	  bits [15:0]   uint16  fractional part (0..65535/65536)
//
// Overflow safety: the worst-case intermediate in refill is
// int64(elapsedMS) * int64(tpsFP).
// With elapsedMS <= int32 max (~24.8 days) and tpsFP <= 65535*65536 = 4,294,901,760,
// the product is at most ~9.2e18, which fits in int64 (max ~9.2e18).
//
// Timestamp wraparound: the uint32 ms counter wraps at ~49.7 days. The signed
// elapsed computation is uint32(nowMS) - uint32(lastMS) reinterpreted as int32.
// Modular subtraction gives the correct signed result as long as the real elapsed
// time is within (-24.8 days, +24.8 days). The eviction TTL is 10 minutes, so
// no bucket lives long enough to encounter the ~24.8-day half-window. Worst case
// (a bucket somehow surviving past 24.8 days idle): one refill cycle is skipped;
// the bucket recovers on the next call. This is benign.
const (
	packedFracBits  = 16
	packedFracScale = uint64(1 << packedFracBits) // 65536

	// MaxPackedBurst is the maximum configurable burst (and tokens_per_second).
	// The packed token field is 32 bits of 16.16 fixed-point, so the integer
	// part overflows at 65536. The config validator enforces this at startup;
	// AllowN does not re-check at runtime.
	MaxPackedBurst = float64((1 << 16) - 1) // 65535
)

// packState assembles a packed state word from a fixed-point token count and a
// millisecond timestamp.
func packState(tokenFP uint32, ms uint32) uint64 {
	return uint64(ms)<<32 | uint64(tokenFP)
}

// unpackTokenFP extracts the 16.16 fixed-point token count from a packed word.
func unpackTokenFP(w uint64) uint32 { return uint32(w) } //nolint:gosec // G115: intentional truncation to lower 32 bits (token field)

// unpackMS extracts the millisecond timestamp from a packed word.
func unpackMS(w uint64) uint32 { return uint32(w >> 32) }

// nowFn is the time source used by token buckets. It can be replaced in tests
// via newBucketWithClock.
type nowFn func() time.Time

// bucket is a single per-client token bucket. It is safe for concurrent use.
//
// Token state (current count + last-refill timestamp) is packed into a single
// atomic.Uint64:
//
//	bits [63:32] — millisecond timestamp mod 2^32 (wraps every 49.7 days)
//	bits [31:0]  — 16.16 fixed-point token count (integer in [31:16], fractional in [15:0])
//
// Packing eliminates the per-admitted-request heap allocation that the former
// atomic.Pointer[bucketState] design incurred. AllowN remains lock-free.
//
// Refill granularity: timestamps are millisecond-precision. Sub-millisecond
// calls see elapsedMS=0 and skip refill; the stored timestamp is not advanced
// until at least 1ms has elapsed since the last refill. This is a behavioral
// change from the nanosecond-precision predecessor: sub-ms traffic patterns
// at very high rates accumulate tokens only at 1ms resolution rather than
// continuously. For all rates the config accepts (max 65535 t/s = 1 token per
// ~15µs), this is negligible.
//
// lastAccessNs is a separate atomic so eviction reads never contend with AllowN writes.
type bucket struct {
	state        atomic.Uint64
	lastAccessNs atomic.Int64 // Unix nanoseconds; updated on every AllowN
	tpsFP        uint64       // tokensPerSecond * packedFracScale, pre-computed
	burstFP      uint64       // burst * packedFracScale, pre-computed
	now          nowFn
}

func newBucket(tokensPerSecond, burst float64, now nowFn) *bucket {
	t := now()
	b := &bucket{
		tpsFP:   uint64(tokensPerSecond * float64(packedFracScale)),
		burstFP: uint64(burst * float64(packedFracScale)),
		now:     now,
	}
	// Guard: tpsFP must be at least 1 to avoid division by zero in retryAfter.
	// This handles rates below 1/65536 t/s (~1 token/18h); the effective minimum
	// is quantized to 1/65536 t/s.
	if b.tpsFP == 0 {
		b.tpsFP = 1
	}
	initialFP := uint32(burst * float64(packedFracScale))
	ms := uint32(t.UnixMilli()) //nolint:gosec // G115: intentional mod-2^32 truncation of ms timestamp (wraps every ~49.7 days)
	b.state.Store(packState(initialFP, ms))
	b.lastAccessNs.Store(t.UnixNano())
	return b
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
//
// Implementation: lock-free CAS loop. Each iteration reads the current packed
// state, computes the next state, and attempts a CAS swap. On CAS failure
// (another goroutine raced us) the loop retries with the fresh value.
// After maxCASRetries unsuccessful swaps the request is conservatively denied;
// this is an extremely rare safety-valve — in practice contention resolves
// within one or two retries.
//
// retryAfter formula: ceil(deficitFP / tpsFP). Both deficitFP and tpsFP carry
// the same ×packedFracScale factor, so the quotient is in units of seconds.
const maxCASRetries = 100

func (b *bucket) AllowN(cost float64) (ok bool, retryAfter int) {
	if cost < 1 {
		cost = 1
	}
	costFP := uint64(cost * float64(packedFracScale))

	nowT := b.now()
	nowNs := nowT.UnixNano()
	b.lastAccessNs.Store(nowNs)
	nowMS := uint32(nowT.UnixMilli()) //nolint:gosec // G115: intentional mod-2^32 truncation of ms timestamp

	for i := 0; i < maxCASRetries; i++ {
		old := b.state.Load()
		lastMS := unpackMS(old)
		tokenFP := uint64(unpackTokenFP(old))

		// Compute signed elapsed milliseconds via modular subtraction.
		// Casting the unsigned difference to int32 handles backwards-clock
		// steps (negative elapsed → no refill) and the uint32 wraparound at
		// ~49.7 days (see package-level comment).
		elapsedMS := int32(nowMS - lastMS) //nolint:gosec // G115: intentional signed-modular-diff for backwards-clock detection

		var newTokenFP uint64
		var newMS uint32
		if elapsedMS > 0 {
			// refill = elapsed_ms * tpsFP / 1000
			// Both elapsed_ms (int32, max ~2.1e9) and tpsFP (max ~4.3e9) fit
			// in int64 when multiplied (~9.2e18 < int64 max).
			refillFP := uint64(int64(elapsedMS)*int64(b.tpsFP)) / 1000 //nolint:gosec // G115: tpsFP <= 65535*65536 = 4,294,901,760 fits int64; product fits int64 (max ~9.2e18)
			newTokenFP = tokenFP + refillFP
			if newTokenFP > b.burstFP {
				newTokenFP = b.burstFP
			}
			newMS = nowMS
		} else {
			newTokenFP = tokenFP
			newMS = lastMS
		}

		if newTokenFP >= costFP {
			remainingFP := newTokenFP - costFP
			// Defensive mask: ensures the token bits never spill into the
			// timestamp half of the word even if a caller bypasses the
			// config validator (e.g., a direct newBucket call with burst>65535).
			next := uint64(newMS)<<32 | (uint64(remainingFP) & 0xFFFFFFFF)
			if b.state.CompareAndSwap(old, next) {
				return true, 0
			}
			// CAS lost — retry with fresh state.
			continue
		}

		// Not enough tokens; compute wait in seconds using ceiling division.
		// deficitFP and tpsFP both carry ×packedFracScale, so the quotient is
		// in seconds.
		deficitFP := costFP - newTokenFP
		retrySeconds := int((deficitFP + b.tpsFP - 1) / b.tpsFP) //nolint:gosec // G115: quotient is seconds; burst <= 65535 bounds deficitFP
		return false, retrySeconds
	}

	// Exhausted retries under extreme contention — deny conservatively.
	return false, 1
}

// idleSince returns how long since the last AllowN call. Reads the atomic
// lastAccessNs directly — no lock needed.
func (b *bucket) idleSince(now time.Time) time.Duration {
	lastNs := b.lastAccessNs.Load()
	return now.Sub(time.Unix(0, lastNs))
}

// Limiter maintains per-client token buckets, lazily created on first use.
//
// Buckets that go idle for longer than limiterEvictTTL are dropped by a
// background eviction goroutine started in NewLimiter. The key space today
// is bounded by configured profile names (low cardinality), but eviction is
// wired in as defense-in-depth so future changes to the key space cannot
// create an OOM vector via attacker-influenced identities.
//
// Hot-path design: AllowN uses sync.Map so the steady-state bucket lookup
// (Load only) is lock-free after warm-up. New bucket creation uses
// LoadOrStore to avoid a separate mutex without introducing a TOCTOU window.
type Limiter struct {
	buckets         sync.Map // map[string]*bucket; lock-free reads on warm path
	tokensPerSecond float64
	burst           float64
	now             nowFn

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// newLimiterWithClock creates a Limiter with the given rate parameters and an
// injectable time source. It starts a background eviction goroutine; the caller
// MUST invoke (*Limiter).Stop on shutdown to halt it.
func newLimiterWithClock(tokensPerSecond, burst float64, now nowFn) *Limiter {
	l := &Limiter{
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
	l.buckets.Range(func(key, val any) bool {
		b := val.(*bucket)
		if b.idleSince(now) > ttl {
			l.buckets.Delete(key)
		}
		return true
	})
}

// AllowN checks whether clientID may proceed at the given token cost.
// If clientID is empty the request is bucketed under AnonymousClientID.
//
// Hot path: Load is lock-free for existing buckets (sync.Map read-path).
// Cold path (new client): LoadOrStore races to store a fresh bucket; if two
// goroutines race, one wins and the other discards its candidate — both use
// the winner's bucket thereafter.
func (l *Limiter) AllowN(clientID string, cost float64) (ok bool, retryAfter int) {
	if clientID == "" {
		clientID = AnonymousClientID
	}

	// Optimistic load: no allocation on warm path.
	if val, hit := l.buckets.Load(clientID); hit {
		return val.(*bucket).AllowN(cost)
	}

	// Cold path: create a candidate and race to store it.
	candidate := newBucket(l.tokensPerSecond, l.burst, l.now)
	actual, _ := l.buckets.LoadOrStore(clientID, candidate)
	return actual.(*bucket).AllowN(cost)
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
// The sampler stores last-emit timestamps in a sync.Map keyed by
// clientReasonKey. The hot path is the rejection branch (in-window
// duplicates), which becomes lock-free via sync.Map.Load; only the first
// emit per window pays for a CompareAndSwap.
//
// AuditSampler also runs a background eviction goroutine to prevent unbounded
// memory growth from many unique client IDs.
type AuditSampler struct {
	// lastHit maps clientReasonKey → *time.Time. Pointer values let
	// CompareAndSwap detect races without re-reading under a lock.
	lastHit sync.Map
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
		now: now,
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
	nowPtr := &now

	// First-time emission: LoadOrStore returns loaded=false and the win.
	prev, loaded := s.lastHit.LoadOrStore(key, nowPtr)
	if !loaded {
		return true
	}

	lastPtr, ok := prev.(*time.Time)
	if !ok || now.Sub(*lastPtr) < auditEmitWindow {
		return false
	}
	// Window has elapsed; race the swap. Losing the race means another
	// goroutine emitted ~simultaneously, which is the correct outcome —
	// 1 emit per window per key, not 1-per-caller.
	return s.lastHit.CompareAndSwap(key, lastPtr, nowPtr)
}

// evict removes entries older than ttl from the sampler map. The Range
// iteration is unsynchronized, which is fine because CompareAndDelete only
// removes entries whose pointer hasn't been swapped by a racing ShouldEmit.
func (s *AuditSampler) evict(ttl time.Duration) {
	cutoff := s.now().Add(-ttl)
	s.lastHit.Range(func(k, v any) bool {
		t, ok := v.(*time.Time)
		if !ok {
			s.lastHit.Delete(k)
			return true
		}
		if t.Before(cutoff) {
			s.lastHit.CompareAndDelete(k, v)
		}
		return true
	})
}
