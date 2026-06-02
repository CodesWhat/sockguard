package ratelimit

import "time"

// NewLimiter and (*Limiter).Allow are test-only conveniences retained here so
// unit tests can stay concise. Production code constructs limiters via
// newLimiterWithClock (with an injectable clock) and withdraws tokens via
// AllowN (with an explicit cost), so neither wrapper ships in the binary.

// NewLimiter creates a Limiter with the given rate parameters and a real clock.
// The caller MUST invoke (*Limiter).Stop on shutdown to halt the eviction loop.
func NewLimiter(tokensPerSecond, burst float64) *Limiter {
	return newLimiterWithClock(tokensPerSecond, burst, time.Now)
}

// Allow is shorthand for AllowN(clientID, 1) — withdraws a single token.
func (l *Limiter) Allow(clientID string) (ok bool, retryAfter int) {
	return l.AllowN(clientID, 1)
}
