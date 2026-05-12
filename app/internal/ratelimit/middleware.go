package ratelimit

import (
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/metrics"
)

// RateLimitResponse is the JSON body returned on a 429 for rate-limit denial.
type RateLimitResponse struct {
	Reason            string `json:"reason"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// ConcurrencyLimitResponse is the JSON body returned on a 429 for concurrency denial.
type ConcurrencyLimitResponse struct {
	Reason string `json:"reason"`
}

// ProfileOptions configures rate limiting and concurrency caps for a single
// named profile.
type ProfileOptions struct {
	// Rate enables token-bucket rate limiting. Nil disables it.
	Rate *RateOptions
	// Concurrency enables per-client inflight caps. Nil disables it.
	Concurrency *ConcurrencyOptions
}

// RateOptions configures token-bucket parameters.
type RateOptions struct {
	TokensPerSecond float64
	Burst           float64
}

// ConcurrencyOptions configures the concurrency cap.
type ConcurrencyOptions struct {
	MaxInflight int64
}

// compiledProfile holds the runtime state for a single profile's limits.
type compiledProfile struct {
	rate        *RateOptions
	concurrency *ConcurrencyOptions
	limiter     *Limiter
	tracker     *InflightTracker
}

func compileProfile(opts ProfileOptions) *compiledProfile {
	if opts.Rate == nil && opts.Concurrency == nil {
		return nil
	}
	cp := &compiledProfile{
		rate:        opts.Rate,
		concurrency: opts.Concurrency,
	}
	if opts.Rate != nil {
		burst := opts.Rate.Burst
		if burst == 0 {
			burst = opts.Rate.TokensPerSecond
		}
		cp.limiter = NewLimiter(opts.Rate.TokensPerSecond, burst)
	}
	if opts.Concurrency != nil {
		cp.tracker = &InflightTracker{}
	}
	return cp
}

// MiddlewareOptions configures the multi-profile rate-limit middleware.
type MiddlewareOptions struct {
	// Profiles maps profile name → per-profile limits. Requests with a
	// profile not in this map are passed through without limiting.
	Profiles map[string]ProfileOptions
	// ResolveProfile extracts the resolved profile name from a request.
	// When the profile is empty the request is bucketed under AnonymousClientID
	// in any applicable default profile entry.
	ResolveProfile func(*http.Request) (string, bool)
}

// Middleware returns an HTTP middleware that enforces per-profile rate limiting
// and concurrency caps. It returns 429 when a request is denied.
//
// registry may be nil when Prometheus metrics are disabled.
//
// auditSampler may be nil; when non-nil it gates the slog throttle record to
// the first throttle of each (client, reason) tuple per second.
func Middleware(
	logger *slog.Logger,
	registry *metrics.Registry,
	auditSampler *AuditSampler,
	opts MiddlewareOptions,
) func(http.Handler) http.Handler {
	if len(opts.Profiles) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	// Pre-compile all profile limiters at middleware construction time.
	compiled := make(map[string]*compiledProfile, len(opts.Profiles))
	hasAny := false
	for name, profileOpts := range opts.Profiles {
		cp := compileProfile(profileOpts)
		if cp != nil {
			compiled[name] = cp
			hasAny = true
		}
	}
	if !hasAny {
		return func(next http.Handler) http.Handler { return next }
	}

	resolveProfile := opts.ResolveProfile

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			profile := ""
			if resolveProfile != nil {
				profile, _ = resolveProfile(r)
			}

			// Requests with no resolved profile are bucketed under
			// AnonymousClientID so they cannot bypass limits by skipping
			// identification.
			effectiveID := profile
			if effectiveID == "" {
				effectiveID = AnonymousClientID
			}

			cp := compiled[effectiveID]
			if cp == nil {
				// No limits for this profile; pass through.
				next.ServeHTTP(w, r)
				return
			}

			// --- Rate limit check ---
			if cp.limiter != nil {
				ok, retryAfter := cp.limiter.Allow(effectiveID)
				if !ok {
					registry.ObserveThrottle(effectiveID, string(ReasonRateLimit))
					if auditSampler != nil && auditSampler.ShouldEmit(effectiveID, ReasonRateLimit) {
						attrs := logging.AppendCorrelationAttrs(nil, r)
						attrs = append(attrs,
							slog.String("client_id", effectiveID),
							slog.String("reason", string(ReasonRateLimit)),
							slog.Float64("tokens_per_second", cp.rate.TokensPerSecond),
							slog.Float64("burst", cp.rate.Burst),
						)
						logger.InfoContext(r.Context(), "throttle",
							slog.Group("throttle", attrsToAny(attrs)...))
					}
					logging.SetDeniedWithCode(w, r, string(ReasonRateLimit), "rate limit exceeded", filter.NormalizePath)
					w.Header().Set("Retry-After", itoa(retryAfter))
					_ = httpjson.Write(w, http.StatusTooManyRequests, RateLimitResponse{
						Reason:            string(ReasonRateLimit),
						RetryAfterSeconds: retryAfter,
					})
					return
				}
			}

			// --- Concurrency cap check ---
			// A 429 denial does NOT increment the inflight counter — we check
			// before acquiring so throttled requests are never counted as
			// in-flight.
			if cp.tracker != nil {
				ok, current := cp.tracker.Acquire(effectiveID, cp.concurrency.MaxInflight)
				if !ok {
					registry.ObserveThrottle(effectiveID, string(ReasonConcurrency))
					if auditSampler != nil && auditSampler.ShouldEmit(effectiveID, ReasonConcurrency) {
						attrs := logging.AppendCorrelationAttrs(nil, r)
						attrs = append(attrs,
							slog.String("client_id", effectiveID),
							slog.String("reason", string(ReasonConcurrency)),
							slog.Int64("current_inflight", current),
							slog.Int64("max_inflight", cp.concurrency.MaxInflight),
						)
						logger.InfoContext(r.Context(), "throttle",
							slog.Group("throttle", attrsToAny(attrs)...))
					}
					logging.SetDeniedWithCode(w, r, string(ReasonConcurrency), "concurrency cap exceeded", filter.NormalizePath)
					_ = httpjson.Write(w, http.StatusTooManyRequests, ConcurrencyLimitResponse{
						Reason: string(ReasonConcurrency),
					})
					return
				}
				// Release the in-flight counter on handler return, including panic.
				defer func() {
					cp.tracker.Release(effectiveID)
					registry.SetInflight(effectiveID, cp.tracker.Current(effectiveID))
				}()
				registry.SetInflight(effectiveID, current)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func attrsToAny(attrs []slog.Attr) []any {
	result := make([]any, len(attrs))
	for i, a := range attrs {
		result[i] = a
	}
	return result
}

// itoa converts an int to its decimal string representation without importing
// strconv at the call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	// Reverse.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
