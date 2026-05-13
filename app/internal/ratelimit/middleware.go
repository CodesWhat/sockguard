package ratelimit

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

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
	// Priority is the profile's tier for the global priority-aware fairness
	// gate. Ignored when MiddlewareOptions.GlobalConcurrency is nil. Zero
	// value (PriorityNormal) preserves prior behavior.
	Priority Priority
}

// GlobalConcurrencyOptions configures a system-wide concurrency cap shared
// across all profiles. When set, each profile is admitted only if total
// inflight is below its priority share of MaxInflight (low=50%, normal=80%,
// high=100%). Per-profile concurrency caps still apply on top of this gate.
type GlobalConcurrencyOptions struct {
	// MaxInflight is the system-wide ceiling on simultaneous in-flight
	// requests. Must be > 0; zero disables the gate.
	MaxInflight int64
}

// RateOptions configures token-bucket parameters.
type RateOptions struct {
	TokensPerSecond float64
	Burst           float64
	// EndpointCosts weights specific endpoints higher than the default 1 token
	// per request. First match in declaration order wins; unmatched requests
	// cost 1 token. Each entry's Cost must be >= 1 and <= the effective burst
	// (enforced by config validation; a cost greater than burst is permanently
	// un-satisfiable). PathGlob uses the same glob dialect as filter rules and
	// matches the normalized path (Docker API version prefix stripped).
	EndpointCosts []EndpointCost
}

// EndpointCost weights a specific endpoint pattern higher than the default
// 1 token per request, letting operators apply tighter budgets to expensive
// Docker operations such as build, image pull, and exec.
type EndpointCost struct {
	// PathGlob is matched against the normalized request path. Empty matches
	// nothing (config validator rejects empty patterns).
	PathGlob string
	// Methods restricts the rule to specific HTTP methods (case-insensitive).
	// Empty matches all methods.
	Methods []string
	// Cost is the number of tokens to withdraw on match. Must be >= 1.
	Cost float64
}

// compiledEndpointCost is the runtime form of an EndpointCost.
type compiledEndpointCost struct {
	pathRE  *regexp.Regexp
	methods map[string]struct{} // empty = match all
	cost    float64
}

// compileEndpointCosts converts the public-API slice into the runtime matcher
// table. It returns the first compile error encountered (typically an invalid
// regex from a malformed glob); callers should report it at startup. A nil
// input returns a nil slice (no per-endpoint weighting).
func compileEndpointCosts(costs []EndpointCost) ([]compiledEndpointCost, error) {
	if len(costs) == 0 {
		return nil, nil
	}
	compiled := make([]compiledEndpointCost, 0, len(costs))
	for i, ec := range costs {
		regex := "^" + filter.GlobToRegexString(ec.PathGlob) + "$"
		re, err := regexp.Compile(regex)
		if err != nil {
			return nil, fmt.Errorf("endpoint_costs[%d]: invalid path glob %q: %w", i, ec.PathGlob, err)
		}
		var methods map[string]struct{}
		if len(ec.Methods) > 0 {
			methods = make(map[string]struct{}, len(ec.Methods))
			for _, m := range ec.Methods {
				methods[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
			}
		}
		compiled = append(compiled, compiledEndpointCost{
			pathRE:  re,
			methods: methods,
			cost:    ec.Cost,
		})
	}
	return compiled, nil
}

// costFor returns the configured token cost for r, or 1 if no rule matches.
func (cp *compiledProfile) costFor(r *http.Request) float64 {
	if len(cp.endpointCosts) == 0 {
		return 1
	}
	path := filter.NormalizePath(r.URL.Path)
	method := strings.ToUpper(r.Method)
	for _, ec := range cp.endpointCosts {
		if len(ec.methods) > 0 {
			if _, ok := ec.methods[method]; !ok {
				continue
			}
		}
		if ec.pathRE.MatchString(path) {
			return ec.cost
		}
	}
	return 1
}

// ConcurrencyOptions configures the concurrency cap.
type ConcurrencyOptions struct {
	MaxInflight int64
}

// compiledProfile holds the runtime state for a single profile's limits.
type compiledProfile struct {
	rate          *RateOptions
	concurrency   *ConcurrencyOptions
	limiter       *Limiter
	tracker       *InflightTracker
	endpointCosts []compiledEndpointCost
	priority      Priority
}

func compileProfile(opts ProfileOptions) (*compiledProfile, error) {
	if opts.Rate == nil && opts.Concurrency == nil && opts.Priority == PriorityNormal {
		return nil, nil
	}
	cp := &compiledProfile{
		rate:        opts.Rate,
		concurrency: opts.Concurrency,
		priority:    opts.Priority,
	}
	if opts.Rate != nil {
		burst := opts.Rate.Burst
		if burst == 0 {
			burst = opts.Rate.TokensPerSecond
		}
		cp.limiter = NewLimiter(opts.Rate.TokensPerSecond, burst)

		compiled, err := compileEndpointCosts(opts.Rate.EndpointCosts)
		if err != nil {
			return nil, err
		}
		cp.endpointCosts = compiled
	}
	if opts.Concurrency != nil {
		cp.tracker = &InflightTracker{}
	}
	return cp, nil
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
	// GlobalConcurrency enables the system-wide priority-aware fairness gate.
	// Nil disables it, in which case per-profile priorities have no effect.
	GlobalConcurrency *GlobalConcurrencyOptions
}

// Middleware returns an HTTP middleware that enforces per-profile rate limiting
// and concurrency caps. It returns 429 when a request is denied.
//
// registry may be nil when Prometheus metrics are disabled.
//
// auditSampler may be nil; when non-nil it gates the slog throttle record to
// the first throttle of each (client, reason) tuple per second.
//
// An error is returned only when a profile's EndpointCost glob fails to compile
// — the config validator catches this at startup, so under normal use the error
// is nil.
func Middleware(
	logger *slog.Logger,
	registry *metrics.Registry,
	auditSampler *AuditSampler,
	opts MiddlewareOptions,
) (func(http.Handler) http.Handler, error) {
	var globalMax int64
	if opts.GlobalConcurrency != nil {
		globalMax = opts.GlobalConcurrency.MaxInflight
	}

	if len(opts.Profiles) == 0 && globalMax <= 0 {
		return func(next http.Handler) http.Handler { return next }, nil
	}

	// Pre-compile all profile limiters at middleware construction time.
	compiled := make(map[string]*compiledProfile, len(opts.Profiles))
	hasAny := false
	for name, profileOpts := range opts.Profiles {
		cp, err := compileProfile(profileOpts)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		if cp != nil {
			compiled[name] = cp
			hasAny = true
		}
	}
	if !hasAny && globalMax <= 0 {
		return func(next http.Handler) http.Handler { return next }, nil
	}

	var globalTracker *GlobalInflightTracker
	if globalMax > 0 {
		globalTracker = &GlobalInflightTracker{}
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
			if cp == nil && globalTracker == nil {
				// No per-profile limits and no global gate; pass through.
				next.ServeHTTP(w, r)
				return
			}

			// --- Rate limit check ---
			if cp != nil && cp.limiter != nil {
				cost := cp.costFor(r)
				ok, retryAfter := cp.limiter.AllowN(effectiveID, cost)
				if !ok {
					registry.ObserveThrottle(effectiveID, string(ReasonRateLimit))
					if auditSampler != nil && auditSampler.ShouldEmit(effectiveID, ReasonRateLimit) {
						attrs := logging.AppendCorrelationAttrs(nil, r)
						attrs = append(attrs,
							slog.String("client_id", effectiveID),
							slog.String("reason", string(ReasonRateLimit)),
							slog.Float64("tokens_per_second", cp.rate.TokensPerSecond),
							slog.Float64("burst", cp.rate.Burst),
							slog.Float64("cost", cost),
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

			// --- Global priority-aware fairness gate ---
			// Checked before the per-profile concurrency cap so a low-priority
			// caller hitting the gate cannot consume a per-profile slot. A 429
			// here does NOT increment any inflight counter. Profiles with no
			// compiled limits (cp == nil) still pass through this gate with
			// PriorityNormal so a single client cannot evade it by skipping
			// per-profile config.
			if globalTracker != nil {
				priority := PriorityNormal
				if cp != nil {
					priority = cp.priority
				}
				ok, current, threshold := globalTracker.Acquire(priority, globalMax)
				if !ok {
					registry.ObserveThrottle(effectiveID, string(ReasonPriorityFloor))
					if auditSampler != nil && auditSampler.ShouldEmit(effectiveID, ReasonPriorityFloor) {
						attrs := logging.AppendCorrelationAttrs(nil, r)
						attrs = append(attrs,
							slog.String("client_id", effectiveID),
							slog.String("reason", string(ReasonPriorityFloor)),
							slog.String("priority", priority.String()),
							slog.Int64("current_global_inflight", current),
							slog.Int64("priority_threshold", threshold),
							slog.Int64("global_max_inflight", globalMax),
						)
						logger.InfoContext(r.Context(), "throttle",
							slog.Group("throttle", attrsToAny(attrs)...))
					}
					logging.SetDeniedWithCode(w, r, string(ReasonPriorityFloor), "priority floor exceeded", filter.NormalizePath)
					_ = httpjson.Write(w, http.StatusTooManyRequests, ConcurrencyLimitResponse{
						Reason: string(ReasonPriorityFloor),
					})
					return
				}
				defer globalTracker.Release()
			}

			// --- Per-profile concurrency cap check ---
			// A 429 denial does NOT increment the inflight counter — we check
			// before acquiring so throttled requests are never counted as
			// in-flight.
			if cp != nil && cp.tracker != nil {
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
	}, nil
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
