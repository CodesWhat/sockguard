package ratelimit

import (
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/metrics"
)

// profileReleaser is a zero-alloc handle for releasing a per-profile
// concurrency slot. It is pooled via profileReleaserPool so the per-request
// cost of an admitted concurrency-capped request amortises to ~0.
//
// Callers must call Done() exactly once and then return the struct to the
// pool via put(). The idiomatic pattern is:
//
//	rel := getProfileReleaser(cp, clientID, reg)
//	defer rel.done()
type profileReleaser struct {
	tracker  *InflightTracker
	registry *metrics.Registry
	clientID string
}

var profileReleaserPool = sync.Pool{
	New: func() any { return new(profileReleaser) },
}

func getProfileReleaser(cp *compiledProfile, clientID string, registry *metrics.Registry) *profileReleaser {
	r := profileReleaserPool.Get().(*profileReleaser)
	r.tracker = cp.tracker
	r.registry = registry
	r.clientID = clientID
	return r
}

func (r *profileReleaser) done() {
	r.tracker.Release(r.clientID)
	r.registry.SetInflight(r.clientID, r.tracker.Current(r.clientID))
	// Zero fields before returning to pool to prevent accidental reuse.
	r.tracker = nil
	r.registry = nil
	r.clientID = ""
	profileReleaserPool.Put(r)
}

// ThrottleResponse is the JSON body returned on every 429 throttle response.
// RetryAfterSeconds is included only for rate-limit denials (where the bucket
// math yields a meaningful wait time); concurrency and priority-floor denials
// omit it because the available capacity depends on other clients finishing.
type ThrottleResponse struct {
	Reason            string `json:"reason"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
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
// table. A nil input returns a nil slice (no per-endpoint weighting).
//
// Compilation uses regexp.MustCompile: filter.GlobToRegexString output is
// always valid regex (every input character is either an explicit glob token
// or regexp.QuoteMeta'd), so a Compile failure here means globToRegex has a
// programming bug and the proxy must fail-fast at startup rather than silently
// run without rate limiting. The config validator already rejects malformed
// user input via regexp.Compile, so untrusted globs never reach this path.
func compileEndpointCosts(costs []EndpointCost) []compiledEndpointCost {
	if len(costs) == 0 {
		return nil
	}
	compiled := make([]compiledEndpointCost, 0, len(costs))
	for _, ec := range costs {
		regex := "^" + filter.GlobToRegexString(ec.PathGlob) + "$"
		re := regexp.MustCompile(regex)
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
	return compiled
}

// costFor returns the configured token cost for r against the pre-normalized
// path, or 1 if no rule matches. The caller normalizes once per request and
// reuses the result for cost lookup, audit logging, and the deny path.
func (cp *compiledProfile) costFor(method, normPath string) float64 {
	if len(cp.endpointCosts) == 0 {
		return 1
	}
	method = strings.ToUpper(method)
	for _, ec := range cp.endpointCosts {
		if len(ec.methods) > 0 {
			if _, ok := ec.methods[method]; !ok {
				continue
			}
		}
		if ec.pathRE.MatchString(normPath) {
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

func compileProfile(opts ProfileOptions, now func() time.Time) *compiledProfile {
	if opts.Rate == nil && opts.Concurrency == nil && opts.Priority == PriorityNormal {
		return nil
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
		cp.limiter = newLimiterWithClock(opts.Rate.TokensPerSecond, burst, now)
		cp.endpointCosts = compileEndpointCosts(opts.Rate.EndpointCosts)
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
	// GlobalConcurrency enables the system-wide priority-aware fairness gate.
	// Nil disables it, in which case per-profile priorities have no effect.
	GlobalConcurrency *GlobalConcurrencyOptions
	// Now overrides the time source for every per-profile Limiter created by
	// this Middleware. Tests that need deterministic refill behavior inject a
	// fixed-clock function; production code leaves this nil to use time.Now.
	Now func() time.Time
}

// Middleware returns an HTTP middleware that enforces per-profile rate limiting
// and concurrency caps, plus a stop function that halts every per-profile
// Limiter eviction goroutine started during compilation. It returns 429 when a
// request is denied.
//
// registry may be nil when Prometheus metrics are disabled.
//
// auditSampler may be nil; when non-nil it gates the slog throttle record to
// the first throttle of each (client, reason) tuple per second.
//
// Callers MUST invoke the returned stop function on shutdown to avoid leaking
// background goroutines. Calling stop is safe even when no Limiter was started
// (no profile has rate limiting): it is a no-op in that case.
func Middleware(
	logger *slog.Logger,
	registry *metrics.Registry,
	auditSampler *AuditSampler,
	opts MiddlewareOptions,
) (mw func(http.Handler) http.Handler, stop func()) {
	var globalMax int64
	if opts.GlobalConcurrency != nil {
		globalMax = opts.GlobalConcurrency.MaxInflight
	}

	noop := func(next http.Handler) http.Handler { return next }
	noopStop := func() {}

	if len(opts.Profiles) == 0 && globalMax <= 0 {
		return noop, noopStop
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	// Pre-compile all profile limiters at middleware construction time.
	compiled := make(map[string]*compiledProfile, len(opts.Profiles))
	var limiters []*Limiter
	hasAny := false
	for name, profileOpts := range opts.Profiles {
		cp := compileProfile(profileOpts, now)
		if cp == nil {
			continue
		}
		compiled[name] = cp
		hasAny = true
		if cp.limiter != nil {
			limiters = append(limiters, cp.limiter)
		}
	}
	if !hasAny && globalMax <= 0 {
		return noop, noopStop
	}

	var globalTracker *GlobalInflightTracker
	if globalMax > 0 {
		globalTracker = &GlobalInflightTracker{}
	}

	h := &throttleHandler{
		logger:        logger,
		registry:      registry,
		auditSampler:  auditSampler,
		compiled:      compiled,
		globalTracker: globalTracker,
		globalMax:     globalMax,
		resolve:       opts.ResolveProfile,
	}

	mw = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.serve(w, r, next)
		})
	}
	stop = func() {
		for _, l := range limiters {
			l.Stop()
		}
	}
	return mw, stop
}

// throttleHandler holds the precompiled state shared across requests.
type throttleHandler struct {
	logger        *slog.Logger
	registry      *metrics.Registry
	auditSampler  *AuditSampler
	compiled      map[string]*compiledProfile
	globalTracker *GlobalInflightTracker
	globalMax     int64
	resolve       func(*http.Request) (string, bool)
}

func (h *throttleHandler) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	profile := ""
	if h.resolve != nil {
		profile, _ = h.resolve(r)
	}

	// Requests with no resolved profile are bucketed under AnonymousClientID
	// so they cannot bypass limits by skipping identification.
	effectiveID := profile
	if effectiveID == "" {
		effectiveID = AnonymousClientID
	}

	cp := h.compiled[effectiveID]
	if cp == nil && h.globalTracker == nil {
		// No per-profile limits and no global gate; pass through.
		next.ServeHTTP(w, r)
		return
	}

	// Normalize the request path once. Reused for endpoint-cost lookup, the
	// throttle audit record, and the deny path's metrics label.
	normPath := filter.NormalizePath(r.URL.Path)

	if h.checkRateLimit(w, r, cp, effectiveID, normPath) {
		return
	}

	// Global priority gate. Returns (admitted, needsRelease): when admitted
	// and needsRelease is true, the global counter was incremented and must be
	// decremented on exit. We call h.globalTracker.Release() directly rather
	// than storing a func() method value to avoid the heap alloc.
	globalAdmitted, globalNeedsRelease := h.checkGlobalPriority(w, r, cp, effectiveID, normPath)
	if !globalAdmitted {
		return
	}
	if globalNeedsRelease {
		defer h.globalTracker.Release()
	}

	// Per-profile concurrency gate. profileRel is non-nil when admitted under
	// a concurrency cap; nil when the profile has no cap (pass-through).
	// profileReleaser is pooled to keep the per-request alloc cost near zero.
	profileRel, ok := h.checkProfileConcurrency(w, r, cp, effectiveID, normPath)
	if !ok {
		return
	}
	if profileRel != nil {
		defer profileRel.done()
	}

	next.ServeHTTP(w, r)
}

// checkRateLimit applies the token-bucket gate. Returns true when the request
// was denied (handler should stop), false to continue.
//
// When the resolved profile's rollout mode permits pass-through (warn /
// audit), the throttle counter and audit record still fire (operators need
// "what would have been blocked" data even during dry-runs), but the request
// is admitted and the access log decision becomes would_deny instead of deny.
func (h *throttleHandler) checkRateLimit(w http.ResponseWriter, r *http.Request, cp *compiledProfile, clientID, normPath string) (denied bool) {
	if cp == nil || cp.limiter == nil {
		return false
	}
	cost := cp.costFor(r.Method, normPath)
	ok, retryAfter := cp.limiter.AllowN(clientID, cost)
	if ok {
		return false
	}
	meta := logging.MetaForRequest(w, r)
	h.registry.ObserveThrottle(clientID, string(ReasonRateLimit), rolloutModeOf(meta))
	h.emitThrottleAudit(r, clientID, ReasonRateLimit, normPath,
		slog.Float64("tokens_per_second", cp.rate.TokensPerSecond),
		slog.Float64("burst", cp.rate.Burst),
		slog.Float64("cost", cost),
	)
	if meta.AllowsPassThrough() {
		logging.SetWouldDenyWithCode(w, r, string(ReasonRateLimit), "rate limit exceeded", filter.NormalizePath)
		return false
	}
	logging.SetDeniedWithCode(w, r, string(ReasonRateLimit), "rate limit exceeded", filter.NormalizePath)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	_ = httpjson.Write(w, http.StatusTooManyRequests, ThrottleResponse{
		Reason:            string(ReasonRateLimit),
		RetryAfterSeconds: retryAfter,
	})
	return true
}

// checkGlobalPriority applies the system-wide priority-aware fairness gate.
// Returns (admitted=true, needsRelease=true) when the request was admitted and
// the caller must call h.globalTracker.Release() on completion. Returns
// (admitted=true, needsRelease=false) when there is no global gate. Returns
// (admitted=false, _) when the request is denied and the caller must stop.
//
// Profiles with no compiled limits (cp == nil) still pass through this gate
// as PriorityNormal so a single client cannot evade it by skipping per-profile
// config.
//
// Returning a plain bool pair instead of a func() release eliminates the
// heap allocation a method-value closure would incur per admitted request.
func (h *throttleHandler) checkGlobalPriority(w http.ResponseWriter, r *http.Request, cp *compiledProfile, clientID, normPath string) (admitted bool, needsRelease bool) {
	if h.globalTracker == nil {
		return true, false
	}
	priority := PriorityNormal
	if cp != nil {
		priority = cp.priority
	}
	ok, current, threshold := h.globalTracker.Acquire(priority, h.globalMax)
	if ok {
		return true, true
	}
	meta := logging.MetaForRequest(w, r)
	h.registry.ObserveThrottle(clientID, string(ReasonPriorityFloor), rolloutModeOf(meta))
	h.emitThrottleAudit(r, clientID, ReasonPriorityFloor, normPath,
		slog.String("priority", priority.String()),
		slog.Int64("current_global_inflight", current),
		slog.Int64("priority_threshold", threshold),
		slog.Int64("global_max_inflight", h.globalMax),
	)
	if meta.AllowsPassThrough() {
		// The request would be denied under enforce mode, but the profile is in
		// warn / audit rollout posture so it must still reach upstream. We
		// increment the global gauge anyway so operators can correctly observe
		// real concurrency while sizing a new global cap from dashboard data.
		h.globalTracker.AcquirePassThrough() // increments; caller defers Release via needsRelease=true
		logging.SetWouldDenyWithCode(w, r, string(ReasonPriorityFloor), "priority floor exceeded", filter.NormalizePath)
		return true, true
	}
	logging.SetDeniedWithCode(w, r, string(ReasonPriorityFloor), "priority floor exceeded", filter.NormalizePath)
	_ = httpjson.Write(w, http.StatusTooManyRequests, ThrottleResponse{
		Reason: string(ReasonPriorityFloor),
	})
	return false, false
}

// checkProfileConcurrency applies the per-profile concurrency cap. A denial
// does NOT increment the inflight counter — Acquire returns admit before
// counting, so throttled requests are never counted as in-flight. Returns
// (releaser, true) on admit (caller must call releaser.done()), (nil, true)
// when there is no cap, and (nil, false) on denial.
//
// The returned *profileReleaser is drawn from a sync.Pool so the per-request
// cost of an admitted request under a concurrency cap amortises to ~0.
func (h *throttleHandler) checkProfileConcurrency(w http.ResponseWriter, r *http.Request, cp *compiledProfile, clientID, normPath string) (rel *profileReleaser, ok bool) {
	if cp == nil || cp.tracker == nil {
		return nil, true
	}
	admitted, current := cp.tracker.Acquire(clientID, cp.concurrency.MaxInflight)
	if !admitted {
		meta := logging.MetaForRequest(w, r)
		h.registry.ObserveThrottle(clientID, string(ReasonConcurrency), rolloutModeOf(meta))
		h.emitThrottleAudit(r, clientID, ReasonConcurrency, normPath,
			slog.Int64("current_inflight", current),
			slog.Int64("max_inflight", cp.concurrency.MaxInflight),
		)
		if meta.AllowsPassThrough() {
			logging.SetWouldDenyWithCode(w, r, string(ReasonConcurrency), "concurrency cap exceeded", filter.NormalizePath)
			return nil, true
		}
		logging.SetDeniedWithCode(w, r, string(ReasonConcurrency), "concurrency cap exceeded", filter.NormalizePath)
		_ = httpjson.Write(w, http.StatusTooManyRequests, ThrottleResponse{
			Reason: string(ReasonConcurrency),
		})
		return nil, false
	}
	h.registry.SetInflight(clientID, current)
	return getProfileReleaser(cp, clientID, h.registry), true
}

// emitThrottleAudit writes one throttle record through the sampler. The
// sampler suppresses repeats within a 1-second window per (client, reason)
// so the slog volume can't blow out under attack; the Prometheus counter
// fires unconditionally in the caller.
func (h *throttleHandler) emitThrottleAudit(r *http.Request, clientID string, reason ThrottleReason, normPath string, extras ...slog.Attr) {
	if h.auditSampler == nil || !h.auditSampler.ShouldEmit(clientID, reason) {
		return
	}
	attrs := logging.AppendCorrelationAttrs(nil, r)
	attrs = append(attrs,
		slog.String("client_id", clientID),
		slog.String("reason", string(reason)),
		slog.String("path", normPath),
	)
	attrs = append(attrs, extras...)
	h.logger.InfoContext(r.Context(), "throttle",
		slog.Group("throttle", attrsToAny(attrs)...))
}

func attrsToAny(attrs []slog.Attr) []any {
	result := make([]any, len(attrs))
	for i, a := range attrs {
		result[i] = a
	}
	return result
}

// rolloutModeOf returns the rollout mode label for the request's resolved
// profile, normalizing empty / nil to "enforce" so the metrics label is
// always one of the documented {enforce, warn, audit} values.
func rolloutModeOf(meta *logging.RequestMeta) string {
	if meta == nil || meta.RolloutMode == "" {
		return "enforce"
	}
	return meta.RolloutMode
}
