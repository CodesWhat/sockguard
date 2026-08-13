package ratelimit

import (
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/glob"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/metrics"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"sync"
	"sync/atomic"
	"time"
)

// profileReleaser is a zero-alloc handle for releasing a per-profile
// concurrency slot. It is pooled via profileReleaserPool so the per-request
// cost of an admitted concurrency-capped request amortizes to ~0.
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
// Compilation uses regexp.MustCompile: glob.ToRegexString output is always
// valid regex (every input character is either an explicit glob token or
// regexp.QuoteMeta'd), so a Compile failure here means ToRegexString has a
// programming bug and the proxy must fail-fast at startup rather than silently
// run without rate limiting. The config validator already rejects malformed
// user input via regexp.Compile, so untrusted globs never reach this path.
func compileEndpointCosts(costs []EndpointCost) []compiledEndpointCost {
	if len(costs) == 0 {
		return nil
	}
	compiled := make([]compiledEndpointCost, 0, len(costs))
	for _, ec := range costs {
		regex := "^" + glob.ToRegexString(ec.PathGlob) + "$"
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

	effectiveID := profile
	if effectiveID == "" {
		effectiveID = AnonymousClientID
	}

	cp := h.compiled[effectiveID]
	if cp == nil && h.globalTracker == nil {

		next.ServeHTTP(w, r)
		return
	}

	// Normalize the request path once. Reused for endpoint-cost lookup, the
	// throttle audit record, and the deny path's metrics label. If a prior
	// middleware already cached the normalized path on RequestMeta, reuse it
	// instead of re-scanning the raw path — NormalizePath is otherwise the
	// only per-request string scan most non-throttled requests do.
	var normPath string
	if meta := logging.MetaForRequest(w, r); meta != nil && meta.NormPath != "" {
		normPath = meta.NormPath
	} else {
		normPath = filter.NormalizePath(r.URL.Path)
		if meta != nil {
			meta.NormPath = normPath
		}
	}

	if h.checkRateLimit(w, r, cp, effectiveID, normPath) {
		return
	}

	globalAdmitted, globalNeedsRelease := h.checkGlobalPriority(w, r, cp, effectiveID, normPath)
	if !globalAdmitted {
		return
	}
	if globalNeedsRelease {
		defer h.globalTracker.Release()
	}

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

		h.globalTracker.AcquirePassThrough()
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
// cost of an admitted request under a concurrency cap amortizes to ~0.
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
	h.logger.LogAttrs(r.Context(), slog.LevelInfo, "throttle",
		slog.Attr{Key: "throttle", Value: slog.GroupValue(attrs...)})
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

// Priority is the per-profile priority tier used by the global-concurrency
// fairness gate. Higher tiers reserve more of the global concurrency budget
// so that admin or otherwise latency-sensitive profiles cannot be starved by
// noisy low-priority callers under contention.
type Priority int

const (
	// PriorityNormal is the default tier. Equivalent to no priority field set.
	PriorityNormal Priority = iota
	// PriorityLow tier yields the most under contention.
	PriorityLow
	// PriorityHigh tier reserves the full global budget for its requests.
	PriorityHigh
)

// String returns the lowercase config-form name of the priority.
func (p Priority) String() string {
	switch p {
	case PriorityLow:
		return "low"
	case PriorityHigh:
		return "high"
	default:
		return "normal"
	}
}

// ParsePriority resolves a config string to a Priority value. Empty input
// returns PriorityNormal so omitting the field preserves prior behavior.
// Unknown values return (PriorityNormal, false) so the validator can flag them.
func ParsePriority(s string) (Priority, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "normal":
		return PriorityNormal, true
	case "low":
		return PriorityLow, true
	case "high":
		return PriorityHigh, true
	default:
		return PriorityNormal, false
	}
}

// priorityShare returns the fraction of the global concurrency budget a
// priority tier may consume. Soft preemption: a higher tier's floor sits
// above the lower tier's floor, so when total inflight exceeds the lower
// tier's threshold the lower tier 429s while higher tiers keep going.
//
// Shares are hardcoded for v0.7.0 to keep the public config surface minimal.
// Operators have asked for configurable shares before we expose them.
func priorityShare(p Priority) float64 {
	switch p {
	case PriorityLow:
		return 0.5
	case PriorityHigh:
		return 1.0
	default:
		return 0.8
	}
}

// priorityThreshold computes the integer in-flight ceiling for a priority
// tier against a global cap. Rounded down so a profile cannot exceed its
// share by even one request.
func priorityThreshold(p Priority, globalMax int64) int64 {
	if globalMax <= 0 {
		return 0
	}
	share := priorityShare(p)
	t := int64(math.Floor(float64(globalMax) * share))
	if t < 1 {

		if p == PriorityHigh {
			return 1
		}
		return 0
	}
	return t
}

// GlobalInflightTracker tracks the system-wide in-flight request count
// across all profiles and gates admission on a priority-aware threshold.
//
// Acquire is non-blocking: requests above their priority's threshold are
// denied immediately. The caller must call Release exactly once per
// successful Acquire, via defer immediately after checking the return value.
type GlobalInflightTracker struct {
	current atomic.Int64
}

// Acquire admits the request when global inflight is below the priority's
// threshold. Returns (ok=true, current=incremented value, threshold) on
// success; (ok=false, current=unchanged, threshold) on denial.
//
// globalMax <= 0 disables the gate (always admits, current still tracked).
//
// CAS loop bounds the increment so the gate never over-admits under
// concurrent Acquire calls.
func (t *GlobalInflightTracker) Acquire(p Priority, globalMax int64) (ok bool, current int64, threshold int64) {
	if globalMax <= 0 {
		next := t.current.Add(1)
		return true, next, 0
	}
	threshold = priorityThreshold(p, globalMax)
	for {
		curr := t.current.Load()
		if curr >= threshold {
			return false, curr, threshold
		}
		if t.current.CompareAndSwap(curr, curr+1) {
			return true, curr + 1, threshold
		}

	}
}

// AcquirePassThrough unconditionally increments the global in-flight counter.
// It is used for requests that were denied by the priority gate but are allowed
// to pass through under warn / audit rollout mode. The gauge must reflect real
// concurrency during staged rollouts so operators can correctly size the global
// cap from dashboard data.
//
// The caller is responsible for calling Release exactly once after the request
// completes. AcquirePassThrough does not return a release function to avoid the
// heap allocation a method-value closure would incur; the caller holds a direct
// reference to the tracker and calls Release() itself.
func (t *GlobalInflightTracker) AcquirePassThrough() {
	t.current.Add(1)
}

// Release decrements the global in-flight counter. Safe to call multiple
// times only as paired releases for successful Acquire calls; underflow is
// clamped at zero to guard against bookkeeping errors.
func (t *GlobalInflightTracker) Release() {
	for {
		curr := t.current.Load()
		if curr <= 0 {
			return
		}
		if t.current.CompareAndSwap(curr, curr-1) {
			return
		}
	}
}

// Current returns the current global in-flight count without modifying it.
func (t *GlobalInflightTracker) Current() int64 {
	return t.current.Load()
}

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
func unpackTokenFP(w uint64) uint32 { return uint32(w) }

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

	if b.tpsFP == 0 {
		b.tpsFP = 1
	}
	initialFP := uint32(burst * float64(packedFracScale))
	ms := uint32(t.UnixMilli())
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
	nowMS := uint32(nowT.UnixMilli())

	for i := 0; i < maxCASRetries; i++ {
		old := b.state.Load()
		lastMS := unpackMS(old)
		tokenFP := uint64(unpackTokenFP(old))

		elapsedMS := int32(nowMS - lastMS)

		var newTokenFP uint64
		var newMS uint32
		if elapsedMS > 0 {

			refillFP := uint64(int64(elapsedMS)*int64(b.tpsFP)) / 1000
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

			next := uint64(newMS)<<32 | (uint64(remainingFP) & 0xFFFFFFFF)
			if b.state.CompareAndSwap(old, next) {
				return true, 0
			}

			continue
		}

		deficitFP := costFP - newTokenFP
		retrySeconds := int((deficitFP + b.tpsFP - 1) / b.tpsFP)
		return false, retrySeconds
	}

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
// background eviction goroutine started in newLimiterWithClock. The key space today
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

	if val, hit := l.buckets.Load(clientID); hit {
		return val.(*bucket).AllowN(cost)
	}

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

	val, _ := t.counters.LoadOrStore(clientID, &atomic.Int64{})
	counter := val.(*atomic.Int64)

	for {
		curr := counter.Load()
		if curr >= maxInflight {
			return false, curr
		}
		if counter.CompareAndSwap(curr, curr+1) {
			return true, curr + 1
		}

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
	// lastHit maps clientReasonKey → *atomic.Int64 holding the last-emit time in
	// Unix nanoseconds. The pointer is allocated once per key; ShouldEmit then
	// mutates the int64 in place via CompareAndSwap, so the steady-state hot path
	// (the in-window rejection branch) allocates nothing — unlike the previous
	// *time.Time design, which heap-allocated a timestamp on every call.
	lastHit sync.Map
	now     nowFn
}

func newAuditTimestamp(ns int64) *atomic.Int64 {
	a := &atomic.Int64{}
	a.Store(ns)
	return a
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
	nowNs := s.now().UnixNano()

	v, loaded := s.lastHit.Load(key)
	if !loaded {

		stored, raced := s.lastHit.LoadOrStore(key, newAuditTimestamp(nowNs))
		if !raced {
			return true
		}
		v = stored
	}

	last := v.(*atomic.Int64)
	prev := last.Load()
	if nowNs-prev < int64(auditEmitWindow) {
		return false
	}

	return last.CompareAndSwap(prev, nowNs)
}

// evict removes entries older than ttl from the sampler map. The Range
// iteration is unsynchronized, which is fine because CompareAndDelete only
// removes entries whose pointer hasn't been swapped by a racing ShouldEmit.
func (s *AuditSampler) evict(ttl time.Duration) {
	cutoffNs := s.now().Add(-ttl).UnixNano()
	s.lastHit.Range(func(k, v any) bool {
		a, ok := v.(*atomic.Int64)
		if !ok {
			s.lastHit.Delete(k)
			return true
		}

		if a.Load() < cutoffNs {
			s.lastHit.CompareAndDelete(k, v)
		}
		return true
	})
}
