package metrics

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"net/http"
	"cmp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/version"
)

const contentTypePrometheusText = "text/plain; version=0.0.4; charset=utf-8"

var defaultDurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// prometheusLabelEscaper escapes the three characters that would break
// Prometheus text-format label values: backslash, newline, and double-quote.
// Hoisted to a package-level var so it is allocated once at init time rather
// than once per labelValue call (observe calls labelValue 5+ times per request).
var prometheusLabelEscaper = strings.NewReplacer(
	`\`, `\\`,
	"\n", `\n`,
	`"`, `\"`,
)

// Registry stores in-process Prometheus metrics for the proxy.
//
// Hot-path observations (requests, denies, duration histograms, throttles,
// upstream watchdog ticks, config-reload counters, per-profile in-flight) all
// run lock-free against sync.Map entries whose values are atomic counters or
// atomic-only histograms. The cold scrape path walks each sync.Map and reads
// each counter atomically — there is no shared mutex between observe() and
// writePrometheus(), so a slow scrape no longer blocks the request hot path.
// Pre-v0.8.1 a single Registry.mu serialized every observe call against the
// scrape, which became a measurable tail-latency contributor under sustained
// scrape pressure (the v0.8.0 NAS soak saw the lock held for the full clone
// duration of every map on every scrape).
type Registry struct {
	activeRequests atomic.Int64
	upstreamKnown  atomic.Bool
	upstreamUp     atomic.Int64

	// configReloadLastKnown distinguishes "never reloaded" (still 0) from
	// "reloaded successfully at the start of the Unix epoch", so the gauge
	// can be omitted from scrape output until the first successful reload lands.
	configReloadLastKnown atomic.Bool
	configReloadLastNanos atomic.Uint64

	// policyVersionKnown gates emission of sockguard_policy_version so the
	// gauge stays absent until the reload coordinator (or startup wiring)
	// publishes a first snapshot. Counter is monotonic per process.
	policyVersionKnown atomic.Bool
	policyVersion      atomic.Int64

	startedAt time.Time

	// inflight tracks current per-profile in-flight request counts under a
	// concurrency cap. SetInflight is called twice per admitted request on
	// the rate-limit hot path; per-profile *atomic.Int64 keeps it lock-free.
	inflight sync.Map // map[string]*atomic.Int64

	// Lock-free counter maps. Each entry is a *atomic.Uint64 stored under
	// the label-struct key; the first observation for a fresh label tuple
	// pays a sync.Map.LoadOrStore, subsequent observations are a single
	// atomic Add. The exposition path walks each map with sync.Map.Range
	// and reads the counter atomically — no shared mutex.
	requests      sync.Map // map[requestLabels]*atomic.Uint64
	denies        sync.Map // map[denyLabels]*atomic.Uint64
	upstream      sync.Map // map[upstreamWatchdogLabels]*atomic.Uint64
	throttles     sync.Map // map[throttleLabels]*atomic.Uint64
	configReloads sync.Map // map[configReloadLabels]*atomic.Uint64

	// Duration histograms are also lock-free: each entry is a *atomicHistogram
	// whose buckets/count/sum are atomic. observeDuration runs one atomic
	// Add per crossed bucket plus a Float64 sum CAS; scrape reads each
	// bucket / count / sum atomically.
	duration sync.Map // map[durationLabels]*atomicHistogram
}

type requestLabels struct {
	decision string
	method   string
	profile  string
	route    string
	status   string
}

type denyLabels struct {
	profile    string
	reasonCode string
	route      string
	// mode is the rollout posture in effect when the deny was decided:
	// enforce (request blocked), warn or audit (request passed through to
	// upstream but the gate said deny). Dashboards filter by mode to
	// distinguish real denies from dry-run signal.
	mode string
}

type durationLabels struct {
	decision string
	method   string
	profile  string
	route    string
}

type upstreamWatchdogLabels struct {
	result string
}

type throttleLabels struct {
	reasonCode string
	profile    string
	mode       string
}

type configReloadLabels struct {
	result string
}

// atomicHistogram is the lock-free histogram representation. Each bucket
// counter and the count + sum fields are read and written atomically; the
// sum holds math.Float64bits(value) so a single CAS loop folds a new
// observation into it without a per-histogram mutex. The bucket slice is
// allocated once at construction and never resized — len(buckets) is fixed
// at len(defaultDurationBuckets).
type atomicHistogram struct {
	buckets []atomic.Uint64
	count   atomic.Uint64
	sum     atomic.Uint64 // math.Float64bits(sum-of-seconds)
}

func newAtomicHistogram() *atomicHistogram {
	return &atomicHistogram{buckets: make([]atomic.Uint64, len(defaultDurationBuckets))}
}

func (h *atomicHistogram) observe(seconds float64) {
	for i, bucket := range defaultDurationBuckets {
		if seconds <= bucket {
			h.buckets[i].Add(1)
		}
	}
	h.count.Add(1)
	// CAS loop to add seconds into a float64 stored as its uint64 bits. Under
	// contention this retries; under typical load (one observation per
	// request, no shared writers across histograms) the loop exits on the
	// first iteration.
	for {
		old := h.sum.Load()
		next := math.Float64bits(math.Float64frombits(old) + seconds)
		if h.sum.CompareAndSwap(old, next) {
			return
		}
	}
}

// snapshot reads the histogram fields atomically into a plain struct for the
// scrape path. Bucket reads happen left-to-right, so the snapshot can show a
// later-bucket count that lags the count field by one observation; that is
// acceptable for Prometheus exposition (the scrape is approximate anyway).
type histogramSnapshot struct {
	buckets []uint64
	count   uint64
	sum     float64
}

func (h *atomicHistogram) snapshot() histogramSnapshot {
	buckets := make([]uint64, len(h.buckets))
	for i := range h.buckets {
		buckets[i] = h.buckets[i].Load()
	}
	return histogramSnapshot{
		buckets: buckets,
		count:   h.count.Load(),
		sum:     math.Float64frombits(h.sum.Load()),
	}
}

// NewRegistry constructs an empty metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		startedAt: time.Now(),
	}
}

// addCounter increments the counter stored at key in m by 1, allocating a
// fresh *atomic.Uint64 on first use. The LoadOrStore is paid only the first
// time a label tuple is observed; subsequent observations are a single
// atomic Add. Shared by every counter-map observer below.
func addCounter[K comparable](m *sync.Map, key K) {
	val, ok := m.Load(key)
	if !ok {
		actual, _ := m.LoadOrStore(key, &atomic.Uint64{})
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// collectCounters walks a counter sync.Map into an ordinary map for the
// sort/emit phase of writePrometheus. The walk reads each counter atomically.
func collectCounters[K comparable](m *sync.Map) map[K]uint64 {
	out := make(map[K]uint64)
	m.Range(func(k, v any) bool {
		out[k.(K)] = v.(*atomic.Uint64).Load()
		return true
	})
	return out
}

// ObserveConfigReload increments the config reload counter for the given
// outcome. result is one of "ok", "reject_load", "reject_validation",
// "reject_immutable", "reject_signature" — see internal/cmd reload
// pipeline for the canonical list. When result is "ok" the registry also
// stamps the last-success timestamp gauge for scrape-side visibility.
func (r *Registry) ObserveConfigReload(result string) {
	if r == nil {
		return
	}
	addCounter(&r.configReloads, configReloadLabels{result: result})

	if result == "ok" {
		ts := time.Now().UnixNano()
		if ts < 0 {
			return
		}
		r.configReloadLastNanos.Store(uint64(ts))
		r.configReloadLastKnown.Store(true)
	}
}

// SetPolicyVersion publishes the current monotonic policy generation
// counter to the metrics scrape surface. Called once at startup (after the
// initial snapshot is built) and once per successful hot reload. n is the
// value returned by admin.PolicyVersioner.Update — the registry does not
// own counter assignment, only its visibility.
func (r *Registry) SetPolicyVersion(n int64) {
	if r == nil {
		return
	}
	r.policyVersion.Store(n)
	r.policyVersionKnown.Store(true)
}

// ObserveThrottle increments the throttle counter for the given profile,
// reason, and rollout mode. This always fires — audit-log sampling is handled
// by the caller. mode is one of enforce / warn / audit; an empty string is
// normalized to enforce.
func (r *Registry) ObserveThrottle(profile, reason, mode string) {
	if r == nil {
		return
	}
	if mode == "" {
		mode = "enforce"
	}
	addCounter(&r.throttles, throttleLabels{reasonCode: reason, profile: profile, mode: mode})
}

// SetInflight updates the current in-flight count gauge for a profile.
// Lock-free: per-profile counters are stored in a sync.Map keyed by profile
// name; the call writes one atomic.Int64 without touching the registry mutex.
func (r *Registry) SetInflight(profile string, count int64) {
	if r == nil {
		return
	}
	val, _ := r.inflight.LoadOrStore(profile, &atomic.Int64{})
	val.(*atomic.Int64).Store(count)
}

// Middleware records one metrics observation for each completed HTTP request.
func (r *Registry) Middleware() func(http.Handler) http.Handler {
	if r == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			r.activeRequests.Add(1)
			defer r.activeRequests.Add(-1)

			mw := acquireResponseWriter(w, req)
			next.ServeHTTP(mw, req)
			r.observe(req, mw.meta, mw.status, time.Since(start).Seconds())
			releaseResponseWriter(mw)
		})
	}
}

// Handler returns a Prometheus text exposition handler.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", contentTypePrometheusText)
		if r == nil {
			return
		}

		r.writePrometheus(w)
	})
}

// ObserveUpstreamWatchdog records one active upstream watchdog check result.
func (r *Registry) ObserveUpstreamWatchdog(up bool) {
	if r == nil {
		return
	}
	result := "unreachable"
	if up {
		result = "connected"
	}
	addCounter(&r.upstream, upstreamWatchdogLabels{result: result})
}

// SetUpstreamSocketState updates the current active upstream socket state.
func (r *Registry) SetUpstreamSocketState(up bool) {
	if r == nil {
		return
	}
	if up {
		r.upstreamUp.Store(1)
	} else {
		r.upstreamUp.Store(0)
	}
	r.upstreamKnown.Store(true)
}

func (r *Registry) observe(req *http.Request, meta *logging.RequestMeta, status int, seconds float64) {
	decision := decisionLabel(meta, status)
	method := methodLabel(req)
	profile := profileLabel(meta)
	route := routeLabel(req, meta)
	statusLabel := strconv.Itoa(status)

	requestKey := requestLabels{
		decision: decision,
		method:   method,
		profile:  profile,
		route:    route,
		status:   statusLabel,
	}
	durationKey := durationLabels{
		decision: decision,
		method:   method,
		profile:  profile,
		route:    route,
	}

	addCounter(&r.requests, requestKey)
	r.observeDuration(durationKey, seconds)
	// Both real denies (enforce mode) and would-be-denies (warn / audit) are
	// counted here; the mode label distinguishes them so dashboards can
	// compare "blocked" vs "would-have-been-blocked" volume.
	if decision == "deny" || decision == logging.DecisionWouldDeny {
		addCounter(&r.denies, denyLabels{
			profile:    profile,
			reasonCode: reasonCodeLabel(meta),
			route:      route,
			mode:       rolloutModeLabel(meta),
		})
	}
}

func (r *Registry) observeDuration(key durationLabels, seconds float64) {
	val, ok := r.duration.Load(key)
	if !ok {
		actual, _ := r.duration.LoadOrStore(key, newAtomicHistogram())
		val = actual
	}
	val.(*atomicHistogram).observe(seconds)
}

func (r *Registry) writePrometheus(w http.ResponseWriter) {
	// Each sync.Map walk reads counters atomically. Without a shared mutex
	// between hot observe() and cold writePrometheus(), individual counters
	// remain self-consistent but the set is not a single instant — that is
	// the standard Prometheus exposition contract (scrapes are approximate).
	requests := collectCounters[requestLabels](&r.requests)
	denies := collectCounters[denyLabels](&r.denies)
	durations := snapshotHistograms(&r.duration)
	upstream := collectCounters[upstreamWatchdogLabels](&r.upstream)
	throttles := collectCounters[throttleLabels](&r.throttles)
	reloads := collectCounters[configReloadLabels](&r.configReloads)

	active := r.activeRequests.Load()
	upstreamKnown := r.upstreamKnown.Load()
	upstreamUp := r.upstreamUp.Load()
	reloadLastKnown := r.configReloadLastKnown.Load()
	reloadLastNanos := r.configReloadLastNanos.Load()
	policyVersionKnown := r.policyVersionKnown.Load()
	policyVersion := r.policyVersion.Load()

	inflight := snapshotInflight(&r.inflight)

	fmt.Fprintln(w, "# HELP sockguard_build_info Sockguard build metadata exposed as constant labels.")
	fmt.Fprintln(w, "# TYPE sockguard_build_info gauge")
	fmt.Fprintf(w, "sockguard_build_info{version=%s,commit=%s,build_date=%s,go_version=%s} 1\n",
		labelValue(version.Version), labelValue(version.Commit), labelValue(version.BuildDate), labelValue(runtime.Version()))

	fmt.Fprintln(w, "# HELP sockguard_start_time_seconds Unix timestamp at which the metrics registry was created.")
	fmt.Fprintln(w, "# TYPE sockguard_start_time_seconds gauge")
	fmt.Fprintf(w, "sockguard_start_time_seconds %s\n", strconv.FormatFloat(float64(r.startedAt.UnixNano())/1e9, 'f', -1, 64))

	fmt.Fprintln(w, "# HELP sockguard_http_requests_total Total HTTP requests handled by Sockguard.")
	fmt.Fprintln(w, "# TYPE sockguard_http_requests_total counter")
	for _, key := range sortedRequestLabels(requests) {
		fmt.Fprintf(w, "sockguard_http_requests_total{decision=%s,method=%s,profile=%s,route=%s,status=%s} %d\n",
			labelValue(key.decision), labelValue(key.method), labelValue(key.profile), labelValue(key.route), labelValue(key.status), requests[key])
	}

	fmt.Fprintln(w, "# HELP sockguard_http_denied_requests_total Total requests denied by Sockguard policy or admission checks. mode is enforce (request was blocked) or warn / audit (request would have been blocked, passed through under rollout mode).")
	fmt.Fprintln(w, "# TYPE sockguard_http_denied_requests_total counter")
	for _, key := range sortedDenyLabels(denies) {
		fmt.Fprintf(w, "sockguard_http_denied_requests_total{mode=%s,profile=%s,reason_code=%s,route=%s} %d\n",
			labelValue(key.mode), labelValue(key.profile), labelValue(key.reasonCode), labelValue(key.route), denies[key])
	}

	fmt.Fprintln(w, "# HELP sockguard_http_request_duration_seconds HTTP request latency in seconds.")
	fmt.Fprintln(w, "# TYPE sockguard_http_request_duration_seconds histogram")
	for _, key := range sortedDurationLabels(durations) {
		h := durations[key]
		for i, bucket := range defaultDurationBuckets {
			fmt.Fprintf(w, "sockguard_http_request_duration_seconds_bucket{decision=%s,method=%s,profile=%s,route=%s,le=%s} %d\n",
				labelValue(key.decision), labelValue(key.method), labelValue(key.profile), labelValue(key.route), labelValue(formatBucket(bucket)), h.buckets[i])
		}
		fmt.Fprintf(w, "sockguard_http_request_duration_seconds_bucket{decision=%s,method=%s,profile=%s,route=%s,le=%s} %d\n",
			labelValue(key.decision), labelValue(key.method), labelValue(key.profile), labelValue(key.route), labelValue("+Inf"), h.count)
		fmt.Fprintf(w, "sockguard_http_request_duration_seconds_sum{decision=%s,method=%s,profile=%s,route=%s} %s\n",
			labelValue(key.decision), labelValue(key.method), labelValue(key.profile), labelValue(key.route), strconv.FormatFloat(h.sum, 'g', -1, 64))
		fmt.Fprintf(w, "sockguard_http_request_duration_seconds_count{decision=%s,method=%s,profile=%s,route=%s} %d\n",
			labelValue(key.decision), labelValue(key.method), labelValue(key.profile), labelValue(key.route), h.count)
	}

	fmt.Fprintln(w, "# HELP sockguard_http_requests_active Currently active HTTP requests.")
	fmt.Fprintln(w, "# TYPE sockguard_http_requests_active gauge")
	fmt.Fprintf(w, "sockguard_http_requests_active %d\n", active)

	if upstreamKnown {
		fmt.Fprintln(w, "# HELP sockguard_upstream_socket_up Whether the active upstream Docker socket watchdog currently reports the socket as reachable.")
		fmt.Fprintln(w, "# TYPE sockguard_upstream_socket_up gauge")
		fmt.Fprintf(w, "sockguard_upstream_socket_up %d\n", upstreamUp)
	}

	fmt.Fprintln(w, "# HELP sockguard_upstream_watchdog_checks_total Total active upstream socket watchdog checks.")
	fmt.Fprintln(w, "# TYPE sockguard_upstream_watchdog_checks_total counter")
	for _, key := range sortedUpstreamWatchdogLabels(upstream) {
		fmt.Fprintf(w, "sockguard_upstream_watchdog_checks_total{result=%s} %d\n", labelValue(key.result), upstream[key])
	}

	fmt.Fprintln(w, "# HELP sockguard_throttle_requests_total Total requests denied by rate limiting or concurrency caps. mode is enforce (request was blocked with 429) or warn / audit (passed through under rollout mode).")
	fmt.Fprintln(w, "# TYPE sockguard_throttle_requests_total counter")
	for _, key := range sortedThrottleLabels(throttles) {
		fmt.Fprintf(w, "sockguard_throttle_requests_total{mode=%s,profile=%s,reason_code=%s} %d\n",
			labelValue(key.mode), labelValue(key.profile), labelValue(key.reasonCode), throttles[key])
	}

	fmt.Fprintln(w, "# HELP sockguard_inflight_requests Current number of in-flight requests per profile under a concurrency cap.")
	fmt.Fprintln(w, "# TYPE sockguard_inflight_requests gauge")
	for _, profile := range sortedInflightKeys(inflight) {
		fmt.Fprintf(w, "sockguard_inflight_requests{profile=%s} %d\n",
			labelValue(profile), inflight[profile])
	}

	fmt.Fprintln(w, "# HELP sockguard_config_reload_total Total hot-reload attempts since startup. result is ok (applied), reject_load (file read or parse failed), reject_validation (validator rejected the candidate config), reject_immutable (an immutable field changed and the reload was refused), or reject_signature (the configured policy bundle signature did not verify).")
	fmt.Fprintln(w, "# TYPE sockguard_config_reload_total counter")
	for _, key := range sortedConfigReloadLabels(reloads) {
		fmt.Fprintf(w, "sockguard_config_reload_total{result=%s} %d\n",
			labelValue(key.result), reloads[key])
	}

	if reloadLastKnown {
		fmt.Fprintln(w, "# HELP sockguard_config_reload_last_success_timestamp_seconds Unix timestamp at which the most recent reload was successfully applied. Omitted until the first successful reload.")
		fmt.Fprintln(w, "# TYPE sockguard_config_reload_last_success_timestamp_seconds gauge")
		fmt.Fprintf(w, "sockguard_config_reload_last_success_timestamp_seconds %s\n",
			strconv.FormatFloat(float64(reloadLastNanos)/1e9, 'f', -1, 64))
	}

	if policyVersionKnown {
		fmt.Fprintln(w, "# HELP sockguard_policy_version Monotonic counter of the active policy generation. Starts at 1 on first publish; ticks on every successful hot reload. A stable value across scrapes means the running policy did not move. Omitted until the first publish.")
		fmt.Fprintln(w, "# TYPE sockguard_policy_version gauge")
		fmt.Fprintf(w, "sockguard_policy_version %d\n", policyVersion)
	}
}

func sortedConfigReloadLabels(values map[configReloadLabels]uint64) []configReloadLabels {
	keys := make([]configReloadLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b configReloadLabels) int {
		return cmp.Compare(a.result, b.result)
	})
	return keys
}

// snapshotInflight reads the lock-free inflight sync.Map into a plain map for
// stable sorted iteration during Prometheus exposition.
func snapshotInflight(m *sync.Map) map[string]int64 {
	dst := make(map[string]int64)
	m.Range(func(key, value any) bool {
		dst[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})
	return dst
}

func sortedThrottleLabels(values map[throttleLabels]uint64) []throttleLabels {
	keys := make([]throttleLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b throttleLabels) int {
		ka := a.mode + "\x00" + a.profile + "\x00" + a.reasonCode
		kb := b.mode + "\x00" + b.profile + "\x00" + b.reasonCode
		return cmp.Compare(ka, kb)
	})
	return keys
}

func sortedInflightKeys(values map[string]int64) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// snapshotHistograms walks the lock-free histogram sync.Map and returns
// per-key atomic snapshots for the exposition path. Each histogram's bucket
// counts, total count, and sum are read atomically from the live histogram.
func snapshotHistograms(m *sync.Map) map[durationLabels]histogramSnapshot {
	dst := make(map[durationLabels]histogramSnapshot)
	m.Range(func(k, v any) bool {
		dst[k.(durationLabels)] = v.(*atomicHistogram).snapshot()
		return true
	})
	return dst
}

func sortedRequestLabels(values map[requestLabels]uint64) []requestLabels {
	keys := make([]requestLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b requestLabels) int {
		return cmp.Compare(requestLabelSortKey(a), requestLabelSortKey(b))
	})
	return keys
}

func sortedDenyLabels(values map[denyLabels]uint64) []denyLabels {
	keys := make([]denyLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b denyLabels) int {
		return cmp.Compare(denyLabelSortKey(a), denyLabelSortKey(b))
	})
	return keys
}

func sortedDurationLabels(values map[durationLabels]histogramSnapshot) []durationLabels {
	keys := make([]durationLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b durationLabels) int {
		return cmp.Compare(durationLabelSortKey(a), durationLabelSortKey(b))
	})
	return keys
}

func sortedUpstreamWatchdogLabels(values map[upstreamWatchdogLabels]uint64) []upstreamWatchdogLabels {
	keys := make([]upstreamWatchdogLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b upstreamWatchdogLabels) int {
		return cmp.Compare(a.result, b.result)
	})
	return keys
}

func requestLabelSortKey(key requestLabels) string {
	return strings.Join([]string{key.decision, key.method, key.profile, key.route, key.status}, "\x00")
}

func denyLabelSortKey(key denyLabels) string {
	return strings.Join([]string{key.mode, key.profile, key.reasonCode, key.route}, "\x00")
}

func durationLabelSortKey(key durationLabels) string {
	return strings.Join([]string{key.decision, key.method, key.profile, key.route}, "\x00")
}

func formatBucket(bucket float64) string {
	if math.IsInf(bucket, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(bucket, 'g', -1, 64)
}

func labelValue(value string) string {
	return `"` + prometheusLabelEscaper.Replace(value) + `"`
}

func decisionLabel(meta *logging.RequestMeta, status int) string {
	if meta != nil && meta.Decision != "" {
		return meta.Decision
	}
	if status >= http.StatusBadRequest {
		return "error"
	}
	return "allow"
}

func methodLabel(req *http.Request) string {
	if req == nil || req.Method == "" {
		return "UNKNOWN"
	}
	return req.Method
}

func profileLabel(meta *logging.RequestMeta) string {
	if meta != nil && meta.Profile != "" {
		return meta.Profile
	}
	return "default"
}

func reasonCodeLabel(meta *logging.RequestMeta) string {
	if meta != nil && meta.ReasonCode != "" {
		return meta.ReasonCode
	}
	return "unknown"
}

// rolloutModeLabel returns the rollout posture in effect for the request,
// normalizing empty (unconfigured) to "enforce" so the label cardinality
// matches the dashboarded set {enforce, warn, audit}.
func rolloutModeLabel(meta *logging.RequestMeta) string {
	if meta != nil && meta.RolloutMode != "" {
		return meta.RolloutMode
	}
	return "enforce"
}

func routeLabel(req *http.Request, meta *logging.RequestMeta) string {
	if meta != nil && meta.NormPath != "" {
		return RouteCategory(meta.NormPath)
	}
	if req == nil || req.URL == nil {
		return "unknown"
	}
	return RouteCategory(req.URL.Path)
}

// RouteCategory converts Docker API paths into low-cardinality route templates.
func RouteCategory(rawPath string) string {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return "unknown"
	}
	path = stripVersionPrefix(path)
	segments := splitPath(path)
	if len(segments) == 0 {
		return "/"
	}

	switch segments[0] {
	case "_ping", "version", "events", "info", "build":
		return "/" + segments[0]
	case "system":
		return routeWithStaticTail("system", segments, map[string]bool{"df": true})
	case "containers":
		return containerRoute(segments)
	case "exec":
		return routeWithID("exec", segments)
	case "images":
		return imageRoute(segments)
	case "volumes":
		return routeWithStaticTail("volumes", segments, map[string]bool{"create": true})
	case "networks":
		return routeWithStaticTail("networks", segments, map[string]bool{"create": true})
	case "secrets":
		return routeWithStaticTail("secrets", segments, map[string]bool{"create": true})
	case "configs":
		return routeWithStaticTail("configs", segments, map[string]bool{"create": true})
	case "services":
		return routeWithStaticTail("services", segments, map[string]bool{"create": true})
	case "swarm":
		return routeWithKnownPrefix("swarm", segments)
	case "nodes":
		return routeWithID("nodes", segments)
	case "plugins":
		return pluginRoute(segments)
	default:
		return "/" + segments[0] + "/..."
	}
}

func stripVersionPrefix(path string) string {
	segments := splitPath(path)
	if len(segments) == 0 || !isDockerVersionSegment(segments[0]) {
		if strings.HasPrefix(path, "/") {
			return path
		}
		return "/" + path
	}
	return "/" + strings.Join(segments[1:], "/")
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func isDockerVersionSegment(segment string) bool {
	if len(segment) < 2 || segment[0] != 'v' {
		return false
	}
	for _, r := range segment[1:] {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

func containerRoute(segments []string) string {
	if len(segments) == 1 {
		return "/containers"
	}
	if segments[1] == "json" || segments[1] == "create" || segments[1] == "prune" {
		return "/containers/" + segments[1]
	}
	return routeWithID("containers", segments)
}

func imageRoute(segments []string) string {
	if len(segments) == 1 {
		return "/images"
	}
	switch segments[1] {
	case "json", "create", "load", "prune", "search":
		return "/images/" + segments[1]
	}
	return routeWithID("images", segments)
}

func pluginRoute(segments []string) string {
	if len(segments) == 1 {
		return "/plugins"
	}
	switch segments[1] {
	case "pull", "create", "privileges":
		return "/plugins/" + segments[1]
	}
	if len(segments) == 2 {
		return "/plugins/{name}"
	}
	return "/plugins/{name}/" + segments[2]
}

func routeWithStaticTail(prefix string, segments []string, static map[string]bool) string {
	if len(segments) == 1 {
		return "/" + prefix
	}
	if static[segments[1]] {
		return "/" + prefix + "/" + segments[1]
	}
	return routeWithID(prefix, segments)
}

func routeWithKnownPrefix(prefix string, segments []string) string {
	if len(segments) == 1 {
		return "/" + prefix
	}
	return "/" + prefix + "/" + segments[1]
}

func routeWithID(prefix string, segments []string) string {
	if len(segments) == 1 {
		return "/" + prefix
	}
	if len(segments) == 2 {
		return "/" + prefix + "/{id}"
	}
	// Docker image names may contain slashes (registry/owner/repo:tag), so
	// the {id} slot has to swallow every segment between the prefix and the
	// trailing action verb. Without this, /images/owner/repo:tag/json would
	// expose "owner" as the id and drop the /json action — every distinct
	// image becomes its own timeseries.
	return "/" + prefix + "/{id}/" + segments[len(segments)-1]
}

type responseWriter struct {
	http.ResponseWriter
	status int
	meta   *logging.RequestMeta
	// ownsMeta is true when this wrapper allocated a fresh RequestMeta
	// because the inbound request had none attached. Returning that meta to
	// any shared pool would corrupt it; ownsMeta is the marker for the
	// release path to drop the reference instead of caching it.
	ownsMeta bool
}

var _ http.Flusher = (*responseWriter)(nil)
var _ http.Hijacker = (*responseWriter)(nil)

var metricsResponseWriterPool = sync.Pool{
	New: func() any { return &responseWriter{} },
}

func acquireResponseWriter(w http.ResponseWriter, req *http.Request) *responseWriter {
	mw, _ := metricsResponseWriterPool.Get().(*responseWriter)
	if mw == nil {
		mw = &responseWriter{}
	}
	mw.ResponseWriter = w
	mw.status = http.StatusOK
	if meta := logging.MetaForRequest(w, req); meta != nil {
		mw.meta = meta
		mw.ownsMeta = false
	} else {
		mw.meta = &logging.RequestMeta{}
		mw.ownsMeta = true
	}
	return mw
}

func releaseResponseWriter(mw *responseWriter) {
	if mw == nil {
		return
	}
	mw.ResponseWriter = nil
	if mw.ownsMeta {
		// The fallback RequestMeta is request-scoped; drop the reference so
		// the GC reclaims it rather than letting it tail behind the wrapper.
		mw.meta = nil
		mw.ownsMeta = false
	} else {
		mw.meta = nil
	}
	mw.status = 0
	metricsResponseWriterPool.Put(mw)
}

func (w *responseWriter) RequestMeta() *logging.RequestMeta {
	return w.meta
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
