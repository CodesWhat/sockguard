package metrics

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeswhat/sockguard/internal/logging"
)

const contentTypePrometheusText = "text/plain; version=0.0.4; charset=utf-8"

var defaultDurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Registry stores in-process Prometheus metrics for the proxy.
type Registry struct {
	activeRequests atomic.Int64
	upstreamKnown  atomic.Bool
	upstreamUp     atomic.Int64

	mu       sync.Mutex
	requests map[requestLabels]uint64
	denies   map[denyLabels]uint64
	duration map[durationLabels]*histogram
	upstream map[upstreamWatchdogLabels]uint64
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
	rule       string
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

type histogram struct {
	buckets []uint64
	count   uint64
	sum     float64
}

// NewRegistry constructs an empty metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		requests: make(map[requestLabels]uint64),
		denies:   make(map[denyLabels]uint64),
		duration: make(map[durationLabels]*histogram),
		upstream: make(map[upstreamWatchdogLabels]uint64),
	}
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

			mw := newMetricsResponseWriter(w, req)
			next.ServeHTTP(mw, req)

			r.observe(req, mw.meta, mw.status, time.Since(start).Seconds())
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

	r.mu.Lock()
	r.upstream[upstreamWatchdogLabels{result: result}]++
	r.mu.Unlock()
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

	r.mu.Lock()
	defer r.mu.Unlock()

	r.requests[requestKey]++
	r.observeDurationLocked(durationKey, seconds)
	if decision == "deny" {
		r.denies[denyLabels{
			profile:    profile,
			reasonCode: reasonCodeLabel(meta),
			route:      route,
			rule:       ruleLabel(meta),
		}]++
	}
}

func (r *Registry) observeDurationLocked(key durationLabels, seconds float64) {
	h := r.duration[key]
	if h == nil {
		h = &histogram{buckets: make([]uint64, len(defaultDurationBuckets))}
		r.duration[key] = h
	}
	for i, bucket := range defaultDurationBuckets {
		if seconds <= bucket {
			h.buckets[i]++
		}
	}
	h.count++
	h.sum += seconds
}

func (r *Registry) writePrometheus(w http.ResponseWriter) {
	r.mu.Lock()
	requests := cloneMap(r.requests)
	denies := cloneMap(r.denies)
	durations := cloneHistograms(r.duration)
	upstream := cloneMap(r.upstream)
	active := r.activeRequests.Load()
	upstreamKnown := r.upstreamKnown.Load()
	upstreamUp := r.upstreamUp.Load()
	r.mu.Unlock()

	fmt.Fprintln(w, "# HELP sockguard_http_requests_total Total HTTP requests handled by Sockguard.")
	fmt.Fprintln(w, "# TYPE sockguard_http_requests_total counter")
	for _, key := range sortedRequestLabels(requests) {
		fmt.Fprintf(w, "sockguard_http_requests_total{decision=%s,method=%s,profile=%s,route=%s,status=%s} %d\n",
			labelValue(key.decision), labelValue(key.method), labelValue(key.profile), labelValue(key.route), labelValue(key.status), requests[key])
	}

	fmt.Fprintln(w, "# HELP sockguard_http_denied_requests_total Total requests denied by Sockguard policy or admission checks.")
	fmt.Fprintln(w, "# TYPE sockguard_http_denied_requests_total counter")
	for _, key := range sortedDenyLabels(denies) {
		fmt.Fprintf(w, "sockguard_http_denied_requests_total{profile=%s,reason_code=%s,route=%s,rule=%s} %d\n",
			labelValue(key.profile), labelValue(key.reasonCode), labelValue(key.route), labelValue(key.rule), denies[key])
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
}

func cloneMap[K comparable](src map[K]uint64) map[K]uint64 {
	dst := make(map[K]uint64, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneHistograms(src map[durationLabels]*histogram) map[durationLabels]*histogram {
	dst := make(map[durationLabels]*histogram, len(src))
	for key, value := range src {
		if value == nil {
			continue
		}
		buckets := make([]uint64, len(value.buckets))
		copy(buckets, value.buckets)
		dst[key] = &histogram{buckets: buckets, count: value.count, sum: value.sum}
	}
	return dst
}

func sortedRequestLabels(values map[requestLabels]uint64) []requestLabels {
	keys := make([]requestLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return requestLabelSortKey(keys[i]) < requestLabelSortKey(keys[j])
	})
	return keys
}

func sortedDenyLabels(values map[denyLabels]uint64) []denyLabels {
	keys := make([]denyLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return denyLabelSortKey(keys[i]) < denyLabelSortKey(keys[j])
	})
	return keys
}

func sortedDurationLabels(values map[durationLabels]*histogram) []durationLabels {
	keys := make([]durationLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return durationLabelSortKey(keys[i]) < durationLabelSortKey(keys[j])
	})
	return keys
}

func sortedUpstreamWatchdogLabels(values map[upstreamWatchdogLabels]uint64) []upstreamWatchdogLabels {
	keys := make([]upstreamWatchdogLabels, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].result < keys[j].result
	})
	return keys
}

func requestLabelSortKey(key requestLabels) string {
	return strings.Join([]string{key.decision, key.method, key.profile, key.route, key.status}, "\x00")
}

func denyLabelSortKey(key denyLabels) string {
	return strings.Join([]string{key.profile, key.reasonCode, key.route, key.rule}, "\x00")
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
	escaped := strings.NewReplacer(
		`\`, `\\`,
		"\n", `\n`,
		`"`, `\"`,
	).Replace(value)
	return `"` + escaped + `"`
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

func ruleLabel(meta *logging.RequestMeta) string {
	if meta == nil {
		return "-1"
	}
	return strconv.Itoa(meta.Rule)
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
	if segments[1] == "json" || segments[1] == "create" || segments[1] == "load" || segments[1] == "prune" || segments[1] == "search" {
		return "/images/" + segments[1]
	}
	return routeWithID("images", segments)
}

func pluginRoute(segments []string) string {
	if len(segments) == 1 {
		return "/plugins"
	}
	if segments[1] == "pull" || segments[1] == "create" || segments[1] == "privileges" {
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
	return "/" + prefix + "/{id}/" + segments[2]
}

type responseWriter struct {
	http.ResponseWriter
	status int
	meta   *logging.RequestMeta
}

var _ http.Flusher = (*responseWriter)(nil)
var _ http.Hijacker = (*responseWriter)(nil)

func newMetricsResponseWriter(w http.ResponseWriter, req *http.Request) *responseWriter {
	meta := logging.MetaForRequest(w, req)
	if meta == nil {
		meta = &logging.RequestMeta{}
	}
	return &responseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
		meta:           meta,
	}
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
