package metrics

import (
	"bufio"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/logging"
)

func TestMiddlewareRecordsRequestDecisionMetrics(t *testing.T) {
	registry := NewRegistry()
	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := logging.MetaForRequest(w, r)
		if meta == nil {
			t.Fatal("expected metrics middleware to expose request metadata")
			return
		}
		meta.Decision = "deny"
		meta.Rule = 2
		meta.ReasonCode = "matched_deny_rule"
		meta.NormPath = "/containers/web/update"
		meta.Profile = "watchtower"
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/web/update", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_http_requests_total{decision="deny",method="POST",profile="watchtower",route="/containers/{id}/update",status="403"} 1`)
	assertContains(t, out, `sockguard_http_denied_requests_total{mode="enforce",profile="watchtower",reason_code="matched_deny_rule",route="/containers/{id}/update"} 1`)
	assertContains(t, out, `sockguard_http_request_duration_seconds_count{decision="deny",method="POST",profile="watchtower",route="/containers/{id}/update"} 1`)
	assertContains(t, out, "sockguard_http_requests_active 0")
}

func TestMiddlewareRecordsWouldDenyWithModeLabel(t *testing.T) {
	registry := NewRegistry()
	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := logging.MetaForRequest(w, r)
		// would_deny is the marker the rollout-aware deny sites stamp when a
		// gate fires under warn or audit and the request is passed through.
		meta.Decision = logging.DecisionWouldDeny
		meta.Rule = 2
		meta.ReasonCode = "matched_deny_rule"
		meta.NormPath = "/containers/web/update"
		meta.Profile = "watchtower"
		meta.RolloutMode = "warn"
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/web/update", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_http_denied_requests_total{mode="warn",profile="watchtower",reason_code="matched_deny_rule",route="/containers/{id}/update"} 1`)
}

func TestObserveThrottleEmitsModeLabel(t *testing.T) {
	registry := NewRegistry()
	registry.ObserveThrottle("ci", "rate_limit", "warn")
	registry.ObserveThrottle("ci", "rate_limit", "enforce")
	registry.ObserveThrottle("ci", "rate_limit", "") // empty normalizes to enforce

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_throttle_requests_total{mode="enforce",profile="ci",reason_code="rate_limit"} 2`)
	assertContains(t, out, `sockguard_throttle_requests_total{mode="warn",profile="ci",reason_code="rate_limit"} 1`)
}

func TestRouteCategoryKeepsDockerPathLabelsBounded(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "static ping", path: "/_ping", want: "/_ping"},
		{name: "container update id", path: "/containers/web/update", want: "/containers/{id}/update"},
		{name: "container list static", path: "/containers/json", want: "/containers/json"},
		{name: "exec start id", path: "/exec/abc/start", want: "/exec/{id}/start"},
		{name: "network connect id", path: "/networks/frontend/connect", want: "/networks/{id}/connect"},
		{name: "plugin upgrade name", path: "/plugins/example/upgrade", want: "/plugins/{name}/upgrade"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RouteCategory(tt.path); got != tt.want {
				t.Fatalf("RouteCategory(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestHandlerWritesPrometheusTextFormat(t *testing.T) {
	registry := NewRegistry()
	rec := httptest.NewRecorder()

	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if got := rec.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want Prometheus text format", got)
	}
	body := rec.Body.String()
	assertContains(t, body, "# HELP sockguard_http_requests_total Total HTTP requests handled by Sockguard.")
	assertContains(t, body, "# TYPE sockguard_http_requests_active gauge")
}

func TestRegistryEmitsBuildInfoAndStartTime(t *testing.T) {
	before := float64(time.Now().UnixNano()) / 1e9
	registry := NewRegistry()
	after := float64(time.Now().UnixNano()) / 1e9

	out := renderMetrics(t, registry)
	assertContains(t, out, "# HELP sockguard_build_info")
	assertContains(t, out, "# TYPE sockguard_build_info gauge")
	assertContains(t, out, `sockguard_build_info{version=`)
	assertContains(t, out, "go_version=") // runtime version always non-empty
	assertContains(t, out, "} 1\n")

	assertContains(t, out, "# TYPE sockguard_start_time_seconds gauge")

	prefix := "\nsockguard_start_time_seconds "
	idx := strings.Index(out, prefix)
	if idx < 0 {
		t.Fatalf("missing sockguard_start_time_seconds gauge: %s", out)
	}
	rest := out[idx+len(prefix):]
	end := strings.IndexByte(rest, '\n')
	if end < 0 {
		t.Fatalf("malformed start_time line: %s", rest)
	}
	val, err := strconv.ParseFloat(rest[:end], 64)
	if err != nil {
		t.Fatalf("start_time not a float: %v", err)
	}
	if val < before || val > after {
		t.Fatalf("start_time %f outside [%f, %f]", val, before, after)
	}
}

func TestRegistryOmitsPolicyVersionUntilSet(t *testing.T) {
	registry := NewRegistry()
	out := renderMetrics(t, registry)
	if strings.Contains(out, "sockguard_policy_version") {
		t.Fatalf("policy_version gauge present before SetPolicyVersion: %s", out)
	}
}

func TestRegistryEmitsPolicyVersionAfterSet(t *testing.T) {
	registry := NewRegistry()
	registry.SetPolicyVersion(1)
	registry.SetPolicyVersion(7) // monotonic in production; test the latest-wins behavior

	out := renderMetrics(t, registry)
	assertContains(t, out, "# TYPE sockguard_policy_version gauge")
	assertContains(t, out, "\nsockguard_policy_version 7\n")
}

func TestNilRegistrySetPolicyVersionIsNoop(t *testing.T) {
	var registry *Registry
	registry.SetPolicyVersion(42) // must not panic
}

func TestRegistryRecordsUpstreamWatchdogState(t *testing.T) {
	registry := NewRegistry()

	registry.ObserveUpstreamWatchdog(false)
	registry.SetUpstreamSocketState(false)
	registry.ObserveUpstreamWatchdog(true)
	registry.SetUpstreamSocketState(true)

	out := renderMetrics(t, registry)
	assertContains(t, out, "sockguard_upstream_socket_up 1")
	assertContains(t, out, `sockguard_upstream_watchdog_checks_total{result="unreachable"} 1`)
	assertContains(t, out, `sockguard_upstream_watchdog_checks_total{result="connected"} 1`)
}

func TestNilRegistryNoOps(t *testing.T) {
	var registry *Registry

	called := false
	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_ping", nil))

	if !called {
		t.Fatal("nil registry middleware did not call next handler")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}

	registry.ObserveUpstreamWatchdog(true)
	registry.SetUpstreamSocketState(true)

	rec = httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if got := rec.Body.String(); got != "" {
		t.Fatalf("nil registry handler body = %q, want empty", got)
	}
	assertContentType(t, rec, contentTypePrometheusText)
}

func TestActiveRequestsGaugeIncludesInFlightRequests(t *testing.T) {
	registry := NewRegistry()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))

	go func() {
		defer close(done)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))
	}()

	<-started
	assertContains(t, renderMetrics(t, registry), "sockguard_http_requests_active 1")

	close(release)
	<-done
	assertContains(t, renderMetrics(t, registry), "sockguard_http_requests_active 0")
}

func TestDefaultLabelsForMissingMetaRequestAndDenyDetails(t *testing.T) {
	registry := NewRegistry()

	registry.observe(nil, nil, http.StatusInternalServerError, 0.001)
	registry.observe(
		&http.Request{URL: &url.URL{Path: "/v1.45/containers/create"}},
		&logging.RequestMeta{Decision: "deny"},
		http.StatusForbidden,
		0.002,
	)

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_http_requests_total{decision="error",method="UNKNOWN",profile="default",route="unknown",status="500"} 1`)
	assertContains(t, out, `sockguard_http_requests_total{decision="deny",method="UNKNOWN",profile="default",route="/containers/create",status="403"} 1`)
	assertContains(t, out, `sockguard_http_denied_requests_total{mode="enforce",profile="default",reason_code="unknown",route="/containers/create"} 1`)

	if got := routeLabel(&http.Request{}, nil); got != "unknown" {
		t.Fatalf("routeLabel(request without URL) = %q, want unknown", got)
	}
}

func TestRouteCategoryCoversDockerRouteFamiliesAndPathEdges(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: " \t", want: "unknown"},
		{name: "root", path: "/", want: "/"},
		{name: "relative gets slash", path: "containers/json", want: "/containers/json"},
		{name: "version prefix root", path: "/v1.45", want: "/"},
		{name: "invalid version prefix kept", path: "/v1x/containers/json", want: "/v1x/..."},
		{name: "container collection", path: "/containers", want: "/containers"},
		{name: "system known tail", path: "/system/df", want: "/system/df"},
		{name: "system id tail", path: "/system/foo/bar", want: "/system/{id}/bar"},
		{name: "exec collection", path: "/exec", want: "/exec"},
		{name: "exec id", path: "/exec/abc", want: "/exec/{id}"},
		{name: "image collection", path: "/images", want: "/images"},
		{name: "image static", path: "/images/search", want: "/images/search"},
		{name: "image id", path: "/images/alpine/json", want: "/images/{id}/json"},
		{name: "image namespaced id", path: "/images/linuxserver/qbittorrent:latest/json", want: "/images/{id}/json"},
		{name: "image registry-namespaced id", path: "/images/ghcr.io/seerr-team/seerr:latest/json", want: "/images/{id}/json"},
		{name: "image namespaced history", path: "/images/codeswhat/drydock:1.5.0-rc.9/history", want: "/images/{id}/history"},
		{name: "volume collection", path: "/volumes", want: "/volumes"},
		{name: "secret static", path: "/secrets/create", want: "/secrets/create"},
		{name: "config static", path: "/configs/create", want: "/configs/create"},
		{name: "service static", path: "/services/create", want: "/services/create"},
		{name: "plugin collection", path: "/plugins", want: "/plugins"},
		{name: "plugin static", path: "/plugins/privileges", want: "/plugins/privileges"},
		{name: "plugin name", path: "/plugins/example", want: "/plugins/{name}"},
		{name: "swarm collection", path: "/swarm", want: "/swarm"},
		{name: "swarm known prefix", path: "/swarm/update", want: "/swarm/update"},
		{name: "nodes id", path: "/nodes/node-1/update", want: "/nodes/{id}/update"},
		{name: "unknown prefix", path: "/distribution/alpine/json", want: "/distribution/..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RouteCategory(tt.path); got != tt.want {
				t.Fatalf("RouteCategory(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSortKeysBucketFormattingAndLabelEscaping(t *testing.T) {
	requestKey := requestLabels{decision: "allow", method: "GET", profile: "default", route: "/_ping", status: "200"}
	if got := requestLabelSortKey(requestKey); got != "allow\x00GET\x00default\x00/_ping\x00200" {
		t.Fatalf("requestLabelSortKey() = %q", got)
	}

	denyKey := denyLabels{mode: "enforce", profile: "default", reasonCode: "matched", route: "/containers/{id}/start"}
	if got := denyLabelSortKey(denyKey); got != "enforce\x00default\x00matched\x00/containers/{id}/start" {
		t.Fatalf("denyLabelSortKey() = %q", got)
	}

	durationKey := durationLabels{decision: "deny", method: "POST", profile: "admin", route: "/build"}
	if got := durationLabelSortKey(durationKey); got != "deny\x00POST\x00admin\x00/build" {
		t.Fatalf("durationLabelSortKey() = %q", got)
	}

	if got := formatBucket(math.Inf(1)); got != "+Inf" {
		t.Fatalf("formatBucket(+Inf) = %q, want +Inf", got)
	}
	if got := formatBucket(0.025); got != "0.025" {
		t.Fatalf("formatBucket(0.025) = %q, want 0.025", got)
	}
	if got := labelValue("quote\" slash\\\nnext"); got != `"quote\" slash\\\nnext"` {
		t.Fatalf("labelValue escaped = %q", got)
	}
}

// TestSnapshotHistogramsReadsAtomicCountersAndIsolatesSlice replaces the
// pre-v0.8.1 clone test: the live histogram now stores atomic.Uint64 buckets
// + a CAS-folded sum, and snapshotHistograms reads each one atomically into
// a fresh histogramSnapshot. Mutating the snapshot's bucket slice must not
// affect the live histogram, and the live histogram must keep counting after
// the snapshot is taken.
func TestSnapshotHistogramsReadsAtomicCountersAndIsolatesSlice(t *testing.T) {
	key := durationLabels{decision: "allow", method: "GET", profile: "default", route: "/_ping"}

	var live sync.Map
	h := newAtomicHistogram()
	h.observe(0.004) // lands in the smallest bucket
	h.observe(0.012)
	h.observe(0.040)
	live.Store(key, h)

	snap := snapshotHistograms(&live)
	got, ok := snap[key]
	if !ok {
		t.Fatalf("snapshot missing key %v", key)
	}
	if got.count != 3 {
		t.Fatalf("snapshot count = %d, want 3", got.count)
	}
	if got.sum < 0.055 || got.sum > 0.057 {
		t.Fatalf("snapshot sum = %g, want ~0.056", got.sum)
	}

	// Mutating the snapshot's bucket slice must not propagate to the live
	// histogram — that would defeat the point of snapshotting.
	got.buckets[0] = 999
	live2 := snapshotHistograms(&live)
	if live2[key].buckets[0] == 999 {
		t.Fatal("snapshotHistograms aliased the live histogram bucket slice")
	}

	// New observations after the snapshot must keep accumulating on the
	// live histogram regardless of what we did to the snapshot.
	h.observe(0.001)
	live3 := snapshotHistograms(&live)
	if got := live3[key].count; got != 4 {
		t.Fatalf("post-snapshot count = %d, want 4", got)
	}
}

func TestSortedLabelHelpersOrderDeterministically(t *testing.T) {
	requests := sortedRequestLabels(map[requestLabels]uint64{
		{decision: "deny", method: "POST", profile: "b", route: "/z", status: "403"}: 1,
		{decision: "allow", method: "GET", profile: "a", route: "/a", status: "200"}: 1,
	})
	if got := requestLabelSortKey(requests[0]); got != "allow\x00GET\x00a\x00/a\x00200" {
		t.Fatalf("first sorted request key = %q", got)
	}

	denies := sortedDenyLabels(map[denyLabels]uint64{
		{mode: "enforce", profile: "b", reasonCode: "z", route: "/z"}: 1,
		{mode: "enforce", profile: "a", reasonCode: "a", route: "/a"}: 1,
	})
	if got := denyLabelSortKey(denies[0]); got != "enforce\x00a\x00a\x00/a" {
		t.Fatalf("first sorted deny key = %q", got)
	}

	durations := sortedDurationLabels(map[durationLabels]histogramSnapshot{
		{decision: "deny", method: "POST", profile: "b", route: "/z"}:  {},
		{decision: "allow", method: "GET", profile: "a", route: "/a"}: {},
	})
	if got := durationLabelSortKey(durations[0]); got != "allow\x00GET\x00a\x00/a" {
		t.Fatalf("first sorted duration key = %q", got)
	}
}

func TestResponseWriterFlushAndHijackDelegation(t *testing.T) {
	rw := &delegatingResponseWriter{header: make(http.Header)}
	wrapped := newMetricsResponseWriter(rw, httptest.NewRequest(http.MethodGet, "/_ping", nil))

	wrapped.Flush()
	if !rw.flushed {
		t.Fatal("Flush did not delegate to wrapped response writer")
	}

	conn, buf, err := wrapped.Hijack()
	if err != nil {
		t.Fatalf("Hijack returned error: %v", err)
	}
	if conn == nil || buf == nil {
		t.Fatalf("Hijack returned conn=%v buf=%v, want non-nil", conn, buf)
	}
	_ = conn.Close()
	rw.closePeer()

	plain := newMetricsResponseWriter(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))
	conn, buf, err = plain.Hijack()
	if !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack without underlying support error = %v, want %v", err, http.ErrNotSupported)
	}
	if conn != nil || buf != nil {
		t.Fatalf("Hijack without support returned conn=%v buf=%v, want nils", conn, buf)
	}
}

type delegatingResponseWriter struct {
	header  http.Header
	flushed bool
	once    sync.Once
	peer    net.Conn
}

func (w *delegatingResponseWriter) Header() http.Header {
	return w.header
}

func (w *delegatingResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (w *delegatingResponseWriter) WriteHeader(statusCode int) {}

func (w *delegatingResponseWriter) Flush() {
	w.flushed = true
}

func (w *delegatingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	w.peer = client
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func (w *delegatingResponseWriter) closePeer() {
	w.once.Do(func() {
		if w.peer != nil {
			_ = w.peer.Close()
		}
	})
}

func renderMetrics(t *testing.T, registry *Registry) string {
	t.Helper()

	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func assertContentType(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()

	if got := rec.Header().Get("Content-Type"); got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()

	if !strings.Contains(got, want) {
		t.Fatalf("expected output to contain %q, got:\n%s", want, got)
	}
}

// TestRegistryConcurrentObserveAndScrape exercises the v0.8.1 lock-free
// observation path: many goroutines hammer observe / ObserveThrottle /
// ObserveConfigReload / ObserveUpstreamWatchdog while another goroutine
// repeatedly scrapes the registry. Pre-v0.8.1 the registry serialized every
// observation against the scrape on a single Registry.mu; this test would
// still pass under that scheme but verifies the post-refactor totals are
// correct under the new sync.Map + atomic-counter storage and that no
// observation is lost when it races a scrape.
func TestRegistryConcurrentObserveAndScrape(t *testing.T) {
	registry := NewRegistry()

	const writers = 8
	const opsPerWriter = 200
	var writerWG sync.WaitGroup
	writerWG.Add(writers)

	// Counter observers — every iteration bumps the same labels so the
	// final totals are deterministic regardless of interleaving.
	for w := 0; w < writers; w++ {
		go func() {
			defer writerWG.Done()
			req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
			meta := &logging.RequestMeta{Decision: "allow", NormPath: "/_ping", Profile: "ci"}
			for i := 0; i < opsPerWriter; i++ {
				registry.observe(req, meta, http.StatusOK, 0.003)
				registry.ObserveThrottle("ci", "rate_limit", "enforce")
				registry.ObserveConfigReload("ok")
				registry.ObserveUpstreamWatchdog(true)
			}
		}()
	}

	// Scraper — continuously asks the registry for its current state. The
	// goroutine must not deadlock against any observer; under the old mutex
	// scheme it would have blocked them on every scrape, under the
	// post-refactor lock-free path both run concurrently without serializing.
	stop := make(chan struct{})
	scraperDone := make(chan struct{})
	go func() {
		defer close(scraperDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			rec := httptest.NewRecorder()
			registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		}
	}()

	writersDone := make(chan struct{})
	go func() { writerWG.Wait(); close(writersDone) }()
	select {
	case <-writersDone:
	case <-time.After(10 * time.Second):
		t.Fatal("writers did not finish within 10s — possible deadlock between observe and scrape")
	}
	close(stop)
	<-scraperDone

	expected := uint64(writers * opsPerWriter)
	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_http_requests_total{decision="allow",method="GET",profile="ci",route="/_ping",status="200"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_throttle_requests_total{mode="enforce",profile="ci",reason_code="rate_limit"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_config_reload_total{result="ok"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_upstream_watchdog_checks_total{result="connected"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_http_request_duration_seconds_count{decision="allow",method="GET",profile="ci",route="/_ping"} `+strconv.FormatUint(expected, 10))
}
