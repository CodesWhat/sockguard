package metrics

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	"github.com/codeswhat/sockguard/app/internal/logging"
)

func TestMiddlewareRecordsRequestDecisionMetrics(t *testing.T) {
	t.Parallel()
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
	assertContains(t, out, `sockguard_http_requests_total{decision="deny",listener="default",method="POST",profile="watchtower",route="/containers/{id}/update",status="403"} 1`)
	assertContains(t, out, `sockguard_http_denied_requests_total{listener="default",mode="enforce",profile="watchtower",reason_code="matched_deny_rule",route="/containers/{id}/update"} 1`)
	assertContains(t, out, `sockguard_http_request_duration_seconds_count{decision="deny",listener="default",method="POST",profile="watchtower",route="/containers/{id}/update"} 1`)
	assertContains(t, out, "sockguard_http_requests_active 0")
}

func TestMiddlewareRecordsWouldDenyWithModeLabel(t *testing.T) {
	t.Parallel()
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
	assertContains(t, out, `sockguard_http_denied_requests_total{listener="default",mode="warn",profile="watchtower",reason_code="matched_deny_rule",route="/containers/{id}/update"} 1`)
}

func TestObserveThrottleEmitsModeLabel(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	registry.ObserveThrottle("ci", "rate_limit", "warn")
	registry.ObserveThrottle("ci", "rate_limit", "enforce")
	registry.ObserveThrottle("ci", "rate_limit", "") // empty normalizes to enforce

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_throttle_requests_total{mode="enforce",profile="ci",reason_code="rate_limit"} 2`)
	assertContains(t, out, `sockguard_throttle_requests_total{mode="warn",profile="ci",reason_code="rate_limit"} 1`)
}

func TestRouteCategoryKeepsDockerPathLabelsBounded(t *testing.T) {
	t.Parallel()
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

func TestRouteCategoryCollapsesUnrecognizedActionsToFiniteTemplates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		format string
		want   string
	}{
		{name: "system", format: "/system/custom-%d", want: "/system/{action}"},
		{name: "container", format: "/containers/web/custom-%d", want: "/containers/{id}/{action}"},
		{name: "exec", format: "/exec/process/custom-%d", want: "/exec/{id}/{action}"},
		{name: "image", format: "/images/alpine/custom-%d", want: "/images/{id}/{action}"},
		{name: "volume", format: "/volumes/data/custom-%d", want: "/volumes/{id}/{action}"},
		{name: "network", format: "/networks/frontend/custom-%d", want: "/networks/{id}/{action}"},
		{name: "secret", format: "/secrets/password/custom-%d", want: "/secrets/{id}/{action}"},
		{name: "config", format: "/configs/settings/custom-%d", want: "/configs/{id}/{action}"},
		{name: "service", format: "/services/web/custom-%d", want: "/services/{id}/{action}"},
		{name: "swarm", format: "/swarm/custom-%d", want: "/swarm/{action}"},
		{name: "node", format: "/nodes/worker/custom-%d", want: "/nodes/{id}/{action}"},
		{name: "plugin", format: "/plugins/example/custom-%d", want: "/plugins/{name}/{action}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for i := 0; i < 100; i++ {
				path := fmt.Sprintf(tt.format, i)
				if got := RouteCategory(path); got != tt.want {
					t.Fatalf("RouteCategory(%q) = %q, want %q", path, got, tt.want)
				}
			}
		})
	}
}

func TestRouteCategoryPreservesKnownFiniteTemplates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want string
	}{
		{path: "/containers/web/logs", want: "/containers/{id}/logs"},
		{path: "/exec/process/resize", want: "/exec/{id}/resize"},
		{path: "/images/get", want: "/images/get"},
		{path: "/images/alpine/push", want: "/images/{id}/push"},
		{path: "/volumes/prune", want: "/volumes/prune"},
		{path: "/networks/prune", want: "/networks/prune"},
		{path: "/secrets/password/update", want: "/secrets/{id}/update"},
		{path: "/configs/settings/update", want: "/configs/{id}/update"},
		{path: "/services/web/logs", want: "/services/{id}/logs"},
		{path: "/swarm/unlockkey", want: "/swarm/unlockkey"},
		{path: "/nodes/worker/update", want: "/nodes/{id}/update"},
		{path: "/plugins/example/set", want: "/plugins/{name}/set"},
	}

	for _, tt := range tests {
		if got := RouteCategory(tt.path); got != tt.want {
			t.Errorf("RouteCategory(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestUntrustedMethodsAndUnknownRoutesCollapseToBoundedSeries(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(fmt.Sprintf("CUSTOM-%d", i), fmt.Sprintf("/untrusted-%d/value", i), nil)
		registry.observe(req, &logging.RequestMeta{
			Decision:   "deny",
			ReasonCode: "matched_deny_rule",
		}, http.StatusForbidden, 0.001)
	}

	if got := syncMapLen(&registry.requests); got != 1 {
		t.Fatalf("request series = %d, want 1", got)
	}
	if got := syncMapLen(&registry.denies); got != 1 {
		t.Fatalf("deny series = %d, want 1", got)
	}
	if got := syncMapLen(&registry.duration); got != 1 {
		t.Fatalf("duration series = %d, want 1", got)
	}
	out := renderMetrics(t, registry)
	assertContains(t, out, `method="OTHER"`)
	assertContains(t, out, `route="unknown"`)
}

func syncMapLen(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func TestHandlerWritesPrometheusTextFormat(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	registry := NewRegistry()
	out := renderMetrics(t, registry)
	if strings.Contains(out, "sockguard_policy_version") {
		t.Fatalf("policy_version gauge present before SetPolicyVersion: %s", out)
	}
}

func TestRegistryEmitsPolicyVersionAfterSet(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	registry.SetPolicyVersion(1)
	registry.SetPolicyVersion(7) // monotonic in production; test the latest-wins behavior

	out := renderMetrics(t, registry)
	assertContains(t, out, "# TYPE sockguard_policy_version gauge")
	assertContains(t, out, "\nsockguard_policy_version 7\n")
}

func TestNilRegistrySetPolicyVersionIsNoop(t *testing.T) {
	t.Parallel()
	var registry *Registry
	registry.SetPolicyVersion(42) // must not panic
}

func TestRegistryRecordsUpstreamWatchdogState(t *testing.T) {
	t.Parallel()
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

func TestRegistryRecordsUpstreamReadinessState(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()

	registry.ObserveUpstreamReadiness(false)
	registry.SetUpstreamAPIState(false)
	registry.ObserveUpstreamReadiness(true)
	registry.SetUpstreamAPIState(true)

	out := renderMetrics(t, registry)
	assertContains(t, out, "sockguard_upstream_api_up 1")
	assertContains(t, out, `sockguard_upstream_readiness_checks_total{result="unreachable"} 1`)
	assertContains(t, out, `sockguard_upstream_readiness_checks_total{result="ready"} 1`)
}

func TestRegistryOmitsUpstreamAPIGaugeUntilObserved(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()

	out := renderMetrics(t, registry)
	if strings.Contains(out, "sockguard_upstream_api_up") {
		t.Fatalf("expected sockguard_upstream_api_up to be omitted before first probe, got:\n%s", out)
	}
}

func TestNilRegistryNoOps(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	registry := NewRegistry()

	registry.observe(nil, nil, http.StatusInternalServerError, 0.001)
	registry.observe(
		&http.Request{URL: &url.URL{Path: "/v1.45/containers/create"}},
		&logging.RequestMeta{Decision: "deny"},
		http.StatusForbidden,
		0.002,
	)

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_http_requests_total{decision="error",listener="default",method="UNKNOWN",profile="default",route="unknown",status="500"} 1`)
	assertContains(t, out, `sockguard_http_requests_total{decision="deny",listener="default",method="UNKNOWN",profile="default",route="/containers/create",status="403"} 1`)
	assertContains(t, out, `sockguard_http_denied_requests_total{listener="default",mode="enforce",profile="default",reason_code="unknown",route="/containers/create"} 1`)

	if got := routeLabel(&http.Request{}, nil); got != "unknown" {
		t.Fatalf("routeLabel(request without URL) = %q, want unknown", got)
	}
}

func TestRouteCategoryCoversDockerRouteFamiliesAndPathEdges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: " \t", want: "unknown"},
		{name: "root", path: "/", want: "/"},
		{name: "relative gets slash", path: "containers/json", want: "/containers/json"},
		{name: "version prefix root", path: "/v1.45", want: "/"},
		// Regression (#148): metrics' own stripVersionPrefix splits on any
		// digit/dot run (isDockerVersionSegment), so it already strips a
		// three-part Podman semver prefix correctly — unlike the filter
		// package's stripVersionPrefix, which needed a dedicated fix. Pinned
		// here so a future refactor can't silently reintroduce the filter
		// package's bug on this side.
		{name: "three-part version prefix stripped", path: "/v5.0.0/containers/json", want: "/containers/json"},
		// Podman prerelease/dev builds (this fix): the version segment class
		// is [0-9][0-9A-Za-z.-]*, so a trailing letter run like "1x" strips
		// just like a digit-only segment.
		{name: "letter suffix in version segment stripped", path: "/v1x/containers/json", want: "/containers/json"},
		{name: "no digit after v is not a version segment", path: "/vx/containers/json", want: "unknown"},
		{name: "container collection", path: "/containers", want: "/containers"},
		{name: "system known tail", path: "/system/df", want: "/system/df"},
		{name: "system unknown path", path: "/system/foo/bar", want: "/system/{action}"},
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
		{name: "unknown prefix", path: "/distribution/alpine/json", want: "unknown"},
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
	t.Parallel()
	// The label comparators order field-by-field with later fields breaking ties.
	// Equal keys compare 0; a difference in the last field still orders them.
	requestKey := requestLabels{decision: "allow", method: "GET", profile: "default", route: "/_ping", status: "200"}
	if got := requestLabelCompare(requestKey, requestKey); got != 0 {
		t.Fatalf("requestLabelCompare(self) = %d, want 0", got)
	}
	requestKeyHigher := requestKey
	requestKeyHigher.status = "201"
	if got := requestLabelCompare(requestKey, requestKeyHigher); got >= 0 {
		t.Fatalf("requestLabelCompare did not break ties on status: %d", got)
	}

	denyKey := denyLabels{mode: "enforce", profile: "default", reasonCode: "matched", route: "/containers/{id}/start"}
	denyKeyHigher := denyKey
	denyKeyHigher.route = "/containers/{id}/stop"
	if got := denyLabelCompare(denyKey, denyKeyHigher); got >= 0 {
		t.Fatalf("denyLabelCompare did not break ties on route: %d", got)
	}

	durationKey := durationLabels{decision: "deny", method: "POST", profile: "admin", route: "/build"}
	durationKeyLower := durationKey
	durationKeyLower.decision = "allow"
	if got := durationLabelCompare(durationKeyLower, durationKey); got >= 0 {
		t.Fatalf("durationLabelCompare did not order by decision: %d", got)
	}

	if got := formatBucket(math.Inf(1)); got != "+Inf" {
		t.Fatalf("formatBucket(+Inf) = %q, want +Inf", got)
	}
	if got := formatBucket(0.025); got != "0.025" {
		t.Fatalf("formatBucket(0.025) = %q, want 0.025", got)
	}
	if got := labelValue("quote\" slash\\\nnext\rline"); got != "\"quote\\\" slash\\\\\\nnext\rline\"" {
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
	t.Parallel()
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
	t.Parallel()
	requests := sortedRequestLabels(map[requestLabels]uint64{
		{decision: "deny", method: "POST", profile: "b", route: "/z", status: "403"}: 1,
		{decision: "allow", method: "GET", profile: "a", route: "/a", status: "200"}: 1,
	})
	if want := (requestLabels{decision: "allow", method: "GET", profile: "a", route: "/a", status: "200"}); requests[0] != want {
		t.Fatalf("first sorted request label = %+v, want %+v", requests[0], want)
	}

	denies := sortedDenyLabels(map[denyLabels]uint64{
		{mode: "enforce", profile: "b", reasonCode: "z", route: "/z"}: 1,
		{mode: "enforce", profile: "a", reasonCode: "a", route: "/a"}: 1,
	})
	if want := (denyLabels{mode: "enforce", profile: "a", reasonCode: "a", route: "/a"}); denies[0] != want {
		t.Fatalf("first sorted deny label = %+v, want %+v", denies[0], want)
	}

	durations := sortedDurationLabels(map[durationLabels]histogramSnapshot{
		{decision: "deny", method: "POST", profile: "b", route: "/z"}: {},
		{decision: "allow", method: "GET", profile: "a", route: "/a"}: {},
	})
	if want := (durationLabels{decision: "allow", method: "GET", profile: "a", route: "/a"}); durations[0] != want {
		t.Fatalf("first sorted duration label = %+v, want %+v", durations[0], want)
	}
}

func TestResponseWriterFlushAndHijackDelegation(t *testing.T) {
	t.Parallel()
	rw := &delegatingResponseWriter{header: make(http.Header)}
	wrapped := acquireResponseWriter(rw, httptest.NewRequest(http.MethodGet, "/_ping", nil))

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

	plain := acquireResponseWriter(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))
	conn, buf, err = plain.Hijack()
	if !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack without underlying support error = %v, want %v", err, http.ErrNotSupported)
	}
	if conn != nil || buf != nil {
		t.Fatalf("Hijack without support returned conn=%v buf=%v, want nils", conn, buf)
	}
}

type metricsDeadlineResponseWriter struct {
	http.ResponseWriter
	deadlines []time.Time
}

func (w *metricsDeadlineResponseWriter) SetReadDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestMiddlewarePreservesResponseControllerDeadlineThroughAccessLog(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	want := time.Now().Add(time.Minute)
	underlying := &metricsDeadlineResponseWriter{ResponseWriter: httptest.NewRecorder()}
	handler := logging.AccessLogMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)))(
		registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if err := http.NewResponseController(w).SetReadDeadline(want); err != nil {
				t.Fatalf("SetReadDeadline() error = %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		})),
	)

	handler.ServeHTTP(underlying, httptest.NewRequest(http.MethodPost, "/containers/create", nil))

	if len(underlying.deadlines) != 1 {
		t.Fatalf("SetReadDeadline() calls = %d, want 1", len(underlying.deadlines))
	}
	if !underlying.deadlines[0].Equal(want) {
		t.Fatalf("SetReadDeadline() = %v, want %v", underlying.deadlines[0], want)
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

// TestDeleteInflightProfileRemovesSeriesFromScrape verifies that
// DeleteInflightProfile removes a profile's series from exposition.
func TestDeleteInflightProfileRemovesSeriesFromScrape(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.SetInflight("ci", 3)

	out := renderMetrics(t, r)
	assertContains(t, out, `sockguard_inflight_requests{profile="ci"} 3`)

	r.DeleteInflightProfile("ci")
	out = renderMetrics(t, r)
	if strings.Contains(out, `sockguard_inflight_requests{profile="ci"}`) {
		t.Fatalf("profile ci series still present after DeleteInflightProfile: %s", out)
	}
}

// TestDeleteInflightProfileThenSetInflightReCreatesAtZero verifies the
// race-safety property: a completing old-chain request that calls SetInflight
// after deletion re-creates the entry at the tracker's clamped count (0 for a
// drained request), not at a negative value.
func TestDeleteInflightProfileThenSetInflightReCreatesAtZero(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.SetInflight("ci", 1)

	r.DeleteInflightProfile("ci")

	// Simulate old-chain profileReleaser.done(): tracker.Current() returns 0
	// after Release() because the last request finished.
	r.SetInflight("ci", 0)

	out := renderMetrics(t, r)
	// Re-created at 0 is correct and visible; the next reload will delete it.
	assertContains(t, out, `sockguard_inflight_requests{profile="ci"} 0`)

	// Verify no negative values appear.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, `sockguard_inflight_requests{profile="ci"}`) {
			if strings.HasSuffix(strings.TrimSpace(line), "-1") {
				t.Fatalf("inflight gauge went negative: %s", line)
			}
		}
	}
}

// TestNilRegistryDeleteInflightIsNoop verifies nil-safety.
func TestNilRegistryDeleteInflightIsNoop(t *testing.T) {
	t.Parallel()
	var r *Registry
	r.DeleteInflightProfile("ci") // must not panic
}

// TestDeleteInflightProfileConcurrentSetInflightIsRaceSafe hammers concurrent
// SetInflight and DeleteInflightProfile under the race detector to verify no
// data races between the sync.Map Delete and concurrent LoadOrStore/Store pairs.
func TestDeleteInflightProfileConcurrentSetInflightIsRaceSafe(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.SetInflight("ci", 5)

	const goroutines = 8
	const iters = 200
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Concurrent SetInflight callers (simulating old-chain completions).
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				r.SetInflight("ci", int64(n%3))
			}
		}(i)
	}

	// Concurrent DeleteInflightProfile caller (simulating reload).
	go func() {
		defer wg.Done()
		for j := 0; j < iters; j++ {
			r.DeleteInflightProfile("ci")
		}
	}()

	wg.Wait()
	// After all goroutines finish, the gauge is either present at some
	// non-negative value or absent. Neither is a correctness failure.
	out := renderMetrics(t, r)
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, `sockguard_inflight_requests{profile="ci"}`) {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		val, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			t.Fatalf("non-numeric inflight value: %s", line)
		}
		if val < 0 {
			t.Fatalf("inflight gauge is negative: %s", line)
		}
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
	t.Parallel()
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
	assertContains(t, out, `sockguard_http_requests_total{decision="allow",listener="default",method="GET",profile="ci",route="/_ping",status="200"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_throttle_requests_total{mode="enforce",profile="ci",reason_code="rate_limit"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_config_reload_total{result="ok"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_upstream_watchdog_checks_total{result="connected"} `+strconv.FormatUint(expected, 10))
	assertContains(t, out, `sockguard_http_request_duration_seconds_count{decision="allow",listener="default",method="GET",profile="ci",route="/_ping"} `+strconv.FormatUint(expected, 10))
}

// --- Mutation-boundary coverage (mutation-report.txt LIVED mutants) ---
//
// The tests below pin exact boundary/precision/formatting behavior that
// gremlins' CONDITIONALS_NEGATION, CONDITIONALS_BOUNDARY, ARITHMETIC_BASE,
// and INVERT_NEGATIVES mutants at specific metrics.go lines flipped without
// failing any prior test.

// TestHistogramObserveBucketBoundaryIsInclusive pins atomicHistogram.observe's
// `seconds <= bucket` comparison at metrics.go:181. A value exactly equal to
// a bucket boundary must land in that bucket (rules out CONDITIONALS_BOUNDARY
// turning <= into <), and a value strictly greater than a bucket must not
// land in it while still landing in the next one up (rules out
// CONDITIONALS_NEGATION turning <= into >).
func TestHistogramObserveBucketBoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	h := newAtomicHistogram()
	h.observe(defaultDurationBuckets[0]) // exactly on the smallest bucket boundary
	if got := h.buckets[0].Load(); got != 1 {
		t.Fatalf("bucket[0] count after observe(bucket[0]) = %d, want 1 (<= must include equal)", got)
	}

	h2 := newAtomicHistogram()
	h2.observe(defaultDurationBuckets[0] + 0.0001) // strictly greater than bucket[0], still under bucket[1]
	if got := h2.buckets[0].Load(); got != 0 {
		t.Fatalf("bucket[0] count after observe(bucket[0]+epsilon) = %d, want 0 (value exceeds bucket)", got)
	}
	if got := h2.buckets[1].Load(); got != 1 {
		t.Fatalf("bucket[1] count after observe(bucket[0]+epsilon) = %d, want 1", got)
	}
}

// TestObserveConfigReloadOnlyStampsTimestampOnOk pins the `result == "ok"`
// guard at metrics.go:263. A non-"ok" result must never publish the
// last-success timestamp gauge (rules out CONDITIONALS_NEGATION turning ==
// into !=, which would stamp the timestamp on every non-ok result and
// suppress it on "ok").
func TestObserveConfigReloadOnlyStampsTimestampOnOk(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()

	registry.ObserveConfigReload("reject_load")
	out := renderMetrics(t, registry)
	if strings.Contains(out, "sockguard_config_reload_last_success_timestamp_seconds") {
		t.Fatalf("last-success timestamp gauge present after non-ok result:\n%s", out)
	}

	registry.ObserveConfigReload("ok")
	out = renderMetrics(t, registry)
	assertContains(t, out, "sockguard_config_reload_last_success_timestamp_seconds")
}

// TestConfigReloadTimestampGaugeUsesFullPrecisionSecondsConversion pins the
// nanos-to-seconds conversion at metrics.go:613 — `float64(reloadLastNanos)/1e9`
// formatted with strconv.FormatFloat(..., 'f', -1, 64). It stores the nanos
// gauge directly (same package, bypassing the real-clock write path in
// ObserveConfigReload) so the expected value is exact and reproducible.
// Comparing the full rendered string rules out ARITHMETIC_BASE turning /
// into * at col 48, and rules out INVERT_NEGATIVES / ARITHMETIC_BASE turning
// the -1 (shortest round-trip) precision into 1 at col 59 — a 1-digit
// rounding would produce a visibly different string for this value.
func TestConfigReloadTimestampGaugeUsesFullPrecisionSecondsConversion(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()

	const nanos = uint64(1234567890123456)
	registry.configReloadLastNanos.Store(nanos)
	registry.configReloadLastKnown.Store(true)

	out := renderMetrics(t, registry)
	want := "sockguard_config_reload_last_success_timestamp_seconds " +
		strconv.FormatFloat(float64(nanos)/1e9, 'f', -1, 64) + "\n"
	assertContains(t, out, want)
}

// TestDurationSumUsesFullFloatPrecision pins the histogram `_sum` formatting
// at metrics.go:548 — strconv.FormatFloat(h.sum, 'g', -1, 64). A single
// observe() from a zero-valued histogram makes the exported sum exactly
// equal to the observed value, so comparing against the same FormatFloat
// call with precision -1 rules out INVERT_NEGATIVES / ARITHMETIC_BASE
// collapsing that precision to 1 (which would round away the fractional
// digits this value depends on).
func TestDurationSumUsesFullFloatPrecision(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()

	const seconds = 0.123456789012345
	registry.observe(nil, nil, http.StatusOK, seconds)

	out := renderMetrics(t, registry)
	want := `sockguard_http_request_duration_seconds_sum{decision="allow",listener="default",method="UNKNOWN",profile="default",route="unknown"} ` +
		strconv.FormatFloat(seconds, 'g', -1, 64) + "\n"
	assertContains(t, out, want)
}

// TestDecisionLabelStatusBoundary pins the `status >= http.StatusBadRequest`
// comparison at metrics.go:795. Exactly 400 must classify as "error" (rules
// out CONDITIONALS_BOUNDARY turning >= into >), while 399 must stay "allow".
func TestDecisionLabelStatusBoundary(t *testing.T) {
	t.Parallel()

	if got := decisionLabel(nil, http.StatusBadRequest); got != "error" {
		t.Fatalf("decisionLabel(nil, %d) = %q, want error", http.StatusBadRequest, got)
	}
	if got := decisionLabel(nil, http.StatusBadRequest-1); got != "allow" {
		t.Fatalf("decisionLabel(nil, %d) = %q, want allow", http.StatusBadRequest-1, got)
	}
}

// TestIsDockerVersionSegmentLengthAndDigitBoundaries pins two comparisons in
// isDockerVersionSegment: `len(segment) < 2` at metrics.go:936 and
// `r > '9'` at metrics.go:940. "v1" is exactly 2 characters — the shortest
// string the function must still accept — which rules out
// CONDITIONALS_BOUNDARY turning < into <= (that would reject length-2
// segments). "v9" ends in the digit '9' — the largest still-valid digit —
// which rules out CONDITIONALS_BOUNDARY turning > into >= (that would reject
// '9' itself).
func TestIsDockerVersionSegmentLengthAndDigitBoundaries(t *testing.T) {
	t.Parallel()

	if !isDockerVersionSegment("v1") {
		t.Fatal(`isDockerVersionSegment("v1") = false, want true (2-char segment is the minimum valid length)`)
	}
	if !isDockerVersionSegment("v9") {
		t.Fatal(`isDockerVersionSegment("v9") = false, want true ('9' is the largest valid digit)`)
	}
}

// TestContainerRoutePruneTail pins the `segments[1] == "prune"` comparison at
// metrics.go:951. Rules out CONDITIONALS_NEGATION turning == into != there,
// which would route "/containers/prune" through routeWithID's {id} template
// instead of the finite "/containers/prune" tail.
func TestContainerRoutePruneTail(t *testing.T) {
	t.Parallel()

	if got := containerRoute([]string{"containers", "prune"}); got != "/containers/prune" {
		t.Fatalf(`containerRoute(["containers","prune"]) = %q, want "/containers/prune"`, got)
	}
}

// TestReleaseResponseWriterNilIsNoop pins the `mw == nil` guard at
// metrics.go:1098. Rules out CONDITIONALS_NEGATION turning == into !=, which
// would skip the guard for a nil mw and panic on the following field
// assignment instead of returning.
func TestReleaseResponseWriterNilIsNoop(t *testing.T) {
	t.Parallel()
	releaseResponseWriter(nil) // must not panic
}

// TestAcquireResponseWriterRecoversFromNilPoolEntry pins the `mw == nil`
// guard at metrics.go:1082. sync.Pool.Get does not reliably return an
// entry that was just Put — Get may skip it and the runtime is free to
// drop pooled items at any time, including under -race — so seeding the
// pool with an explicit nil Put is not deterministic. Instead this
// overrides the pool's New func to return a typed nil *responseWriter,
// then calls acquireResponseWriter many times without releasing any of
// them: each Get first drains whatever real entries other tests left in
// the pool, and once those run out every subsequent Get falls through to
// New, which now returns nil deterministically. The original code must
// allocate a fresh writer on that path (asserted non-nil and initialized
// on every iteration); CONDITIONALS_NEGATION turning == into != would
// instead try to reuse the nil entry and panic on mw.ResponseWriter = w.
//
// Deliberately not t.Parallel(): every other test in this file is, and the
// Go test runner runs all non-parallel tests to completion (in the order
// declared) before any parallel test's body resumes past its t.Parallel()
// call, so this test's override of the shared package-level pool's New
// func is isolated from them.
func TestAcquireResponseWriterRecoversFromNilPoolEntry(t *testing.T) {
	originalNew := metricsResponseWriterPool.New
	metricsResponseWriterPool.New = func() any { return (*responseWriter)(nil) }
	t.Cleanup(func() { metricsResponseWriterPool.New = originalNew })

	for i := 0; i < 1024; i++ {
		mw := acquireResponseWriter(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))
		if mw == nil {
			t.Fatalf("iteration %d: acquireResponseWriter returned nil", i)
		}
		if mw.ResponseWriter == nil {
			t.Fatalf("iteration %d: acquireResponseWriter did not initialize ResponseWriter", i)
		}
	}
}
