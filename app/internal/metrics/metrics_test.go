package metrics

import (
	"bufio"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/internal/logging"
)

func TestMiddlewareRecordsRequestDecisionMetrics(t *testing.T) {
	registry := NewRegistry()
	handler := registry.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := logging.MetaForRequest(w, r)
		if meta == nil {
			t.Fatal("expected metrics middleware to expose request metadata")
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
	assertContains(t, out, `sockguard_http_denied_requests_total{profile="watchtower",reason_code="matched_deny_rule",route="/containers/{id}/update",rule="2"} 1`)
	assertContains(t, out, `sockguard_http_request_duration_seconds_count{decision="deny",method="POST",profile="watchtower",route="/containers/{id}/update"} 1`)
	assertContains(t, out, "sockguard_http_requests_active 0")
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
	assertContains(t, out, `sockguard_http_denied_requests_total{profile="default",reason_code="unknown",route="/containers/create",rule="0"} 1`)

	if got := ruleLabel(nil); got != "-1" {
		t.Fatalf("ruleLabel(nil) = %q, want -1", got)
	}
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

	denyKey := denyLabels{profile: "default", reasonCode: "matched", route: "/containers/{id}/start", rule: "3"}
	if got := denyLabelSortKey(denyKey); got != "default\x00matched\x00/containers/{id}/start\x003" {
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

func TestCloneHistogramsSkipsNilAndCopiesBuckets(t *testing.T) {
	key := durationLabels{decision: "allow", method: "GET", profile: "default", route: "/_ping"}
	nilKey := durationLabels{decision: "deny", method: "POST", profile: "default", route: "/build"}
	original := map[durationLabels]*histogram{
		key:    {buckets: []uint64{1, 2, 3}, count: 3, sum: 0.75},
		nilKey: nil,
	}

	cloned := cloneHistograms(original)
	if _, ok := cloned[nilKey]; ok {
		t.Fatal("cloneHistograms copied nil histogram entry")
	}
	cloned[key].buckets[0] = 99
	if original[key].buckets[0] != 1 {
		t.Fatalf("cloneHistograms reused bucket slice, original bucket = %d", original[key].buckets[0])
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
		{profile: "b", reasonCode: "z", route: "/z", rule: "2"}: 1,
		{profile: "a", reasonCode: "a", route: "/a", rule: "1"}: 1,
	})
	if got := denyLabelSortKey(denies[0]); got != "a\x00a\x00/a\x001" {
		t.Fatalf("first sorted deny key = %q", got)
	}

	durations := sortedDurationLabels(map[durationLabels]*histogram{
		{decision: "deny", method: "POST", profile: "b", route: "/z"}: {},
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
