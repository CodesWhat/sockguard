package otlp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// collector is an httptest OTLP endpoint that records raw bodies.
type collector struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
}

func newCollector(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, n int)) *collector {
	t.Helper()
	c := &collector{}
	var n atomic.Int32
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		c.headers = append(c.headers, r.Header.Clone())
		c.mu.Unlock()
		idx := int(n.Add(1))
		if handler != nil {
			handler(w, r, idx)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *collector) raw() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, body := range c.bodies {
		b.Write(body)
	}
	return b.String()
}

func (c *collector) requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func testOptions(endpoint string) Options {
	return Options{
		Endpoint:       endpoint,
		Timeout:        2 * time.Second,
		FlushInterval:  10 * time.Millisecond,
		QueueSize:      64,
		BatchSize:      16,
		ServiceName:    "sockguard-test",
		ServiceVersion: "9.9.9",
	}
}

func newTestExporter(t *testing.T, opts Options) *Exporter {
	t.Helper()
	e, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.sleep = func(context.Context, time.Duration) bool { return true }
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Close(ctx)
	})
	return e
}

func closeExporter(t *testing.T, e *Exporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// payload mirrors the OTLP JSON shape the exporter must produce.
type payload struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []kv `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			Spans []struct {
				TraceID           string `json:"traceId"`
				SpanID            string `json:"spanId"`
				ParentSpanID      string `json:"parentSpanId"`
				Name              string `json:"name"`
				Kind              int    `json:"kind"`
				StartTimeUnixNano string `json:"startTimeUnixNano"`
				EndTimeUnixNano   string `json:"endTimeUnixNano"`
				Attributes        []kv   `json:"attributes"`
				Status            struct {
					Code int `json:"code"`
				} `json:"status"`
			} `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type kv struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string `json:"stringValue"`
		IntValue    *string `json:"intValue"`
	} `json:"value"`
}

func attrMap(attrs []kv) map[string]string {
	m := map[string]string{}
	for _, a := range attrs {
		switch {
		case a.Value.StringValue != nil:
			m[a.Key] = *a.Value.StringValue
		case a.Value.IntValue != nil:
			m[a.Key] = "int:" + *a.Value.IntValue
		}
	}
	return m
}

func decodeSpans(t *testing.T, c *collector) []struct {
	TraceID, SpanID, ParentSpanID, Name, Start, End string
	Kind, Status                                    int
	Attrs                                           map[string]string
} {
	t.Helper()
	type out = struct {
		TraceID, SpanID, ParentSpanID, Name, Start, End string
		Kind, Status                                    int
		Attrs                                           map[string]string
	}
	var spans []out
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, body := range c.bodies {
		var p payload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatalf("decode payload: %v\n%s", err, body)
		}
		for _, rs := range p.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					spans = append(spans, out{s.TraceID, s.SpanID, s.ParentSpanID, s.Name, s.StartTimeUnixNano, s.EndTimeUnixNano, s.Kind, s.Status.Code, attrMap(s.Attributes)})
				}
			}
		}
	}
	return spans
}

// chain builds the production-ordered layers: trace context and request ID
// outside, OTLP inside.
func chain(e *Exporter, sample func() bool, h http.Handler) http.Handler {
	return logging.TraceContextMiddlewareWithRootSampler(sample)(
		logging.RequestIDMiddleware()(Middleware(e)(h)))
}

func allowAll() bool { return true }

func denyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.SetDeniedWithCode(w, r, "rule_deny", "hunter2 is why this was denied", func(p string) string { return p })
		w.WriteHeader(http.StatusForbidden)
	})
}

func TestJSONShape(t *testing.T) {
	c := newCollector(t, nil)
	e := newTestExporter(t, testOptions(c.srv.URL))
	h := chain(e, allowAll, denyHandler())

	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/create", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), req)
	closeExporter(t, e)

	spans := decodeSpans(t, c)
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1", len(spans))
	}
	s := spans[0]
	if s.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("traceId = %q", s.TraceID)
	}
	if len(s.SpanID) != 16 || len(s.TraceID) != 32 {
		t.Errorf("id lengths: span %d trace %d", len(s.SpanID), len(s.TraceID))
	}
	if s.ParentSpanID != "00f067aa0ba902b7" {
		t.Errorf("parentSpanId = %q", s.ParentSpanID)
	}
	if s.Kind != 2 {
		t.Errorf("kind = %d, want 2", s.Kind)
	}
	if s.Status != 0 {
		t.Errorf("deny 403 must not be ERROR, status = %d", s.Status)
	}
	for _, ts := range []string{s.Start, s.End} {
		if len(ts) < 18 || strings.Trim(ts, "0123456789") != "" {
			t.Errorf("nano timestamp %q is not a decimal string", ts)
		}
	}
	if !strings.HasPrefix(s.Name, "POST ") {
		t.Errorf("name = %q", s.Name)
	}
	want := map[string]string{
		"http.request.method":       "POST",
		"http.response.status_code": "int:403",
		"sockguard.normalized_path": "/v1.45/containers/create",
		"sockguard.decision":        "deny",
		"sockguard.reason_code":     "rule_deny",
		"network.peer.address":      "10.1.2.3",
	}
	for k, v := range want {
		if s.Attrs[k] != v {
			t.Errorf("attr %s = %q, want %q", k, s.Attrs[k], v)
		}
	}
	if s.Attrs["http.route"] == "" || s.Attrs["sockguard.request_id"] == "" {
		t.Errorf("missing route/request id attrs: %v", s.Attrs)
	}

	var p payload
	_ = json.Unmarshal(c.bodies[0], &p)
	res := attrMap(p.ResourceSpans[0].Resource.Attributes)
	if res["service.name"] != "sockguard-test" || res["service.version"] != "9.9.9" {
		t.Errorf("resource attrs = %v", res)
	}
	if p.ResourceSpans[0].ScopeSpans[0].Scope.Name != ScopeName {
		t.Errorf("scope = %q", p.ResourceSpans[0].ScopeSpans[0].Scope.Name)
	}
	if got := c.headers[0].Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestServerErrorIsErrorStatus(t *testing.T) {
	c := newCollector(t, nil)
	e := newTestExporter(t, testOptions(c.srv.URL))
	h := chain(e, allowAll, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	closeExporter(t, e)
	spans := decodeSpans(t, c)
	if len(spans) != 1 || spans[0].Status != 2 {
		t.Fatalf("spans = %+v, want one with status ERROR(2)", spans)
	}
}

func TestContentGuard(t *testing.T) {
	c := newCollector(t, nil)
	opts := testOptions(c.srv.URL)
	opts.Headers = map[string]string{"Authorization": "Bearer collector-secret"}
	e := newTestExporter(t, opts)
	h := chain(e, allowAll, denyHandler())

	req := httptest.NewRequest(http.MethodPost, "/containers/create?secret=hunter2&name=x",
		strings.NewReader(`{"Env":["PASSWORD=hunter2"]}`))
	req.Header.Set("X-Registry-Auth", "hunter2-registry")
	req.Header.Set("Authorization", "Basic hunter2-auth")
	req.Header.Set("X-Request-Id", "client-supplied-hunter2")
	h.ServeHTTP(httptest.NewRecorder(), req)
	closeExporter(t, e)

	raw := c.raw()
	if raw == "" {
		t.Fatal("nothing exported")
	}
	for _, leak := range []string{"hunter2", "secret=", "X-Registry-Auth", "Basic ", "collector-secret", "is why this was denied", "PASSWORD"} {
		if strings.Contains(raw, leak) {
			t.Errorf("exported payload leaks %q:\n%s", leak, raw)
		}
	}
	// The collector auth header goes on the wire as a header, not in the body.
	if got := c.headers[0].Get("Authorization"); got != "Bearer collector-secret" {
		t.Errorf("configured header not sent, got %q", got)
	}
}

func TestUnknownMethodIsBounded(t *testing.T) {
	s := buildSpan(logging.RequestSummary{Method: "SECRETVERB", NormalizedPath: "/containers/json", Status: 200})
	if !strings.HasPrefix(s.Name, "_OTHER ") || strings.Contains(s.Name, "SECRETVERB") {
		t.Errorf("name = %q", s.Name)
	}
	if got := attrMap(toKVs(s.Attrs))["http.request.method"]; got != "_OTHER" {
		t.Errorf("method attr = %q", got)
	}
}

func TestBackpressureNeverBlocksRequests(t *testing.T) {
	release := make(chan struct{})
	c := newCollector(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	opts := testOptions(c.srv.URL)
	opts.QueueSize = 8
	opts.BatchSize = 4
	e, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(release)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Close(ctx)
	})
	h := chain(e, allowAll, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	before := runtime.NumGoroutine()
	total := opts.QueueSize * 3
	var worst time.Duration
	start := time.Now()
	for i := 0; i < total; i++ {
		t0 := time.Now()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/containers/json", nil))
		if d := time.Since(t0); d > worst {
			worst = d
		}
	}
	if worst > 50*time.Millisecond {
		t.Errorf("slowest request took %v, want < 50ms", worst)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("%d requests took %v", total, elapsed)
	}
	if got := e.Stats().DroppedQueueFull; got == 0 {
		t.Errorf("DroppedQueueFull = 0, want > 0 with a blocked collector")
	}
	if grew := runtime.NumGoroutine() - before; grew > 4 {
		t.Errorf("goroutines grew by %d", grew)
	}
}

func TestRetryBehavior(t *testing.T) {
	tests := []struct {
		name         string
		handler      func(w http.ResponseWriter, r *http.Request, n int)
		wantRequests int
		wantExported uint64
		wantFailed   uint64
		wantSuccess  uint64
		wantRetry    uint64
		wantPerm     uint64
	}{
		{
			name: "503 twice then 200",
			handler: func(w http.ResponseWriter, r *http.Request, n int) {
				if n <= 2 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
			},
			wantRequests: 3, wantExported: 1, wantSuccess: 1, wantRetry: 2,
		},
		{
			name:         "400 is permanent",
			handler:      func(w http.ResponseWriter, r *http.Request, n int) { w.WriteHeader(http.StatusBadRequest) },
			wantRequests: 1, wantFailed: 1, wantPerm: 1,
		},
		{
			name:         "503 forever gives up after three attempts",
			handler:      func(w http.ResponseWriter, r *http.Request, n int) { w.WriteHeader(http.StatusServiceUnavailable) },
			wantRequests: 3, wantFailed: 1, wantRetry: 3,
		},
		{
			name: "redirect is permanent",
			handler: func(w http.ResponseWriter, r *http.Request, n int) {
				w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
				w.WriteHeader(http.StatusTemporaryRedirect)
			},
			wantRequests: 1, wantFailed: 1, wantPerm: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCollector(t, tt.handler)
			e := newTestExporter(t, testOptions(c.srv.URL))
			e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "GET x", Start: time.Now(), End: time.Now()})
			closeExporter(t, e)
			s := e.Stats()
			if c.requests() != tt.wantRequests {
				t.Errorf("collector saw %d requests, want %d", c.requests(), tt.wantRequests)
			}
			if s.Exported != tt.wantExported || s.DroppedExportFailed != tt.wantFailed ||
				s.RequestsSuccess != tt.wantSuccess || s.RequestsRetryable != tt.wantRetry || s.RequestsPermanent != tt.wantPerm {
				t.Errorf("stats = %+v", s)
			}
		})
	}
}

func TestPartialSuccessCountsRejectedSpans(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantExported uint64
		wantFailed   uint64
	}{
		{"numeric", `{"partialSuccess":{"rejectedSpans":1,"errorMessage":"secret-msg"}}`, 1, 1},
		{"string", `{"partialSuccess":{"rejectedSpans":"1"}}`, 1, 1},
		{"more than batch is clamped", `{"partialSuccess":{"rejectedSpans":"99"}}`, 0, 2},
		{"undecodable counts as exported", `not json`, 2, 0},
		{"empty partialSuccess", `{"partialSuccess":{}}`, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCollector(t, func(w http.ResponseWriter, r *http.Request, n int) {
				_, _ = w.Write([]byte(tt.body))
			})
			e := newTestExporter(t, testOptions(c.srv.URL))
			e.send([]Span{
				{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "a", Start: time.Now(), End: time.Now()},
				{TraceID: strings.Repeat("c", 32), SpanID: strings.Repeat("d", 16), Name: "b", Start: time.Now(), End: time.Now()},
			})
			s := e.Stats()
			if c.requests() != 1 {
				t.Errorf("requests = %d, want 1 (no retry)", c.requests())
			}
			if s.Exported != tt.wantExported || s.DroppedExportFailed != tt.wantFailed || s.RequestsSuccess != 1 {
				t.Errorf("stats = %+v", s)
			}
		})
	}
}

func TestEnqueueDropLogsOutsideAdmissionLock(t *testing.T) {
	e := newTestExporter(t, testOptions("http://127.0.0.1:1"))
	closeExporter(t, e)
	// After close every Enqueue drops. The lock must be free afterwards.
	e.Enqueue(Span{})
	done := make(chan struct{})
	go func() {
		e.admissionMu.Lock()
		e.admissionMu.Unlock() //nolint:staticcheck // probing that the lock is free
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("admissionMu still held after Enqueue returned")
	}
	if got := e.Stats().DroppedShutdown; got == 0 {
		t.Errorf("DroppedShutdown = %d, want >0", got)
	}
}

func TestConnectionRefusedDropsAfterAttempts(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := srv.URL
	srv.Close() // nothing listens here now
	e := newTestExporter(t, testOptions(endpoint))
	e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "GET x", Start: time.Now(), End: time.Now()})
	closeExporter(t, e)
	s := e.Stats()
	if s.DroppedExportFailed != 1 || s.RequestsRetryable != 3 || s.Exported != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestRetryAfterHonoredAndCapped(t *testing.T) {
	var mu sync.Mutex
	var delays []time.Duration
	hdr := []string{"2", "9999"}
	c := newCollector(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n <= 2 {
			w.Header().Set("Retry-After", hdr[n-1])
			w.WriteHeader(http.StatusTooManyRequests)
		}
	})
	e, err := New(testOptions(c.srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	e.sleep = func(_ context.Context, d time.Duration) bool {
		mu.Lock()
		delays = append(delays, d)
		mu.Unlock()
		return true
	}
	e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "GET x", Start: time.Now(), End: time.Now()})
	closeExporter(t, e)
	mu.Lock()
	defer mu.Unlock()
	if len(delays) != 2 || delays[0] != 2*time.Second || delays[1] != 5*time.Second {
		t.Errorf("delays = %v, want [2s 5s]", delays)
	}
	if e.Stats().Exported != 1 {
		t.Errorf("stats = %+v", e.Stats())
	}
}

func TestDefaultBackoffWithoutRetryAfter(t *testing.T) {
	var delays []time.Duration
	c := newCollector(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n <= 2 {
			w.WriteHeader(http.StatusBadGateway)
		}
	})
	e, err := New(testOptions(c.srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	e.sleep = func(_ context.Context, d time.Duration) bool { delays = append(delays, d); return true }
	e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "x", Start: time.Now(), End: time.Now()})
	closeExporter(t, e)
	if len(delays) != 2 || delays[0] != 200*time.Millisecond || delays[1] != 400*time.Millisecond {
		t.Errorf("delays = %v, want [200ms 400ms]", delays)
	}
}

func TestShutdownFlushesPending(t *testing.T) {
	c := newCollector(t, nil)
	opts := testOptions(c.srv.URL)
	opts.FlushInterval = time.Hour // only Close can flush
	opts.BatchSize = 64
	e := newTestExporter(t, opts)
	for i := 0; i < 5; i++ {
		e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "x", Start: time.Now(), End: time.Now()})
	}
	closeExporter(t, e)
	if got := len(decodeSpans(t, c)); got != 5 {
		t.Errorf("flushed %d spans, want 5", got)
	}
	if e.Stats().Exported != 5 {
		t.Errorf("stats = %+v", e.Stats())
	}
}

func TestCloseWithHangingCollectorHonorsDeadline(t *testing.T) {
	release := make(chan struct{})
	c := newCollector(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(release) })
	opts := testOptions(c.srv.URL)
	opts.Timeout = 30 * time.Second
	e, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "x", Start: time.Now(), End: time.Now()})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = e.Close(ctx)
	if err == nil {
		t.Error("Close with hanging collector returned nil, want deadline error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Close took %v, want ~200ms", d)
	}
	if e.Stats().Exported != 0 {
		t.Errorf("stats = %+v", e.Stats())
	}
}

func TestEnqueueAfterCloseDropsWithoutPanic(t *testing.T) {
	c := newCollector(t, nil)
	e := newTestExporter(t, testOptions(c.srv.URL))
	closeExporter(t, e)
	e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16)})
	if got := e.Stats().DroppedShutdown; got != 1 {
		t.Errorf("DroppedShutdown = %d, want 1", got)
	}
	closeExporter(t, e) // idempotent
	var nilExporter *Exporter
	nilExporter.Enqueue(Span{})
	if err := nilExporter.Close(context.Background()); err != nil {
		t.Errorf("nil Close = %v", err)
	}
}

func TestConcurrentEnqueueAndClose(t *testing.T) {
	c := newCollector(t, nil)
	e := newTestExporter(t, testOptions(c.srv.URL))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				e.Enqueue(Span{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Name: "x", Start: time.Now(), End: time.Now()})
			}
		}()
	}
	closeExporter(t, e)
	wg.Wait()
	s := e.Stats()
	if s.Exported+s.DroppedQueueFull+s.DroppedShutdown+s.DroppedExportFailed != 1600 {
		t.Errorf("spans unaccounted for: %+v", s)
	}
}

func TestSampling(t *testing.T) {
	tests := []struct {
		name        string
		traceparent string
		ratio       float64
		wantSpans   int
		wantFlags   string
	}{
		{"sampled parent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", 0, 1, "01"},
		{"unsampled parent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", 1, 0, "00"},
		{"root ratio 0", "", 0, 0, "00"},
		{"root ratio 1", "", 1, 1, "01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCollector(t, nil)
			e := newTestExporter(t, testOptions(c.srv.URL))
			h := chain(e, RootSampler(tt.ratio), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
			req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
			if tt.traceparent != "" {
				req.Header.Set("Traceparent", tt.traceparent)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			closeExporter(t, e)
			if got := len(decodeSpans(t, c)); got != tt.wantSpans {
				t.Errorf("spans = %d, want %d", got, tt.wantSpans)
			}
			// The traceparent handed to the response agrees with the export decision.
			if tp := rec.Header().Get("Traceparent"); !strings.HasSuffix(tp, "-"+tt.wantFlags) {
				t.Errorf("traceparent %q, want flags %s", tp, tt.wantFlags)
			}
		})
	}
}

func TestSpanStringsAreCapped(t *testing.T) {
	c := newCollector(t, nil)
	e := newTestExporter(t, testOptions(c.srv.URL))
	h := chain(e, RootSampler(0), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.SetDeniedWithCode(w, r, "rule_deny", "no", func(p string) string { return p })
		w.WriteHeader(http.StatusForbidden)
	}))
	// 255 ASCII bytes then a 3-byte rune straddles the 256-byte boundary.
	path := "/containers/" + strings.Repeat("a", 243) + strings.Repeat("\u20ac", 70000/3)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.URL.Path = path
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), req)
	closeExporter(t, e)
	spans := decodeSpans(t, c)
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1", len(spans))
	}
	if len(spans[0].Name) > maxSpanString || !utf8.ValidString(spans[0].Name) {
		t.Errorf("span name not capped/valid: %d bytes", len(spans[0].Name))
	}
	if _, ok := spans[0].Attrs["sockguard.normalized_path"]; !ok {
		t.Error("normalized_path attribute missing")
	}
	for k, v := range spans[0].Attrs {
		if len(v) > maxSpanString || !utf8.ValidString(v) {
			t.Errorf("attribute %s: %d bytes, valid=%v", k, len(v), utf8.ValidString(v))
		}
	}
}

func TestCapString(t *testing.T) {
	in := strings.Repeat("a", 255) + "\u20ac" + "tail"
	got := capString(in)
	if got != strings.Repeat("a", 255) {
		t.Errorf("got %d bytes, want cut at rune boundary 255", len(got))
	}
	if capString("short") != "short" {
		t.Error("short string changed")
	}
	line := "GET /v1.45/containers/json?" + strings.Repeat("q", 100) + " HTTP/1.1"
	short := line[:3]
	if got := capString(short); unsafe.StringData(got) == unsafe.StringData(short) {
		t.Error("short string shares backing memory with its source")
	}
}

func TestRootSamplerFractional(t *testing.T) {
	s := RootSampler(0.5)
	hit := 0
	for i := 0; i < 2000; i++ {
		if s() {
			hit++
		}
	}
	if hit < 600 || hit > 1400 {
		t.Errorf("ratio 0.5 sampled %d/2000", hit)
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	good := testOptions("http://127.0.0.1:4318/v1/traces")
	for name, mutate := range map[string]func(*Options){
		"queue":    func(o *Options) { o.QueueSize = 0 },
		"endpoint": func(o *Options) { o.Endpoint = "not a url" },
		"ca":       func(o *Options) { o.CAFile = "/nonexistent/ca.pem" },
	} {
		o := good
		mutate(&o)
		if e, err := New(o); err == nil {
			_ = e.Close(context.Background())
			t.Errorf("%s: New succeeded, want error", name)
		} else if strings.Contains(err.Error(), "/nonexistent") {
			t.Errorf("%s: error leaks path: %v", name, err)
		}
	}
}

func TestErrorsNeverLeakEndpointOrHeaders(t *testing.T) {
	// post() classifies failures; the reason must not carry the URL.
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := srv.URL + "/v1/traces?key=endpoint-secret"
	srv.Close()
	opts := testOptions(endpoint)
	opts.Headers = map[string]string{"X-Key": "header-secret"}
	e := newTestExporter(t, opts)
	_, _, _, reason, _ := e.post([]byte("{}"))
	if strings.Contains(reason, "endpoint-secret") || strings.Contains(reason, "header-secret") || strings.Contains(reason, "127.0.0.1") {
		t.Errorf("reason leaks: %q", reason)
	}
}

func toKVs(attrs []Attr) []kv {
	out := make([]kv, len(attrs))
	for i, a := range attrs {
		k := toKeyValue(a)
		out[i].Key = k.Key
		out[i].Value.StringValue = k.Value.StringValue
		out[i].Value.IntValue = k.Value.IntValue
	}
	return out
}
