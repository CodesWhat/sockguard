package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func isEventsStream(_ http.ResponseWriter, r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/events")
}

// streamHarness holds /events requests open until release is closed and
// answers everything else immediately.
type streamHarness struct {
	h       http.Handler
	entered chan struct{}
	release chan struct{}
	wg      sync.WaitGroup
}

func newStreamHarness(t *testing.T, opts MiddlewareOptions) *streamHarness {
	t.Helper()
	sh := &streamHarness{entered: make(chan struct{}, 128), release: make(chan struct{})}
	opts.IsLongLived = isEventsStream
	if opts.ResolveProfile == nil {
		opts.ResolveProfile = resolveProfileFn("ci")
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isEventsStream(w, r) {
			sh.entered <- struct{}{}
			<-sh.release
		}
		w.WriteHeader(http.StatusOK)
	})
	sh.h = mustMiddleware(t, newTestLogger(), nil, nil, opts)(inner)
	t.Cleanup(func() { sh.finish() })
	return sh
}

// openStream starts an /events request and waits until it is inside the handler.
func (sh *streamHarness) openStream() {
	sh.wg.Add(1)
	go func() {
		defer sh.wg.Done()
		sh.h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/events", nil))
	}()
	<-sh.entered
}

func (sh *streamHarness) do(method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	sh.h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func (sh *streamHarness) finish() {
	select {
	case <-sh.release:
	default:
		close(sh.release)
	}
	sh.wg.Wait()
}

func TestStreamCap_StreamsSkipMaxInflight(t *testing.T) {
	t.Parallel()
	sh := newStreamHarness(t, MiddlewareOptions{Profiles: map[string]ProfileOptions{
		"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 1, MaxStreams: 8}},
	}})
	sh.openStream()
	sh.openStream()
	sh.openStream()
	// Three streams are open against MaxInflight=1; an ordinary request still gets its slot.
	if rec := sh.do(http.MethodGet, "/containers/json"); rec.Code != http.StatusOK {
		t.Fatalf("ordinary request with streams open: got %d, want 200", rec.Code)
	}
}

func TestStreamCap_NonStreamsStillCountAgainstMaxInflight(t *testing.T) {
	t.Parallel()
	enter := make(chan struct{})
	release := make(chan struct{})
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 1, MaxStreams: 8}},
		},
		ResolveProfile: resolveProfileFn("ci"),
		IsLongLived:    isEventsStream,
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enter <- struct{}{}
		<-release
	}))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/containers/abc/stop", nil))
	}()
	<-enter
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/containers/abc/restart", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("non-stream over MaxInflight: got %d, want 429", rec.Code)
	}
	close(release)
	wg.Wait()
}

func TestStreamCap_DeniesOverMaxStreams(t *testing.T) {
	t.Parallel()
	sh := newStreamHarness(t, MiddlewareOptions{Profiles: map[string]ProfileOptions{
		"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 4, MaxStreams: 2}},
	}})
	sh.openStream()
	sh.openStream()
	rec := sh.do(http.MethodGet, "/events")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third stream: got %d, want 429", rec.Code)
	}
	var body ThrottleResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Reason != string(ReasonStreamCap) || body.Message == "" {
		t.Fatalf("body = %+v, want reason %q and a message", body, ReasonStreamCap)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("stream cap 429 should set Retry-After")
	}
}

func TestStreamCap_SlotReleasedWhenStreamEnds(t *testing.T) {
	t.Parallel()
	sh := newStreamHarness(t, MiddlewareOptions{Profiles: map[string]ProfileOptions{
		"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 4, MaxStreams: 1}},
	}})
	sh.openStream()
	if rec := sh.do(http.MethodGet, "/events"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second stream: got %d, want 429", rec.Code)
	}
	sh.finish()
	// A fresh harness handler would reset state, so reuse the closed-release
	// handler: streams now return immediately and the slot must be free.
	if rec := sh.do(http.MethodGet, "/events"); rec.Code != http.StatusOK {
		t.Fatalf("stream after the first ended: got %d, want 200", rec.Code)
	}
}

func TestStreamCap_ZeroMeansUnlimited(t *testing.T) {
	t.Parallel()
	sh := newStreamHarness(t, MiddlewareOptions{Profiles: map[string]ProfileOptions{
		"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 1, MaxStreams: 0}},
	}})
	for range 50 {
		sh.openStream()
	}
}

func TestStreamCap_PerClient(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	current := "a"
	sh := newStreamHarness(t, MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"a": {Concurrency: &ConcurrencyOptions{MaxInflight: 4, MaxStreams: 1}},
			"b": {Concurrency: &ConcurrencyOptions{MaxInflight: 4, MaxStreams: 1}},
		},
		ResolveProfile: func(*http.Request) (string, bool) {
			mu.Lock()
			defer mu.Unlock()
			return current, true
		},
	})
	sh.openStream()
	mu.Lock()
	current = "b"
	mu.Unlock()
	sh.openStream() // b has its own budget
}

func TestStreamCap_GlobalGateSkippedAndDefaultCapApplies(t *testing.T) {
	t.Parallel()
	// A profile with no concurrency block, and a small global gate: streams skip
	// the gate but are bounded by DefaultMaxStreams.
	sh := newStreamHarness(t, MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {Rate: &RateOptions{TokensPerSecond: 1000, Burst: 1000}},
		},
		GlobalConcurrency: &GlobalConcurrencyOptions{MaxInflight: 10},
	})
	for range DefaultMaxStreams {
		sh.openStream()
	}
	if rec := sh.do(http.MethodGet, "/events"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("stream past the default cap: got %d, want 429", rec.Code)
	}
	if rec := sh.do(http.MethodGet, "/containers/json"); rec.Code != http.StatusOK {
		t.Fatalf("ordinary request with the global gate full of streams: got %d, want 200", rec.Code)
	}
}

func TestStreamCap_NoClassifierKeepsOldBehavior(t *testing.T) {
	t.Parallel()
	enter := make(chan struct{})
	release := make(chan struct{})
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 1}},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enter <- struct{}{}
		<-release
	}))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/events", nil))
	}()
	<-enter
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 when no classifier is set", rec.Code)
	}
	close(release)
	wg.Wait()
}

func TestStreamCap_WarnRolloutAdmitsOverCap(t *testing.T) {
	t.Parallel()
	sh := newStreamHarness(t, MiddlewareOptions{Profiles: map[string]ProfileOptions{
		"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 4, MaxStreams: 1}},
	}})
	sh.openStream()

	meta := metaWithRolloutMode("warn")
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req = req.WithContext(metaContext(req, meta))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		sh.h.ServeHTTP(rec, req)
		close(done)
	}()
	<-sh.entered
	if meta.Decision != "would_deny" {
		t.Fatalf("meta.Decision = %q, want would_deny", meta.Decision)
	}
	sh.finish()
	<-done
	if rec.Code != http.StatusOK {
		t.Fatalf("warn-mode over-cap stream: got %d, want 200", rec.Code)
	}
}

func TestRateLimit_PingCostsNoTokens(t *testing.T) {
	t.Parallel()
	clk := newFixedClock(time.Unix(0, 0))
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			// Burst of 1 and a catch-all cost of 1: one real call uses the budget.
			"ci": {Rate: &RateOptions{TokensPerSecond: 1, Burst: 1, EndpointCosts: []EndpointCost{{PathGlob: "/**", Cost: 1}}}},
		},
		ResolveProfile: resolveProfileFn("ci"),
		Now:            clk.Now,
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(okHandler)
	do := func(method, target string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
		return rec.Code
	}
	for _, target := range []string{"/_ping", "/v1.45/_ping", "/libpod/_ping"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			if code := do(method, target); code != http.StatusOK {
				t.Fatalf("%s %s: got %d, want 200", method, target, code)
			}
		}
	}
	if code := do(http.MethodGet, "/containers/json"); code != http.StatusOK {
		t.Fatalf("first real call after pings: got %d, want 200 (pings must not spend tokens)", code)
	}
	if code := do(http.MethodGet, "/containers/json"); code != http.StatusTooManyRequests {
		t.Fatalf("second real call: got %d, want 429", code)
	}
}

func TestConcurrency_PingStillCounts(t *testing.T) {
	t.Parallel()
	enter := make(chan struct{})
	release := make(chan struct{})
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 1}},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/json" {
			enter <- struct{}{}
			<-release
		}
	}))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	}()
	<-enter
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_ping", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("ping over the concurrency cap: got %d, want 429", rec.Code)
	}
	close(release)
	wg.Wait()
}
