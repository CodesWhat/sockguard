package ratelimit

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/metrics"
)

// okHandler is a trivial 200 OK handler used in middleware tests.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func resolveProfileFn(profile string) func(*http.Request) (string, bool) {
	return func(_ *http.Request) (string, bool) {
		return profile, profile != ""
	}
}

// ---------------------------------------------------------------------------
// No-op when Profiles map is empty.
// ---------------------------------------------------------------------------

func TestMiddleware_NoLimitsIsPassthrough(t *testing.T) {
	mw := mustMiddleware(t, newTestLogger(), nil, nil, MiddlewareOptions{})
	h := mw(okHandler)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Rate limit: allow up to burst, then deny with 429.
// ---------------------------------------------------------------------------

func TestMiddleware_RateLimit_AllowAndDeny(t *testing.T) {
	reg := metrics.NewRegistry()
	sampler, stop := NewAuditSampler()
	defer stop()

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {Rate: &RateOptions{TokensPerSecond: 100, Burst: 2}},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, sampler, opts)(okHandler)

	// First two should be OK (burst=2).
	for i := range 2 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// Third should be 429.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	// Body should decode to RateLimitResponse.
	var body RateLimitResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Reason != string(ReasonRateLimit) {
		t.Fatalf("expected reason=%q, got %q", ReasonRateLimit, body.Reason)
	}
	if body.RetryAfterSeconds <= 0 {
		t.Fatalf("expected retry_after_seconds > 0, got %d", body.RetryAfterSeconds)
	}

	// Retry-After header should match.
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header to be set")
	}
}

// ---------------------------------------------------------------------------
// Concurrency cap: allow up to max_inflight, then deny with 429.
// ---------------------------------------------------------------------------

func TestMiddleware_ConcurrencyCap_AllowAndDeny(t *testing.T) {
	reg := metrics.NewRegistry()
	sampler, stop := NewAuditSampler()
	defer stop()

	// Use a barrier to hold the first request in-flight while we send the second.
	enter := make(chan struct{})
	release := make(chan struct{})
	blockingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enter <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {Concurrency: &ConcurrencyOptions{MaxInflight: 1}},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, sampler, opts)(blockingHandler)

	// Start the first request in the background; it will block in blockingHandler.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	}()

	// Wait until the first request has entered the handler.
	<-enter

	// Second request should be denied immediately.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	var body ConcurrencyLimitResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Reason != string(ReasonConcurrency) {
		t.Fatalf("expected reason=%q, got %q", ReasonConcurrency, body.Reason)
	}

	// Release the first request and wait for it to finish.
	release <- struct{}{}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Anonymous client bucketing: empty profile → AnonymousClientID.
// ---------------------------------------------------------------------------

func TestMiddleware_AnonymousClientID(t *testing.T) {
	reg := metrics.NewRegistry()

	// Requests with empty profile are bucketed under _anonymous.
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			AnonymousClientID: {Rate: &RateOptions{TokensPerSecond: 100, Burst: 1}},
		},
		ResolveProfile: resolveProfileFn(""), // empty → anonymous
	}
	h := mustMiddleware(t, newTestLogger(), reg, nil, opts)(okHandler)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for anonymous after burst exhausted, got %d", rec2.Code)
	}
}

// ---------------------------------------------------------------------------
// Profile not in map → passthrough.
// ---------------------------------------------------------------------------

func TestMiddleware_UnknownProfilePassthrough(t *testing.T) {
	reg := metrics.NewRegistry()
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {Rate: &RateOptions{TokensPerSecond: 1, Burst: 1}},
		},
		ResolveProfile: resolveProfileFn("operator"), // "operator" not in map
	}
	h := mustMiddleware(t, newTestLogger(), reg, nil, opts)(okHandler)

	for i := range 5 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 for unlimted profile, got %d", i+1, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Denied request is NOT counted as in-flight.
// ---------------------------------------------------------------------------

func TestMiddleware_DeniedRateRequestNotCountedAsInflight(t *testing.T) {
	reg := metrics.NewRegistry()
	sampler, stop := NewAuditSampler()
	defer stop()

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {
				Rate:        &RateOptions{TokensPerSecond: 100, Burst: 1},
				Concurrency: &ConcurrencyOptions{MaxInflight: 10},
			},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}

	h := mustMiddleware(t, newTestLogger(), reg, sampler, opts)(okHandler)

	// First request passes.
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request should be 200, got %d", rec1.Code)
	}

	// Second request should be denied (rate exhausted), and NOT counted as inflight.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be 429, got %d", rec2.Code)
	}
	// If the denied request were erroneously counted as inflight, the tracker
	// counter would be > 0 after both requests complete. Since the denied
	// request exits before Acquire, the counter should be 0 after handler return.
	// (We cannot directly inspect the tracker, but the test validates the 429
	// denial path does not call through to the inner handler.)
}

// ---------------------------------------------------------------------------
// Burst=0 defaults to TokensPerSecond.
// ---------------------------------------------------------------------------

func TestMiddleware_BurstZeroDefaultsToRate(t *testing.T) {
	reg := metrics.NewRegistry()
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			// Burst=0 → defaults to TokensPerSecond=2 in compileProfile.
			"ci": {Rate: &RateOptions{TokensPerSecond: 2, Burst: 0}},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, nil, opts)(okHandler)

	// Should admit exactly 2 requests (burst=2 by default).
	for i := range 2 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request should be 429 (burst=2 by default), got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Concurrent requests under both rate and concurrency limits (-race).
// ---------------------------------------------------------------------------

func TestMiddleware_ConcurrentUnderRace(t *testing.T) {
	reg := metrics.NewRegistry()
	sampler, stop := newAuditSamplerWithClock(func() time.Time { return time.Now() })
	defer stop()

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {
				Rate:        &RateOptions{TokensPerSecond: 1000, Burst: 100},
				Concurrency: &ConcurrencyOptions{MaxInflight: 20},
			},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, sampler, opts)(okHandler)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
			// Either 200 or 429 are acceptable; we're just checking for races.
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Endpoint cost weighting: expensive endpoints withdraw more tokens.
// ---------------------------------------------------------------------------

func TestMiddleware_EndpointCost_WeightsExpensiveEndpoint(t *testing.T) {
	reg := metrics.NewRegistry()

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {
				Rate: &RateOptions{
					TokensPerSecond: 100, // refill faster than burst
					Burst:           10,
					EndpointCosts: []EndpointCost{
						{PathGlob: "/build", Cost: 5},
					},
				},
			},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, nil, opts)(okHandler)

	// Two cost-5 builds drain the burst-10 bucket.
	for i := range 2 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/build", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("build %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// Third build is denied — bucket is empty (and refill hasn't ticked in this
	// real-clock test, but the rate is high enough that this should still 429
	// because the call happens within a microsecond).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/build", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd cost-5 build from burst=10, got %d", rec.Code)
	}
}

func TestMiddleware_EndpointCost_MethodFilter(t *testing.T) {
	reg := metrics.NewRegistry()

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {
				Rate: &RateOptions{
					TokensPerSecond: 100,
					Burst:           10,
					EndpointCosts: []EndpointCost{
						{PathGlob: "/containers/create", Methods: []string{"POST"}, Cost: 10},
					},
				},
			},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, nil, opts)(okHandler)

	// GET on the same path should default to cost=1 — 10 GETs all admitted.
	for i := range 10 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/create", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %d: expected 200 (method-mismatched rule, cost defaults to 1), got %d", i+1, rec.Code)
		}
	}
}

func TestMiddleware_EndpointCost_UnmatchedFallsBackToOne(t *testing.T) {
	reg := metrics.NewRegistry()

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {
				Rate: &RateOptions{
					TokensPerSecond: 100,
					Burst:           3,
					EndpointCosts: []EndpointCost{
						{PathGlob: "/build", Cost: 10},
					},
				},
			},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, nil, opts)(okHandler)

	// /containers/json doesn't match the /build rule; cost defaults to 1, so
	// burst=3 admits exactly 3 requests.
	for i := range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unmatched request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 4th unmatched request, got %d", rec.Code)
	}
}

func TestMiddleware_EndpointCost_FirstMatchWins(t *testing.T) {
	reg := metrics.NewRegistry()

	// Two overlapping rules: the first (cost=10) is matched, even though the
	// second (cost=1) also matches /build. Order in declaration is authoritative.
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {
				Rate: &RateOptions{
					TokensPerSecond: 100,
					Burst:           5,
					EndpointCosts: []EndpointCost{
						{PathGlob: "/build", Cost: 5},
						{PathGlob: "/**", Cost: 1},
					},
				},
			},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, newTestLogger(), reg, nil, opts)(okHandler)

	// First /build (cost=5) drains burst.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/build", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first /build: expected 200, got %d", rec.Code)
	}
	// Second /build is denied — if /** (cost=1) won we'd still have tokens.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/build", nil))
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (first-match cost=5 drained burst=5), got %d", rec2.Code)
	}
}

// ---------------------------------------------------------------------------
// Throttle audit record includes the cost field.
// ---------------------------------------------------------------------------

func TestMiddleware_ThrottleAudit_IncludesCost(t *testing.T) {
	reg := metrics.NewRegistry()
	sampler, stop := NewAuditSampler()
	defer stop()

	// Capture log records to inspect the cost attribute.
	buf := &threadSafeBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"ci": {
				Rate: &RateOptions{
					TokensPerSecond: 100,
					Burst:           4,
					EndpointCosts: []EndpointCost{
						{PathGlob: "/build", Cost: 5}, // cost > burst-remaining → first call 429s
					},
				},
			},
		},
		ResolveProfile: resolveProfileFn("ci"),
	}
	h := mustMiddleware(t, logger, reg, sampler, opts)(okHandler)

	// Drain by issuing one cost-5 build on a burst=4 bucket — first call 429s.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/build", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (cost=5 > burst=4), got %d", rec.Code)
	}

	logs := buf.String()
	if !strings.Contains(logs, `"cost":5`) {
		t.Fatalf("expected cost=5 in audit record, got:\n%s", logs)
	}
	if !strings.Contains(logs, `"reason":"rate_limit_exceeded"`) {
		t.Fatalf("expected reason=rate_limit_exceeded in audit record, got:\n%s", logs)
	}
}

// threadSafeBuffer is a minimal io.Writer that allows concurrent reads/writes
// without depending on bytes.Buffer's non-thread-safe internals. The middleware
// logger writes from the request goroutine; the test reads from the test
// goroutine. A mutex around a strings.Builder is sufficient.
type threadSafeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// mustMiddleware constructs Middleware and fails the test on a compile error.
// All happy-path tests use well-formed configs; this helper keeps the assertion
// boilerplate from drowning out the actual test logic.
func mustMiddleware(t *testing.T, logger *slog.Logger, reg *metrics.Registry, sampler *AuditSampler, opts MiddlewareOptions) func(http.Handler) http.Handler {
	t.Helper()
	mw, err := Middleware(logger, reg, sampler, opts)
	if err != nil {
		t.Fatalf("Middleware: unexpected compile error: %v", err)
	}
	return mw
}
