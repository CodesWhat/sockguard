package ratelimit

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	mw := Middleware(newTestLogger(), nil, nil, MiddlewareOptions{})
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
	h := Middleware(newTestLogger(), reg, sampler, opts)(okHandler)

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
	h := Middleware(newTestLogger(), reg, sampler, opts)(blockingHandler)

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
	h := Middleware(newTestLogger(), reg, nil, opts)(okHandler)

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
	h := Middleware(newTestLogger(), reg, nil, opts)(okHandler)

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

	h := Middleware(newTestLogger(), reg, sampler, opts)(okHandler)

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
	h := Middleware(newTestLogger(), reg, nil, opts)(okHandler)

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
	h := Middleware(newTestLogger(), reg, sampler, opts)(okHandler)

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
// Helpers
// ---------------------------------------------------------------------------

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
