package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// ParsePriority + priorityThreshold
// ---------------------------------------------------------------------------

func TestParsePriority_KnownValues(t *testing.T) {
	cases := []struct {
		in   string
		want Priority
		ok   bool
	}{
		{"", PriorityNormal, true},
		{"normal", PriorityNormal, true},
		{"NORMAL", PriorityNormal, true},
		{"  low  ", PriorityLow, true},
		{"high", PriorityHigh, true},
		{"medium", PriorityNormal, false},
		{"emergency", PriorityNormal, false},
	}
	for _, tc := range cases {
		got, ok := ParsePriority(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParsePriority(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPriority_String(t *testing.T) {
	cases := map[Priority]string{
		PriorityLow:    "low",
		PriorityNormal: "normal",
		PriorityHigh:   "high",
	}
	for p, want := range cases {
		if got := p.String(); got != want {
			t.Errorf("Priority(%d).String() = %q, want %q", p, got, want)
		}
	}
}

func TestPriorityThreshold_HardcodedShares(t *testing.T) {
	cases := []struct {
		priority  Priority
		globalMax int64
		want      int64
	}{
		// share=0.5 for low, 0.8 for normal, 1.0 for high
		{PriorityLow, 100, 50},
		{PriorityNormal, 100, 80},
		{PriorityHigh, 100, 100},
		// Rounded down (floor)
		{PriorityNormal, 11, 8}, // 11 * 0.8 = 8.8 → 8
		{PriorityLow, 11, 5},    // 11 * 0.5 = 5.5 → 5
		// Tiny caps: high gets at least 1
		{PriorityHigh, 1, 1},
		{PriorityLow, 1, 0}, // 1 * 0.5 = 0.5 → 0 floor
		// Disabled gate → 0
		{PriorityNormal, 0, 0},
		{PriorityHigh, -1, 0},
	}
	for _, tc := range cases {
		got := priorityThreshold(tc.priority, tc.globalMax)
		if got != tc.want {
			t.Errorf("priorityThreshold(%v, %d) = %d, want %d", tc.priority, tc.globalMax, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// GlobalInflightTracker
// ---------------------------------------------------------------------------

func TestGlobalInflightTracker_AdmitsBelowThreshold(t *testing.T) {
	tr := &GlobalInflightTracker{}

	// globalMax=10, normal share=0.8 → threshold=8
	for i := 1; i <= 8; i++ {
		ok, curr, thr := tr.Acquire(PriorityNormal, 10)
		if !ok {
			t.Fatalf("acquire #%d: expected admit, got deny (curr=%d, thr=%d)", i, curr, thr)
		}
		if curr != int64(i) {
			t.Fatalf("acquire #%d: current=%d, want %d", i, curr, i)
		}
		if thr != 8 {
			t.Fatalf("acquire #%d: threshold=%d, want 8", i, thr)
		}
	}

	// 9th normal request should be denied.
	ok, curr, thr := tr.Acquire(PriorityNormal, 10)
	if ok {
		t.Fatalf("9th normal acquire should deny, got admit (curr=%d, thr=%d)", curr, thr)
	}
	if curr != 8 {
		t.Fatalf("denied acquire current=%d, want 8 (unchanged)", curr)
	}
}

func TestGlobalInflightTracker_HighPriorityBypassesNormalFloor(t *testing.T) {
	tr := &GlobalInflightTracker{}

	// Fill to 8 with normal — at normal threshold.
	for range 8 {
		ok, _, _ := tr.Acquire(PriorityNormal, 10)
		if !ok {
			t.Fatal("normal pre-fill should admit")
		}
	}

	// Normal denied at threshold.
	if ok, _, _ := tr.Acquire(PriorityNormal, 10); ok {
		t.Fatal("normal at threshold should deny")
	}

	// Low also denied (its threshold=5 is already exceeded).
	if ok, _, _ := tr.Acquire(PriorityLow, 10); ok {
		t.Fatal("low above its floor should deny")
	}

	// High still admitted (threshold=10, currently at 8).
	if ok, _, _ := tr.Acquire(PriorityHigh, 10); !ok {
		t.Fatal("high below its threshold should admit")
	}
	if ok, _, _ := tr.Acquire(PriorityHigh, 10); !ok {
		t.Fatal("high below threshold should admit (#2)")
	}
	if ok, _, _ := tr.Acquire(PriorityHigh, 10); ok {
		t.Fatal("high at threshold=10 should deny")
	}
}

func TestGlobalInflightTracker_Release(t *testing.T) {
	tr := &GlobalInflightTracker{}

	for range 5 {
		ok, _, _ := tr.Acquire(PriorityNormal, 100)
		if !ok {
			t.Fatal("acquire should admit")
		}
	}
	if got := tr.Current(); got != 5 {
		t.Fatalf("current=%d, want 5", got)
	}

	for range 5 {
		tr.Release()
	}
	if got := tr.Current(); got != 0 {
		t.Fatalf("current after releases=%d, want 0", got)
	}

	// Underflow protection: extra releases stay at 0.
	tr.Release()
	tr.Release()
	if got := tr.Current(); got != 0 {
		t.Fatalf("current after extra releases=%d, want 0", got)
	}
}

func TestGlobalInflightTracker_DisabledGateAdmitsAll(t *testing.T) {
	tr := &GlobalInflightTracker{}
	// globalMax=0 disables the gate; all priorities admit.
	for _, p := range []Priority{PriorityLow, PriorityNormal, PriorityHigh} {
		ok, _, thr := tr.Acquire(p, 0)
		if !ok {
			t.Fatalf("priority %v should admit when globalMax=0", p)
		}
		if thr != 0 {
			t.Fatalf("priority %v: threshold should be 0 for disabled gate, got %d", p, thr)
		}
	}
}

func TestGlobalInflightTracker_ConcurrentAcquireRespectsCap(t *testing.T) {
	tr := &GlobalInflightTracker{}
	const goroutines = 200
	const globalMax = 20

	var admitted int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			ok, _, _ := tr.Acquire(PriorityNormal, globalMax)
			if ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Normal threshold = 20 * 0.8 = 16.
	if admitted != 16 {
		t.Fatalf("admitted=%d, want 16 (threshold for normal at globalMax=20)", admitted)
	}
	if got := tr.Current(); got != 16 {
		t.Fatalf("current=%d, want 16", got)
	}
}

// ---------------------------------------------------------------------------
// Middleware integration
// ---------------------------------------------------------------------------

func TestMiddleware_GlobalConcurrency_LowProfileHitsPriorityFloor(t *testing.T) {
	enter := make(chan struct{})
	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enter <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"scraper": {Priority: PriorityLow},
		},
		ResolveProfile:    resolveProfileFn("scraper"),
		GlobalConcurrency: &GlobalConcurrencyOptions{MaxInflight: 10},
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(blocking)

	// Hold 5 in-flight requests (low threshold = 10*0.5 = 5).
	var wg sync.WaitGroup
	wg.Add(5)
	for range 5 {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		}()
		<-enter
	}

	// 6th low request hits priority_floor (threshold=5, current=5).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	var body ConcurrencyLimitResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Reason != string(ReasonPriorityFloor) {
		t.Fatalf("expected reason=%q, got %q", ReasonPriorityFloor, body.Reason)
	}

	for range 5 {
		release <- struct{}{}
	}
	wg.Wait()
}

func TestMiddleware_GlobalConcurrency_HighProfilePassesBelowGlobalCap(t *testing.T) {
	enter := make(chan struct{})
	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enter <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	// Two profiles: a low-priority scraper and a high-priority admin.
	resolveByHeader := func(r *http.Request) (string, bool) {
		p := r.Header.Get("X-Profile")
		return p, p != ""
	}
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			"scraper": {Priority: PriorityLow},
			"admin":   {Priority: PriorityHigh},
		},
		ResolveProfile:    resolveByHeader,
		GlobalConcurrency: &GlobalConcurrencyOptions{MaxInflight: 10},
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(blocking)

	// Fill 5 low-priority in-flight requests (at low threshold).
	var wg sync.WaitGroup
	wg.Add(5)
	for range 5 {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("X-Profile", "scraper")
			h.ServeHTTP(httptest.NewRecorder(), req)
		}()
		<-enter
	}

	// Now admin (high) should still be admitted up to threshold=10.
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("X-Profile", "admin")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()
	<-enter

	// Another low request should still be denied.
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Profile", "scraper")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("low at threshold should 429, got %d", rec.Code)
	}

	for range 6 {
		release <- struct{}{}
	}
	wg.Wait()
}

func TestMiddleware_GlobalConcurrency_NoProfileFallsBackToNormal(t *testing.T) {
	enter := make(chan struct{})
	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enter <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	// No profiles at all — global gate must still apply, treating callers as
	// normal priority (threshold = 10 * 0.8 = 8).
	opts := MiddlewareOptions{
		ResolveProfile:    resolveProfileFn(""),
		GlobalConcurrency: &GlobalConcurrencyOptions{MaxInflight: 10},
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(blocking)

	var wg sync.WaitGroup
	wg.Add(8)
	for range 8 {
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
		}()
		<-enter
	}

	// 9th request denied (above normal threshold of 8).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 at normal threshold=8, got %d", rec.Code)
	}

	for range 8 {
		release <- struct{}{}
	}
	wg.Wait()
}

func TestMiddleware_GlobalConcurrency_DeniedRequestReleasesNoSlot(t *testing.T) {
	// Verifies that a request denied at the priority floor does NOT consume
	// or leak a global slot (no Acquire happened on the denied path).
	tr := &GlobalInflightTracker{}
	for range 5 {
		ok, _, _ := tr.Acquire(PriorityLow, 10)
		if !ok {
			t.Fatal("pre-fill should succeed")
		}
	}

	// Low above its threshold: denied without increment.
	if ok, curr, _ := tr.Acquire(PriorityLow, 10); ok {
		t.Fatalf("low at threshold should deny (got admit, curr=%d)", curr)
	}
	if got := tr.Current(); got != 5 {
		t.Fatalf("denied acquire must not increment; current=%d, want 5", got)
	}
}
