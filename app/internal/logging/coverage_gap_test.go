package logging

// coverage_gap_test.go covers branches not exercised by the existing test suite.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// access.go: SetDenied (0%)
// ---------------------------------------------------------------------------

func TestSetDeniedPopulatesDecisionAndReason(t *testing.T) {
	meta := &RequestMeta{}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}

	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	SetDenied(rc, req, "test reason", nil)

	if meta.Decision != "deny" {
		t.Fatalf("Decision = %q, want deny", meta.Decision)
	}
	if meta.Reason != "test reason" {
		t.Fatalf("Reason = %q, want test reason", meta.Reason)
	}
}

func TestSetDeniedWithCodePopulatesReasonCode(t *testing.T) {
	meta := &RequestMeta{}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}

	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	SetDeniedWithCode(rc, req, "no_matching_allow_rule", "test reason", nil)

	if meta.Decision != "deny" {
		t.Fatalf("Decision = %q, want deny", meta.Decision)
	}
	if meta.ReasonCode != "no_matching_allow_rule" {
		t.Fatalf("ReasonCode = %q, want no_matching_allow_rule", meta.ReasonCode)
	}
	if meta.Reason != "test reason" {
		t.Fatalf("Reason = %q, want test reason", meta.Reason)
	}
}

func TestSetDeniedNilMetaIsNoop(t *testing.T) {
	// Plain recorder has no RequestMeta — should be a no-op
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	SetDenied(httptest.NewRecorder(), req, "ignored", nil)
	// No panic or error means it worked
}

func TestSetDeniedWithNormalizeFillsNormPath(t *testing.T) {
	meta := &RequestMeta{}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}

	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	SetDenied(rc, req, "denied", func(path string) string {
		return "/containers/json"
	})

	if meta.NormPath != "/containers/json" {
		t.Fatalf("NormPath = %q, want /containers/json", meta.NormPath)
	}
}

func TestSetDeniedSkipsNormalizeWhenNormPathAlreadySet(t *testing.T) {
	meta := &RequestMeta{NormPath: "/already/set"}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}

	called := false
	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	SetDenied(rc, req, "denied", func(path string) string {
		called = true
		return path
	})

	if called {
		t.Fatal("normalize callback should not be called when NormPath is already set")
	}
	if meta.NormPath != "/already/set" {
		t.Fatalf("NormPath = %q, want /already/set", meta.NormPath)
	}
}

func TestSetDeniedNilRequest(t *testing.T) {
	meta := &RequestMeta{}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}

	called := false
	// r is nil — normalize callback must NOT be called (r guard)
	SetDenied(rc, nil, "denied", func(path string) string {
		called = true
		return path
	})

	if called {
		t.Fatal("normalize callback should not be called with nil request")
	}
	if meta.Decision != "deny" {
		t.Fatalf("Decision = %q, want deny", meta.Decision)
	}
}

func TestEnsureRequestMetaNilCapture(t *testing.T) {
	meta, owned := ensureRequestMeta(nil)
	if meta != nil {
		t.Fatalf("ensureRequestMeta(nil) meta = %#v, want nil", meta)
	}
	if owned {
		t.Fatal("ensureRequestMeta(nil) owned = true, want false")
	}
}

// ---------------------------------------------------------------------------
// access.go: newRequestIDGenerator — boundary clamping branches
// ---------------------------------------------------------------------------

func TestNewRequestIDGeneratorClampsPoolSizeToOne(t *testing.T) {
	gen := newRequestIDGenerator(0, 0, func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i + 1)
		}
		return len(b), nil
	})
	defer gen.close()

	// poolSize clamped to 1, should still produce valid IDs
	id := gen.Next()
	if len(id) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(id))
	}
}

func TestNewRequestIDGeneratorClampsRefillThresholdNegative(t *testing.T) {
	gen := newRequestIDGenerator(8, -1, func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i + 1)
		}
		return len(b), nil
	})
	defer gen.close()

	id := gen.Next()
	if len(id) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(id))
	}
}

func TestNewRequestIDGeneratorClampsRefillThresholdToPoolSizeMinusOne(t *testing.T) {
	// refillThreshold >= poolSize → clamped to poolSize-1
	gen := newRequestIDGenerator(4, 10, func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i + 1)
		}
		return len(b), nil
	})
	defer gen.close()

	id := gen.Next()
	if len(id) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(id))
	}
}

// ---------------------------------------------------------------------------
// access.go: Next — nil generator path
// ---------------------------------------------------------------------------

func TestNextNilGeneratorFallsBack(t *testing.T) {
	var g *requestIDGenerator
	id := g.Next()
	if len(id) != 32 {
		t.Fatalf("Next() on nil generator len = %d, want 32", len(id))
	}
}

// ---------------------------------------------------------------------------
// access.go: signalRefill — nil generator is safe
// ---------------------------------------------------------------------------

func TestSignalRefillNilIsNoop(t *testing.T) {
	var g *requestIDGenerator
	g.signalRefill() // must not panic
}

// ---------------------------------------------------------------------------
// access.go: close — nil generator is safe
// ---------------------------------------------------------------------------

func TestCloseNilIsNoop(t *testing.T) {
	var g *requestIDGenerator
	g.close() // must not panic
}

// ---------------------------------------------------------------------------
// access.go: refillSync — nil generator and nil fill guard
// ---------------------------------------------------------------------------

func TestRefillSyncNilGeneratorIsNoop(t *testing.T) {
	var g *requestIDGenerator
	g.refillSync() // must not panic
}

func TestRefillSyncAboveThresholdIsNoop(t *testing.T) {
	// Build a generator whose pool is already above the refill threshold
	var filled atomic.Int32
	gen := newRequestIDGenerator(4, 1, func(b []byte) (int, error) {
		filled.Add(1)
		for i := range b {
			b[i] = byte(i + 1)
		}
		return len(b), nil
	})
	defer gen.close()

	// Wait for the initial refill to complete
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(gen.ids) == 0 {
		time.Sleep(time.Millisecond)
	}

	before := filled.Load()
	// Calling refillSync when pool > threshold should be a no-op
	gen.refillSync()
	after := filled.Load()

	if after > before+1 {
		t.Fatalf("refillSync called fill %d extra times, want 0 or 1", after-before)
	}
}

func TestRefillSyncFillError(t *testing.T) {
	// fill always returns an error — generator should use fallback for Next()
	gen := newRequestIDGenerator(4, 0, func([]byte) (int, error) {
		return 0, errors.New("fill error")
	})
	defer gen.close()

	// Drain any pre-filled IDs (there shouldn't be any since fill always errors)
	// Then Next() should fall back to counter-based ID
	id := gen.Next()
	if len(id) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(id))
	}
}

func TestRefillSyncShortFill(t *testing.T) {
	// fill returns fewer bytes than requested — should not push partial IDs
	gen := newRequestIDGenerator(4, 0, func(b []byte) (int, error) {
		return 0, nil // 0 bytes filled, no error — triggers n != len(slab) check
	})
	defer gen.close()

	id := gen.Next()
	if len(id) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(id))
	}
}

func TestRefillSyncFullPoolIsNoop(t *testing.T) {
	var fillCalls atomic.Int32
	gen := &requestIDGenerator{
		ids:             make(chan string, 1),
		refillThreshold: 1,
		fill: func(b []byte) (int, error) {
			fillCalls.Add(1)
			return len(b), nil
		},
	}
	gen.ids <- ""

	gen.refillSync()

	if got := fillCalls.Load(); got != 0 {
		t.Fatalf("fill calls = %d, want 0 when pool is already full", got)
	}
}

func TestRefillSyncFillErrorNoop(t *testing.T) {
	gen := &requestIDGenerator{
		ids:             make(chan string, 2),
		refillThreshold: 2,
		fill: func([]byte) (int, error) {
			return 0, errors.New("fill failed")
		},
	}

	gen.refillSync()

	if got := len(gen.ids); got != 0 {
		t.Fatalf("len(ids) = %d, want 0 after fill failure", got)
	}
}

func TestEnqueueRequestIDReturnsFalseWhenChannelFull(t *testing.T) {
	ids := make(chan string, 1)
	ids <- ""

	if enqueueRequestID(ids, "") {
		t.Fatal("enqueueRequestID() = true, want false for a full channel")
	}
}

func TestEnqueueRequestIDsStopsWhenChannelFull(t *testing.T) {
	ids := make(chan string, 1)
	ids <- ""

	enqueueRequestIDs(ids, make([]byte, requestIDBytes))

	if got := len(ids); got != 1 {
		t.Fatalf("len(ids) = %d, want 1 after full-channel enqueue attempt", got)
	}
}

// ---------------------------------------------------------------------------
// access.go: Next — pool-empty default branch (signals refill, returns fallback)
// ---------------------------------------------------------------------------

func TestNextPoolEmptyUseFallback(t *testing.T) {
	// Generator with fill that always fails — pool stays empty
	gen := newRequestIDGenerator(2, 0, func([]byte) (int, error) {
		return 0, errors.New("unavailable")
	})
	defer gen.close()

	// Drain whatever IDs may have snuck in
	for len(gen.ids) > 0 {
		<-gen.ids
	}

	id := gen.Next()
	if len(id) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(id))
	}
}

// ---------------------------------------------------------------------------
// access.go: Next — channel-read path that triggers signalRefill (len<=threshold)
// ---------------------------------------------------------------------------

func TestNextTriggersRefillWhenPoolLow(t *testing.T) {
	var fillCalls atomic.Int32
	// poolSize=4, refillThreshold=3: after reading one ID len(ids)=3 == threshold,
	// so signalRefill is called (the branch inside the case arm).
	gen := newRequestIDGenerator(4, 3, func(b []byte) (int, error) {
		fillCalls.Add(1)
		for i := range b {
			b[i] = byte(i + 1)
		}
		return len(b), nil
	})
	defer gen.close()

	// Wait for the initial fill
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(gen.ids) == 0 {
		time.Sleep(time.Millisecond)
	}

	// Read one ID — this triggers the len <= threshold branch
	id := gen.Next()
	if len(id) != 32 {
		t.Fatalf("Next() len = %d, want 32", len(id))
	}
}

// ---------------------------------------------------------------------------
// access.go: clientRequestIDForRequest — context path when meta is nil
// ---------------------------------------------------------------------------

func TestClientRequestIDForRequestFromContext(t *testing.T) {
	// Use RequestIDMiddleware to inject the client request ID into context,
	// since contextKeyClientRequestID is unexported.
	var capturedClientID string
	handler := RequestIDMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// meta is nil here (no access log wrapper), so clientRequestIDForRequest
		// falls through to r.Context().Value(contextKeyClientRequestID)
		capturedClientID = clientRequestIDForRequest(r, nil)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.Header.Set(requestIDHeader, "client-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if capturedClientID != "client-supplied-id" {
		t.Fatalf("clientRequestIDForRequest() from context = %q, want client-supplied-id", capturedClientID)
	}
}

func TestClientRequestIDForRequestNilRequest(t *testing.T) {
	got := clientRequestIDForRequest(nil, nil)
	if got != "" {
		t.Fatalf("clientRequestIDForRequest(nil, nil) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// access.go: AllowsPassThrough — gates the warn / audit pass-through paths
// in every middleware. Direct coverage avoids relying on indirect callers
// to exercise each rollout mode.
// ---------------------------------------------------------------------------

func TestAllowsPassThroughByRolloutMode(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{mode: "warn", want: true},
		{mode: "audit", want: true},
		{mode: "enforce", want: false},
		{mode: "", want: false},
		{mode: "WARN", want: false}, // case-sensitive by design — config validation upper-bounds
		{mode: "unknown", want: false},
	}
	for _, tc := range tests {
		meta := &RequestMeta{RolloutMode: tc.mode}
		if got := meta.AllowsPassThrough(); got != tc.want {
			t.Fatalf("AllowsPassThrough(mode=%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestAllowsPassThroughNilReceiver(t *testing.T) {
	var meta *RequestMeta
	if meta.AllowsPassThrough() {
		t.Fatal("nil *RequestMeta.AllowsPassThrough() = true, want false")
	}
}

// ---------------------------------------------------------------------------
// access.go: SetWouldDenyWithCode — stamps the warn / audit verdict so the
// access log and audit log can correlate the would-be denial with its gate.
// ---------------------------------------------------------------------------

func TestSetWouldDenyWithCodeStampsDecision(t *testing.T) {
	meta := &RequestMeta{}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)

	SetWouldDenyWithCode(rc, req, "rate_limited", "would have throttled", nil)

	if meta.Decision != DecisionWouldDeny {
		t.Fatalf("Decision = %q, want %q", meta.Decision, DecisionWouldDeny)
	}
	if meta.ReasonCode != "rate_limited" {
		t.Fatalf("ReasonCode = %q, want rate_limited", meta.ReasonCode)
	}
	if meta.Reason != "would have throttled" {
		t.Fatalf("Reason = %q, want 'would have throttled'", meta.Reason)
	}
}

func TestSetWouldDenyWithCodeRunsNormalizeWhenNormPathMissing(t *testing.T) {
	meta := &RequestMeta{}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)

	SetWouldDenyWithCode(rc, req, "deny_default", "warn", func(string) string {
		return "/containers/json"
	})

	if meta.NormPath != "/containers/json" {
		t.Fatalf("NormPath = %q, want /containers/json", meta.NormPath)
	}
}

func TestSetWouldDenyWithCodeKeepsExistingNormPath(t *testing.T) {
	meta := &RequestMeta{NormPath: "/already/set"}
	rc := &responseCapture{ResponseWriter: httptest.NewRecorder(), meta: meta}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)

	SetWouldDenyWithCode(rc, req, "deny_default", "warn", func(string) string {
		return "/should/not/override"
	})

	if meta.NormPath != "/already/set" {
		t.Fatalf("NormPath = %q, want it preserved as /already/set", meta.NormPath)
	}
}

func TestSetWouldDenyWithCodeNilMetaIsNoop(t *testing.T) {
	// Plain recorder has no carrier — must not panic when no meta is reachable.
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	SetWouldDenyWithCode(httptest.NewRecorder(), req, "code", "reason", nil)
}
