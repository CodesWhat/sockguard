package reload

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSwappableHandlerInitialHandlerRoutes(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "initial")
	})
	s := NewSwappableHandler(h)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Body.String(); got != "initial" {
		t.Fatalf("body = %q, want %q", got, "initial")
	}
}

func TestSwappableHandlerSwapRoutesToNew(t *testing.T) {
	initial := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "initial")
	})
	replacement := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "replacement")
	})

	s := NewSwappableHandler(initial)

	rec1 := httptest.NewRecorder()
	s.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec1.Body.String(); got != "initial" {
		t.Fatalf("pre-swap body = %q, want %q", got, "initial")
	}

	s.Swap(replacement)

	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec2.Body.String(); got != "replacement" {
		t.Fatalf("post-swap body = %q, want %q", got, "replacement")
	}
}

// TestSwappableHandlerInFlightCompletesOnOldHandler exercises the contract
// that a Swap landing mid-request doesn't interrupt the in-flight call —
// it must finish on whichever handler was current at admission time.
//
// The initial handler blocks on a release channel; the test triggers a
// Swap while that request is parked, then verifies the parked request
// completes through the ORIGINAL handler and that a fresh request reaches
// the replacement.
func TestSwappableHandlerInFlightCompletesOnOldHandler(t *testing.T) {
	release := make(chan struct{})
	inHandler := make(chan struct{})

	initial := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(inHandler) // signal handler entered
		<-release        // park until released
		_, _ = fmt.Fprint(w, "initial")
	})
	replacement := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "replacement")
	})

	s := NewSwappableHandler(initial)

	// Kick off the parked request in the background.
	parkedRec := httptest.NewRecorder()
	parkedDone := make(chan struct{})
	go func() {
		defer close(parkedDone)
		s.ServeHTTP(parkedRec, httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	<-inHandler // ensure the request is past the pointer load

	// Swap while a request is in flight on the old handler.
	s.Swap(replacement)

	// A fresh request must see the replacement.
	freshRec := httptest.NewRecorder()
	s.ServeHTTP(freshRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := freshRec.Body.String(); got != "replacement" {
		t.Fatalf("fresh request post-swap body = %q, want %q", got, "replacement")
	}

	// Release the parked request and verify it completed on the OLD handler.
	close(release)
	<-parkedDone
	if got := parkedRec.Body.String(); got != "initial" {
		t.Fatalf("parked (pre-swap) request body = %q, want %q", got, "initial")
	}
}

// TestSwappableHandlerSwapDoesNotDropInFlightRequests verifies the
// zero-downtime guarantee: every request that entered ServeHTTP before Swap
// was called completes through the original handler tree. Requests that enter
// after Swap see the replacement.
//
// The implementation loads the current handler pointer once at the top of
// ServeHTTP (atomic.Pointer[http.Handler] load). Swap stores a new pointer
// for subsequent loads. Any request already past that load cannot see the new
// pointer, so its full lifecycle is isolated to the original handler.
//
// Test mechanics:
//  1. Handler A blocks on a "gate" channel, then writes "A" to the response.
//  2. N goroutines call ServeHTTP and park inside A.
//  3. Once all N goroutines are inside the handler, Swap installs handler B.
//  4. A fresh request is served to confirm it lands on B.
//  5. The gate is opened; all N parked requests complete.
//  6. We assert every response body is "A" — none were switched mid-flight.
func TestSwappableHandlerSwapDoesNotDropInFlightRequests(t *testing.T) {
	const numInFlight = 8

	gate := make(chan struct{})
	entered := make(chan struct{}, numInFlight)

	handlerA := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{} // signal: inside A, past the pointer load
		<-gate                // block until released
		_, _ = fmt.Fprint(w, "A")
	})
	handlerB := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "B")
	})

	s := NewSwappableHandler(handlerA)

	// Launch all in-flight requests.
	type result struct{ body string }
	results := make(chan result, numInFlight)
	for i := 0; i < numInFlight; i++ {
		go func() {
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			results <- result{body: rec.Body.String()}
		}()
	}

	// Wait until every goroutine is inside handler A (past the pointer load).
	for i := 0; i < numInFlight; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for all goroutines to enter handler A")
		}
	}

	// Swap to B while all N requests are parked inside A.
	s.Swap(handlerB)

	// A brand-new request must reach B immediately.
	freshRec := httptest.NewRecorder()
	s.ServeHTTP(freshRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := freshRec.Body.String(); got != "B" {
		t.Fatalf("post-swap fresh request body = %q, want %q", got, "B")
	}

	// Release all parked requests.
	close(gate)

	// Collect results — every in-flight request must have finished on A.
	for i := 0; i < numInFlight; i++ {
		select {
		case r := <-results:
			if r.body != "A" {
				t.Errorf("in-flight request %d: body = %q, want %q (was dropped to handler B mid-flight)", i, r.body, "A")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for in-flight result %d", i)
		}
	}
}

func TestSwappableHandlerSwapConcurrentWithRequests(t *testing.T) {
	// Race-detector exerciser: hammer ServeHTTP from many goroutines while
	// another goroutine flips between two handlers. The test does not
	// assert routing semantics here — go test -race is what does the work.
	var counter atomic.Int64
	makeH := func(tag int64) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			counter.Add(tag)
			w.WriteHeader(http.StatusOK)
		})
	}

	s := NewSwappableHandler(makeH(1))

	var wg sync.WaitGroup
	const callers = 16
	const calls = 200
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < calls; j++ {
				rec := httptest.NewRecorder()
				s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			s.Swap(makeH(int64(i % 3)))
		}
	}()

	wg.Wait()

	// Sanity: every call hit some handler.
	if counter.Load() < 0 {
		t.Fatalf("counter went negative: %d", counter.Load())
	}
}

func TestNewSwappableHandlerPanicsOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil handler")
		}
	}()
	_ = NewSwappableHandler(nil)
}

func TestSwapPanicsOnNil(t *testing.T) {
	s := NewSwappableHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil swap target")
		}
	}()
	s.Swap(nil)
}

func TestSwappableHandlerCurrentReturnsLatest(t *testing.T) {
	initial := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	replacement := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	s := NewSwappableHandler(initial)

	if got := s.Current(); fmt.Sprintf("%p", got) != fmt.Sprintf("%p", initial) {
		t.Fatalf("Current() = %p, want %p", got, initial)
	}
	s.Swap(replacement)
	if got := s.Current(); fmt.Sprintf("%p", got) != fmt.Sprintf("%p", replacement) {
		t.Fatalf("Current() after Swap = %p, want %p", got, replacement)
	}
}
