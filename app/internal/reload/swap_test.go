package reload

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
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
