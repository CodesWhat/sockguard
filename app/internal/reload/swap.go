// Package reload implements sockguard's hot-reload pipeline.
//
// The pipeline has three pieces:
//
//   - SwappableHandler — an atomic.Pointer-backed http.Handler that lets the
//     server route every request through the current handler tree without
//     rebuilding the listener or breaking in-flight requests.
//   - ImmutableDiff — a structural comparison that rejects reloads whose
//     immutable surface (listener, upstream socket, log sinks, metrics,
//     health monitor, admin endpoint) changed at all. Those fields are
//     wired into goroutines and sockets that cannot be replaced without
//     a process restart.
//   - Reloader — a goroutine that watches the on-disk config file via
//     fsnotify, listens for SIGHUP, debounces rapid bursts, and invokes a
//     reload callback wired up by internal/cmd.
//
// The package owns the mechanism. internal/cmd owns the policy: which
// validators run, what gets rebuilt, and how reload outcomes are surfaced
// in metrics and logs.
package reload

import (
	"net/http"
	"sync/atomic"
)

// SwappableHandler is an http.Handler whose downstream handler can be
// replaced atomically. Every request loads the current pointer once at the
// start of ServeHTTP, so a swap that lands mid-request never affects an
// in-flight call — the request runs to completion through whichever chain
// was current at admission time.
//
// Use NewSwappableHandler to construct one with the initial handler; calling
// Swap with a new handler replaces it for subsequent requests.
type SwappableHandler struct {
	current atomic.Pointer[http.Handler]
}

// NewSwappableHandler returns a SwappableHandler that routes through h
// until Swap is called.
//
// h must be non-nil — a SwappableHandler with a nil current handler would
// panic on the first request, and that is a programmer error worth catching
// at construction time rather than at request time.
func NewSwappableHandler(h http.Handler) *SwappableHandler {
	if h == nil {
		panic("reload: NewSwappableHandler requires non-nil http.Handler")
	}
	s := &SwappableHandler{}
	s.current.Store(&h)
	return s
}

// Swap atomically replaces the downstream handler. Subsequent requests will
// be routed through h. In-flight requests already past ServeHTTP's pointer
// load continue on the previous handler tree until they return.
//
// Callers must guarantee h is non-nil; passing nil is a programmer error
// and will panic, matching NewSwappableHandler's invariant.
func (s *SwappableHandler) Swap(h http.Handler) {
	if h == nil {
		panic("reload: Swap requires non-nil http.Handler")
	}
	s.current.Store(&h)
}

// Current returns the handler the next request would route through. Mostly
// useful for tests; production code should not depend on the pointer
// identity because Swap can change it at any time.
func (s *SwappableHandler) Current() http.Handler {
	return *s.current.Load()
}

// ServeHTTP routes the request through the current downstream handler.
func (s *SwappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*s.current.Load()).ServeHTTP(w, r)
}
