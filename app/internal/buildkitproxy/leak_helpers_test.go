package buildkitproxy

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// goroutineLeakCheck captures the live goroutine count at call time and
// returns a check function that fails t unless the count has settled back to
// at or below that baseline within a bounded retry window. Stdlib-only
// (runtime.NumGoroutine) — this repo's testing conventions
// (CLAUDE.md: "No external test dependencies — stdlib only") rule out a
// dedicated leak-detection library like uber-go/goleak.
//
// Callers must register the returned func via t.Cleanup BEFORE constructing
// whatever they're checking for leaks (see this file's usage in
// bridge_leak_test.go): t.Cleanup runs its callbacks in LIFO order, so a
// leak-check cleanup registered first runs LAST — after every other
// t.Cleanup a helper like newTestBridge registers for its own teardown has
// already run and (in the non-leaking case) already let torn-down
// goroutines exit.
func goroutineLeakCheck(t *testing.T) func() {
	t.Helper()
	runtime.GC()
	before := runtime.NumGoroutine()
	return func() {
		t.Helper()
		const (
			settleAttempts = 100
			settleInterval = 20 * time.Millisecond
		)
		var after int
		for i := 0; i < settleAttempts; i++ {
			runtime.GC()
			after = runtime.NumGoroutine()
			if after <= before {
				return
			}
			time.Sleep(settleInterval)
		}
		t.Errorf("goroutine leak: started with %d live goroutines, still at %d after %v of settling", before, after, time.Duration(settleAttempts)*settleInterval)
	}
}

// runBridgeAndWaitClosed builds one bridged tunnel entirely in-process — the
// same net.Pipe-based wiring newTestBridge uses (bridge_test.go) — drives it
// via drive, then tears it down and blocks until BOTH runBridge and the
// daemon handler's own ServeConn goroutine have actually returned, before
// returning itself.
//
// This exists alongside newTestBridge specifically for the leak/DoS tests in
// this file's siblings: newTestBridge defers its teardown-and-wait to
// t.Cleanup, so a test driving many bridge lifecycles in a loop would leave
// every prior iteration's teardown pending until the whole test function
// returns — fine for ordinary correctness tests, but it defeats a
// per-iteration goroutine-count assertion, which needs each lifecycle fully
// wound down before the next one starts.
func runBridgeAndWaitClosed(t *testing.T, endpoint Endpoint, policy Policy, limits Limits, daemonHandler http.Handler, drive func(driver *http2.ClientConn)) {
	t.Helper()

	serverLeg, driverConn := net.Pipe()
	daemonSide, clientLegForBridge := net.Pipe()

	daemonDone := make(chan struct{})
	go func() {
		defer close(daemonDone)
		(&http2.Server{}).ServeConn(daemonSide, &http2.ServeConnOpts{Handler: daemonHandler})
	}()

	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "leak-test-client", Profile: "leak-test-profile"}, endpoint, "")
	legs := bridgeLegs{endpoint: endpoint, serverConn: serverLeg, clientConn: clientLegForBridge}

	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		_ = runBridge(context.Background(), legs, session, policy, limits, noopLogger(), registry, nil)
	}()

	tr := &http2.Transport{AllowHTTP: true}
	driver, err := tr.NewClientConn(driverConn)
	if err != nil {
		t.Fatalf("NewClientConn (driver): %v", err)
	}

	if drive != nil {
		drive(driver)
	}

	_ = driver.Close()
	_ = driverConn.Close()

	select {
	case <-bridgeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("runBridge did not return within 5s of the driver connection closing")
	}

	_ = daemonSide.Close()
	select {
	case <-daemonDone:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon handler's ServeConn did not return within 5s of teardown")
	}
}
