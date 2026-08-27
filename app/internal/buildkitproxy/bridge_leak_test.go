package buildkitproxy

import (
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestBridgeSetupTeardownDoesNotLeakGoroutines drives many full bridge
// lifecycles (setup, one admitted round trip, client-initiated teardown) in
// a row and asserts the process's live goroutine count settles back to its
// pre-test baseline once the last one completes — sockguard's own runBridge,
// http2.Server.ServeConn, and the daemon-leg http2.Server this test spins up
// must all actually exit rather than leaking a per-tunnel goroutine on the
// ordinary, non-error teardown path.
func TestBridgeSetupTeardownDoesNotLeakGoroutines(t *testing.T) {
	check := goroutineLeakCheck(t)
	t.Cleanup(check)

	const iterations = 25
	for i := 0; i < iterations; i++ {
		runBridgeAndWaitClosed(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler(), func(driver *http2.ClientConn) {
			resp, err := driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", "payload"))
			if err != nil {
				t.Fatalf("iteration %d: RoundTrip: %v", i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		})
	}
}

// TestBridgeDeniedStreamBudgetTeardownDoesNotLeakGoroutines is
// TestBridgeSetupTeardownDoesNotLeakGoroutines' sibling for the OTHER
// teardown path: closeAll invoked internally by
// recordDeniedAndMaybeClose once the denied-stream abuse budget trips,
// rather than the client closing its own connection. Both paths route
// through the same closeOnce-guarded closeAll (bridge.go), but only a
// dedicated test proves the abuse-triggered path unwinds every goroutine
// too.
func TestBridgeDeniedStreamBudgetTeardownDoesNotLeakGoroutines(t *testing.T) {
	check := goroutineLeakCheck(t)
	t.Cleanup(check)

	limits := DefaultLimits()
	limits.DeniedStreamBudget = 1
	limits.DeniedStreamWindow = time.Minute

	const iterations = 15
	for i := 0; i < iterations; i++ {
		runBridgeAndWaitClosed(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler(), func(driver *http2.ClientConn) {
			for range 3 {
				resp, err := driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Prune", ""))
				if err != nil {
					// The connection may already be torn down by the abuse
					// budget by the time this RoundTrip is attempted —
					// acceptable, since that's exactly the behavior under test.
					break
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		})
	}
}

// TestBridgeIdleTimeoutTeardownDoesNotLeakGoroutines is the third teardown
// path: Limits.IdleTimeout closing a tunnel with no stream activity at all,
// entirely from inside golang.org/x/net/http2.Server's own idle-connection
// machinery, with no client-initiated close and no denied stream ever sent.
func TestBridgeIdleTimeoutTeardownDoesNotLeakGoroutines(t *testing.T) {
	check := goroutineLeakCheck(t)
	t.Cleanup(check)

	limits := DefaultLimits()
	limits.IdleTimeout = 30 * time.Millisecond

	const iterations = 10
	for i := 0; i < iterations; i++ {
		runBridgeAndWaitClosed(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler(), func(_ *http2.ClientConn) {
			// Hold the connection idle past Limits.IdleTimeout so
			// http2.Server's own idle machinery closes the tunnel,
			// rather than the helper's client-initiated close winning
			// the race — otherwise this measures the same teardown path
			// TestBridgeSetupTeardownDoesNotLeakGoroutines already covers.
			time.Sleep(4 * limits.IdleTimeout)
		})
	}
}

// TestBridgeRapidDeniedStreamChurnTerminatesTunnelWithoutLeak fires a burst
// of concurrent Deny-classified requests at once (rather than
// TestBridgeDeniedStreamBudgetTerminatesTunnel's sequential loop in
// bridge_test.go) — closer to the actual shape of a Rapid-Reset-style
// abusive client hammering many streams simultaneously — and asserts both
// that the denied-stream budget still tears the tunnel down and that doing
// so under concurrent load doesn't leak goroutines.
func TestBridgeRapidDeniedStreamChurnTerminatesTunnelWithoutLeak(t *testing.T) {
	check := goroutineLeakCheck(t)
	t.Cleanup(check)

	limits := DefaultLimits()
	limits.DeniedStreamBudget = 5
	limits.DeniedStreamWindow = time.Minute

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler())

	const churn = 50
	var workers sync.WaitGroup
	workers.Add(churn)
	for i := 0; i < churn; i++ {
		go func() {
			defer workers.Done()
			resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Prune", ""))
			if err != nil {
				return // tunnel may already be torn down under this churn — expected
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	select {
	case <-tb.done:
		if tb.err == nil {
			t.Fatal("runBridge returned nil error after rapid denied-stream churn exceeded the budget, want a non-nil teardown error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runBridge did not terminate the tunnel after rapid denied-stream churn exceeded the budget")
	}

	select {
	case <-workersDone:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent RoundTrip calls remained blocked after the denied-stream budget terminated the tunnel")
	}
}
