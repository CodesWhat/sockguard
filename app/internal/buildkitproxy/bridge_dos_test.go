package buildkitproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
)

// newConcurrencyTestBridge is newTestBridge's (bridge_test.go) sibling for
// this file's concurrency-cap tests specifically: it drives the bridge with
// an http2.Transport configured with StrictMaxConcurrentStreams: true, so a
// RoundTrip issued once the server's advertised
// SETTINGS_MAX_CONCURRENT_STREAMS is saturated BLOCKS and waits for a slot —
// matching how a well-behaved gRPC/BuildKit client actually behaves — rather
// than failing immediately with "http2: client conn not usable", which is
// what golang.org/x/net/http2.ClientConn.RoundTrip does by default once a
// single ClientConn (not the full pooling Transport) hits the cap. This
// package's other tests never intentionally saturate the cap, so
// newTestBridge itself is left using the simpler, non-strict Transport.
func newConcurrencyTestBridge(t *testing.T, limits Limits, daemonHandler http.Handler) *http2.ClientConn {
	t.Helper()

	serverLeg, driverConn := net.Pipe()
	daemonSide, clientLegForBridge := net.Pipe()

	go (&http2.Server{}).ServeConn(daemonSide, &http2.ServeConnOpts{Handler: daemonHandler})

	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "dos-test-client", Profile: "dos-test-profile"}, EndpointGRPC, "")
	legs := bridgeLegs{endpoint: EndpointGRPC, serverConn: serverLeg, clientConn: clientLegForBridge}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runBridge(context.Background(), legs, session, allowAllPolicy, limits, noopLogger(), registry)
	}()

	tr := &http2.Transport{AllowHTTP: true, StrictMaxConcurrentStreams: true}
	driver, err := tr.NewClientConn(driverConn)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}

	// Warm-up round trip: StrictMaxConcurrentStreams only blocks a RoundTrip
	// once the client has actually LEARNED the server's real
	// SETTINGS_MAX_CONCURRENT_STREAMS — until that SETTINGS frame is
	// processed, http2.ClientConn optimistically assumes a large default and
	// will happily send more streams than the server actually allows, which
	// the SERVER then answers with REFUSED_STREAM (a real, spec-correct
	// safely-retryable HTTP/2 outcome — but this test drives a single
	// low-level ClientConn directly, with none of Transport's automatic
	// retry-on-a-new-connection logic, so it would otherwise surface as a
	// bare RoundTrip error). One synchronous round trip against a method the
	// bridge answers WITHOUT ever touching daemonHandler (a Deny-classified
	// method) forces that SETTINGS exchange to complete before this helper
	// returns, so the caller's own concurrency-cap assertions start from a
	// connection that already knows the real limit.
	warmupResp, err := driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Prune", ""))
	if err != nil {
		t.Fatalf("warm-up RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, warmupResp.Body)
	_ = warmupResp.Body.Close()

	t.Cleanup(func() {
		_ = driver.Close()
		_ = driverConn.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("runBridge did not return within 2s of the driver connection closing")
		}
	})

	return driver
}

// TestBridgeMaxConcurrentStreamsEnforced holds a fixed number of streams
// open at once (the daemon handler blocks on each until the test explicitly
// lets it finish) while a larger number of concurrent RoundTrips are
// attempted, and asserts the daemon never observes more requests in flight
// simultaneously than Limits.MaxConcurrentStreams — the http2.Server this
// package configures with that field (bridge.go's runBridge) is
// responsible for enforcing the ceiling; this proves it's actually wired
// through, not just carried in the struct.
func TestBridgeMaxConcurrentStreamsEnforced(t *testing.T) {
	const maxStreams = 2

	var inFlight, maxObserved int32
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			old := atomic.LoadInt32(&maxObserved)
			if n <= old || atomic.CompareAndSwapInt32(&maxObserved, old, n) {
				break
			}
		}
		// A short, deliberate hold so concurrently-issued RoundTrips have a
		// real window to overlap at the daemon — without this every request
		// could complete before the next is even dispatched, and the max
		// concurrency actually reached would trivially be 1 regardless of
		// whether the cap does anything.
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		w.WriteHeader(http.StatusOK)
	})

	limits := DefaultLimits()
	limits.MaxConcurrentStreams = maxStreams

	driver := newConcurrencyTestBridge(t, limits, daemon)

	const attempted = maxStreams + 4
	var wg sync.WaitGroup
	errs := make(chan error, attempted)
	for i := 0; i < attempted; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", ""))
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("unexpected RoundTrip error while under the concurrency cap: %v", err)
	}
	if got := atomic.LoadInt32(&maxObserved); got > maxStreams {
		t.Fatalf("daemon observed %d concurrent requests in flight, want <= %d (Limits.MaxConcurrentStreams)", got, maxStreams)
	}
}

// TestBridgeControlMediatedSolveSizeCapBoundary is the live-bridge boundary
// test for readUnaryGRPCMessage's size cap on Control/Solve's mediated path
// (forwardControlMediated), at the two values that matter: a payload of
// EXACTLY Limits.MaxMessageBytes (must be admitted — the cap's contract is
// "exceeds", not "reaches", matching limitedReadCloser's own documented
// off-by-one fix) and one byte OVER it (must trip RESOURCE_EXHAUSTED,
// stream-local, without tearing down the tunnel).
func TestBridgeControlMediatedSolveSizeCapBoundary(t *testing.T) {
	payload := mustMarshal(t, &control.SolveRequest{Ref: "boundary-ref", Session: testBuildkitSessionID})

	t.Run("payload exactly at the cap is admitted", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxMessageBytes = int64(len(payload))
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler())

		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", string(grpcFrame(payload))))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			code, msg := grpcStatusOf(t, resp)
			t.Fatalf("status = %d (Grpc-Status %d %q), want 200 — a payload exactly at the cap must be admitted", resp.StatusCode, code, msg)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	})

	t.Run("payload one byte over the cap trips RESOURCE_EXHAUSTED without tearing down the tunnel", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxMessageBytes = int64(len(payload)) - 1
		tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler())

		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", string(grpcFrame(payload))))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeResourceExhausted {
			t.Fatalf("Grpc-Status = %d, want %d (RESOURCE_EXHAUSTED)", code, grpcCodeResourceExhausted)
		}

		// Fail-closed granularity per bridge.go's own doc comment: a
		// size-cap trip ends only this stream — the tunnel itself must
		// survive and admit a subsequent, properly-sized request.
		resp2, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", ""))
		if err != nil {
			t.Fatalf("RoundTrip after size-cap trip: %v", err)
		}
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("status after size-cap trip = %d, want 200 (tunnel must survive a stream-local size-cap denial)", resp2.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp2.Body)
		_ = resp2.Body.Close()
	})
}

// TestBridgeIdleTimeoutClosesTunnel asserts Limits.IdleTimeout — passed
// straight through to http2.Server (bridge.go's runBridge) — actually
// closes a bridged tunnel that never carries any stream activity, rather
// than just being a struct field nothing consults.
func TestBridgeIdleTimeoutClosesTunnel(t *testing.T) {
	limits := DefaultLimits()
	limits.IdleTimeout = 30 * time.Millisecond

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler())

	select {
	case <-tb.done:
		// runBridge returned on its own — the idle timeout fired. Whether
		// finalErr is nil or non-nil isn't asserted: an idle timeout is a
		// graceful, expected closure from http2.Server's own perspective,
		// not the "protocol/transport failure" runBridge's doc comment
		// reserves a non-nil return for.
	case <-time.After(2 * time.Second):
		t.Fatal("runBridge did not terminate an idle tunnel within Limits.IdleTimeout plus a generous margin")
	}
}

// TestBridgeStreamsHeldAtConcurrencyCapDoNotDeadlockFurtherRequests holds
// EXACTLY MaxConcurrentStreams streams open indefinitely (until the test
// releases them) and confirms one further request, issued while the cap is
// fully saturated, still eventually completes once a slot frees up — proving
// the cap creates backpressure (a queued request waits for room) rather than
// a hang, a crash, or an incorrectly-doubled ceiling.
func TestBridgeStreamsHeldAtConcurrencyCapDoNotDeadlockFurtherRequests(t *testing.T) {
	const maxStreams = 3

	release := make(chan struct{})
	// arrivedAll closes once maxStreams requests have reached the daemon —
	// NOT a sync.WaitGroup counting down to zero, because the "extra"
	// request issued below eventually reaches this same handler too (once a
	// slot frees up), and a WaitGroup would panic on the resulting extra
	// Done() call past zero.
	var arrivedCount atomic.Int32
	arrivedAll := make(chan struct{})
	var closeArrivedOnce sync.Once
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if arrivedCount.Add(1) == int32(maxStreams) {
			closeArrivedOnce.Do(func() { close(arrivedAll) })
		}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	limits := DefaultLimits()
	limits.MaxConcurrentStreams = maxStreams

	driver := newConcurrencyTestBridge(t, limits, daemon)

	holderDone := make(chan struct{}, maxStreams)
	for i := 0; i < maxStreams; i++ {
		go func() {
			resp, err := driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", ""))
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			holderDone <- struct{}{}
		}()
	}

	// Wait for all maxStreams holder requests to actually reach the daemon
	// (i.e. be admitted) before issuing the one-more-than-the-cap request
	// below, so this test genuinely exercises "at the cap", not "before it".
	select {
	case <-arrivedAll:
	case <-time.After(2 * time.Second):
		t.Fatal("the holder requests never all reached the daemon — cannot exercise the saturated-cap case")
	}

	extraDone := make(chan error, 1)
	go func() {
		resp, err := driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", ""))
		if err != nil {
			extraDone <- err
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		extraDone <- nil
	}()

	// The extra request must NOT complete yet — every stream slot is held.
	select {
	case err := <-extraDone:
		t.Fatalf("the request issued while the cap was fully saturated completed too early (err=%v) — it should have been queued until a slot freed", err)
	case <-time.After(100 * time.Millisecond):
		// expected: still queued
	}

	close(release)
	for i := 0; i < maxStreams; i++ {
		<-holderDone
	}

	select {
	case err := <-extraDone:
		if err != nil {
			t.Fatalf("the queued request failed after a slot freed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request queued behind the saturated cap never completed after a slot freed — possible deadlock")
	}
}
