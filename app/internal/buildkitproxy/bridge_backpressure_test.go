package buildkitproxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestBridgeBackpressureSlowClientReaderResponseCapStillEnforced covers the
// "fast-writing daemon, slow-reading client" direction of this package's
// #185 Phase 6 backpressure requirement: the daemon writes far more than
// Limits.MaxMessageBytes as fast as it can, while the test drains the
// response a few bytes at a time with a deliberate delay between reads —
// slower than the daemon can produce data. Two things must both hold
// regardless of that speed mismatch: the response size cap still trips
// (RESOURCE_EXHAUSTED), and the TOTAL bytes ever delivered to the slow
// reader never exceeds the cap by more than limitedReadCloser's documented
// one-byte sentinel margin — i.e. sockguard never buffers the daemon's
// full, oversized response internally waiting for the slow client to catch
// up. This is the "assert bounded memory via the existing caps rather than
// measuring heap precisely" the task calls for.
func TestBridgeBackpressureSlowClientReaderResponseCapStillEnforced(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxMessageBytes = 4096 // small, for a fast test

	const daemonChunks = 20
	const daemonChunkSize = 1024 // daemonChunks*daemonChunkSize = 20 KiB, far past the 4 KiB cap

	fastDaemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := bytes.Repeat([]byte("x"), daemonChunkSize)
		fl, _ := w.(http.Flusher)
		for i := 0; i < daemonChunks; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	})

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, fastDaemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/grpc.health.v1.Health/Check", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	var total int
	buf := make([]byte, 64)
	for {
		n, readErr := resp.Body.Read(buf)
		total += n
		if readErr != nil {
			break
		}
		// Deliberately slower than the daemon's own write loop above —
		// forces the daemon (and sockguard's relaying io.Copy) to backpressure
		// against this reader rather than racing ahead of it.
		time.Sleep(time.Millisecond)
	}
	_ = resp.Body.Close()

	if total > int(limits.MaxMessageBytes)+1 {
		t.Fatalf("slow reader received %d bytes through a %d-byte-capped response, want <= cap+1 — the cap must bound what's ever forwarded even under reader backpressure, not just what's eventually read", total, limits.MaxMessageBytes)
	}

	if got := resp.Trailer.Get("Grpc-Status"); got != strconv.Itoa(grpcCodeResourceExhausted) {
		t.Fatalf("Grpc-Status trailer = %q, want %d (RESOURCE_EXHAUSTED)", got, grpcCodeResourceExhausted)
	}
}

// TestBridgeBackpressureSlowDaemonReaderStillDeliversFullBody covers the
// "fast-writing client, slow-reading daemon" direction: the driver sends a
// body comfortably under Limits.MaxMessageBytes as fast as HTTP/2 flow
// control allows, while the daemon handler deliberately reads it in small,
// delayed chunks. The request must still complete correctly — full,
// unmodified byte count received — within a generous but bounded deadline,
// proving the relay path streams under backpressure instead of either
// deadlocking or requiring an unbounded buffer to route around a slow
// consumer.
//
// This intentionally stays UNDER the size cap rather than exercising a
// request-body cap trip against a slow daemon: see
// TestBridgeForwardRequestSizeCapTripsResourceExhaustedWithoutClosingTunnel's
// own doc comment (bridge_test.go) for why driving a genuinely oversized
// request body through a live RoundTrip races the client's in-flight body
// write against the server's response and is avoided elsewhere in this
// package's tests in favor of deterministic, isolated coverage — the same
// reasoning applies here, so the cap-boundary case is covered separately
// (TestBridgeControlMediatedSolveSizeCapBoundary, bridge_dos_test.go)
// without the added variable of a slow reader.
func TestBridgeBackpressureSlowDaemonReaderStillDeliversFullBody(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxMessageBytes = 1 << 20 // 1 MiB cap

	const bodySize = 256 * 1024 // comfortably under the cap
	body := bytes.Repeat([]byte("y"), bodySize)

	var gotTotal int64
	daemonDone := make(chan struct{})
	slowDaemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(daemonDone)
		buf := make([]byte, 512)
		for {
			n, err := r.Body.Read(buf)
			atomic.AddInt64(&gotTotal, int64(n))
			if err != nil {
				break
			}
			time.Sleep(200 * time.Microsecond) // deliberately slower than the client can produce data
		}
		w.WriteHeader(http.StatusOK)
	})

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, slowDaemon)

	roundTripDone := make(chan error, 1)
	go func() {
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/grpc.health.v1.Health/Check", string(body)))
		if err != nil {
			roundTripDone <- err
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		roundTripDone <- nil
	}()

	select {
	case err := <-roundTripDone:
		if err != nil {
			t.Fatalf("RoundTrip against a slow-reading daemon failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request against a slow-reading daemon did not complete within 10s — possible deadlock under backpressure")
	}

	select {
	case <-daemonDone:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon handler never finished reading the request body")
	}

	if got := atomic.LoadInt64(&gotTotal); got != int64(bodySize) {
		t.Fatalf("daemon received %d bytes, want the full %d-byte body — backpressure must never drop or truncate data", got, bodySize)
	}
}
