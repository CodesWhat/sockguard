package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

// TestHealthHandlerProbeInProgressDoesNotLogWriteFailureOnSuccess drives the
// !known ("upstream check in progress") branch of the /health handler and
// pins its `writeErr != nil` guard: httptest.ResponseRecorder never fails a
// write, so the "failed to write unhealthy response" warn must not fire.
//
// !known is reached only when a probe is already in flight (refreshNow is
// not the leader) and no verdict has ever landed (cached.present is false).
// A stalled dial on the first-ever request gives exactly that: the leader
// request blocks inside the dial, and a second concurrent request finds
// nothing cached and cannot become leader either.
func TestHealthHandlerProbeInProgressDoesNotLogWriteFailureOnSuccess(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	dialEntered := make(chan struct{})
	collector := &testhelp.CollectingHandler{}

	checker := newUpstreamHealthChecker(
		2*time.Second,
		30*time.Second,
		time.Now,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialEntered)
			select {
			case <-release:
				return noopConn{}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), collector.Logger(), checker)
	handler := monitor.Handler()

	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	}()

	select {
	case <-dialEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("leader request never reached the dial")
	}

	// The leader's probe is stalled and no verdict has ever landed, so this
	// request must hit the !known branch: stateForRequest reports known =
	// false and the handler answers "upstream check in progress" directly,
	// without waiting.
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	var body HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if rec.Code != http.StatusServiceUnavailable || body.Upstream != upstreamStatusChecking {
		t.Fatalf("in-progress request = %d/%q, want %d/%q (must reach the !known branch to exercise it)", rec.Code, body.Upstream, http.StatusServiceUnavailable, upstreamStatusChecking)
	}

	close(release)
	<-leaderDone

	// httptest.ResponseRecorder.Write never fails, so the write inside the
	// !known branch always succeeds; the write-failure warn must not fire.
	if warns := collector.FindMessage("failed to write unhealthy response"); len(warns) != 0 {
		t.Fatalf("write-failure warnings = %d, want 0 (the write succeeded); records: %#v", len(warns), collector.Records())
	}
}
