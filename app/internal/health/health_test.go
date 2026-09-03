package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/testhelp"
	"github.com/codeswhat/sockguard/app/internal/version"
)

type devNull struct{}

func (devNull) Write(b []byte) (int, error) { return len(b), nil }

type noopConn struct{}

func (noopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (noopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (noopConn) Close() error                     { return nil }
func (noopConn) LocalAddr() net.Addr              { return &net.UnixAddr{Name: "local", Net: "unix"} }
func (noopConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "remote", Net: "unix"} }
func (noopConn) SetDeadline(time.Time) error      { return nil }
func (noopConn) SetReadDeadline(time.Time) error  { return nil }
func (noopConn) SetWriteDeadline(time.Time) error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type headerCallTrackingWriter struct {
	*httptest.ResponseRecorder
	headerCalls int
}

func (w *headerCallTrackingWriter) Header() http.Header {
	w.headerCalls++
	return w.ResponseRecorder.Header()
}

func TestHealthReachable(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	startTime := time.Now().Add(-90 * time.Second)
	handler := Handler(sock, startTime, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.Status != "healthy" {
		t.Errorf("expected status healthy, got %v", body.Status)
	}
	if body.Upstream != "connected" {
		t.Errorf("expected upstream connected, got %v", body.Upstream)
	}
	if body.Error != "" {
		t.Errorf("expected empty error for healthy response, got %q", body.Error)
	}
	if body.Version != version.Version {
		t.Errorf("expected version %q, got %q", version.Version, body.Version)
	}
	if body.UptimeSeconds < 90 {
		t.Errorf("expected uptime >= 90, got %d", body.UptimeSeconds)
	}
}

func TestHealthHandlerSetsContentTypeOnce(t *testing.T) {
	t.Parallel()
	handler := Handler("/nonexistent/socket.sock", time.Now(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := &headerCallTrackingWriter{ResponseRecorder: httptest.NewRecorder()}

	handler.ServeHTTP(rec, req)

	if rec.headerCalls != 1 {
		t.Fatalf("Header() calls = %d, want 1", rec.headerCalls)
	}
	if got := rec.Result().Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}

func TestHealthCheckerTimesOutWithBlockingDial(t *testing.T) {
	t.Parallel()
	checker := newUpstreamHealthChecker(
		0,
		10*time.Millisecond,
		time.Now,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)

	start := time.Now()
	status, err := checker.check(context.Background(), "/tmp/upstream.sock")

	if status != "unreachable" {
		t.Fatalf("status = %q, want unreachable", status)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("timeout check took %v, want under 250ms", elapsed)
	}
}

func TestHealthUnreachable(t *testing.T) {
	t.Parallel()
	startTime := time.Now().Add(-45 * time.Second)
	handler := Handler("/nonexistent/socket.sock", startTime, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}

	var body HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.Status != "unhealthy" {
		t.Errorf("expected status unhealthy, got %v", body.Status)
	}
	if body.Upstream != "unreachable" {
		t.Errorf("expected upstream unreachable, got %v", body.Upstream)
	}
	if body.Error != "upstream unreachable" {
		t.Errorf("expected generic error message, got %q", body.Error)
	}
	if body.Version != version.Version {
		t.Errorf("expected version %q, got %q", version.Version, body.Version)
	}
	if body.UptimeSeconds < 45 {
		t.Errorf("expected uptime >= 45, got %d", body.UptimeSeconds)
	}
	if strings.Contains(rec.Body.String(), "/nonexistent/socket.sock") {
		t.Fatalf("response leaked upstream socket path: %q", rec.Body.String())
	}
}

func TestHealthCachesUpstreamStatusWithinTTL(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return noopConn{}, nil
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("first check = (%q, %v), want connected with nil error", status, err)
	}

	nowOffset.Store(int64(1500 * time.Millisecond))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("cached check = (%q, %v), want connected with nil error", status, err)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls within TTL = %d, want 1", dialCalls.Load())
	}

	nowOffset.Store(int64(2500 * time.Millisecond))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("post-TTL check = (%q, %v), want connected with nil error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after TTL = %d, want 2", dialCalls.Load())
	}
}

func TestHealthCacheExpiresPreciselyAtTTLBoundary(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return noopConn{}, nil
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("first check = (%q, %v), want connected with nil error", status, err)
	}

	// Exactly at the TTL boundary: now.Sub(cachedAt) == cacheTTL. The cache
	// window is a strict "<", so this must already count as expired and
	// trigger a fresh dial; a mutant turning "<" into "<=" would treat the
	// entry as still fresh and skip the dial.
	nowOffset.Store(int64(2 * time.Second))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("boundary check = (%q, %v), want connected with nil error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls exactly at TTL boundary = %d, want 2 (cache must expire at the boundary)", dialCalls.Load())
	}
}

func TestHealthCheckerZeroTTLNeverCachesEvenWithBackwardClockDrift(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		0, // ttl == 0: the cache branch must be a no-op regardless of clock drift
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return noopConn{}, nil
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("first check = (%q, %v), want connected with nil error", status, err)
	}

	// Move the clock backward relative to cachedAt (an NTP-style correction).
	// With ttl == 0 the cache must never be consulted no matter the sign of
	// now.Sub(cachedAt); only a mutant turning "cacheTTL > 0" into ">= 0"
	// lets a negative diff satisfy "diff < cacheTTL" and serve a stale value.
	nowOffset.Store(int64(-100 * time.Millisecond))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("second check = (%q, %v), want connected with nil error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls with ttl=0 despite backward clock drift = %d, want 2 (cache must never be used when ttl==0)", dialCalls.Load())
	}
}

func TestHealthCheckerFailureTTLZeroNeverCachesFailure(t *testing.T) {
	t.Parallel()
	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("upstream down")
		},
	)
	checker.failureTTL = 0

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("check = (%q, %v), want unreachable with error", status, err)
	}

	// With failureTTL == 0 the failure branch must never populate the cache,
	// even though the caller's context was neither canceled nor past its
	// deadline. A mutant turning "failureTTL > 0" into ">= 0" would cache
	// the failure here instead of falling through to the reset branch.
	checker.mu.Lock()
	cacheReady := checker.cacheReady
	cachedErr := checker.cachedErr
	checker.mu.Unlock()
	if cacheReady || cachedErr != nil {
		t.Fatalf("checker state after zero-failureTTL failure = (cacheReady=%v, cachedErr=%v), want (false, nil)", cacheReady, cachedErr)
	}
}

func TestHealthDoesNotCacheUnhealthyStatusWithinTTL(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("upstream down")
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("first check = (%q, %v), want unreachable with error", status, err)
	}

	nowOffset.Store(int64(1500 * time.Millisecond))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("second check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls within TTL after unhealthy result = %d, want 2", dialCalls.Load())
	}
}

func TestHealthBrieflyCachesUnhealthyStatusForLateCallers(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("upstream down")
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("first check = (%q, %v), want unreachable with error", status, err)
	}

	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("immediate follow-up check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls for immediate follow-up = %d, want 1", dialCalls.Load())
	}

	nowOffset.Store(int64(time.Second))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("later check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after brief failure cache window = %d, want 2", dialCalls.Load())
	}
}

func TestHealthDoesNotCacheCallerCancelledFailure(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time { return baseNow },
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialCalls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	status, err := checker.check(canceledCtx, "/tmp/upstream.sock")
	if status != "unreachable" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled check = (%q, %v), want unreachable with context canceled", status, err)
	}

	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("fresh check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after canceled failure = %d, want 2", dialCalls.Load())
	}
}

func TestHealthDoesNotCacheCallerDeadlineFailure(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		50*time.Millisecond,
		func() time.Time { return baseNow },
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialCalls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)

	// Caller deadline fires before dial returns. Caller gave up, not upstream,
	// so we must not cache this as a health verdict.
	deadlineCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	status, err := checker.check(deadlineCtx, "/tmp/upstream.sock")
	if status != "unreachable" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline check = (%q, %v), want unreachable with context deadline exceeded", status, err)
	}

	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("fresh check after deadline = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after deadline failure = %d, want 2 (no cache)", dialCalls.Load())
	}
}

func TestHealthCheckerCoalescesConcurrentCacheMisses(t *testing.T) {
	t.Parallel()
	const callers = 16

	releaseDial := make(chan struct{})
	startChecks := make(chan struct{})
	dialEntered := make(chan struct{}, callers)
	results := make(chan struct {
		status string
		err    error
	}, callers)

	var ready sync.WaitGroup
	ready.Add(callers)

	var wg sync.WaitGroup
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			dialEntered <- struct{}{}
			<-releaseDial
			return nil, errors.New("upstream down")
		},
	)
	// Keep the failure cache comfortably open so any straggler that enters
	// check() after the leader cleared inFlight still hits the cached error
	// instead of becoming a new leader. Covers scheduling jitter under -race.
	checker.failureTTL = 10 * time.Second

	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-startChecks
			status, err := checker.check(context.Background(), "/tmp/upstream.sock")
			results <- struct {
				status string
				err    error
			}{status: status, err: err}
		}()
	}

	ready.Wait()
	close(startChecks)

	select {
	case <-dialEntered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected at least one upstream dial")
	}

	close(releaseDial)
	wg.Wait()
	close(results)

	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls = %d, want 1", dialCalls.Load())
	}

	for result := range results {
		if result.status != "unreachable" || result.err == nil {
			t.Fatalf("check = (%q, %v), want unreachable with error", result.status, result.err)
		}
	}
}

func TestHealthCheckerWaitsForInFlightCheck(t *testing.T) {
	t.Parallel()
	releaseDial := make(chan struct{})
	dialEntered := make(chan struct{}, 2)
	waiterJoined := make(chan struct{}, 1)
	results := make(chan struct {
		status string
		err    error
	}, 2)
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		0,
		time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			dialEntered <- struct{}{}
			<-releaseDial
			return noopConn{}, nil
		},
	)
	checker.failureTTL = 0
	checker.onWaiterJoined = func() { waiterJoined <- struct{}{} }

	go func() {
		status, err := checker.check(context.Background(), "/tmp/upstream.sock")
		results <- struct {
			status string
			err    error
		}{status: status, err: err}
	}()

	select {
	case <-dialEntered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected leader health check to dial upstream")
	}

	go func() {
		status, err := checker.check(context.Background(), "/tmp/upstream.sock")
		results <- struct {
			status string
			err    error
		}{status: status, err: err}
	}()

	// Wait until the second goroutine has joined the in-flight call (no new
	// dial) before asserting the dial count — replaces a time.Sleep rendezvous.
	select {
	case <-waiterJoined:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected second check to join in-flight call")
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls while first check is in flight = %d, want 1", dialCalls.Load())
	}
	select {
	case <-dialEntered:
		t.Fatal("second health check started a duplicate upstream dial")
	default:
	}

	close(releaseDial)
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.status != "connected" || result.err != nil {
				t.Fatalf("check = (%q, %v), want connected with nil error", result.status, result.err)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatal("timed out waiting for health check result")
		}
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("final dial calls = %d, want 1", dialCalls.Load())
	}
}

func TestMonitorWatchdogReportsStateChanges(t *testing.T) {
	t.Parallel()
	var dialCalls atomic.Int32
	checker := newUpstreamHealthChecker(
		0,
		50*time.Millisecond,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			if dialCalls.Add(1) == 1 {
				return nil, errors.New("upstream down")
			}
			return noopConn{}, nil
		},
	)
	checker.failureTTL = 0
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), testLogger(), checker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	states := make(chan WatchdogState, 4)
	monitor.StartWatchdog(ctx, 5*time.Millisecond, func(state WatchdogState) {
		states <- state
	})

	first := readWatchdogState(t, states)
	second := readWatchdogState(t, states)

	if first.Up || first.Status != "unreachable" || first.Err == nil {
		t.Fatalf("first watchdog state = %#v, want unreachable with error", first)
	}
	if !second.Up || second.Status != "connected" || second.Err != nil {
		t.Fatalf("second watchdog state = %#v, want connected with nil error", second)
	}
}

func TestMonitorDefaultsNilLogger(t *testing.T) {
	t.Parallel()
	checker := newUpstreamHealthChecker(
		0,
		time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			return noopConn{}, nil
		},
	)

	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), nil, checker)

	if monitor.logger == nil {
		t.Fatal("logger is nil, want default logger")
	}
	state := monitor.check(context.Background())
	if !state.Up || state.Status != "connected" || state.Err != nil {
		t.Fatalf("state = %#v, want connected upstream", state)
	}
}

func TestNilMonitorStateAndStartWatchdogAreNoops(t *testing.T) {
	t.Parallel()
	var monitor *Monitor

	if state, ok := monitor.State(); ok || state != (WatchdogState{}) {
		t.Fatalf("nil monitor State() = (%#v, %v), want zero state and false", state, ok)
	}

	monitor.StartWatchdog(context.Background(), time.Millisecond, func(WatchdogState) {
		t.Fatal("nil monitor should not observe watchdog states")
	})
}

func TestMonitorStartWatchdogIgnoresNonPositiveInterval(t *testing.T) {
	t.Parallel()
	checker := newUpstreamHealthChecker(
		0,
		time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("watchdog should not dial with a non-positive interval")
			return nil, errors.New("unexpected dial")
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), testLogger(), checker)

	observed := make(chan WatchdogState, 1)
	monitor.StartWatchdog(context.Background(), 0, func(state WatchdogState) {
		observed <- state
	})

	select {
	case state := <-observed:
		t.Fatalf("unexpected watchdog state = %#v", state)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestMonitorEmitWatchdogCheckLogsUnhealthyChange(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	checkErr := errors.New("upstream down")
	checker := newUpstreamHealthChecker(
		0,
		time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			return nil, checkErr
		},
	)
	checker.failureTTL = 0
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), collector.Logger(), checker)
	monitor.storeState("connected", nil)

	observed := make(chan WatchdogState, 1)
	monitor.emitWatchdogCheck(context.Background(), func(state WatchdogState) {
		observed <- state
	})

	state := readWatchdogState(t, observed)
	if !state.Changed || state.Up || state.Status != "unreachable" || !errors.Is(state.Err, checkErr) {
		t.Fatalf("watchdog state = %#v, want changed unhealthy state", state)
	}

	// Assert on structured records: expect a WARN record with error attr == checkErr.Error().
	// The production code logs via slog.String("error", err.Error()), so the attr is a string.
	var foundWarn bool
	var gotErrAttr string
	for _, r := range collector.Records() {
		if r.Level == slog.LevelWarn {
			gotErrAttr, _ = r.Attrs["error"].(string)
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Fatalf("no WARN record logged; all records: %#v", collector.Records())
	}
	if gotErrAttr != checkErr.Error() {
		t.Fatalf("WARN record error attr = %q, want %q", gotErrAttr, checkErr.Error())
	}
}

func readWatchdogState(t *testing.T, states <-chan WatchdogState) WatchdogState {
	t.Helper()

	select {
	case state := <-states:
		return state
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for watchdog state")
		return WatchdogState{}
	}
}

type failingWriter struct {
	header http.Header
	status int
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestHealthHandlerHealthyEncodeFailure(t *testing.T) {
	t.Parallel()
	sock := fmt.Sprintf("/tmp/health-encode-%d.sock", os.Getpid())
	_ = os.Remove(sock)
	t.Cleanup(func() {
		_ = os.Remove(sock)
	})
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	handler := Handler(sock, time.Now(), testLogger())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	writer := &failingWriter{}

	handler.ServeHTTP(writer, req)

	if writer.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusOK)
	}
}

func TestHealthHandlerUnhealthyEncodeFailure(t *testing.T) {
	t.Parallel()
	handler := Handler("/nonexistent/socket.sock", time.Now(), testLogger())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	writer := &failingWriter{}

	handler.ServeHTTP(writer, req)

	if writer.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusServiceUnavailable)
	}
}

// healthMonitorWithLogger builds a Monitor with a pre-seeded watchdog state
// and listener snapshot, wired to logger, without dialing anything. It lets
// the three response branches in Handler (upstream-unhealthy,
// listener-not-serving, healthy) be exercised individually so an encode
// failure on each branch can be attributed to the right log call site.
func healthMonitorWithLogger(state WatchdogState, listeners []ListenerStatus, logger *slog.Logger) *Monitor {
	m := newMonitorWithChecker("docker", time.Now(), logger, newUpstreamHealthChecker(0, time.Second, time.Now, nil))
	m.mu.Lock()
	m.last = state
	m.hasState = true
	m.mu.Unlock()
	if listeners != nil {
		m.ListenersFunc = func() []ListenerStatus { return append([]ListenerStatus(nil), listeners...) }
	}
	return m
}

func TestHealthHandlerLogsEncodeFailureOnUnhealthyUpstreamPath(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	m := healthMonitorWithLogger(WatchdogState{Status: "unreachable", Err: errors.New("dial failed")}, nil, collector.Logger())
	writer := &failingWriter{}

	m.Handler()(writer, httptest.NewRequest(http.MethodGet, "/health", nil))

	if writer.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusServiceUnavailable)
	}
	// A mutant turning "encErr != nil" into "== nil" would log on the
	// (impossible here) success case instead of this write failure, so the
	// WARN record would never appear.
	if len(collector.FindMessage("failed to encode unhealthy response")) == 0 {
		t.Fatalf("expected a \"failed to encode unhealthy response\" WARN record when the write fails; got %#v", collector.Records())
	}
}

func TestHealthHandlerLogsEncodeFailureOnListenerNotServingPath(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	listeners := []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateFailed}}
	m := healthMonitorWithLogger(WatchdogState{Status: "connected", Up: true}, listeners, collector.Logger())
	writer := &failingWriter{}

	m.Handler()(writer, httptest.NewRequest(http.MethodGet, "/health", nil))

	if writer.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusServiceUnavailable)
	}
	// A mutant turning "encErr != nil" into "== nil" on this branch's write
	// check would suppress the WARN record on this write failure.
	if len(collector.FindMessage("failed to encode unhealthy response")) == 0 {
		t.Fatalf("expected a \"failed to encode unhealthy response\" WARN record when the write fails; got %#v", collector.Records())
	}
}

func TestHealthHandlerLogsEncodeFailureOnHealthyPath(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	listeners := []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateServing}}
	m := healthMonitorWithLogger(WatchdogState{Status: "connected", Up: true}, listeners, collector.Logger())
	writer := &failingWriter{}

	m.Handler()(writer, httptest.NewRequest(http.MethodGet, "/health", nil))

	if writer.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusOK)
	}
	// A mutant turning "encErr != nil" into "== nil" on the healthy branch
	// would suppress the WARN record on this write failure.
	if len(collector.FindMessage("failed to encode healthy response")) == 0 {
		t.Fatalf("expected a \"failed to encode healthy response\" WARN record when the write fails; got %#v", collector.Records())
	}
}
