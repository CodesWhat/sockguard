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
	if entry := checker.cached.Load(); entry != nil {
		t.Fatalf("checker cache after zero-failureTTL failure = (status=%q, err=%v), want no entry at all", entry.status, entry.err)
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

func TestHealthHandlerHealthyWriteFailure(t *testing.T) {
	t.Parallel()
	sock := fmt.Sprintf("/tmp/health-write-%d.sock", os.Getpid())
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

func TestHealthHandlerUnhealthyWriteFailure(t *testing.T) {
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
// listener-not-serving, healthy) be exercised individually so a write
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

func TestHealthHandlerLogsWriteFailureOnUnhealthyUpstreamPath(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	m := healthMonitorWithLogger(WatchdogState{Status: "unreachable", Err: errors.New("dial failed")}, nil, collector.Logger())
	writer := &failingWriter{}

	m.Handler()(writer, httptest.NewRequest(http.MethodGet, "/health", nil))

	if writer.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusServiceUnavailable)
	}
	// A mutant turning "writeErr != nil" into "== nil" would log on the
	// (impossible here) success case instead of this write failure, so the
	// WARN record would never appear.
	if len(collector.FindMessage("failed to write unhealthy response")) == 0 {
		t.Fatalf("expected a \"failed to write unhealthy response\" WARN record when the write fails; got %#v", collector.Records())
	}
}

func TestHealthHandlerLogsWriteFailureOnListenerNotServingPath(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	listeners := []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateFailed}}
	m := healthMonitorWithLogger(WatchdogState{Status: "connected", Up: true}, listeners, collector.Logger())
	writer := &failingWriter{}

	m.Handler()(writer, httptest.NewRequest(http.MethodGet, "/health", nil))

	if writer.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusServiceUnavailable)
	}
	// A mutant turning "writeErr != nil" into "== nil" on this branch's write
	// check would suppress the WARN record on this write failure.
	if len(collector.FindMessage("failed to write unhealthy response")) == 0 {
		t.Fatalf("expected a \"failed to write unhealthy response\" WARN record when the write fails; got %#v", collector.Records())
	}
}

func TestHealthHandlerLogsWriteFailureOnHealthyPath(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	listeners := []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateServing}}
	m := healthMonitorWithLogger(WatchdogState{Status: "connected", Up: true}, listeners, collector.Logger())
	writer := &failingWriter{}

	m.Handler()(writer, httptest.NewRequest(http.MethodGet, "/health", nil))

	if writer.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusOK)
	}
	// A mutant turning "writeErr != nil" into "== nil" on the healthy branch
	// would suppress the WARN record on this write failure.
	if len(collector.FindMessage("failed to write healthy response")) == 0 {
		t.Fatalf("expected a \"failed to write healthy response\" WARN record when the write fails; got %#v", collector.Records())
	}
}

// requestHealth issues one /health request and returns the recorder plus the
// decoded body, so a test can assert on the status and the verdict together.
func requestHealth(t *testing.T, handler http.HandlerFunc) (*httptest.ResponseRecorder, HealthResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /health body %q: %v", rec.Body.String(), err)
	}
	return rec, body
}

// TestHealthHandlerReprobesAfterCacheTTLWithoutWatchdog pins the default
// (watchdog-off) /health contract: the endpoint answers from a cached upstream
// probe, and the cache is healthCacheTTL wide rather than the process lifetime.
// The regression this closes had the handler publish its own probe as watchdog
// state, which pinned hasState true and made every later request short-circuit
// on the stored verdict, so an upstream that went away after the first request
// was never noticed.
func TestHealthHandlerReprobesAfterCacheTTLWithoutWatchdog(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32
	var upstreamDown atomic.Bool

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			if upstreamDown.Load() {
				return nil, errors.New("upstream down")
			}
			return noopConn{}, nil
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), testLogger(), checker)
	handler := monitor.Handler()

	rec, body := requestHealth(t, handler)
	if rec.Code != http.StatusOK || body.Upstream != "connected" {
		t.Fatalf("first request = %d/%q, want %d/connected", rec.Code, body.Upstream, http.StatusOK)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls after first request = %d, want 1", dialCalls.Load())
	}

	nowOffset.Store(int64(1500 * time.Millisecond))
	rec, body = requestHealth(t, handler)
	if rec.Code != http.StatusOK || body.Upstream != "connected" {
		t.Fatalf("within-TTL request = %d/%q, want %d/connected", rec.Code, body.Upstream, http.StatusOK)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls within TTL = %d, want 1 (the cached verdict must be reused)", dialCalls.Load())
	}

	// The upstream disappears and the TTL lapses: the next request runs the
	// replacement probe itself and reports the outage instead of replaying the
	// first verdict.
	upstreamDown.Store(true)
	nowOffset.Store(int64(2500 * time.Millisecond))
	rec, body = requestHealth(t, handler)
	if rec.Code != http.StatusServiceUnavailable || body.Status != "unhealthy" || body.Upstream != "unreachable" {
		t.Fatalf("post-TTL request = %d/%q/%q, want %d/unhealthy/unreachable (the TTL must expire and re-probe)", rec.Code, body.Status, body.Upstream, http.StatusServiceUnavailable)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after TTL = %d, want 2", dialCalls.Load())
	}
}

// TestHealthHandlerRecoversWhenUpstreamComesUpAfterTheProxy covers the boot
// order the frozen verdict deadlocked: the daemon is not up when the proxy
// starts, so the first probe fails, and nothing re-checked. /health has to flip
// to 200 on its own once the daemon appears. It also pins that the unreachable
// warning is logged once per probe rather than once per request served, since
// /health sits ahead of the rate limiter.
func TestHealthHandlerRecoversWhenUpstreamComesUpAfterTheProxy(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32
	var upstreamUp atomic.Bool
	collector := &testhelp.CollectingHandler{}

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			if !upstreamUp.Load() {
				return nil, errors.New("no such file or directory")
			}
			return noopConn{}, nil
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), collector.Logger(), checker)
	handler := monitor.Handler()

	rec, body := requestHealth(t, handler)
	if rec.Code != http.StatusServiceUnavailable || body.Upstream != "unreachable" {
		t.Fatalf("boot request = %d/%q, want %d/unreachable", rec.Code, body.Upstream, http.StatusServiceUnavailable)
	}

	// Inside the failure-cache window the same verdict answers without dialing.
	rec, _ = requestHealth(t, handler)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("within-failure-TTL request = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	// The daemon comes up. One failure-TTL window later the next request runs
	// the probe that notices it.
	upstreamUp.Store(true)
	nowOffset.Store(int64(150 * time.Millisecond))
	rec, body = requestHealth(t, handler)
	if rec.Code != http.StatusOK || body.Status != "healthy" || body.Upstream != "connected" {
		t.Fatalf("recovered request = %d/%q/%q, want %d/healthy/connected", rec.Code, body.Status, body.Upstream, http.StatusOK)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls = %d, want 2 (one per probe, not one per request)", dialCalls.Load())
	}
	// Three requests were served, two of them a failing verdict, but only the
	// one failed probe may have logged.
	if warns := collector.FindMessage("health check failed: upstream unreachable"); len(warns) != 1 {
		t.Fatalf("unreachable warnings = %d, want exactly 1 (once per probe, not once per request); records: %#v", len(warns), collector.Records())
	}
}

// TestHealthHandlerParksAtMostOneRequestOnAStalledProbe is the amplification
// guard. The endpoint is unauthenticated and sits ahead of the rate limiter, so
// a blackholed daemon must not turn request volume into blocked goroutines:
// exactly the one request running the probe waits for it, and everything else
// is answered immediately. The dial here stalls until the test releases it and
// the dial timeout is far longer than the deadline below, so an implementation
// that queues callers behind the probe fails this test rather than merely
// being slow.
func TestHealthHandlerParksAtMostOneRequestOnAStalledProbe(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		30*time.Second,
		time.Now,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialCalls.Add(1)
			select {
			case <-release:
				return noopConn{}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), testLogger(), checker)
	handler := monitor.Handler()

	const requests = 1000
	codes := make([]int, requests)
	upstreams := make([]string, requests)
	var completed atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
			var body HealthResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			codes[i] = rec.Code
			upstreams[i] = body.Upstream
			completed.Add(1)
		}()
	}
	close(start)

	// Everything but the one request running the probe must come back while
	// the dial is still stalled.
	deadline := time.Now().Add(5 * time.Second)
	for completed.Load() < requests-1 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d concurrent /health requests returned while the upstream dial was stalled, want %d", completed.Load(), requests, requests-1)
		}
		time.Sleep(time.Millisecond)
	}
	// And the probe's own request must still be outstanding: nothing can
	// finish it but the release below.
	time.Sleep(50 * time.Millisecond)
	if got := completed.Load(); got != requests-1 {
		t.Fatalf("completed requests while the dial was stalled = %d, want exactly %d (one must still be waiting on the probe)", got, requests-1)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls under a %d-request flood = %d, want 1", requests, dialCalls.Load())
	}

	close(release)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the request waiting on the probe never returned after the dial was released")
	}

	var served, waited int
	for i := range requests {
		switch {
		case codes[i] == http.StatusServiceUnavailable && upstreams[i] == upstreamStatusChecking:
			served++
		case codes[i] == http.StatusOK && upstreams[i] == "connected":
			waited++
		default:
			t.Fatalf("request %d = %d/%q, want %d/%q or %d/connected", i, codes[i], upstreams[i], http.StatusServiceUnavailable, upstreamStatusChecking, http.StatusOK)
		}
	}
	if waited != 1 || served != requests-1 {
		t.Fatalf("responses = %d probe-backed and %d immediate, want 1 and %d", waited, served, requests-1)
	}

	rec, body := requestHealth(t, handler)
	if rec.Code != http.StatusOK || body.Upstream != "connected" {
		t.Fatalf("post-release request = %d/%q, want %d/connected", rec.Code, body.Upstream, http.StatusOK)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls after the flood = %d, want 1 (the released probe's verdict must be reused)", dialCalls.Load())
	}
}

// TestHealthHandlerServesStaleVerdictWhileAProbeRuns pins the other half of the
// amplification guard: with a verdict already on hand, a request arriving while
// the replacement probe runs is answered from the cache instead of queueing,
// so only the probe's own request can ever be waiting.
func TestHealthHandlerServesStaleVerdictWhileAProbeRuns(t *testing.T) {
	t.Parallel()
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32
	dialEntered := make(chan struct{})
	release := make(chan struct{})

	checker := newUpstreamHealthChecker(
		2*time.Second,
		30*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			if dialCalls.Add(1) == 1 {
				return noopConn{}, nil
			}
			close(dialEntered)
			select {
			case <-release:
				return nil, errors.New("upstream down")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), testLogger(), checker)
	handler := monitor.Handler()

	if rec, _ := requestHealth(t, handler); rec.Code != http.StatusOK {
		t.Fatalf("first request = %d, want %d", rec.Code, http.StatusOK)
	}

	// The verdict lapses and one request goes off to replace it.
	nowOffset.Store(int64(2500 * time.Millisecond))
	refresher := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		refresher <- rec.Code
	}()
	select {
	case <-dialEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the stale verdict never triggered a replacement probe")
	}

	// A second request during that probe must be answered from the cache.
	rec, body := requestHealth(t, handler)
	if rec.Code != http.StatusOK || body.Upstream != "connected" {
		t.Fatalf("request during the probe = %d/%q, want the stale %d/connected", rec.Code, body.Upstream, http.StatusOK)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls = %d, want 2 (the second request must not start its own probe)", dialCalls.Load())
	}

	close(release)
	select {
	case code := <-refresher:
		if code != http.StatusServiceUnavailable {
			t.Fatalf("probe-backed request = %d, want %d", code, http.StatusServiceUnavailable)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe-backed request never returned")
	}
}

// TestHealthHandlerServesWatchdogStateWithoutProbing pins that once the
// watchdog owns the state, /health serves that snapshot and does not probe. The
// watchdog's configured interval is the poll rate an operator asked for, its
// once-per-edge transition logging is computed against the stored state, and
// the exported gauges are fed from the same callback — a request-driven probe
// would outpace the interval, race the edge, and let /health disagree with the
// metrics.
func TestHealthHandlerServesWatchdogStateWithoutProbing(t *testing.T) {
	t.Parallel()
	var dialCalls atomic.Int32
	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("upstream down")
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), testLogger(), checker)
	monitor.onRefreshDone = func() { t.Error("watchdog state must not trigger a request-driven probe") }
	monitor.storeState("connected", nil)
	handler := monitor.Handler()

	for i := range 3 {
		rec, body := requestHealth(t, handler)
		if rec.Code != http.StatusOK || body.Upstream != "connected" {
			t.Fatalf("request %d = %d/%q, want %d/connected (the watchdog snapshot must be served verbatim)", i, rec.Code, body.Upstream, http.StatusOK)
		}
	}
	if dialCalls.Load() != 0 {
		t.Fatalf("dial calls with watchdog state present = %d, want 0", dialCalls.Load())
	}
}

// TestHealthProbeIgnoresRequestCancellation pins that the probe a request runs
// is detached from that request's context. check() discards caller-canceled
// verdicts instead of caching them, and evicts the entry it held, so a probe on
// the requester's context would let a client that hangs up mid-check drive one
// upstream dial per request. The dial reads the context it was handed only
// after the test has canceled the request, so inheriting it is observable
// rather than a scheduling coin flip.
func TestHealthProbeIgnoresRequestCancellation(t *testing.T) {
	t.Parallel()
	dialEntered := make(chan struct{})
	release := make(chan struct{})
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		30*time.Second,
		time.Now,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			if dialCalls.Add(1) == 1 {
				close(dialEntered)
			}
			<-release
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return noopConn{}, nil
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), testLogger(), checker)
	handler := monitor.Handler()

	ctx, cancel := context.WithCancel(context.Background())
	codes := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/health", nil).WithContext(ctx))
		codes <- rec.Code
	}()

	select {
	case <-dialEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never started a probe")
	}
	cancel()
	close(release)

	select {
	case code := <-codes:
		if code != http.StatusOK {
			t.Fatalf("canceled caller's request = %d, want %d (the probe must not inherit the caller's cancellation)", code, http.StatusOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the canceled caller's request never returned")
	}

	rec, body := requestHealth(t, handler)
	if rec.Code != http.StatusOK || body.Upstream != "connected" {
		t.Fatalf("follow-up request = %d/%q, want %d/connected", rec.Code, body.Upstream, http.StatusOK)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls = %d, want 1 (the canceled caller's verdict must still be cached)", dialCalls.Load())
	}
}
