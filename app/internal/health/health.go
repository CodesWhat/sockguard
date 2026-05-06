package health

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/version"
)

const healthCacheTTL = 2 * time.Second
const healthFailureCacheTTL = 100 * time.Millisecond
const healthDialTimeout = 3 * time.Second

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// HealthResponse is the JSON body returned by the /health endpoint.
type HealthResponse struct {
	Status        string `json:"status"`
	Upstream      string `json:"upstream"`
	Error         string `json:"error,omitempty"`
	Version       string `json:"version"`
	UptimeSeconds int    `json:"uptime_seconds"`
}

type upstreamHealthChecker struct {
	ttl        time.Duration
	failureTTL time.Duration
	timeout    time.Duration
	now        func() time.Time
	dial       dialContextFunc

	mu         sync.Mutex
	cachedAt   time.Time
	cachedUp   string
	cachedErr  error
	cacheReady bool
	inFlight   *healthCheckCall
}

type healthCheckCall struct {
	done   chan struct{}
	status string
	err    error
}

// WatchdogState reports one active upstream socket watchdog observation.
type WatchdogState struct {
	Status    string
	Up        bool
	Err       error
	CheckedAt time.Time
	Changed   bool
}

// Monitor owns upstream health checks shared by /health and the active watchdog.
type Monitor struct {
	upstreamSocket string
	startTime      time.Time
	logger         *slog.Logger
	checker        *upstreamHealthChecker

	mu       sync.RWMutex
	last     WatchdogState
	hasState bool
}

func newUpstreamHealthChecker(ttl, timeout time.Duration, now func() time.Time, dial dialContextFunc) *upstreamHealthChecker {
	return &upstreamHealthChecker{
		ttl:        ttl,
		failureTTL: healthFailureCacheTTL,
		timeout:    timeout,
		now:        now,
		dial:       dial,
	}
}

// NewMonitor constructs a monitor for upstream Docker socket reachability.
func NewMonitor(upstreamSocket string, startTime time.Time, logger *slog.Logger) *Monitor {
	return newMonitorWithChecker(
		upstreamSocket,
		startTime,
		logger,
		newUpstreamHealthChecker(healthCacheTTL, healthDialTimeout, time.Now, (&net.Dialer{}).DialContext),
	)
}

func newMonitorWithChecker(upstreamSocket string, startTime time.Time, logger *slog.Logger, checker *upstreamHealthChecker) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{
		upstreamSocket: upstreamSocket,
		startTime:      startTime,
		logger:         logger,
		checker:        checker,
	}
}

func (c *upstreamHealthChecker) check(ctx context.Context, upstreamSocket string) (string, error) {
	now := c.now()

	c.mu.Lock()
	cacheTTL := c.ttl
	if c.cachedErr != nil {
		cacheTTL = c.failureTTL
	}
	if c.cacheReady && cacheTTL > 0 && now.Sub(c.cachedAt) < cacheTTL {
		status, err := c.cachedUp, c.cachedErr
		c.mu.Unlock()
		return status, err
	}
	if c.inFlight != nil {
		call := c.inFlight
		c.mu.Unlock()
		<-call.done
		return call.status, call.err
	}
	call := &healthCheckCall{done: make(chan struct{})}
	c.inFlight = call
	c.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := c.dial(dialCtx, "unix", upstreamSocket)
	status := "connected"
	if err == nil {
		conn.Close()
	} else {
		status = "unreachable"
	}

	c.mu.Lock()
	// Failure-cache semantics: we only record an error in the cache if the
	// failure was about the upstream, not about the caller giving up. If the
	// caller's own context was canceled or deadline-exceeded before dial
	// returned, err reflects the caller's state, not upstream health — caching
	// it would unfairly coalesce later well-formed callers onto a verdict
	// their neighbor gave up on. A dial that times out against a healthy
	// caller (c.timeout < caller deadline) IS an upstream signal and gets
	// cached for failureTTL so a burst of probes coalesces into one dial.
	if err == nil {
		c.cachedAt = c.now()
		c.cachedUp = status
		c.cachedErr = nil
		c.cacheReady = true
	} else if c.failureTTL > 0 && !errors.Is(ctx.Err(), context.Canceled) && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		c.cachedAt = c.now()
		c.cachedUp = status
		c.cachedErr = err
		c.cacheReady = true
	} else {
		c.cachedAt = time.Time{}
		c.cachedUp = ""
		c.cachedErr = nil
		c.cacheReady = false
	}
	c.inFlight = nil
	call.status = status
	call.err = err
	close(call.done)
	c.mu.Unlock()

	return status, err
}

// Handler returns an HTTP handler for the /health endpoint.
func (m *Monitor) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uptime := time.Since(m.startTime).Seconds()

		state, ok := m.State()
		if !ok {
			state = m.check(r.Context())
		}
		if state.Err != nil {
			m.logger.WarnContext(r.Context(), "health check failed: upstream unreachable",
				"error", state.Err,
				"upstream_socket", m.upstreamSocket,
			)
			if encErr := httpjson.Write(w, http.StatusServiceUnavailable, HealthResponse{
				Status:        "unhealthy",
				Upstream:      state.Status,
				Error:         "upstream unreachable",
				Version:       version.Version,
				UptimeSeconds: int(uptime),
			}); encErr != nil {
				m.logger.WarnContext(r.Context(), "failed to encode unhealthy response",
					"error", encErr,
				)
			}
			return
		}

		if encErr := httpjson.Write(w, http.StatusOK, HealthResponse{
			Status:        "healthy",
			Upstream:      state.Status,
			Version:       version.Version,
			UptimeSeconds: int(uptime),
		}); encErr != nil {
			m.logger.WarnContext(r.Context(), "failed to encode healthy response",
				"error", encErr,
			)
		}
	}
}

// State returns the latest known upstream watchdog or health-check state.
func (m *Monitor) State() (WatchdogState, bool) {
	if m == nil {
		return WatchdogState{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last, m.hasState
}

// StartWatchdog starts active upstream polling until ctx is canceled. The first
// check runs immediately so operators do not need to wait a full interval for
// /health and metrics to reflect an upstream outage.
func (m *Monitor) StartWatchdog(ctx context.Context, interval time.Duration, observe func(WatchdogState)) {
	if m == nil || interval <= 0 {
		return
	}
	go m.runWatchdog(ctx, interval, observe)
}

func (m *Monitor) runWatchdog(ctx context.Context, interval time.Duration, observe func(WatchdogState)) {
	m.emitWatchdogCheck(ctx, observe)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.emitWatchdogCheck(ctx, observe)
		}
	}
}

func (m *Monitor) emitWatchdogCheck(ctx context.Context, observe func(WatchdogState)) {
	state := m.check(ctx)
	if observe != nil {
		observe(state)
	}
	if !state.Changed {
		return
	}
	level := slog.LevelInfo
	if !state.Up {
		level = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("upstream_socket", m.upstreamSocket),
		slog.String("upstream_status", state.Status),
		slog.Bool("up", state.Up),
	}
	if state.Err != nil {
		attrs = append(attrs, slog.String("error", state.Err.Error()))
	}
	m.logger.LogAttrs(ctx, level, "upstream socket watchdog state changed", attrs...)
}

func (m *Monitor) check(ctx context.Context) WatchdogState {
	status, err := m.checker.check(ctx, m.upstreamSocket)
	return m.storeState(status, err)
}

func (m *Monitor) storeState(status string, err error) WatchdogState {
	state := WatchdogState{
		Status:    status,
		Up:        err == nil,
		Err:       err,
		CheckedAt: time.Now(),
	}

	m.mu.Lock()
	state.Changed = m.hasState && m.last.Up != state.Up
	m.last = state
	m.hasState = true
	m.mu.Unlock()

	return state
}

// Handler returns an HTTP handler for the /health endpoint.
func Handler(upstreamSocket string, startTime time.Time, logger *slog.Logger) http.HandlerFunc {
	return NewMonitor(upstreamSocket, startTime, logger).Handler()
}
