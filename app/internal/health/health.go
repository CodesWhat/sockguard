package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeswhat/sockguard/app/internal/dockerclient"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/upstream"
	"github.com/codeswhat/sockguard/app/internal/version"
)

const healthCacheTTL = 2 * time.Second
const healthFailureCacheTTL = 100 * time.Millisecond
const healthDialTimeout = 3 * time.Second

// upstreamStatusChecking is the HealthResponse.Upstream value reported when a
// probe is in flight and none has ever completed, so a caller can tell "the
// first check has not come back yet" apart from "the upstream answered and it
// is down".
const upstreamStatusChecking = "checking"

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// HealthResponse is the JSON body returned by the /health endpoint.
type HealthResponse struct {
	Status        string `json:"status"`
	Upstream      string `json:"upstream"`
	Error         string `json:"error,omitempty"`
	Version       string `json:"version"`
	UptimeSeconds int    `json:"uptime_seconds"`
	// Listeners reports every configured listener's identity and lifecycle
	// state (#149), populated by Monitor.ListenersFunc when set. It is always
	// encoded (as [] when no listener snapshot is available) so clients can
	// rely on one response schema on healthy and unhealthy paths.
	Listeners []ListenerStatus `json:"listeners"`
}

// ListenerStatus reports one configured listener's (main or admin) identity
// and lifecycle state (#149).
type ListenerStatus struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Network string `json:"network"`
	State   string `json:"state"`
}

// Listener lifecycle states surfaced via ListenerStatus.State. A listener
// transitions bound -> serving -> draining -> stopped on a clean shutdown,
// or bound/serving -> failed if its Serve() call returns unexpectedly
// before an intentional drain begins.
const (
	ListenerStateBound    = "bound"
	ListenerStateServing  = "serving"
	ListenerStateDraining = "draining"
	ListenerStateFailed   = "failed"
	ListenerStateStopped  = "stopped"
)

// listenerRequiresAttention reports whether state is anything other than
// "serving" or "draining" — the two states in which a configured listener is
// still doing its job (actively accepting new connections, or intentionally
// finishing in-flight ones during a clean shutdown). "bound" (never started
// serving), "failed", and "stopped" all indicate the listener is not
// currently doing what an operator configured it to do.
func listenerRequiresAttention(state string) bool {
	return state != ListenerStateServing && state != ListenerStateDraining
}

// anyListenerRequiresAttention reports whether any entry in listeners is not
// currently serving or intentionally draining — see listenerRequiresAttention.
func anyListenerRequiresAttention(listeners []ListenerStatus) bool {
	for _, l := range listeners {
		if listenerRequiresAttention(l.State) {
			return true
		}
	}
	return false
}

type upstreamHealthChecker struct {
	ttl        time.Duration
	failureTTL time.Duration
	timeout    time.Duration
	now        func() time.Time
	dial       dialContextFunc
	// probe, when non-nil, replaces the raw socket dial with a richer upstream
	// check (the readiness monitor probes the Docker API). It returns the status
	// string to surface and a non-nil error when the upstream is not usable.
	probe func(ctx context.Context) (string, error)

	// onWaiterJoined is called (without the mu lock held) each time a caller
	// joins an already-in-flight check rather than starting a new dial.
	// Nil in production; set in tests to replace time.Sleep rendezvous.
	onWaiterJoined func()

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

	// refreshing is held for the duration of the one request-driven probe
	// allowed to be in flight at a time (see refreshNow).
	refreshing atomic.Bool

	// onRefreshDone, when non-nil, is called after a request-driven refresh
	// has published its verdict and released refreshing. Nil in production;
	// set in tests to observe that a probe ran.
	onRefreshDone func()

	// ListenersFunc, when set, is called once per /health request to
	// populate HealthResponse.Listeners and to fold listener state into the
	// 503 decision (#149) — any listener not "serving" or "draining" marks
	// the response unhealthy alongside (or independently of) an upstream
	// failure. Nil for Monitor instances with no listener concept to
	// surface — set by the caller after construction (the listener status
	// board it closes over is only available once the serverGroup has
	// started binding, which happens after NewMonitor/NewReadinessMonitor).
	ListenersFunc func() []ListenerStatus
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

// NewMonitorWithDialer constructs a liveness monitor that dials the upstream
// through dialer (typically an *upstream.Resolver), so /health reflects whether
// the proxy can currently reach an upstream — the active failover endpoint, not
// a fixed socket. label is used only for log/metric identification.
func NewMonitorWithDialer(label string, dialer upstream.Dialer, startTime time.Time, logger *slog.Logger) *Monitor {
	return newMonitorWithChecker(
		label,
		startTime,
		logger,
		newUpstreamHealthChecker(healthCacheTTL, healthDialTimeout, time.Now, dialer.DialContext),
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

// verdict is one cached upstream observation as a non-dialing reader sees it.
type verdict struct {
	status    string
	err       error
	checkedAt time.Time
	// fresh reports that the observation is still inside the TTL that applies
	// to it — the short failure TTL for an error, the full TTL otherwise.
	fresh bool
	// present reports that some probe has completed, so status/err mean
	// something. A stale-but-present verdict is still worth serving.
	present bool
}

// cachedLocked reads the currently held verdict. c.mu must be held. It is the
// single definition of "still fresh", shared by the dialing path (check) and
// the non-dialing one (snapshot), so the two cannot drift apart.
func (c *upstreamHealthChecker) cachedLocked() verdict {
	if !c.cacheReady {
		return verdict{}
	}
	cacheTTL := c.ttl
	if c.cachedErr != nil {
		cacheTTL = c.failureTTL
	}
	return verdict{
		status:    c.cachedUp,
		err:       c.cachedErr,
		checkedAt: c.cachedAt,
		fresh:     cacheTTL > 0 && c.now().Sub(c.cachedAt) < cacheTTL,
		present:   true,
	}
}

// snapshot returns the held verdict without dialing and without waiting on an
// in-flight probe. It is what the /health request path reads.
func (c *upstreamHealthChecker) snapshot() verdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cachedLocked()
}

func (c *upstreamHealthChecker) check(ctx context.Context, upstreamSocket string) (string, error) {
	c.mu.Lock()
	if cached := c.cachedLocked(); cached.fresh {
		c.mu.Unlock()
		return cached.status, cached.err
	}
	if c.inFlight != nil {
		call := c.inFlight
		notify := c.onWaiterJoined
		c.mu.Unlock()
		if notify != nil {
			notify()
		}
		<-call.done
		return call.status, call.err
	}
	call := &healthCheckCall{done: make(chan struct{})}
	c.inFlight = call
	c.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var status string
	var err error
	if c.probe != nil {
		status, err = c.probe(dialCtx)
	} else {
		// For the legacy net.Dialer these (network, address) args select the unix
		// socket. For the resolver-backed dialer (NewMonitorWithDialer) they are
		// ignored — the active failover endpoint is chosen by health — and
		// upstreamSocket here is just the log/metric label.
		var conn net.Conn
		conn, err = c.dial(dialCtx, "unix", upstreamSocket)
		status = "connected"
		if err == nil {
			_ = conn.Close()
		} else {
			status = "unreachable"
		}
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

		state, known := m.stateForRequest()

		listeners := make([]ListenerStatus, 0)
		if m.ListenersFunc != nil {
			listeners = append(listeners, m.ListenersFunc()...)
		}

		if known && state.Err != nil {
			if writeErr := httpjson.Write(w, http.StatusServiceUnavailable, HealthResponse{
				Status:        "unhealthy",
				Upstream:      state.Status,
				Error:         "upstream unreachable",
				Version:       version.Version,
				UptimeSeconds: int(uptime),
				Listeners:     listeners,
			}); writeErr != nil {
				m.logger.WarnContext(r.Context(), "failed to write unhealthy response",
					"error", writeErr,
				)
			}
			return
		}

		if anyListenerRequiresAttention(listeners) {
			m.logger.WarnContext(r.Context(), "health check failed: a configured listener is not serving",
				"listeners", listeners,
			)
			if writeErr := httpjson.Write(w, http.StatusServiceUnavailable, HealthResponse{
				Status:        "unhealthy",
				Upstream:      state.Status,
				Error:         "listener not serving",
				Version:       version.Version,
				UptimeSeconds: int(uptime),
				Listeners:     listeners,
			}); writeErr != nil {
				m.logger.WarnContext(r.Context(), "failed to write unhealthy response",
					"error", writeErr,
				)
			}
			return
		}

		// A probe is running and has never yet produced a verdict, so there
		// is nothing to serve and this request must not queue behind it —
		// see stateForRequest.
		if !known {
			if writeErr := httpjson.Write(w, http.StatusServiceUnavailable, HealthResponse{
				Status:        "unhealthy",
				Upstream:      state.Status,
				Error:         "upstream check in progress",
				Version:       version.Version,
				UptimeSeconds: int(uptime),
				Listeners:     listeners,
			}); writeErr != nil {
				m.logger.WarnContext(r.Context(), "failed to write unhealthy response",
					"error", writeErr,
				)
			}
			return
		}

		if writeErr := httpjson.Write(w, http.StatusOK, HealthResponse{
			Status:        "healthy",
			Upstream:      state.Status,
			Version:       version.Version,
			UptimeSeconds: int(uptime),
			Listeners:     listeners,
		}); writeErr != nil {
			m.logger.WarnContext(r.Context(), "failed to write healthy response",
				"error", writeErr,
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

// stateForRequest returns the verdict /health should answer with, and whether
// one exists at all.
//
// A stored watchdog state wins outright — when the watchdog (or the readiness
// poller) runs it owns the answer at its configured interval, its transition
// logging is once-per-edge against that stored value, and the exported gauges
// come from the same callback, so a request-driven write would race the edge
// and let /health disagree with the metrics.
//
// Without a watchdog nothing writes that state, so requests fall through to the
// checker's cache. A verdict still inside healthCacheTTL is served as is. Once
// it lapses, the first request to arrive runs the replacement probe itself and
// answers with its result, which is what keeps the TTL an actual bound on how
// old the answer can be. Every other request that arrives while that probe is
// running is served the verdict on hand instead of queueing behind it, so the
// number of goroutines waiting on the upstream is one, no matter how much
// traffic arrives: /health is unauthenticated and sits ahead of the rate
// limiter, and a blackholed daemon plus one blocked goroutine per caller is an
// amplification surface. ok is false only in the narrow case where a probe is
// already running and no verdict exists yet to serve in the meantime.
func (m *Monitor) stateForRequest() (WatchdogState, bool) {
	if state, ok := m.State(); ok {
		return state, true
	}

	cached := m.checker.snapshot()
	if cached.fresh {
		return stateFromVerdict(cached), true
	}
	if refreshed, leader := m.refreshNow(); leader {
		return stateFromVerdict(refreshed), true
	}
	if !cached.present {
		return WatchdogState{Status: upstreamStatusChecking}, false
	}
	return stateFromVerdict(cached), true
}

func stateFromVerdict(v verdict) WatchdogState {
	return WatchdogState{
		Status:    v.status,
		Up:        v.err == nil,
		Err:       v.err,
		CheckedAt: v.checkedAt,
	}
}

// refreshNow runs the replacement probe on the calling request's goroutine,
// unless another request is already running one — leader reports which
// happened, and a caller that is not the leader must not wait.
//
// The probe runs on a context of its own rather than the request's. check()
// discards caller-canceled verdicts instead of caching them, and evicts the
// entry it held on the way out, so a client that hangs up mid-probe would
// otherwise leave the cache empty and let one dial per request through. The
// dial stays bounded by the checker's own timeout, which is the bound on how
// long this request can be held.
//
// The unreachable warning is logged here, once per probe, rather than once per
// request served: a per-request log line on an endpoint in front of the rate
// limiter is an amplification surface of its own. Log volume during an outage
// is therefore bounded by the failure TTL instead of by traffic.
func (m *Monitor) refreshNow() (verdict, bool) {
	if !m.refreshing.CompareAndSwap(false, true) {
		return verdict{}, false
	}
	defer func() {
		m.refreshing.Store(false)
		if m.onRefreshDone != nil {
			m.onRefreshDone()
		}
	}()

	status, err := m.checker.check(context.Background(), m.upstreamSocket)
	if err != nil {
		m.logger.Warn("health check failed: upstream unreachable",
			"error", err,
			"upstream_socket", m.upstreamSocket,
		)
	}
	return verdict{
		status:    status,
		err:       err,
		checkedAt: m.checker.now(),
		present:   true,
	}, true
}

func (m *Monitor) check(ctx context.Context) WatchdogState {
	status, err := m.checker.check(ctx, m.upstreamSocket)
	return m.storeState(status, err)
}

// Probe runs one upstream check now and returns its verdict, bypassing both
// the /health request path and the watchdog. It exists for one-shot callers
// that have no HTTP request and no long-running process to hang a watchdog
// off — `sockguard verify` is the only one today — so they exercise the same
// probe /health does instead of dialing the upstream themselves.
func (m *Monitor) Probe(ctx context.Context) WatchdogState {
	return m.check(ctx)
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

func newReadinessChecker(timeout time.Duration, now func() time.Time, probe func(context.Context) (string, error)) *upstreamHealthChecker {
	return &upstreamHealthChecker{
		ttl:        healthCacheTTL,
		failureTTL: healthFailureCacheTTL,
		timeout:    timeout,
		now:        now,
		probe:      probe,
	}
}

// NewReadinessMonitor constructs a Monitor that probes the upstream Docker API
// (GET /containers/json) instead of dialing the socket. The raw dial behind
// /health is a liveness signal — it only proves the socket accepts connections.
// Readiness proves the daemon still answers the API, catching the failure mode
// where the socket stays connectable but request handling has wedged. It reuses
// the Monitor watchdog/state/handler machinery; only the probe differs. A
// non-positive timeout falls back to the default dial timeout.
func NewReadinessMonitor(upstreamSocket string, startTime time.Time, logger *slog.Logger, timeout time.Duration) *Monitor {
	if timeout <= 0 {
		timeout = healthDialTimeout
	}
	client := dockerclient.New(upstreamSocket)
	checker := newReadinessChecker(timeout, time.Now, func(ctx context.Context) (string, error) {
		return probeUpstreamAPI(ctx, client)
	})
	return newMonitorWithChecker(upstreamSocket, startTime, logger, checker)
}

// NewReadinessMonitorWithRoundTripper is NewReadinessMonitor over the shared
// upstream RoundTripper (typically an *upstream.Resolver): the GET
// /containers/json probe runs against the active failover endpoint. label is
// used only for log/metric identification.
func NewReadinessMonitorWithRoundTripper(label string, rt http.RoundTripper, startTime time.Time, logger *slog.Logger, timeout time.Duration) *Monitor {
	if timeout <= 0 {
		timeout = healthDialTimeout
	}
	client := dockerclient.NewWithRoundTripper(rt)
	checker := newReadinessChecker(timeout, time.Now, func(ctx context.Context) (string, error) {
		return probeUpstreamAPI(ctx, client)
	})
	return newMonitorWithChecker(label, startTime, logger, checker)
}

// probeUpstreamAPI issues a minimal GET /containers/json?limit=1 against the
// upstream Docker API. Any transport error or non-2xx status is reported as
// unready. The host in the URL is arbitrary — the client dials the unix socket.
func probeUpstreamAPI(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?limit=1", nil)
	if err != nil {
		return "unreachable", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unreachable", err
	}
	defer resp.Body.Close()
	// Drain the body so the keep-alive connection can be reused by the next probe.
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "unreachable", fmt.Errorf("upstream /containers/json returned status %d", resp.StatusCode)
	}
	return "ready", nil
}
