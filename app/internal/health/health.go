package health

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/version"
)

const healthCacheTTL = 2 * time.Second
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
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time
	dial    dialContextFunc

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

func newUpstreamHealthChecker(ttl, timeout time.Duration, now func() time.Time, dial dialContextFunc) *upstreamHealthChecker {
	return &upstreamHealthChecker{
		ttl:     ttl,
		timeout: timeout,
		now:     now,
		dial:    dial,
	}
}

func (c *upstreamHealthChecker) check(ctx context.Context, upstreamSocket string) (string, error) {
	now := c.now()

	c.mu.Lock()
	if c.cacheReady && now.Sub(c.cachedAt) < c.ttl {
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
	c.cachedAt = c.now()
	c.cachedUp = status
	c.cachedErr = err
	c.cacheReady = true
	c.inFlight = nil
	call.status = status
	call.err = err
	close(call.done)
	c.mu.Unlock()

	return status, err
}

// Handler returns an HTTP handler for the /health endpoint.
func Handler(upstreamSocket string, startTime time.Time, logger *slog.Logger) http.HandlerFunc {
	checker := newUpstreamHealthChecker(healthCacheTTL, healthDialTimeout, time.Now, (&net.Dialer{}).DialContext)

	return func(w http.ResponseWriter, r *http.Request) {
		uptime := time.Since(startTime).Seconds()

		upstreamStatus, err := checker.check(r.Context(), upstreamSocket)
		if err != nil {
			logger.WarnContext(r.Context(), "health check failed: upstream unreachable",
				"error", err,
				"upstream_socket", upstreamSocket,
			)
			if encErr := httpjson.Write(w, http.StatusServiceUnavailable, HealthResponse{
				Status:        "unhealthy",
				Upstream:      upstreamStatus,
				Error:         "upstream unreachable",
				Version:       version.Version,
				UptimeSeconds: int(uptime),
			}); encErr != nil {
				logger.WarnContext(r.Context(), "failed to encode unhealthy response",
					"error", encErr,
				)
			}
			return
		}

		if encErr := httpjson.Write(w, http.StatusOK, HealthResponse{
			Status:        "healthy",
			Upstream:      upstreamStatus,
			Version:       version.Version,
			UptimeSeconds: int(uptime),
		}); encErr != nil {
			logger.WarnContext(r.Context(), "failed to encode healthy response",
				"error", encErr,
			)
		}
	}
}
