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

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type upstreamHealthChecker struct {
	ttl  time.Duration
	now  func() time.Time
	dial dialContextFunc

	mu         sync.Mutex
	cachedAt   time.Time
	cachedUp   string
	cachedErr  error
	cacheReady bool
}

func newUpstreamHealthChecker(ttl time.Duration, now func() time.Time, dial dialContextFunc) *upstreamHealthChecker {
	return &upstreamHealthChecker{
		ttl:  ttl,
		now:  now,
		dial: dial,
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
	c.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := c.dial(dialCtx, "unix", upstreamSocket)
	status := "connected"
	if err == nil {
		conn.Close()
	} else {
		status = "unreachable"
	}

	c.mu.Lock()
	c.cachedAt = now
	c.cachedUp = status
	c.cachedErr = err
	c.cacheReady = true
	c.mu.Unlock()

	return status, err
}

// Handler returns an HTTP handler for the /health endpoint.
func Handler(upstreamSocket string, startTime time.Time, logger *slog.Logger) http.HandlerFunc {
	checker := newUpstreamHealthChecker(healthCacheTTL, time.Now, (&net.Dialer{}).DialContext)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		uptime := time.Since(startTime).Seconds()

		upstreamStatus, err := checker.check(r.Context(), upstreamSocket)
		if err != nil {
			logger.WarnContext(r.Context(), "health check failed: upstream unreachable",
				"error", err,
				"upstream_socket", upstreamSocket,
			)
			if encErr := httpjson.Write(w, http.StatusServiceUnavailable, map[string]interface{}{
				"status":         "unhealthy",
				"upstream":       upstreamStatus,
				"error":          err.Error(),
				"version":        version.Version,
				"uptime_seconds": int(uptime),
			}); encErr != nil {
				logger.WarnContext(r.Context(), "failed to encode unhealthy response",
					"error", encErr,
				)
			}
			return
		}

		if encErr := httpjson.Write(w, http.StatusOK, map[string]interface{}{
			"status":         "healthy",
			"upstream":       upstreamStatus,
			"version":        version.Version,
			"uptime_seconds": int(uptime),
		}); encErr != nil {
			logger.WarnContext(r.Context(), "failed to encode healthy response",
				"error", encErr,
			)
		}
	}
}
