package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/codeswhat/sockguard/internal/version"
)

// Handler returns an HTTP handler for the /health endpoint.
func Handler(upstreamSocket string, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		uptime := time.Since(startTime).Seconds()

		// Check upstream Docker socket
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", upstreamSocket)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "unhealthy",
				"upstream":       "unreachable",
				"error":          err.Error(),
				"version":        version.Version,
				"uptime_seconds": int(uptime),
			})
			return
		}
		conn.Close()

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "healthy",
			"upstream":       "connected",
			"version":        version.Version,
			"uptime_seconds": int(uptime),
		})
	}
}
