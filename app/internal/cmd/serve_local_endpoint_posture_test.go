package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// TestLocalEndpointsSitBehindTheClientCIDRGate pins where /metrics, /health
// and /ready actually sit in the chain. buildServeHandlerChainWithRuntime
// wraps outward, so a layer appended later is the outer one and runs first:
// withClientACL is appended after withMetricsEndpoint and therefore evaluates
// clients.allowed_cidrs before any of these three handlers is reached. The
// observability docs say so; this fails if the append order ever moves.
func TestLocalEndpointsSitBehindTheClientCIDRGate(t *testing.T) {
	paths := []string{"/metrics", "/health", "/ready"}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Metrics.Enabled = true
			cfg.Health.Enabled = true
			cfg.Health.Readiness.Enabled = true
			cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}

			handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, nil, newServeTestDeps())

			denied := httptest.NewRequest(http.MethodGet, path, nil)
			denied.RemoteAddr = "192.0.2.10:1234"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, denied)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s from a disallowed CIDR: status = %d, want %d — the CIDR gate no longer covers this endpoint",
					path, rec.Code, http.StatusForbidden)
			}

			allowed := httptest.NewRequest(http.MethodGet, path, nil)
			allowed.RemoteAddr = "10.1.2.3:1234"
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, allowed)

			if rec.Code == http.StatusForbidden {
				t.Fatalf("%s from an allowed CIDR: status = %d, want anything but %d — the test would pass vacuously if every request were denied",
					path, rec.Code, http.StatusForbidden)
			}
		})
	}
}

// TestLocalEndpointsRunAheadOfTheRateLimiter pins the other half of the same
// ordering, which goes the other way. withRateLimit is appended BEFORE the
// three local endpoints, so it is the inner layer and runs after them: a
// Prometheus scrape or a liveness probe never consumes rate-limit quota. That
// is deliberate — counting scrapes against a client's Docker API budget would
// throttle the wrong thing — but it also means these three endpoints have no
// request-rate ceiling of their own. The observability docs say so.
func TestLocalEndpointsRunAheadOfTheRateLimiter(t *testing.T) {
	cfg := config.Defaults()
	cfg.Metrics.Enabled = true
	cfg.Health.Enabled = true
	cfg.Health.Readiness.Enabled = true
	cfg.Clients.GlobalConcurrency = &config.GlobalConcurrencyConfig{MaxInflight: 4}

	names := serveHandlerLayerNames(buildServeHandlerLayers(&cfg, newDiscardLogger(), nil, nil, newServeTestDeps(), nil))

	index := func(name string) int {
		for i, got := range names {
			if got == name {
				return i
			}
		}
		t.Fatalf("layer %q not in chain %#v", name, names)
		return -1
	}

	rateLimit := index("withRateLimit")
	for _, endpoint := range []string{"withHealth", "withReadiness", "withMetricsEndpoint"} {
		if index(endpoint) < rateLimit {
			t.Fatalf("%s is appended before withRateLimit, so it now runs after it; this endpoint has started consuming rate-limit quota", endpoint)
		}
	}
}
