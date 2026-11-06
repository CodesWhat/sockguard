package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/health"
	"github.com/codeswhat/sockguard/v3/app/internal/metrics"
)

func TestReadinessRuntimePublishesProbeMetrics(t *testing.T) {
	t.Parallel()
	transport := serveResourceRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("[]"))}, nil
	})
	runtime := &serveRuntime{
		readiness: health.NewReadinessMonitorWithRoundTripper("fixture", transport, time.Now(), newDiscardLogger(), time.Second),
		metrics:   metrics.NewRegistry(),
	}
	cfg := &config.Config{}
	cfg.Health.Readiness.Enabled = true
	cfg.Health.Readiness.Interval = "1ms"
	stop := runtime.startReadiness(t.Context(), cfg)
	t.Cleanup(stop)
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		rec := httptest.NewRecorder()
		runtime.metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		body := rec.Body.String()
		if strings.Contains(body, `sockguard_upstream_readiness_checks_total{result="ready"}`) && strings.Contains(body, "sockguard_upstream_api_up 1\n") {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("ready probe was not published in metrics: %s", body)
		}
	}
}
