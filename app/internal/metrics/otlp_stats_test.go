package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(t *testing.T, r *Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func TestOTLPStatsSeriesAbsentUntilRegistered(t *testing.T) {
	var nilRegistry *Registry
	nilRegistry.SetOTLPStats(func() OTLPStats { return OTLPStats{} }) // must not panic

	r := NewRegistry()
	r.SetOTLPStats(nil)
	if strings.Contains(scrape(t, r), "sockguard_otlp_") {
		t.Fatal("otlp series exposed before a source was registered")
	}
	r.SetOTLPStats(func() OTLPStats {
		return OTLPStats{Exported: 7, DroppedQueueFull: 1, DroppedExportFailed: 2, DroppedShutdown: 3, RequestsSuccess: 4, RequestsRetryable: 5, RequestsPermanent: 6}
	})
	body := scrape(t, r)
	for _, want := range []string{
		"sockguard_otlp_spans_exported_total 7",
		`sockguard_otlp_spans_dropped_total{reason="queue_full"} 1`,
		`sockguard_otlp_spans_dropped_total{reason="export_failed"} 2`,
		`sockguard_otlp_spans_dropped_total{reason="shutdown"} 3`,
		`sockguard_otlp_export_requests_total{result="success"} 4`,
		`sockguard_otlp_export_requests_total{result="retryable_error"} 5`,
		`sockguard_otlp_export_requests_total{result="permanent_error"} 6`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}
