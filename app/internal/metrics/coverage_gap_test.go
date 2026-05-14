package metrics

// coverage_gap_test.go covers SetInflight, which was absent from metrics_test.go.

import (
	"strings"
	"testing"
)

// TestSetInflightUpdatesGaugeInScrape verifies that calling SetInflight
// publishes the per-profile in-flight count to the Prometheus /metrics scrape
// surface. It asserts:
//   - Setting a positive value is reflected in sockguard_inflight_requests.
//   - Updating the value replaces (not adds to) the previous gauge reading.
//   - Setting zero is visible in the scrape output (gauge emits 0, not absent).
//   - A nil registry is a no-op and does not panic.
func TestSetInflightUpdatesGaugeInScrape(t *testing.T) {
	registry := NewRegistry()

	// Initial set for two profiles.
	registry.SetInflight("ci", 3)
	registry.SetInflight("watchtower", 7)

	out := renderMetrics(t, registry)
	assertContains(t, out, `sockguard_inflight_requests{profile="ci"} 3`)
	assertContains(t, out, `sockguard_inflight_requests{profile="watchtower"} 7`)

	// Update ci — must replace, not accumulate.
	registry.SetInflight("ci", 1)
	out2 := renderMetrics(t, registry)
	assertContains(t, out2, `sockguard_inflight_requests{profile="ci"} 1`)
	if strings.Contains(out2, `sockguard_inflight_requests{profile="ci"} 3`) {
		t.Fatalf("stale ci inflight value still visible after update:\n%s", out2)
	}

	// Set to zero — gauge must still appear in scrape output.
	registry.SetInflight("ci", 0)
	out3 := renderMetrics(t, registry)
	assertContains(t, out3, `sockguard_inflight_requests{profile="ci"} 0`)

	// Nil registry must not panic.
	var nilReg *Registry
	nilReg.SetInflight("ci", 42) // must not panic
}
