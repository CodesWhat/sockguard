package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/ratelimit"
	"github.com/codeswhat/sockguard/internal/testhelp"
)

// TestConfigLimitsToRateLimitOptions_AllFields is a happy-path test for the
// config translation layer. It constructs a LimitsConfig with every field
// populated and asserts that every value round-trips correctly into the
// returned ratelimit.ProfileOptions. Edge cases are covered by existing tests.
func TestConfigLimitsToRateLimitOptions_AllFields(t *testing.T) {
	limits := config.LimitsConfig{
		Priority: "high",
		Rate: &config.RateLimitConfig{
			TokensPerSecond: 50.0,
			Burst:           100.0,
			EndpointCosts: []config.EndpointCostConfig{
				{Path: "/build", Methods: []string{"POST"}, Cost: 5},
			},
		},
		Concurrency: &config.ConcurrencyConfig{
			MaxInflight: 10,
		},
	}

	got := configLimitsToRateLimitOptions("test-profile", limits, newDiscardLogger())

	// Priority must translate from "high" string to ratelimit.PriorityHigh.
	if got.Priority != ratelimit.PriorityHigh {
		t.Errorf("Priority = %v, want PriorityHigh", got.Priority)
	}

	// Rate sub-block.
	if got.Rate == nil {
		t.Fatal("Rate = nil, want non-nil")
	}
	if got.Rate.TokensPerSecond != 50.0 {
		t.Errorf("Rate.TokensPerSecond = %v, want 50", got.Rate.TokensPerSecond)
	}
	if got.Rate.Burst != 100.0 {
		t.Errorf("Rate.Burst = %v, want 100", got.Rate.Burst)
	}
	if len(got.Rate.EndpointCosts) != 1 {
		t.Fatalf("Rate.EndpointCosts len = %d, want 1", len(got.Rate.EndpointCosts))
	}
	ec := got.Rate.EndpointCosts[0]
	if ec.PathGlob != "/build" {
		t.Errorf("EndpointCosts[0].PathGlob = %q, want /build", ec.PathGlob)
	}
	if len(ec.Methods) != 1 || ec.Methods[0] != "POST" {
		t.Errorf("EndpointCosts[0].Methods = %v, want [POST]", ec.Methods)
	}
	if ec.Cost != 5 {
		t.Errorf("EndpointCosts[0].Cost = %v, want 5", ec.Cost)
	}

	// Concurrency sub-block.
	if got.Concurrency == nil {
		t.Fatal("Concurrency = nil, want non-nil")
	}
	if got.Concurrency.MaxInflight != 10 {
		t.Errorf("Concurrency.MaxInflight = %d, want 10", got.Concurrency.MaxInflight)
	}
}

// TestConfigLimitsToRateLimitOptions_BurstZeroDefaultsToRate pins the
// fallback at serve_ratelimit_translation.go:66–68: when Burst is 0 the
// function substitutes TokensPerSecond so the token bucket has non-zero
// capacity. Without this fallback a zero Burst would silently disable rate
// limiting for the profile — every request would be rejected by a bucket
// that can never hold a token.
func TestConfigLimitsToRateLimitOptions_BurstZeroDefaultsToRate(t *testing.T) {
	cfg := config.LimitsConfig{
		Rate: &config.RateLimitConfig{TokensPerSecond: 10, Burst: 0},
	}

	opts := configLimitsToRateLimitOptions("p1", cfg, newDiscardLogger())

	if opts.Rate == nil {
		t.Fatal("opts.Rate = nil, want non-nil")
	}
	if opts.Rate.TokensPerSecond != 10 {
		t.Errorf("Rate.TokensPerSecond = %v, want 10", opts.Rate.TokensPerSecond)
	}
	// Burst must have been promoted to TokensPerSecond (10), not left at 0.
	if opts.Rate.Burst != 10 {
		t.Errorf("Rate.Burst = %v, want 10 (fallback from TokensPerSecond)", opts.Rate.Burst)
	}
}

// TestConfigLimitsToRateLimitOptions_UnrecognizedPriorityLogsWarn pins the
// Warn branch at serve_ratelimit_translation.go:57–62: an unrecognized
// priority string must emit a warning containing the profile name and the
// offending priority value, and the returned Priority must be PriorityNormal
// (ParsePriority's documented return on !ok — the zero value of Priority).
func TestConfigLimitsToRateLimitOptions_UnrecognizedPriorityLogsWarn(t *testing.T) {
	collector := &testhelp.CollectingHandler{}
	cfg := config.LimitsConfig{Priority: "ultra-high"}

	opts := configLimitsToRateLimitOptions("admin", cfg, collector.Logger())

	const wantMsg = "unrecognized priority value in client profile; falling back to normal"
	if !collector.HasMessage(wantMsg) {
		t.Fatalf("expected warn log %q; records: %#v", wantMsg, collector.Records())
	}

	matches := collector.FindMessage(wantMsg)
	rec := matches[0]
	if got, ok := rec.Attrs["profile"]; !ok || got != "admin" {
		t.Errorf("log attr profile = %v, want %q", got, "admin")
	}
	if got, ok := rec.Attrs["priority"]; !ok || got != "ultra-high" {
		t.Errorf("log attr priority = %v, want %q", got, "ultra-high")
	}

	// ParsePriority returns (PriorityNormal, false) for unknown values; the
	// function leaves opts.Priority at whatever ParsePriority returns, which
	// is PriorityNormal (the zero value of ratelimit.Priority / iota = 0).
	if opts.Priority != ratelimit.PriorityNormal {
		t.Errorf("Priority = %v, want PriorityNormal", opts.Priority)
	}
}
