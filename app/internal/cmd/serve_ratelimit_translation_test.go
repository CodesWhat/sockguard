package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/ratelimit"
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
