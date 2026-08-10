package buildkitproxy

import (
	"testing"
	"time"
)

// TestDefaultLimitsAreSane tables each field's own sanity check so a failure
// names exactly which default regressed.
func TestDefaultLimitsAreSane(t *testing.T) {
	l := DefaultLimits()
	cases := []struct {
		name string
		ok   bool
	}{
		{"MaxConcurrentStreams is positive", l.MaxConcurrentStreams > 0},
		{"MaxMessageBytes is positive", l.MaxMessageBytes > 0},
		{"DeniedStreamBudget is positive (Phase 2 must not ship with the abuse guard disabled)", l.DeniedStreamBudget > 0},
		{"DeniedStreamWindow is positive", l.DeniedStreamWindow > 0},
		{"IdleTimeout is positive", l.IdleTimeout > 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.ok {
				t.Error("got false, want true")
			}
		})
	}
}

// TestStreamAbuseGuardDisabledWhenBudgetZero is left as a single repeated
// loop rather than a named table: every one of its 100 iterations asserts
// the identical invariant (recordDenied never trips) against one shared
// guard, so per-case names would add no information a table normally buys.
func TestStreamAbuseGuardDisabledWhenBudgetZero(t *testing.T) {
	g := newStreamAbuseGuard(Limits{DeniedStreamBudget: 0, DeniedStreamWindow: time.Second})
	for range 100 {
		if g.recordDenied() {
			t.Fatal("recordDenied() = true with DeniedStreamBudget=0, want always false")
		}
	}
}

// TestStreamAbuseGuardTripsAtBudget tables the expected result of each
// sequential recordDenied() call against ONE shared guard — the cases must
// run in declaration order (the default for t.Run, since none call
// t.Parallel) because each call's result depends on the guard's accumulated
// state from every call before it.
func TestStreamAbuseGuardTripsAtBudget(t *testing.T) {
	g := newStreamAbuseGuard(Limits{DeniedStreamBudget: 3, DeniedStreamWindow: time.Minute})
	now := time.Now()
	g.nowFn = func() time.Time { return now }

	cases := []struct {
		name string
		want bool
	}{
		{"1st call", false},
		{"2nd call", false},
		{"3rd call", false},
		{"4th call exceeds budget of 3", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.recordDenied(); got != tc.want {
				t.Fatalf("recordDenied() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStreamAbuseGuardWindowRollsOff tables the same kind of ordered,
// state-dependent sequence as TestStreamAbuseGuardTripsAtBudget, with an
// additional advanceBy field driving the simulated clock forward before a
// given call — reproducing the original test's "burst, then roll the window
// over, then a fresh burst" sequence exactly.
func TestStreamAbuseGuardWindowRollsOff(t *testing.T) {
	g := newStreamAbuseGuard(Limits{DeniedStreamBudget: 2, DeniedStreamWindow: 10 * time.Second})
	now := time.Now()
	g.nowFn = func() time.Time { return now }

	cases := []struct {
		name      string
		advanceBy time.Duration
		want      bool
	}{
		{"1st call", 0, false},
		{"2nd call", 0, false},
		{"after window rollover, 1st call of a fresh burst", time.Minute, false},
		{"2nd call of the fresh burst", 0, false},
		{"3rd call of the fresh burst exceeds budget of 2 again", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now = now.Add(tc.advanceBy)
			if got := g.recordDenied(); got != tc.want {
				t.Fatalf("recordDenied() = %v, want %v", got, tc.want)
			}
		})
	}
}
