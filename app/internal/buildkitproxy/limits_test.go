package buildkitproxy

import (
	"testing"
	"time"
)

func TestDefaultLimitsAreSane(t *testing.T) {
	l := DefaultLimits()
	if l.MaxConcurrentStreams == 0 {
		t.Error("MaxConcurrentStreams = 0, want a positive cap")
	}
	if l.MaxMessageBytes <= 0 {
		t.Error("MaxMessageBytes <= 0, want a positive cap")
	}
	if l.DeniedStreamBudget <= 0 {
		t.Error("DeniedStreamBudget <= 0, want a positive budget (Phase 2 must not ship with the abuse guard disabled)")
	}
	if l.DeniedStreamWindow <= 0 {
		t.Error("DeniedStreamWindow <= 0, want a positive window")
	}
	if l.IdleTimeout <= 0 {
		t.Error("IdleTimeout <= 0, want a positive timeout")
	}
}

func TestStreamAbuseGuardDisabledWhenBudgetZero(t *testing.T) {
	g := newStreamAbuseGuard(Limits{DeniedStreamBudget: 0, DeniedStreamWindow: time.Second})
	for range 100 {
		if g.recordDenied() {
			t.Fatal("recordDenied() = true with DeniedStreamBudget=0, want always false")
		}
	}
}

func TestStreamAbuseGuardTripsAtBudget(t *testing.T) {
	g := newStreamAbuseGuard(Limits{DeniedStreamBudget: 3, DeniedStreamWindow: time.Minute})
	now := time.Now()
	g.nowFn = func() time.Time { return now }

	for i := range 3 {
		if g.recordDenied() {
			t.Fatalf("recordDenied() call %d = true, want false (budget not yet exceeded)", i+1)
		}
	}
	if !g.recordDenied() {
		t.Fatal("4th recordDenied() = false, want true (budget of 3 exceeded)")
	}
}

func TestStreamAbuseGuardWindowRollsOff(t *testing.T) {
	g := newStreamAbuseGuard(Limits{DeniedStreamBudget: 2, DeniedStreamWindow: 10 * time.Second})
	now := time.Now()
	g.nowFn = func() time.Time { return now }

	if g.recordDenied() {
		t.Fatal("1st recordDenied() = true, want false")
	}
	if g.recordDenied() {
		t.Fatal("2nd recordDenied() = true, want false")
	}

	// Advance well past the window: the earlier two events should no longer
	// count, so a fresh burst of (budget) events should again not trip.
	now = now.Add(time.Minute)
	if g.recordDenied() {
		t.Fatal("recordDenied() after window rollover = true, want false (old events must expire)")
	}
	if g.recordDenied() {
		t.Fatal("2nd recordDenied() after rollover = true, want false")
	}
	if !g.recordDenied() {
		t.Fatal("3rd recordDenied() after rollover = false, want true (budget of 2 exceeded again)")
	}
}
