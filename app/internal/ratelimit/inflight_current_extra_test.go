package ratelimit

import (
	"testing"
)

// TestInflightTracker_CurrentEmptyClientIDNormalizesToAnonymous verifies that
// Current("") maps to the same bucket as Current(AnonymousClientID), mirroring
// the analogous behavior of Acquire and AllowN.
func TestInflightTracker_CurrentEmptyClientIDNormalizesToAnonymous(t *testing.T) {
	t.Parallel()
	var tr InflightTracker

	// Acquire under the empty clientID — internally stored as AnonymousClientID.
	ok, _ := tr.Acquire("", 5)
	if !ok {
		t.Fatal("Acquire(\"\", 5) should succeed")
	}

	// Current("") and Current(AnonymousClientID) must both return 1.
	if got := tr.Current(""); got != 1 {
		t.Fatalf("Current(\"\") = %d, want 1", got)
	}
	if got := tr.Current(AnonymousClientID); got != 1 {
		t.Fatalf("Current(%q) = %d, want 1 — empty clientID and AnonymousClientID must share the same counter", AnonymousClientID, got)
	}

	// Acquire one more under the explicit key and verify both views agree.
	ok, _ = tr.Acquire(AnonymousClientID, 5)
	if !ok {
		t.Fatal("Acquire(AnonymousClientID, 5) should succeed (count 2/5)")
	}
	if tr.Current("") != tr.Current(AnonymousClientID) {
		t.Fatalf("Current(\"\") = %d, Current(%q) = %d: must be equal",
			tr.Current(""), AnonymousClientID, tr.Current(AnonymousClientID))
	}
}

// TestInflightTracker_CurrentUnknownClientReturnsZero confirms that Current
// returns 0 for a clientID that has never been Acquired, rather than panicking
// or returning a stale value.
func TestInflightTracker_CurrentUnknownClientReturnsZero(t *testing.T) {
	t.Parallel()
	var tr InflightTracker

	if got := tr.Current("never-seen"); got != 0 {
		t.Fatalf("Current(\"never-seen\") = %d, want 0", got)
	}
	// Empty clientID is normalised to AnonymousClientID; that bucket also does
	// not exist yet, so it must also return 0.
	if got := tr.Current(""); got != 0 {
		t.Fatalf("Current(\"\") = %d, want 0 for unacquired anonymous bucket", got)
	}
}
