package buildkitproxy

import (
	"testing"
	"time"
)

func TestSessionRegistryNilClockFallsBackToWallTime(t *testing.T) {
	t.Parallel()
	r := NewSessionRegistry()
	fixed := time.Unix(1000, 0)
	r.setNow(func() time.Time { return fixed })
	r.mu.Lock()
	got := r.currentTimeLocked()
	r.mu.Unlock()
	if !got.Equal(fixed) {
		t.Fatalf("injected clock ignored: %v", got)
	}

	r.setNow(nil)
	r.mu.Lock()
	got = r.currentTimeLocked()
	r.mu.Unlock()
	if time.Since(got) > time.Minute || time.Since(got) < -time.Minute {
		t.Fatalf("nil clock should restore wall time, got %v", got)
	}

	r.now = nil
	r.mu.Lock()
	got = r.currentTimeLocked()
	r.mu.Unlock()
	if time.Since(got) > time.Minute || time.Since(got) < -time.Minute {
		t.Fatalf("unset clock should read wall time, got %v", got)
	}
}
