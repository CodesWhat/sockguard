package cmd

import (
	"context"
	"errors"
	"testing"
)

// TestHijackTrackerJoinsHandlersFromAZeroValue pins the handler join on a
// tracker whose handler map was never allocated: a reservation is counted, a
// join that times out reports it as still running, and once it ends the join
// returns at once. A reservation made after shutdown started is counted too
// and its cancel runs immediately.
func TestHijackTrackerJoinsHandlersFromAZeroValue(t *testing.T) {
	tracker := &hijackedConnTracker{}
	canceled := 0
	id := tracker.beginHandler(func() { canceled++ })
	if id == 0 || canceled != 0 {
		t.Fatalf("beginHandler id = %d canceled = %d, want a non-zero id and no cancel", id, canceled)
	}

	expired, cancel := context.WithCancel(context.Background())
	cancel()
	remaining, err := tracker.waitHandlers(expired)
	if remaining != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("waitHandlers on expiry = %d, %v; want 1 still running and context.Canceled", remaining, err)
	}

	tracker.endHandler(id)
	if remaining, err := tracker.waitHandlers(context.Background()); remaining != 0 || err != nil {
		t.Fatalf("waitHandlers after end = %d, %v; want 0, nil", remaining, err)
	}

	tracker.mu.Lock()
	tracker.closed = true
	tracker.mu.Unlock()
	late := tracker.beginHandler(func() { canceled++ })
	if late == 0 || canceled != 1 {
		t.Fatalf("late beginHandler id = %d canceled = %d, want a counted reservation canceled at once", late, canceled)
	}
	if remaining, _ := tracker.waitHandlers(expired); remaining != 1 {
		t.Fatalf("late reservation remaining = %d, want 1 until it ends", remaining)
	}
	tracker.endHandler(late)
}
