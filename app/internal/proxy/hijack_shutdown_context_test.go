package proxy

import (
	"context"
	"testing"
)

// TestHijackShutdownContextRoundTrip pins the shutdown signal plumbing: a
// context without one yields a nil channel, which never fires, and the
// channel installed by WithHijackShutdown is the one HijackShutdown returns.
func TestHijackShutdownContextRoundTrip(t *testing.T) {
	if got := HijackShutdown(context.Background()); got != nil {
		t.Fatalf("HijackShutdown(no signal) = %v, want nil", got)
	}
	done := make(chan struct{})
	got := HijackShutdown(WithHijackShutdown(context.Background(), done))
	if got == nil {
		t.Fatal("HijackShutdown lost the installed channel")
	}
	select {
	case <-got:
		t.Fatal("shutdown fired before the channel was closed")
	default:
	}
	close(done)
	select {
	case <-got:
	default:
		t.Fatal("closing the installed channel did not fire the returned one")
	}
}
