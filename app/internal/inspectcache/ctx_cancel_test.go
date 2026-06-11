package inspectcache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A coalesced waiter must honor its own context: when another caller's
// resolve is slow, a waiter whose context is canceled returns promptly with
// ctx.Err() instead of blocking until the in-flight call completes.
func TestLookupWaiterHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	resolverStarted := make(chan struct{})
	cache := New(DefaultTTL, DefaultMaxSize, time.Now,
		func(_ context.Context, _, _ string) (map[string]string, bool, error) {
			close(resolverStarted)
			<-release
			return map[string]string{"k": "v"}, true, nil
		},
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, found, err := cache.Lookup(context.Background(), "container", "abc"); err != nil || !found {
			t.Errorf("first Lookup = found %v, err %v; want found true, nil", found, err)
		}
	}()

	<-resolverStarted

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	var waiterErr error
	go func() {
		defer close(done)
		_, _, waiterErr = cache.Lookup(ctx, "container", "abc")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter still blocked after 2s — ctx cancellation not honored")
	}
	if !errors.Is(waiterErr, context.Canceled) {
		t.Fatalf("waiter err = %v, want context.Canceled", waiterErr)
	}

	// The in-flight resolve is unaffected: release it and the first caller
	// completes normally (and the result is memoized for future lookups).
	close(release)
	wg.Wait()

	labels, found, err := cache.Lookup(context.Background(), "container", "abc")
	if err != nil || !found || labels["k"] != "v" {
		t.Fatalf("post-release Lookup = %v, %v, %v; want cached value", labels, found, err)
	}
}
