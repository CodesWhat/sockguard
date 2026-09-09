package clientacl

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientCacheWaiterCancellationPreservesSharedLookup(t *testing.T) {
	for _, useDeadline := range []bool{false, true} {
		name := "canceled"
		if useDeadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			var workers sync.WaitGroup
			var calls atomic.Int32
			ownerCtx, cancelOwner := context.WithCancel(context.Background())
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(release) })
				workers.Wait()
				cancelOwner()
			})
			cache := newClientCache(time.Minute, 8, time.Now, func(ctx context.Context, _ netip.Addr) (resolvedClient, bool, error) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				return resolvedClient{ID: "shared-client"}, true, ctx.Err()
			})
			addr := mustAddr(t, "10.0.0.8")
			type result struct {
				client resolvedClient
				found  bool
				err    error
			}
			ownerResult := make(chan result, 1)
			workers.Go(func() {
				client, found, err := cache.Lookup(ownerCtx, addr)
				ownerResult <- result{client, found, err}
			})
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("owner resolver did not start")
			}

			// Joining under the cache lock makes the waiter registration observable
			// without sleeps or releasing the blocked shared resolver.
			join := func(ctx context.Context) <-chan result {
				done := make(chan result, 1)
				joining := make(chan struct{})
				workers.Go(func() {
					cache.mu.Lock()
					close(joining)
					client, found, err := cache.resolveAndStoreLocked(ctx, addr)
					done <- result{client, found, err}
				})
				<-joining
				cache.mu.Lock()
				_, inFlight := cache.inFlight[addr]
				cache.mu.Unlock()
				if !inFlight {
					t.Fatal("joining waiter removed the shared lookup")
				}
				return done
			}
			liveResult := join(context.Background())
			var waiterCtx context.Context
			var cancelWaiter context.CancelFunc
			wantErr := context.Canceled
			if useDeadline {
				waiterCtx, cancelWaiter = context.WithTimeout(context.Background(), 50*time.Millisecond)
				wantErr = context.DeadlineExceeded
			} else {
				waiterCtx, cancelWaiter = context.WithCancel(context.Background())
			}
			defer cancelWaiter()
			waiterResult := join(waiterCtx)
			if !useDeadline {
				cancelWaiter()
			}
			select {
			case got := <-waiterResult:
				if !errors.Is(got.err, wantErr) || got.found || got.client.ID != "" {
					t.Fatalf("waiter result = %+v, want empty result and %v", got, wantErr)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled waiter remains blocked while shared resolver is active")
			}
			if ownerCtx.Err() != nil {
				t.Fatalf("waiter canceled owner context: %v", ownerCtx.Err())
			}
			for _, done := range []<-chan result{ownerResult, liveResult} {
				select {
				case got := <-done:
					t.Fatalf("live lookup finished before resolver release: %+v", got)
				default:
				}
			}
			releaseOnce.Do(func() { close(release) })
			for _, done := range []<-chan result{ownerResult, liveResult} {
				select {
				case got := <-done:
					if got.err != nil || !got.found || got.client.ID != "shared-client" {
						t.Fatalf("live lookup result = %+v", got)
					}
				case <-time.After(time.Second):
					t.Fatal("live lookup did not receive shared result")
				}
			}
			client, found, err := cache.Lookup(context.Background(), addr)
			if err != nil || !found || client.ID != "shared-client" || calls.Load() != 1 {
				t.Fatalf("cached lookup = (%+v, %v, %v), resolver calls=%d", client, found, err, calls.Load())
			}
		})
	}
}
