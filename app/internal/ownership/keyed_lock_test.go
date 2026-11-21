package ownership

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

func volumeKey(name string) lockKey { return lockKey{kind: dockerresource.KindVolume, name: name} }

func TestKeyedLocksSerializeOneKeyAndDropEntries(t *testing.T) {
	locks := NewKeyedLocks(time.Second, 0)
	var inside, maxInside int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := locks.Acquire(context.Background(), []lockKey{volumeKey("v")})
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			mu.Lock()
			inside++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Errorf("holders at once = %d, want 1", maxInside)
	}
	if n := locks.size(); n != 0 {
		t.Errorf("entries after release = %d, want 0 (no leak)", n)
	}
}

func TestKeyedLocksDifferentKeysAndKindsDoNotBlock(t *testing.T) {
	locks := NewKeyedLocks(50*time.Millisecond, 0)
	release, err := locks.Acquire(context.Background(), []lockKey{volumeKey("x")})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	other, err := locks.Acquire(context.Background(), []lockKey{{kind: dockerresource.KindNetwork, name: "x"}, volumeKey("y")})
	if err != nil {
		t.Fatalf("a different kind or name blocked: %v", err)
	}
	other()
}

func TestKeyedLocksTimeoutFailsClosedAndCleansUp(t *testing.T) {
	locks := NewKeyedLocks(20*time.Millisecond, 0)
	release, err := locks.Acquire(context.Background(), []lockKey{volumeKey("a")})
	if err != nil {
		t.Fatal(err)
	}
	// The second key is free, and must be handed back when the first times out.
	if _, err := locks.Acquire(context.Background(), []lockKey{volumeKey("0free"), volumeKey("a")}); !errors.Is(err, errLockTimeout) {
		t.Fatalf("err = %v, want errLockTimeout", err)
	}
	release()
	if n := locks.size(); n != 0 {
		t.Errorf("entries after timeout and release = %d, want 0", n)
	}
	again, err := locks.Acquire(context.Background(), []lockKey{volumeKey("0free")})
	if err != nil {
		t.Fatalf("key taken before the timeout was not released: %v", err)
	}
	again()
}

func TestKeyedLocksCanceledContextStopsWaiting(t *testing.T) {
	locks := NewKeyedLocks(time.Minute, 0)
	release, _ := locks.Acquire(context.Background(), []lockKey{volumeKey("a")})
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := locks.Acquire(ctx, []lockKey{volumeKey("a")}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestKeyedLocksBoundTotalKeys(t *testing.T) {
	locks := NewKeyedLocks(time.Second, 2)
	r1, _ := locks.Acquire(context.Background(), []lockKey{volumeKey("a"), volumeKey("b")})
	if _, err := locks.Acquire(context.Background(), []lockKey{volumeKey("c")}); !errors.Is(err, errLockCapacity) {
		t.Fatalf("err = %v, want errLockCapacity", err)
	}
	r1()
	r2, err := locks.Acquire(context.Background(), []lockKey{volumeKey("c")})
	if err != nil {
		t.Fatalf("capacity not returned on release: %v", err)
	}
	r2()
}

func TestKeyedLocksOverlappingSetsDoNotDeadlock(t *testing.T) {
	locks := NewKeyedLocks(5*time.Second, 0)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		keys := []lockKey{volumeKey("a"), volumeKey("b"), volumeKey("a")}
		if i%2 == 1 {
			keys = []lockKey{volumeKey("b"), volumeKey("a")}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := locks.Acquire(context.Background(), keys)
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			release()
			release() // idempotent
		}()
	}
	wg.Wait()
	if n := locks.size(); n != 0 {
		t.Errorf("entries = %d, want 0", n)
	}
}

func TestNormalizeLockNameMatchesDaemonComparison(t *testing.T) {
	for _, tt := range []struct {
		kind       dockerresource.Kind
		in, wanted string
	}{
		{dockerresource.KindContainer, "/web", "web"},
		{dockerresource.KindContainer, "web", "web"},
		{dockerresource.KindLibpodPod, "/p", "p"},
		{dockerresource.KindVolume, "/v", "/v"},
		{dockerresource.KindSecret, "Name", "Name"},
	} {
		if got := normalizeLockName(tt.kind, tt.in); got != tt.wanted {
			t.Errorf("normalizeLockName(%s, %q) = %q, want %q", tt.kind, tt.in, got, tt.wanted)
		}
	}
	refs := &ownershipRequestReferences{}
	refs.addLockName(dockerresource.KindContainer, "")
	refs.addLockName(dockerresource.KindContainer, "/web")
	refs.addLockName(dockerresource.KindContainer, "web")
	keys := lockKeysFor(refs)
	if len(keys) != 2 || keys[0] != keys[1] {
		t.Errorf("keys = %v, want the two spellings to be one key and the empty name skipped", keys)
	}
	if lockKeysFor(nil) != nil {
		t.Error("nil refs must lock nothing")
	}
}

func TestAcquireCreateLocksRefusals(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", nil)
	refs := &ownershipRequestReferences{}
	refs.addLockName(dockerresource.KindVolume, "v")

	// No lock set: nothing is held and nothing is refused.
	if release, ok := acquireCreateLocks(httptest.NewRecorder(), req, Options{}, refs); !ok {
		t.Fatal("no lock set refused")
	} else {
		release()
	}

	locks := NewKeyedLocks(10*time.Millisecond, 1)
	opts := Options{Locks: locks}
	hold, ok := acquireCreateLocks(httptest.NewRecorder(), req, opts, refs)
	if !ok {
		t.Fatal("first acquire refused")
	}
	rec := httptest.NewRecorder()
	if _, ok := acquireCreateLocks(rec, req, opts, refs); ok || rec.Code != http.StatusServiceUnavailable {
		t.Errorf("held name: ok=%v status=%d, want refusal 503", ok, rec.Code)
	}
	other := &ownershipRequestReferences{}
	other.addLockName(dockerresource.KindVolume, "w")
	rec = httptest.NewRecorder()
	if _, ok := acquireCreateLocks(rec, req, opts, other); ok || rec.Code != http.StatusServiceUnavailable {
		t.Errorf("full table: ok=%v status=%d, want refusal 503", ok, rec.Code)
	}
	hold()

	many := &ownershipRequestReferences{}
	for i := 0; i <= maxLockKeysPerRequest; i++ {
		many.addLockName(dockerresource.KindVolume, string(rune('a'+i%26))+string(rune('A'+i/26)))
	}
	rec = httptest.NewRecorder()
	if _, ok := acquireCreateLocks(rec, req, Options{Locks: NewKeyedLocks(0, 0)}, many); ok || rec.Code != http.StatusServiceUnavailable {
		t.Errorf("oversized set: ok=%v status=%d, want refusal 503", ok, rec.Code)
	}
}
