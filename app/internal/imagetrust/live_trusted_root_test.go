package imagetrust

import (
	"errors"
	"sync"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// stubTrustedMaterial is a distinguishable root.TrustedMaterial instance used
// to check LoadLiveTrustedRoot's memoization by pointer identity rather than
// by value equality.
type stubTrustedMaterial struct {
	root.BaseTrustedMaterial
	id int
}

// withStubbedLiveTrustedRootBuilder swaps the package-level TUF trust-root
// builder for build during t, then restores the original builder and
// memoized state on cleanup so other tests in this package are unaffected.
func withStubbedLiveTrustedRootBuilder(t *testing.T, build func() (root.TrustedMaterial, error)) {
	t.Helper()
	liveTrustedRootMu.Lock()
	origBuilder := newLiveTrustedRoot
	origMat := liveTrustedRootMat
	newLiveTrustedRoot = build
	liveTrustedRootMat = nil
	liveTrustedRootMu.Unlock()

	t.Cleanup(func() {
		liveTrustedRootMu.Lock()
		newLiveTrustedRoot = origBuilder
		liveTrustedRootMat = origMat
		liveTrustedRootMu.Unlock()
	})
}

// TestLoadLiveTrustedRoot_MemoizesAcrossReloads is a regression test for the
// TUF background-refresh goroutine leak: root.NewLiveTrustedRoot spawns a
// goroutine (with a 24h ticker) that never exits because
// tuf.DefaultOptions() never sets a context, and before this fix
// LoadLiveTrustedRoot called it fresh on every invocation. Config hot-reload
// rebuilds image-trust policy — and therefore called LoadLiveTrustedRoot — on
// every reload regardless of whether image_trust changed, so each reload
// leaked another goroutine. This asserts LoadLiveTrustedRoot builds the trust
// root at most once across many simulated reloads and always hands back the
// same instance.
func TestLoadLiveTrustedRoot_MemoizesAcrossReloads(t *testing.T) {
	var calls int
	stub := &stubTrustedMaterial{id: 1}
	withStubbedLiveTrustedRootBuilder(t, func() (root.TrustedMaterial, error) {
		calls++
		return stub, nil
	})

	const simulatedReloads = 5
	for i := 0; i < simulatedReloads; i++ {
		tm, err := LoadLiveTrustedRoot()
		if err != nil {
			t.Fatalf("reload %d: LoadLiveTrustedRoot: %v", i, err)
		}
		if tm != root.TrustedMaterial(stub) {
			t.Fatalf("reload %d: LoadLiveTrustedRoot returned a different instance than the memoized singleton", i)
		}
	}
	if calls != 1 {
		t.Fatalf("underlying TUF trust-root builder called %d times across %d reloads, want exactly 1 (each call spawns a new never-exiting background refresh goroutine)", calls, simulatedReloads)
	}
}

// TestLoadLiveTrustedRoot_ConcurrentCallersShareOneBuild simulates the
// multiple call sites that invoke LoadLiveTrustedRoot for the same reload
// (once per client profile and once per request-body surface configuring
// keyless identities): concurrent callers must still only trigger one build.
func TestLoadLiveTrustedRoot_ConcurrentCallersShareOneBuild(t *testing.T) {
	var calls int
	var mu sync.Mutex
	stub := &stubTrustedMaterial{id: 2}
	withStubbedLiveTrustedRootBuilder(t, func() (root.TrustedMaterial, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return stub, nil
	})

	const concurrentCallers = 8
	var wg sync.WaitGroup
	wg.Add(concurrentCallers)
	for i := 0; i < concurrentCallers; i++ {
		go func() {
			defer wg.Done()
			if _, err := LoadLiveTrustedRoot(); err != nil {
				t.Errorf("LoadLiveTrustedRoot: %v", err)
			}
		}()
	}
	wg.Wait()

	if calls != 1 {
		t.Fatalf("underlying TUF trust-root builder called %d times across %d concurrent callers, want exactly 1", calls, concurrentCallers)
	}
}

// TestLoadLiveTrustedRoot_FailureIsNotMemoized ensures a failed build (e.g. no
// network yet at startup) is retried on the next call rather than permanently
// denying every keyless verification for the rest of the process's life.
func TestLoadLiveTrustedRoot_FailureIsNotMemoized(t *testing.T) {
	var calls int
	buildErr := errors.New("tuf mirror unreachable")
	stub := &stubTrustedMaterial{id: 3}
	withStubbedLiveTrustedRootBuilder(t, func() (root.TrustedMaterial, error) {
		calls++
		if calls == 1 {
			return nil, buildErr
		}
		return stub, nil
	})

	if _, err := LoadLiveTrustedRoot(); !errors.Is(err, buildErr) {
		t.Fatalf("first call: err = %v, want %v", err, buildErr)
	}
	tm, err := LoadLiveTrustedRoot()
	if err != nil {
		t.Fatalf("second call: LoadLiveTrustedRoot: %v", err)
	}
	if tm != root.TrustedMaterial(stub) {
		t.Fatal("second call did not retry after the first failure")
	}
	if calls != 2 {
		t.Fatalf("underlying TUF trust-root builder called %d times, want exactly 2 (one failed attempt, one retry)", calls)
	}
}
