package buildkitproxy

import (
	"fmt"
	"sync"
	"testing"
)

// TestSessionRegistryManySessionsManyRefsConcurrentStress goes well beyond
// TestSessionRegistryPutRefRaceWithClose's 500-iteration Open/PutRef-vs-Close
// pairing (session_test.go): many goroutines, each cycling through many
// sessions, each session admitting many refs CONCURRENTLY (not just a single
// racing PutRef) before closing — exercising Open, PutRef, OwnsRef, and
// Close all firing against the same registry at once, across a spread of
// SessionKeys (so both same-key and cross-key concurrency happen). Run under
// `go test -race` per this package's validation gate.
func TestSessionRegistryManySessionsManyRefsConcurrentStress(t *testing.T) {
	const (
		numWorkers             = 50
		numSessionsPerWorker   = 20
		numRefsPerSession      = 10
		numDistinctSessionKeys = 5
	)

	reg := NewSessionRegistry()
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			key := SessionKey{
				ClientIdentity: fmt.Sprintf("client-%d", w%numDistinctSessionKeys),
				Profile:        fmt.Sprintf("profile-%d", w%3),
			}
			for s := 0; s < numSessionsPerWorker; s++ {
				sess := reg.Open(key, EndpointGRPC, "")

				var innerWG sync.WaitGroup
				for r := 0; r < numRefsPerSession; r++ {
					innerWG.Add(1)
					go func(r int) {
						defer innerWG.Done()
						ref := fmt.Sprintf("ref-%d-%d-%d", w, s, r)
						if !reg.PutRef(sess, ref, 0) {
							t.Errorf("worker %d session %d: PutRef(%q) = false, want true (no cap configured)", w, s, ref)
						}
						_ = reg.OwnsRef(key, ref)
					}(r)
				}
				innerWG.Wait()

				reg.Close(sess.ID)
			}
		}(w)
	}
	wg.Wait()

	if got := reg.Len(); got != 0 {
		t.Fatalf("registry.Len() = %d after every session closed, want 0", got)
	}
	if len(reg.refOwners) != 0 {
		t.Fatalf("refOwners still holds %d SessionKey entries after every session closed, want 0: %v", len(reg.refOwners), reg.refOwners)
	}
}

// TestSessionRegistrySharedKeyConcurrentPutCloseStress stresses the
// refcounting path specifically: many sessions sharing ONE SessionKey race
// to PutRef the exact same, overlapping set of ref strings and then Close —
// legitimate under refOwners' "more than one live Session sharing the same
// SessionKey may each PutRef the same ref string" design (registry.go's own
// doc comment). The registry-wide refcount for every shared ref must land
// at exactly zero (and be removed from refOwners entirely) once every
// sharing session has closed, regardless of the interleaving `go test -race`
// explores.
func TestSessionRegistrySharedKeyConcurrentPutCloseStress(t *testing.T) {
	const (
		numSessions    = 100
		refsPerSession = 5
	)

	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "shared-client", Profile: "shared-profile"}

	var wg sync.WaitGroup
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess := reg.Open(key, EndpointGRPC, "")
			for r := 0; r < refsPerSession; r++ {
				ref := fmt.Sprintf("shared-ref-%d", r)
				if !reg.PutRef(sess, ref, 0) {
					t.Errorf("session %d: PutRef(%q) = false, want true", i, ref)
				}
			}
			reg.Close(sess.ID)
		}(i)
	}
	wg.Wait()

	if got := reg.Len(); got != 0 {
		t.Fatalf("registry.Len() = %d after every sharing session closed, want 0", got)
	}
	for r := 0; r < refsPerSession; r++ {
		ref := fmt.Sprintf("shared-ref-%d", r)
		if reg.OwnsRef(key, ref) {
			t.Fatalf("OwnsRef(%q) = true after every sharing session closed, want false", ref)
		}
	}
	if owners, ok := reg.refOwners[key]; ok && len(owners) != 0 {
		t.Fatalf("refOwners[key] = %v after every sharing session closed, want empty/absent", owners)
	}
}

// TestSessionRegistryConcurrentOpenCloseChurnNeverPanics hammers Open/Close
// with no ref traffic at all — the plain session-lifecycle churn a client
// reconnecting rapidly (or an abusive one deliberately cycling connections)
// would produce — concurrently with a separate goroutine repeatedly calling
// Len/Get, so the registry's own bookkeeping map is read and written from
// many goroutines at once with no serialization beyond the registry's own
// locking. No assertion beyond "run clean under -race and never panic" is
// meaningful here (Len is inherently racy against concurrent Open/Close by
// design), but that alone is exactly what this test exists to check.
func TestSessionRegistryConcurrentOpenCloseChurnNeverPanics(t *testing.T) {
	const (
		numWorkers = 30
		numCycles  = 200
	)

	reg := NewSessionRegistry()
	stop := make(chan struct{})

	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = reg.Len()
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			key := SessionKey{ClientIdentity: fmt.Sprintf("churn-%d", w), Profile: "p"}
			for i := 0; i < numCycles; i++ {
				sess := reg.Open(key, EndpointGRPC, "")
				if _, ok := reg.Get(sess.ID); !ok {
					t.Errorf("worker %d cycle %d: Get() immediately after Open() = not found", w, i)
				}
				reg.Close(sess.ID)
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	readerWG.Wait()

	if got := reg.Len(); got != 0 {
		t.Fatalf("registry.Len() = %d after every churned session closed, want 0", got)
	}
}
