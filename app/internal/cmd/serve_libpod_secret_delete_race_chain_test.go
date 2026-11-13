package cmd

import (
	"net/http"
	"sync"
	"testing"
)

// TestServeChainLibpodSecretDeleteNameCannotFallThroughToForeignID has team-a
// create a secret named after a prefix of team-b's secret ID, then delete it
// twice at once.
//
// Podman's delete resolves like Lookup: exact name, then ID prefix. Both
// deletes pass owner isolation's inspect, which finds team-a's secret by name.
// The first one removes it, and the second one's lookup no longer finds the
// name, falls through to the ID prefix and removes team-b's secret. A
// path-targeted secret route naming something that could be a secret ID or a
// prefix of one is refused on Podman, so the name can't shadow the prefix.
func TestServeChainLibpodSecretDeleteNameCannotFallThroughToForeignID(t *testing.T) {
	daemon := newLibpodSecretPrefixChainDaemon()
	daemon.secrets["b0b0"] = chainStoredSecret{ID: "d0d0d0d0d0d0d0d0d0d0d0d04", Owner: "team-a", Data: "team-a shadow"}
	daemon.deleteGate = make(chan struct{}, 1)
	daemon.deleteGate <- struct{}{}
	daemon.deleteWG = &sync.WaitGroup{}
	daemon.deleteWG.Add(2)
	addr := secretPrefixChain(t, daemon)

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A refused delete never reaches the daemon, so release its slot
			// in the barrier.
			status := secretPrefixChainRequest(t, http.MethodDelete, "http://"+addr+"/v5.0.0/libpod/secrets/b0b0", "")
			if status == http.StatusForbidden {
				daemon.deleteWG.Done()
			}
		}()
	}
	wg.Wait()

	if _, ok := daemon.snapshot()["theirs"]; !ok {
		t.Errorf("team-b's secret was deleted through team-a's name: %+v", daemon.snapshot())
	}
}
