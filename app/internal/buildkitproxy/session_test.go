package buildkitproxy

import (
	"fmt"
	"sync"
	"testing"
)

// TestSessionRegistryOpenGetClose is left as a single sequential test rather
// than a table: Open -> Get -> Close -> Get -> double-Close is an ordered
// lifecycle where each step's assertions depend on the previous step having
// actually run, not an independent scenario a table entry could isolate.
func TestSessionRegistryOpenGetClose(t *testing.T) {
	reg := NewSessionRegistry()
	if reg.Len() != 0 {
		t.Fatalf("Len() = %d on a fresh registry, want 0", reg.Len())
	}

	key := SessionKey{ClientIdentity: "unix-peer-uid-1000", Profile: "ci"}
	s := reg.Open(key, EndpointGRPC, "client-uuid-abc")

	if s.ID == 0 {
		t.Error("Session.ID = 0, want a non-zero sockguard-assigned ID")
	}
	if s.Key != key {
		t.Errorf("Session.Key = %+v, want %+v", s.Key, key)
	}
	if s.Profile != key.Profile {
		t.Errorf("Session.Profile = %q, want %q (frozen from SessionKey.Profile at Open)", s.Profile, key.Profile)
	}
	if s.Endpoint != EndpointGRPC {
		t.Errorf("Session.Endpoint = %s, want %s", s.Endpoint, EndpointGRPC)
	}
	if s.ClientUUID != "client-uuid-abc" {
		t.Errorf("Session.ClientUUID = %q, want %q", s.ClientUUID, "client-uuid-abc")
	}
	if s.OpenedAt.IsZero() {
		t.Error("Session.OpenedAt is zero, want a real timestamp")
	}
	if s.Refs == nil {
		t.Error("Session.Refs is nil, want an initialized (empty) map")
	}

	if reg.Len() != 1 {
		t.Fatalf("Len() = %d after Open, want 1", reg.Len())
	}

	got, ok := reg.Get(s.ID)
	if !ok || got != s {
		t.Fatalf("Get(%d) = (%v, %v), want (%v, true)", s.ID, got, ok, s)
	}

	reg.Close(s.ID)
	if reg.Len() != 0 {
		t.Fatalf("Len() = %d after Close, want 0", reg.Len())
	}
	if _, ok := reg.Get(s.ID); ok {
		t.Fatal("Get() after Close = ok, want not found")
	}

	// Closing an already-closed (or never-opened) ID must be a harmless no-op.
	reg.Close(s.ID)
	reg.Close(999999)
}

// TestSessionRegistryDistinctSessionsNeverCollide tables the registry's two
// "must never collapse onto one record" scenarios: the same SessionKey
// opened twice (concurrent sessions from one client+profile), and two
// different clients presenting the identical attacker-chosen
// X-Docker-Expose-Session-Uuid — the #185 sign-off's "never UUID alone"
// requirement, since SessionKey (identity+profile), not ClientUUID, is the
// registry's trust boundary.
func TestSessionRegistryDistinctSessionsNeverCollide(t *testing.T) {
	cases := []struct {
		name      string
		key1      SessionKey
		endpoint1 Endpoint
		uuid1     string
		key2      SessionKey
		endpoint2 Endpoint
		uuid2     string
	}{
		{
			name:      "same SessionKey opened twice",
			key1:      SessionKey{ClientIdentity: "same-client", Profile: "same-profile"},
			endpoint1: EndpointGRPC,
			key2:      SessionKey{ClientIdentity: "same-client", Profile: "same-profile"},
			endpoint2: EndpointSession,
		},
		{
			name:      "different clients presenting the same client-supplied UUID",
			key1:      SessionKey{ClientIdentity: "client-a", Profile: "ci"},
			endpoint1: EndpointGRPC,
			uuid1:     "attacker-chosen-uuid",
			key2:      SessionKey{ClientIdentity: "client-b", Profile: "ci"},
			endpoint2: EndpointGRPC,
			uuid2:     "attacker-chosen-uuid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewSessionRegistry()
			s1 := reg.Open(tc.key1, tc.endpoint1, tc.uuid1)
			s2 := reg.Open(tc.key2, tc.endpoint2, tc.uuid2)

			if s1.ID == s2.ID {
				t.Fatalf("two Open() calls produced the same ID (%d) — the registry must never collapse distinct sessions onto one record", s1.ID)
			}
			if reg.Len() != 2 {
				t.Fatalf("Len() = %d, want 2 (both sessions must independently exist)", reg.Len())
			}
		})
	}
}

// TestSessionRegistryOtherSessionCannotOwnAnothersRef guards the Phase 3+
// invariant that ref ownership never leaks across identity/profile keys.
func TestSessionRegistryOtherSessionCannotOwnAnothersRef(t *testing.T) {
	reg := NewSessionRegistry()
	key1 := SessionKey{ClientIdentity: "a", Profile: "p"}
	key2 := SessionKey{ClientIdentity: "b", Profile: "p"}
	s1 := reg.Open(key1, EndpointGRPC, "")
	reg.Open(key2, EndpointGRPC, "")

	if !reg.PutRef(s1, "sha256:only-s1", 0) {
		t.Fatal("PutRef failed")
	}

	if !reg.OwnsRef(key1, "sha256:only-s1") {
		t.Fatal("admitting key does not own its ref")
	}
	if reg.OwnsRef(key2, "sha256:only-s1") {
		t.Fatal("unrelated key reports owning the ref")
	}
}

func TestSessionTryPutRef(t *testing.T) {
	reg := NewSessionRegistry()
	s := reg.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointGRPC, "")

	ok, isNew := s.tryPutRef("ref-1", 2)
	if !ok || !isNew {
		t.Fatalf("first tryPutRef(ref-1) = (%v, %v), want (true, true)", ok, isNew)
	}

	ok, isNew = s.tryPutRef("ref-1", 2)
	if !ok || isNew {
		t.Fatalf("repeat tryPutRef(ref-1) = (%v, %v), want (true, false)", ok, isNew)
	}

	ok, isNew = s.tryPutRef("ref-2", 2)
	if !ok || !isNew {
		t.Fatalf("tryPutRef(ref-2) at cap = (%v, %v), want (true, true)", ok, isNew)
	}

	ok, isNew = s.tryPutRef("ref-3", 2)
	if ok || isNew {
		t.Fatalf("tryPutRef(ref-3) over cap = (%v, %v), want (false, false)", ok, isNew)
	}

	// A repeat of an already-held ref is still admitted even once the
	// session is at capacity: the cap bounds distinct refs, not calls.
	ok, isNew = s.tryPutRef("ref-1", 2)
	if !ok || isNew {
		t.Fatalf("repeat tryPutRef(ref-1) at cap = (%v, %v), want (true, false)", ok, isNew)
	}

	// maxRefs <= 0 disables the cap entirely.
	ok, isNew = s.tryPutRef("ref-4", 0)
	if !ok || !isNew {
		t.Fatalf("tryPutRef with maxRefs<=0 = (%v, %v), want (true, true)", ok, isNew)
	}
}

func TestSessionRefsSnapshot(t *testing.T) {
	reg := NewSessionRegistry()
	s := reg.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointGRPC, "")

	if got := s.refsSnapshot(); len(got) != 0 {
		t.Fatalf("refsSnapshot() on a fresh session = %v, want empty", got)
	}

	if !reg.PutRef(s, "ref-1", 0) || !reg.PutRef(s, "ref-2", 0) {
		t.Fatal("PutRef failed")
	}

	got := s.refsSnapshot()
	want := map[string]bool{"ref-1": true, "ref-2": true}
	if len(got) != len(want) {
		t.Fatalf("refsSnapshot() = %v, want 2 entries matching %v", got, want)
	}
	for _, ref := range got {
		if !want[ref] {
			t.Errorf("refsSnapshot() contained unexpected ref %q", ref)
		}
	}
}

func TestSessionRegistryPutRefAndOwnsRef(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	s := reg.Open(key, EndpointGRPC, "")

	if reg.OwnsRef(key, "ref-1") {
		t.Fatal("OwnsRef before any PutRef = true, want false")
	}

	if !reg.PutRef(s, "ref-1", 2) {
		t.Fatal("PutRef(ref-1) = false, want true")
	}
	if !reg.OwnsRef(key, "ref-1") {
		t.Fatal("OwnsRef(ref-1) after PutRef = false, want true")
	}
	if reg.OwnsRef(key, "ref-unrelated") {
		t.Fatal("OwnsRef for an unrelated ref = true, want false")
	}

	// A repeated PutRef of the same ref must not double-count the
	// registry-wide refcount (see tryPutRef's doc comment) — verified
	// indirectly below via Close only needing one decrement to release it.
	if !reg.PutRef(s, "ref-1", 2) {
		t.Fatal("repeat PutRef(ref-1) = false, want true (idempotent)")
	}

	if !reg.PutRef(s, "ref-2", 2) {
		t.Fatal("PutRef(ref-2) at cap = false, want true")
	}
	if reg.PutRef(s, "ref-3", 2) {
		t.Fatal("PutRef(ref-3) over cap = true, want false")
	}
	if reg.OwnsRef(key, "ref-3") {
		t.Fatal("OwnsRef(ref-3) after a rejected PutRef = true, want false")
	}

	// A different SessionKey must never observe ownership of this key's ref.
	otherKey := SessionKey{ClientIdentity: "other", Profile: "p"}
	if reg.OwnsRef(otherKey, "ref-1") {
		t.Fatal("OwnsRef under a different SessionKey = true, want false")
	}
}

func TestSessionRegistryCloseReleasesRefs(t *testing.T) {
	t.Run("single session", func(t *testing.T) {
		reg := NewSessionRegistry()
		key := SessionKey{ClientIdentity: "c", Profile: "p"}
		s := reg.Open(key, EndpointGRPC, "")

		if !reg.PutRef(s, "ref-1", 0) {
			t.Fatal("PutRef(ref-1) = false, want true")
		}
		reg.Close(s.ID)

		if reg.OwnsRef(key, "ref-1") {
			t.Fatal("OwnsRef(ref-1) after Close = true, want false")
		}
		if _, ok := reg.refOwners[key]; ok {
			t.Fatal("refOwners still holds an entry for a key with no remaining refs")
		}
	})

	t.Run("closing a session with no refs is a no-op", func(t *testing.T) {
		reg := NewSessionRegistry()
		s := reg.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointGRPC, "")
		reg.Close(s.ID)
		if reg.Len() != 0 {
			t.Fatalf("Len() after Close = %d, want 0", reg.Len())
		}
	})

	t.Run("PutRef after Close is rejected without recording anything", func(t *testing.T) {
		// Deterministic (non-racy) coverage of PutRef's still-registered
		// gate — see TestSessionRegistryPutRefRaceWithClose below for the
		// actual concurrent regression test. Calling PutRef with a *Session
		// obtained before Close ran is exactly what a stream handler
		// goroutine racing tunnel teardown would observe.
		reg := NewSessionRegistry()
		key := SessionKey{ClientIdentity: "c", Profile: "p"}
		s := reg.Open(key, EndpointGRPC, "")
		reg.Close(s.ID)

		if reg.PutRef(s, "late-ref", 0) {
			t.Fatal("PutRef after Close = true, want false (session no longer registered)")
		}
		if reg.OwnsRef(key, "late-ref") {
			t.Fatal("registry-wide OwnsRef(late-ref) = true after a post-Close PutRef, want false")
		}
	})

	t.Run("two sessions sharing a key: closing one leaves the other's ref owned", func(t *testing.T) {
		reg := NewSessionRegistry()
		key := SessionKey{ClientIdentity: "c", Profile: "p"}
		s1 := reg.Open(key, EndpointGRPC, "")
		s2 := reg.Open(key, EndpointGRPC, "")

		if !reg.PutRef(s1, "shared-ref", 0) {
			t.Fatal("PutRef(shared-ref) on s1 = false, want true")
		}
		if !reg.PutRef(s2, "shared-ref", 0) {
			t.Fatal("PutRef(shared-ref) on s2 = false, want true")
		}

		reg.Close(s1.ID)
		if !reg.OwnsRef(key, "shared-ref") {
			t.Fatal("OwnsRef(shared-ref) after closing only s1 = false, want true (s2 still holds it)")
		}

		reg.Close(s2.ID)
		if reg.OwnsRef(key, "shared-ref") {
			t.Fatal("OwnsRef(shared-ref) after closing both sessions = true, want false")
		}
	})
}

// TestSessionRegistryPutRefRaceWithClose is the CodeRabbit-flagged
// concurrent regression test for the two PutRef-vs-Close races PutRef's own
// doc comment describes: (1) a PutRef landing after Close's refsSnapshot
// publishing an orphaned refOwners entry nothing will ever release, and
// (2) a tryPutRef insert landing between Close's r.sessions delete and its
// refsSnapshot, putting the ref into Close's release loop without it ever
// reaching refOwners — decrementing a count a still-open sibling session
// sharing the SessionKey legitimately holds. A sibling session holding the
// same ref throughout the race asserts both directions: its ownership must
// survive the racing pair, and closing it afterwards must fully release the
// index. Run under `go test -race` (per this package's validation gate) so
// a synchronization bug here is caught as a data race too, not just a
// logical assertion failure.
func TestSessionRegistryPutRefRaceWithClose(t *testing.T) {
	const iterations = 500
	key := SessionKey{ClientIdentity: "c", Profile: "p"}

	for i := 0; i < iterations; i++ {
		reg := NewSessionRegistry()
		sibling := reg.Open(key, EndpointGRPC, "")
		if !reg.PutRef(sibling, "race-ref", 0) {
			t.Fatalf("iteration %d: sibling PutRef(race-ref) = false, want true", i)
		}
		s := reg.Open(key, EndpointGRPC, "")

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			reg.PutRef(s, "race-ref", 0)
		}()
		go func() {
			defer wg.Done()
			reg.Close(s.ID)
		}()
		wg.Wait()

		if !reg.OwnsRef(key, "race-ref") {
			t.Fatalf("iteration %d: OwnsRef(race-ref) = false while the sibling session still holds it — Close raced PutRef into releasing a count the closing session never contributed", i)
		}

		reg.Close(sibling.ID)
		if reg.OwnsRef(key, "race-ref") {
			t.Fatalf("iteration %d: OwnsRef(race-ref) = true after every session closed — orphaned refOwners entry", i)
		}
		if owners, ok := reg.refOwners[key]; ok && len(owners) != 0 {
			t.Fatalf("iteration %d: refOwners[key] = %v after every session closed, want empty/absent", i, owners)
		}
	}
}

func TestSessionRegistryHasAdmittedSolve(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	s := reg.Open(key, EndpointGRPC, "")

	if reg.HasAdmittedSolve(key, testBuildkitSessionID) {
		t.Fatal("HasAdmittedSolve() = true before any Solve admission, want false")
	}
	if got := reg.admitSolve(s, testBuildkitSessionID, "ref-1", nil, 0, 0); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	if !reg.HasAdmittedSolve(key, testBuildkitSessionID) {
		t.Fatal("HasAdmittedSolve() = false after a Solve admission, want true")
	}
}

func TestSessionRegistryHasAdmittedSolveIsPerKey(t *testing.T) {
	reg := NewSessionRegistry()
	key1 := SessionKey{ClientIdentity: "c1", Profile: "p"}
	key2 := SessionKey{ClientIdentity: "c2", Profile: "p"}
	s1 := reg.Open(key1, EndpointGRPC, "")
	reg.admitSolve(s1, testBuildkitSessionID, "ref-1", nil, 0, 0)

	if reg.HasAdmittedSolve(key2, testBuildkitSessionID) {
		t.Fatal("HasAdmittedSolve(key2) = true, want false — key2 never admitted anything")
	}
}

func TestSessionRegistryAdmitSolveFirstUploadAdmissionSucceeds(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := reg.Open(key, EndpointGRPC, "")

	if got := reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-1"}, 0, 0); got != solveAdmissionSucceeded {
		t.Fatalf("AdmitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	if !reg.ConsumeUploadKey(key, testBuildkitSessionID, "id-1") {
		t.Fatal("ConsumeUploadKey() = false for a freshly admitted id, want true")
	}
}

func TestSessionRegistryAdmitSolveDuplicateUploadIDIsIdempotent(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := reg.Open(key, EndpointGRPC, "")

	if got := reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-1"}, 0, 1); got != solveAdmissionSucceeded {
		t.Fatalf("first AdmitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	// A duplicate admission of the SAME id, even with maxKeys already at its
	// bound, is a harmless no-op success — it must not count as a second
	// key toward maxKeys.
	if got := reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-1"}, 0, 1); got != solveAdmissionSucceeded {
		t.Fatalf("duplicate AdmitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	if got := reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-2"}, 0, 1); got != solveAdmissionUploadLimitExceeded {
		t.Fatalf("AdmitSolve() for a new id = %v, want solveAdmissionUploadLimitExceeded", got)
	}
}

func TestSessionRegistryAdmitSolveRespectsMaxUploadKeysBound(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := reg.Open(key, EndpointGRPC, "")

	if got := reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-1", "id-2"}, 0, 2); got != solveAdmissionSucceeded {
		t.Fatalf("AdmitSolve() at cap = %v, want solveAdmissionSucceeded", got)
	}
	if got := reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-3"}, 0, 2); got != solveAdmissionUploadLimitExceeded {
		t.Fatalf("AdmitSolve() over cap = %v, want solveAdmissionUploadLimitExceeded", got)
	}
}

func TestSessionRegistryAdmitSolveMaxUploadKeysZeroOrNegativeDisablesBound(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := reg.Open(key, EndpointGRPC, "")

	for i, maxKeys := range []int{0, -1} {
		id := fmt.Sprintf("id-%d", i)
		if got := reg.admitSolve(session, testBuildkitSessionID, fmt.Sprintf("ref-%d", i), []string{id}, 0, maxKeys); got != solveAdmissionSucceeded {
			t.Fatalf("AdmitSolve(%q, maxKeys=%d) = %v, want solveAdmissionSucceeded", id, maxKeys, got)
		}
	}
}

func TestSessionRegistryConsumeUploadKeyIsOneUse(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := reg.Open(key, EndpointGRPC, "")
	reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-1"}, 0, 0)

	if !reg.ConsumeUploadKey(key, testBuildkitSessionID, "id-1") {
		t.Fatal("first ConsumeUploadKey() = false, want true")
	}
	if reg.ConsumeUploadKey(key, testBuildkitSessionID, "id-1") {
		t.Fatal("second ConsumeUploadKey() for the same id = true, want false — one-use")
	}
}

func TestSessionRegistryConsumeUploadKeyNeverAdmitted(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}

	if reg.ConsumeUploadKey(key, testBuildkitSessionID, "never-admitted") {
		t.Fatal("ConsumeUploadKey() for a never-admitted id = true, want false")
	}
}

func TestSessionRegistryConsumeUploadKeyUnknownIDUnderKnownKey(t *testing.T) {
	// key DOES have an entry in uploadKeys (from admitting "id-1"), but
	// "id-2" was never admitted under it — distinct from both "unknown key
	// entirely" and "id-1 admitted, then consumed twice" above.
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := reg.Open(key, EndpointGRPC, "")
	reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-1"}, 0, 0)

	if reg.ConsumeUploadKey(key, testBuildkitSessionID, "id-2") {
		t.Fatal("ConsumeUploadKey() for an unadmitted id under a known key = true, want false")
	}
}

func TestSessionRegistryConsumeUploadKeyUnknownKey(t *testing.T) {
	reg := NewSessionRegistry()
	// No admitted Solve at all for this key — reg.uploadKeys has no
	// entry for it whatsoever, exercising ConsumeUploadKey's "key not
	// present at all" branch distinctly from "id not present under a known
	// key" above.
	if reg.ConsumeUploadKey(SessionKey{ClientIdentity: "nobody", Profile: "p"}, testBuildkitSessionID, "id-1") {
		t.Fatal("ConsumeUploadKey() for an unknown SessionKey = true, want false")
	}
}

func TestSessionRegistryConsumeUploadKeyCleansUpEmptyMapEntry(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := reg.Open(key, EndpointGRPC, "")
	reg.admitSolve(session, testBuildkitSessionID, "ref-1", []string{"id-1"}, 0, 0)
	reg.ConsumeUploadKey(key, testBuildkitSessionID, "id-1")

	if _, ok := reg.uploadKeys[buildkitSessionKey{Principal: key, ID: testBuildkitSessionID}]; ok {
		t.Fatal("reg.uploadKeys[key] still present after its last key was consumed, want the map entry removed")
	}
}

func TestSessionRegistryConsumeUploadKeyRace(t *testing.T) {
	const iterations = 500
	key := SessionKey{ClientIdentity: "c", Profile: "p"}

	for i := 0; i < iterations; i++ {
		reg := NewSessionRegistry()
		session := reg.Open(key, EndpointGRPC, "")
		reg.admitSolve(session, testBuildkitSessionID, "race-ref", []string{"race-id"}, 0, 0)

		var wg sync.WaitGroup
		wg.Add(2)
		successes := make(chan bool, 2)
		go func() {
			defer wg.Done()
			successes <- reg.ConsumeUploadKey(key, testBuildkitSessionID, "race-id")
		}()
		go func() {
			defer wg.Done()
			successes <- reg.ConsumeUploadKey(key, testBuildkitSessionID, "race-id")
		}()
		wg.Wait()
		close(successes)

		successCount := 0
		for ok := range successes {
			if ok {
				successCount++
			}
		}
		if successCount != 1 {
			t.Fatalf("iteration %d: %d concurrent ConsumeUploadKey calls succeeded, want exactly 1 — one-use must hold under a race", i, successCount)
		}
	}
}
