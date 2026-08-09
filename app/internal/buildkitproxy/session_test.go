package buildkitproxy

import (
	"testing"
)

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

func TestSessionRegistryAssignsDistinctIDs(t *testing.T) {
	reg := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "same-client", Profile: "same-profile"}

	s1 := reg.Open(key, EndpointGRPC, "")
	s2 := reg.Open(key, EndpointSession, "")

	if s1.ID == s2.ID {
		t.Fatalf("two Open() calls with the identical SessionKey produced the same ID (%d) — the registry must never collapse concurrent sessions from the same client+profile onto one record", s1.ID)
	}
	if reg.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", reg.Len())
	}
}

func TestSessionRegistryNeverKeysOnClientUUIDAlone(t *testing.T) {
	// Two different clients presenting the SAME client-supplied UUID must not
	// collide in the registry — the #185 sign-off's "never UUID alone"
	// requirement. SessionKey (identity+profile), not ClientUUID, is the
	// registry's trust boundary; ClientUUID is advisory metadata only.
	reg := NewSessionRegistry()
	sameUUID := "attacker-chosen-uuid"

	s1 := reg.Open(SessionKey{ClientIdentity: "client-a", Profile: "ci"}, EndpointGRPC, sameUUID)
	s2 := reg.Open(SessionKey{ClientIdentity: "client-b", Profile: "ci"}, EndpointGRPC, sameUUID)

	if s1.ID == s2.ID {
		t.Fatal("two different clients presenting the same X-Docker-Expose-Session-Uuid collided on one Session ID")
	}
	if reg.Len() != 2 {
		t.Fatalf("Len() = %d, want 2 (both sessions must independently exist)", reg.Len())
	}
}

func TestSessionPutRefAndOwnsRef(t *testing.T) {
	reg := NewSessionRegistry()
	s := reg.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointGRPC, "")

	if s.OwnsRef("sha256:abc") {
		t.Fatal("OwnsRef() before any PutRef = true, want false")
	}

	s.PutRef("sha256:abc")
	if !s.OwnsRef("sha256:abc") {
		t.Fatal("OwnsRef() after PutRef = false, want true")
	}
	if s.OwnsRef("sha256:different") {
		t.Fatal("OwnsRef() for an unrelated ref = true, want false")
	}

	ref, ok := s.Refs["sha256:abc"]
	if !ok {
		t.Fatal("Refs map does not contain the ref PutRef recorded")
	}
	if ref.Ref != "sha256:abc" {
		t.Errorf("RefState.Ref = %q, want %q", ref.Ref, "sha256:abc")
	}
	if ref.OpenedAt.IsZero() {
		t.Error("RefState.OpenedAt is zero, want a real timestamp")
	}
}

// TestSessionRegistryOtherSessionCannotOwnAnothersRef guards the Phase 3+
// invariant this skeleton exists for: two independent sessions' ref sets
// never leak into each other.
func TestSessionRegistryOtherSessionCannotOwnAnothersRef(t *testing.T) {
	reg := NewSessionRegistry()
	s1 := reg.Open(SessionKey{ClientIdentity: "a", Profile: "p"}, EndpointGRPC, "")
	s2 := reg.Open(SessionKey{ClientIdentity: "b", Profile: "p"}, EndpointGRPC, "")

	s1.PutRef("sha256:only-s1")

	if s2.OwnsRef("sha256:only-s1") {
		t.Fatal("session s2 reports owning a ref only s1 ever recorded")
	}
}
