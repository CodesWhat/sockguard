package buildkitproxy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
)

func TestBuildkitSessionIDValidationBoundaries(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "one byte", id: "a", want: true},
		{name: "maximum length", id: strings.Repeat("a", 256), want: true},
		{name: "missing", id: "", want: false},
		{name: "over maximum length", id: strings.Repeat("a", 257), want: false},
		{name: "path separator", id: "session/other", want: false},
		{name: "leading whitespace", id: " session", want: false},
		{name: "non ASCII", id: "session-é", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newUpgradeRequest(t, "/session")
			req.Header.Set(sessionUUIDHeader, tt.id)
			got, ok := buildkitSessionID(req)
			if ok != tt.want {
				t.Fatalf("buildkitSessionID(%q) valid = %v, want %v", tt.id, ok, tt.want)
			}
			if ok && got != tt.id {
				t.Fatalf("buildkitSessionID(%q) = %q, want exact unmodified identifier", tt.id, got)
			}
		})
	}
}

func TestSolveRejectsInvalidBuildkitSessionIDs(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "one byte", id: "a", want: true},
		{name: "maximum length", id: strings.Repeat("a", 256), want: true},
		{name: "missing", id: "", want: false},
		{name: "over maximum length", id: strings.Repeat("a", 257), want: false},
		{name: "path separator", id: "session/other", want: false},
		{name: "embedded whitespace", id: "session other", want: false},
		{name: "non ASCII", id: "session-é", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mustMarshal(t, &control.SolveRequest{Ref: "ref", Session: tt.id})
			_, denial := evaluateSolveRequest(payload, allowAllPolicy)
			if got := denial == nil; got != tt.want {
				t.Fatalf("Solve.Session %q admitted = %v, want %v; denial = %#v", tt.id, got, tt.want, denial)
			}
		})
	}
}

func TestSolveRefLengthBoundaries(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want bool
	}{
		{name: "one byte", ref: "r", want: true},
		{name: "maximum length", ref: strings.Repeat("r", 256), want: true},
		{name: "missing", ref: "", want: false},
		{name: "over maximum length", ref: strings.Repeat("r", 257), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mustMarshal(t, &control.SolveRequest{Ref: tt.ref, Session: testBuildkitSessionID})
			_, denial := evaluateSolveRequest(payload, allowAllPolicy)
			if got := denial == nil; got != tt.want {
				t.Fatalf("Solve.Ref length %d admitted = %v, want %v; denial = %#v", len(tt.ref), got, tt.want, denial)
			}
		})
	}
}

func TestAdmitSolveUploadIDLengthBoundariesAreAtomic(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "principal", Profile: "builder"}
	session := registry.Open(key, EndpointGRPC, "")

	maxID := strings.Repeat("u", 256)
	if got := registry.admitSolve(session, testBuildkitSessionID, "ref-at-boundary", []string{maxID}, 2, 2); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve(maximum upload ID) = %v, want solveAdmissionSucceeded", got)
	}

	overID := strings.Repeat("u", 257)
	if got := registry.admitSolve(session, testBuildkitSessionID, "ref-over-boundary", []string{overID}, 2, 2); got == solveAdmissionSucceeded {
		t.Fatal("admitSolve(overlong upload ID) succeeded")
	}
	if registry.OwnsRef(key, "ref-over-boundary") {
		t.Fatal("Solve rejected for an overlong upload ID retained ref ownership")
	}
	if registry.ConsumeUploadKey(key, testBuildkitSessionID, overID) {
		t.Fatal("Solve rejected for an overlong upload ID retained the upload ID")
	}
	if !registry.ConsumeUploadKey(key, testBuildkitSessionID, maxID) {
		t.Fatal("maximum-length upload ID was not admitted")
	}
}

func TestAdmitSolveReusedRefCannotBypassBuildkitSessionIDCap(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "principal", Profile: "builder"}
	session := registry.Open(key, EndpointGRPC, "")

	const maxDistinctSessionIDs = 256
	for i := range maxDistinctSessionIDs {
		id := fmt.Sprintf("session-%03d", i)
		if got := registry.admitSolve(session, id, "reused-ref", nil, 1, 1); got != solveAdmissionSucceeded {
			t.Fatalf("admitSolve(%d) = %v below the distinct session-ID cap", i, got)
		}
	}
	if got := registry.admitSolve(session, "session-over-limit", "reused-ref", nil, 1, 1); got == solveAdmissionSucceeded {
		t.Fatal("admitSolve() accepted a new BuildKit session ID after the cap despite reusing one ref")
	}
	if !registry.HasAdmittedSolve(key, "session-000") {
		t.Fatal("session admitted before the cap was lost")
	}
	if registry.HasAdmittedSolve(key, "session-over-limit") {
		t.Fatal("session rejected over the cap retained admitted-Solve state")
	}
}

type registryClockSetter interface {
	setNow(func() time.Time)
}

func setRegistryTime(t *testing.T, registry *SessionRegistry, now *time.Time) {
	t.Helper()
	setter, ok := any(registry).(registryClockSetter)
	if !ok {
		t.Fatal("SessionRegistry does not support deterministic clock injection")
	}
	setter.setNow(func() time.Time { return *now })
}

func TestUploadKeySurvivesControlCloseWithinExpiryWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	setRegistryTime(t, registry, &now)
	key := SessionKey{ClientIdentity: "principal", Profile: "builder"}
	session := registry.Open(key, EndpointGRPC, "")
	if got := registry.admitSolve(session, testBuildkitSessionID, "ref", []string{"upload"}, 1, 1); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	registry.Close(session.ID)

	now = now.Add(time.Hour - time.Nanosecond)
	if !registry.ConsumeUploadKey(key, testBuildkitSessionID, "upload") {
		t.Fatal("upload ID expired before the conservative one-hour post-control-close window elapsed")
	}
	if registry.ConsumeUploadKey(key, testBuildkitSessionID, "upload") {
		t.Fatal("upload ID remained reusable after its first consumption")
	}
}

func TestExpiredUploadKeyIsPurgedBeforeQuotaAdmissionAndConsume(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	setRegistryTime(t, registry, &now)
	key := SessionKey{ClientIdentity: "principal", Profile: "builder"}
	oldSession := registry.Open(key, EndpointGRPC, "")
	if got := registry.admitSolve(oldSession, "old-session", "old-ref", []string{"old-upload"}, 1, 1); got != solveAdmissionSucceeded {
		t.Fatalf("old admitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	registry.Close(oldSession.ID)

	now = now.Add(time.Hour)
	newSession := registry.Open(key, EndpointGRPC, "")
	if got := registry.admitSolve(newSession, "new-session", "new-ref", []string{"new-upload"}, 1, 1); got != solveAdmissionSucceeded {
		t.Fatalf("new admitSolve() = %v after expiry, want solveAdmissionSucceeded", got)
	}
	if registry.ConsumeUploadKey(key, "old-session", "old-upload") {
		t.Fatal("expired upload ID remained consumable")
	}
	if !registry.ConsumeUploadKey(key, "new-session", "new-upload") {
		t.Fatal("fresh upload ID was not consumable after stale quota cleanup")
	}
}

func TestUploadKeyExpiryPreservesPrincipalAndSessionIsolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	setRegistryTime(t, registry, &now)
	oldKey := SessionKey{ClientIdentity: "old-principal", Profile: "builder"}
	oldSession := registry.Open(oldKey, EndpointGRPC, "")
	if got := registry.admitSolve(oldSession, "old-session", "old-ref", []string{"shared-upload"}, 1, 1); got != solveAdmissionSucceeded {
		t.Fatalf("old admitSolve() = %v, want solveAdmissionSucceeded", got)
	}

	now = now.Add(30 * time.Minute)
	freshKey := SessionKey{ClientIdentity: "fresh-principal", Profile: "builder"}
	freshSession := registry.Open(freshKey, EndpointGRPC, "")
	if got := registry.admitSolve(freshSession, "fresh-session", "fresh-ref", []string{"shared-upload"}, 1, 1); got != solveAdmissionSucceeded {
		t.Fatalf("fresh admitSolve() = %v, want solveAdmissionSucceeded", got)
	}

	now = now.Add(30 * time.Minute)
	if registry.ConsumeUploadKey(oldKey, "old-session", "shared-upload") {
		t.Fatal("expired upload ID remained consumable in its original scope")
	}
	if registry.ConsumeUploadKey(oldKey, "fresh-session", "shared-upload") {
		t.Fatal("fresh upload ID crossed into another principal/session scope")
	}
	if !registry.ConsumeUploadKey(freshKey, "fresh-session", "shared-upload") {
		t.Fatal("purging an expired scope removed a fresh isolated upload ID")
	}
}
