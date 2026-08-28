package buildkitproxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMediatorRejectsSessionTunnelWithoutBuildkitSessionID(t *testing.T) {
	mediator := NewMediator(&fakeDialer{err: errors.New("must not dial without a session id")}, noopLogger())
	req := newUpgradeRequest(t, "/session")
	req.Header.Del(sessionUUIDHeader)
	rec := httptest.NewRecorder()

	mediator.ServeSession(rec, req, allowAllPolicy, SessionKey{ClientIdentity: "principal", Profile: "builder"})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if mediator.Registry.Len() != 0 {
		t.Fatalf("registry.Len() = %d after rejecting missing session id, want 0", mediator.Registry.Len())
	}
}

func TestSessionRegistryIsolatesSimultaneousBuildkitSessions(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "same-principal", Profile: "builder"}
	grpcSession := registry.Open(key, EndpointGRPC, "")

	if got := registry.admitSolve(grpcSession, "build-a", "ref-a", []string{"shared-upload"}, 0, 0); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve(build-a) = %v, want solveAdmissionSucceeded", got)
	}
	if got := registry.admitSolve(grpcSession, "build-b", "ref-b", []string{"shared-upload"}, 0, 0); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve(build-b) = %v, want solveAdmissionSucceeded", got)
	}

	if !registry.HasAdmittedSolve(key, "build-a") || !registry.HasAdmittedSolve(key, "build-b") {
		t.Fatal("each BuildKit session must retain its own admitted-Solve state")
	}
	if !registry.ConsumeUploadKey(key, "build-a", "shared-upload") {
		t.Fatal("build-a could not consume its admitted upload")
	}
	if !registry.ConsumeUploadKey(key, "build-b", "shared-upload") {
		t.Fatal("build-b upload was consumed or hidden by build-a")
	}
}

func TestSessionRegistryCorrelatesOnlyMatchingPrincipalAndBuildkitSession(t *testing.T) {
	registry := NewSessionRegistry()
	admittingKey := SessionKey{ClientIdentity: "principal-a", Profile: "builder"}
	grpcSession := registry.Open(admittingKey, EndpointGRPC, "")
	if got := registry.admitSolve(grpcSession, "build-a", "ref-a", []string{"upload-a"}, 0, 0); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve() = %v, want solveAdmissionSucceeded", got)
	}

	otherPrincipal := SessionKey{ClientIdentity: "principal-b", Profile: "builder"}
	if registry.HasAdmittedSolve(otherPrincipal, "build-a") {
		t.Fatal("another principal matched admitted FileSend state")
	}
	if registry.HasAdmittedSolve(admittingKey, "build-b") {
		t.Fatal("another BuildKit session matched admitted FileSend state")
	}
	if registry.ConsumeUploadKey(otherPrincipal, "build-a", "upload-a") {
		t.Fatal("another principal consumed the admitted upload")
	}
	if registry.ConsumeUploadKey(admittingKey, "build-b", "upload-a") {
		t.Fatal("another BuildKit session consumed the admitted upload")
	}
	if !registry.HasAdmittedSolve(admittingKey, "build-a") {
		t.Fatal("matching principal/session did not match admitted FileSend state")
	}
	if !registry.ConsumeUploadKey(admittingKey, "build-a", "upload-a") {
		t.Fatal("matching principal/session could not consume the admitted upload")
	}
}

func TestSessionRegistryRejectsUploadAdmissionWithoutBuildkitSession(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "principal", Profile: "builder"}
	grpcSession := registry.Open(key, EndpointGRPC, "")

	if got := registry.admitSolve(grpcSession, "", "ref", []string{"unconsumable-upload"}, 0, 0); got != solveAdmissionSessionIDMissing {
		t.Fatalf("admitSolve() = %v, want solveAdmissionSessionIDMissing", got)
	}
	if registry.HasAdmittedSolve(key, "") {
		t.Fatal("rejected Solve left admitted session state")
	}
}

func TestSessionRegistryUploadCapCannotBeBypassedWithSessionIDs(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "principal", Profile: "builder"}
	grpcSession := registry.Open(key, EndpointGRPC, "")

	if got := registry.admitSolve(grpcSession, "build-a", "ref-a", []string{"upload-a"}, 0, 1); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve(build-a) = %v, want solveAdmissionSucceeded", got)
	}
	if got := registry.admitSolve(grpcSession, "build-b", "ref-b", []string{"upload-b"}, 0, 1); got != solveAdmissionUploadLimitExceeded {
		t.Fatalf("admitSolve(build-b) = %v, want solveAdmissionUploadLimitExceeded", got)
	}
	if registry.HasAdmittedSolve(key, "build-b") {
		t.Fatal("rejected build-b Solve left admitted session state")
	}
}
