package buildkitproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/upload"
)

func newUploadGRPCRequest(t *testing.T, urlhost, urlpath, body string) *http.Request {
	t.Helper()
	req := newGRPCRequest(t, "/moby.upload.v1.Upload/Pull", body)
	if urlhost != "" {
		req.Header.Set("urlhost", urlhost)
	}
	if urlpath != "" {
		req.Header.Set("urlpath", urlpath)
	}
	return req
}

func admitUploadID(t *testing.T, registry *SessionRegistry, key SessionKey, id string) {
	t.Helper()
	session := registry.Open(key, EndpointGRPC, "")
	if got := registry.admitSolve(session, testBuildkitSessionID, "upload-test-ref-"+id, []string{id}, 0, 0); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	registry.Close(session.ID)
}

func TestUploadDeniesWrongURLHost(t *testing.T) {
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)
	admitUploadID(t, tb.registry, tb.session.Key, "abc123")

	resp, err := tb.driver.RoundTrip(newUploadGRPCRequest(t, "not-buildkit-session", "/abc123", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied)", code, grpcCodePermissionDenied)
	}
	if daemonCalled {
		t.Fatal("Upload/Pull with the wrong urlhost must never reach the daemon")
	}
}

func TestUploadDeniesMissingURLPath(t *testing.T) {
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)
	admitUploadID(t, tb.registry, tb.session.Key, "abc123")

	resp, err := tb.driver.RoundTrip(newUploadGRPCRequest(t, uploadSessionHost, "", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied)", code, grpcCodePermissionDenied)
	}
	if daemonCalled {
		t.Fatal("Upload/Pull with an empty urlpath must never reach the daemon")
	}
}

func TestUploadDeniesUnadmittedToken(t *testing.T) {
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)
	// Deliberately never admitted by a Solve.

	resp, err := tb.driver.RoundTrip(newUploadGRPCRequest(t, uploadSessionHost, "/never-admitted", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PermissionDenied)", code, grpcCodePermissionDenied)
	}
	if daemonCalled {
		t.Fatal("Upload/Pull for a never-admitted token must never reach the daemon")
	}
}

func TestUploadAdmittedTokenRelaysVerbatimThenIsOneUse(t *testing.T) {
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)
	admitUploadID(t, tb.registry, tb.session.Key, "abc123")

	payload := mustMarshal(t, &upload.BytesMessage{Data: []byte("uploaded-bytes")})
	resp, err := tb.driver.RoundTrip(newUploadGRPCRequest(t, uploadSessionHost, "/abc123", string(grpcFrame(payload))))
	if err != nil {
		t.Fatalf("first RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("first Grpc-Status = %d, want 0 (OK)", code)
	}
	if want := grpcFrame(payload); !bytes.Equal(body, want) {
		t.Fatalf("body = %v, want the original frame verbatim %v", body, want)
	}

	// Second Pull for the SAME id must be denied — one-use.
	resp2, err := tb.driver.RoundTrip(newUploadGRPCRequest(t, uploadSessionHost, "/abc123", string(grpcFrame(payload))))
	if err != nil {
		t.Fatalf("second RoundTrip: %v", err)
	}
	code2, _ := grpcStatusOf(t, resp2)
	if code2 != grpcCodePermissionDenied {
		t.Fatalf("second Grpc-Status = %d, want %d (PermissionDenied) — a consumed upload token must not be reusable", code2, grpcCodePermissionDenied)
	}
}

func TestUploadURLPathRecoversBareIDViaPathBase(t *testing.T) {
	// provider.go's Pull handler recovers the id via path.Base(urlpath), not
	// a bare prefix trim — confirm sockguard's own recovery agrees by
	// admitting the bare id and presenting a urlpath with a leading slash.
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)
	admitUploadID(t, tb.registry, tb.session.Key, "deadbeef")

	resp, err := tb.driver.RoundTrip(newUploadGRPCRequest(t, uploadSessionHost, "/deadbeef", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != 0 {
		t.Fatalf("Grpc-Status = %d, want 0 (OK)", code)
	}
}

// TestUploadRequestUnknownFieldsDenied exercises the request-direction
// unknown-fields denial via a unit-level bridge (drainingFakeClientLeg)
// rather than a live daemon connection: like FileSend's own request-cap
// test, a mid-stream request-side denial only surfaces once the daemon's
// HTTP/2 handler has already been invoked (headers flow before the body is
// fully read), so "the daemon must never be called" isn't a meaningful,
// deterministic assertion for a streaming relay's in-body validation the way
// it is for the pre-relay urlhost/urlpath/one-use gate above.
func TestUploadRequestUnknownFieldsDenied(t *testing.T) {
	fake := &drainingFakeClientLeg{}
	b := newUnitTestBridge(t, fake)
	b.legs.endpoint = EndpointSession
	b.session.ClientUUID = testBuildkitSessionID
	admitUploadID(t, b.registry, b.session.Key, "abc123")

	req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame(unknownFieldBytes())))
	req.Header.Set("urlhost", uploadSessionHost)
	req.Header.Set("urlpath", "/abc123")
	rec := httptest.NewRecorder()

	b.forwardUploadMediated(rec, req, "moby.upload.v1.Upload", "Pull")

	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeFailedPrecondition {
		t.Fatalf("Grpc-Status = %d, want %d (FailedPrecondition)", code, grpcCodeFailedPrecondition)
	}
	if fake.gotReq == nil {
		t.Fatal("RoundTrip was never invoked — the denial should surface from draining the request body, not from skipping RoundTrip entirely")
	}
}

func TestUploadResponseUnknownFieldsDenied(t *testing.T) {
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(grpcFrame(unknownFieldBytes()))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)
	admitUploadID(t, tb.registry, tb.session.Key, "abc123")

	resp, err := tb.driver.RoundTrip(newUploadGRPCRequest(t, uploadSessionHost, "/abc123", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeFailedPrecondition {
		t.Fatalf("Grpc-Status = %d, want %d (FailedPrecondition)", code, grpcCodeFailedPrecondition)
	}
}

func TestUploadByteCapExceeded(t *testing.T) {
	fake := &drainingFakeClientLeg{}
	b := newUnitTestBridge(t, fake)
	b.legs.endpoint = EndpointSession
	b.session.ClientUUID = testBuildkitSessionID
	b.limits.MaxUploadBytes = 5
	admitUploadID(t, b.registry, b.session.Key, "abc123")

	payload := mustMarshal(t, &upload.BytesMessage{Data: bytes.Repeat([]byte("z"), 100)})
	req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame(payload)))
	req.Header.Set("urlhost", uploadSessionHost)
	req.Header.Set("urlpath", "/abc123")
	rec := httptest.NewRecorder()

	b.forwardUploadMediated(rec, req, "moby.upload.v1.Upload", "Pull")

	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (ResourceExhausted)", code, grpcCodeResourceExhausted)
	}
}

// --- solveUploadKeys -------------------------------------------------------

func TestSolveUploadKeysNilRequestIsEmpty(t *testing.T) {
	if got := solveUploadKeys(nil); len(got) != 0 {
		t.Fatalf("solveUploadKeys(nil) = %v, want empty", got)
	}
}

func TestSolveUploadKeysExtractsContextAndNamedContextURLs(t *testing.T) {
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context":            "http://buildkit-session/id-one",
		"context:additional": "http://buildkit-session/id-two",
	}}
	want := []string{"id-one", "id-two"}
	if got := solveUploadKeys(req); !slices.Equal(got, want) {
		t.Fatalf("solveUploadKeys() = %v, want %v", got, want)
	}
}

func TestSolveUploadKeysSkipsNonMatchingOrMalformedValues(t *testing.T) {
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context":            "https://github.com/example/repo.git",
		"filename":           "Dockerfile",
		"context:bad-url":    "://not a url",
		"context:wrong-host": "http://not-buildkit-session/id",
	}}
	if got := solveUploadKeys(req); len(got) != 0 {
		t.Fatalf("solveUploadKeys() = %v, want empty", got)
	}
}

func TestSessionRegistryAdmitSolveRejectsUploadOverflowAtomically(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := registry.Open(key, EndpointGRPC, "")
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context:a": "http://buildkit-session/id-a",
		"context:b": "http://buildkit-session/id-b",
	}}
	if got := registry.admitSolve(session, testBuildkitSessionID, "ref", solveUploadKeys(req), 0, 1); got != solveAdmissionUploadLimitExceeded {
		t.Fatalf("admitSolve() = %v, want solveAdmissionUploadLimitExceeded", got)
	}
	if registry.OwnsRef(key, "ref") {
		t.Fatal("rejected Solve retained ref ownership")
	}
	if registry.ConsumeUploadKey(key, testBuildkitSessionID, "id-a") || registry.ConsumeUploadKey(key, testBuildkitSessionID, "id-b") {
		t.Fatal("rejected Solve retained an upload id")
	}
}

func TestSessionRegistryAdmitSolvePublishesRefAndUploadIDs(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	session := registry.Open(key, EndpointGRPC, "")
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context:a": "http://buildkit-session/id-a",
		"context:b": "http://buildkit-session/id-b",
	}}
	if got := registry.admitSolve(session, testBuildkitSessionID, "ref", solveUploadKeys(req), 5, 5); got != solveAdmissionSucceeded {
		t.Fatalf("admitSolve() = %v, want solveAdmissionSucceeded", got)
	}
	if !registry.OwnsRef(key, "ref") {
		t.Fatal("admitted Solve did not publish ref ownership")
	}
	if !registry.ConsumeUploadKey(key, testBuildkitSessionID, "id-a") || !registry.ConsumeUploadKey(key, testBuildkitSessionID, "id-b") {
		t.Fatal("admitted Solve did not publish both upload ids")
	}
}

func TestSolveUploadKeysSkipsRootPathIDs(t *testing.T) {
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context": "http://buildkit-session/",
	}}
	if got := solveUploadKeys(req); len(got) != 0 {
		t.Fatalf("solveUploadKeys() = %v, want empty", got)
	}
}

func TestIsContextAttrKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"context:foo", true},
		{"context:", false},
		{"context", false},
		{"other", false},
	}
	for _, tc := range cases {
		if got := isContextAttrKey(tc.key); got != tc.want {
			t.Errorf("isContextAttrKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}
