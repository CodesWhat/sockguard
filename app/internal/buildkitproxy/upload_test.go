package buildkitproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/internal/buildkitproto/upload"
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

func TestUploadDeniesWrongURLHost(t *testing.T) {
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })
	tb := newTestBridge(t, EndpointSession, allowAllPolicy, DefaultLimits(), daemon)
	if !tb.registry.AdmitUploadKey(tb.session.Key, "abc123", 0) {
		t.Fatal("AdmitUploadKey failed")
	}

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
	if !tb.registry.AdmitUploadKey(tb.session.Key, "abc123", 0) {
		t.Fatal("AdmitUploadKey failed")
	}

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
	// Deliberately never admitted via AdmitUploadKey.

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
	if !tb.registry.AdmitUploadKey(tb.session.Key, "abc123", 0) {
		t.Fatal("AdmitUploadKey failed")
	}

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
	if !tb.registry.AdmitUploadKey(tb.session.Key, "deadbeef", 0) {
		t.Fatal("AdmitUploadKey failed")
	}

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
	if !b.registry.AdmitUploadKey(b.session.Key, "abc123", 0) {
		t.Fatal("AdmitUploadKey failed")
	}

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
	if !tb.registry.AdmitUploadKey(tb.session.Key, "abc123", 0) {
		t.Fatal("AdmitUploadKey failed")
	}

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
	b.limits.MaxUploadBytes = 5
	if !b.registry.AdmitUploadKey(b.session.Key, "abc123", 0) {
		t.Fatal("AdmitUploadKey failed")
	}

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

// --- admitSolveUploadKeys --------------------------------------------------

func TestAdmitSolveUploadKeysNilRequestIsNoop(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	admitSolveUploadKeys(registry, key, nil, 0)
	if registry.HasAdmittedSolve(key) {
		t.Fatal("HasAdmittedSolve unexpectedly true after a nil SolveRequest")
	}
	if registry.ConsumeUploadKey(key, "anything") {
		t.Fatal("ConsumeUploadKey unexpectedly succeeded — nothing should have been admitted")
	}
}

func TestAdmitSolveUploadKeysAdmitsContextAndNamedContextURLs(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context":            "http://buildkit-session/id-one",
		"context:additional": "http://buildkit-session/id-two",
	}}
	admitSolveUploadKeys(registry, key, req, 0)

	if !registry.ConsumeUploadKey(key, "id-one") {
		t.Fatal("id-one was not admitted from the \"context\" attr")
	}
	if !registry.ConsumeUploadKey(key, "id-two") {
		t.Fatal("id-two was not admitted from the \"context:additional\" attr")
	}
}

func TestAdmitSolveUploadKeysSkipsNonMatchingOrMalformedValues(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context":            "https://github.com/example/repo.git",
		"filename":           "Dockerfile",
		"context:bad-url":    "://not a url",
		"context:wrong-host": "http://not-buildkit-session/id",
	}}
	admitSolveUploadKeys(registry, key, req, 0)

	if registry.HasAdmittedSolve(key) {
		t.Fatal("HasAdmittedSolve should only reflect PutRef, not upload keys")
	}
	// None of the above should have registered any upload key at all.
	if registry.ConsumeUploadKey(key, "id") || registry.ConsumeUploadKey(key, "repo.git") || registry.ConsumeUploadKey(key, "Dockerfile") {
		t.Fatal("a non-upload-session-shaped FrontendAttrs value was incorrectly admitted as an upload key")
	}
}

func TestAdmitSolveUploadKeysRespectsMaxKeys(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context:a": "http://buildkit-session/id-a",
		"context:b": "http://buildkit-session/id-b",
	}}
	// Two candidates, maxKeys=1: admission must fail (all-or-nothing signal to
	// the caller) and be deterministic — the sorted-first id ("id-a") is the
	// one that gets registered, never a random subset dependent on map order.
	if admitSolveUploadKeys(registry, key, req, 1) {
		t.Fatal("admitSolveUploadKeys = true, want false when candidates exceed maxKeys")
	}
	if !registry.ConsumeUploadKey(key, "id-a") {
		t.Fatal("id-a (sorted first) should have been the admitted key")
	}
	if registry.ConsumeUploadKey(key, "id-b") {
		t.Fatal("id-b should not have been admitted once the maxKeys bound was hit")
	}
}

func TestAdmitSolveUploadKeysAllAdmittedReturnsTrue(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context:a": "http://buildkit-session/id-a",
		"context:b": "http://buildkit-session/id-b",
	}}
	if !admitSolveUploadKeys(registry, key, req, 5) {
		t.Fatal("admitSolveUploadKeys = false, want true when all candidates fit under maxKeys")
	}
	if !registry.ConsumeUploadKey(key, "id-a") || !registry.ConsumeUploadKey(key, "id-b") {
		t.Fatal("both candidate ids should have been admitted")
	}
}

func TestAdmitSolveUploadKeysSkipsRootPathIDs(t *testing.T) {
	registry := NewSessionRegistry()
	key := SessionKey{ClientIdentity: "c", Profile: "p"}
	req := &control.SolveRequest{FrontendAttrs: map[string]string{
		"context": "http://buildkit-session/",
	}}
	admitSolveUploadKeys(registry, key, req, 0)
	if registry.ConsumeUploadKey(key, "/") || registry.ConsumeUploadKey(key, ".") {
		t.Fatal("an upload-session URL with an empty/root path must not be admitted as a token")
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
