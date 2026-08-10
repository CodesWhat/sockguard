package buildkitproxy

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/net/http2"
)

// allowAllPolicy admits every Mediate/Passthrough method this package's
// registry defines, on both endpoints — used by bridge tests that aren't
// specifically exercising the Policy.Allowed gate.
var allowAllPolicy = Policy{
	Control: ControlPolicy{
		AllowInfo:        true,
		AllowListWorkers: true,
		AllowStatus:      true,
		Solve:            SolvePolicy{Allow: true},
	},
	Session: SessionPolicy{
		Health:   true,
		Auth:     AuthPolicy{Allow: true},
		Secrets:  SecretsPolicy{Allow: true},
		SSH:      SSHPolicy{Allow: true},
		FileSync: FileSyncPolicy{Allow: true},
		FileSend: FileSendPolicy{Allow: true},
		Upload:   UploadPolicy{Allow: true},
	},
}

// testBridge wires a runBridge instance entirely in-process: driverConn is
// an h2c client the test uses to send stream requests INTO the bridge's
// server leg, and daemonHandler serves whatever the bridge forwards on its
// client leg (standing in for buildkitd on EndpointGRPC, or the Docker
// client's session server on EndpointSession — bridge.go's routing logic is
// symmetric in the endpoint argument, so EndpointGRPC is used for every case
// that isn't specifically testing endpoint role-wiring, which
// mediator_test.go covers separately).
type testBridge struct {
	driver   *http2.ClientConn
	registry *SessionRegistry
	session  *Session
	// done is CLOSED (never sent-on) once runBridge returns, so both the
	// test body and t.Cleanup can observe completion without racing to
	// consume a single buffered value.
	done chan struct{}
	err  error
}

func newTestBridge(t *testing.T, endpoint Endpoint, policy Policy, limits Limits, daemonHandler http.Handler) *testBridge {
	t.Helper()

	serverLeg, driverConn := net.Pipe()
	daemonSide, clientLegForBridge := net.Pipe()

	daemonSrv := &http2.Server{}
	go daemonSrv.ServeConn(daemonSide, &http2.ServeConnOpts{Handler: daemonHandler})

	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "test-client", Profile: "test-profile"}, endpoint, "")

	legs := bridgeLegs{endpoint: endpoint, serverConn: serverLeg, clientConn: clientLegForBridge}
	tb := &testBridge{registry: registry, session: session, done: make(chan struct{})}
	go func() {
		tb.err = runBridge(context.Background(), legs, session, policy, limits, noopLogger())
		close(tb.done)
	}()

	tr := &http2.Transport{AllowHTTP: true}
	driver, err := tr.NewClientConn(driverConn)
	if err != nil {
		t.Fatalf("NewClientConn (driver): %v", err)
	}
	tb.driver = driver

	t.Cleanup(func() {
		_ = driver.Close()
		_ = driverConn.Close()
		select {
		case <-tb.done:
		case <-time.After(2 * time.Second):
			t.Error("runBridge did not return within 2s of the driver connection closing")
		}
	})

	return tb
}

func newGRPCRequest(t *testing.T, path string, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://buildkit-test"+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	return req
}

func grpcStatusOf(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	status := resp.Header.Get("Grpc-Status")
	if status == "" {
		status = resp.Trailer.Get("Grpc-Status")
	}
	message := resp.Header.Get("Grpc-Message")
	if message == "" {
		message = resp.Trailer.Get("Grpc-Message")
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		t.Fatalf("Grpc-Status %q is not an integer (resp: %+v)", status, resp)
	}
	return code, message
}

func echoDaemonHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemon-Saw-Path", r.URL.Path)
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
}

func TestBridgeDeniesUnregisteredMethod(t *testing.T) {
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Prune", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, msg := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED); message = %q", code, grpcCodePermissionDenied, msg)
	}
	if daemonCalled {
		t.Fatal("a Deny-classified method reached the daemon handler — it must be rejected on sockguard's side of the bridge")
	}
}

func TestBridgeDeniesMalformedPath(t *testing.T) {
	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler())

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/not-a-grpc-path", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeUnimplemented {
		t.Fatalf("Grpc-Status = %d, want %d (UNIMPLEMENTED)", code, grpcCodeUnimplemented)
	}
}

func TestBridgeDeniesWhenPolicyDoesNotAllowMediateMethod(t *testing.T) {
	// Solve is classified Mediate, but this policy never turns
	// Control.Solve.Allow on — the method's CATEGORY is eligible, but this
	// operator's policy doesn't admit it. Must still be denied, and denied
	// BEFORE reaching the daemon.
	daemonCalled := false
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled = true })

	tb := newTestBridge(t, EndpointGRPC, Policy{Control: ControlPolicy{AllowInfo: true}}, DefaultLimits(), daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", "payload"))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, msg := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED); message = %q", code, grpcCodePermissionDenied, msg)
	}
	if daemonCalled {
		t.Fatal("Solve reached the daemon despite Control.Solve.Allow being false")
	}
}

func TestBridgeForwardsAdmittedMethodVerbatim(t *testing.T) {
	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler())

	const payload = "this-is-the-exact-request-body-bytes"
	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", payload))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Daemon-Saw-Path"); got != "/moby.buildkit.v1.Control/Solve" {
		t.Fatalf("daemon saw path %q, want /moby.buildkit.v1.Control/Solve", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != payload {
		t.Fatalf("response body = %q, want the daemon's exact echo %q (no re-encoding on the forward path)", body, payload)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want %q (the daemon's own trailer must pass through unmodified)", got, "0")
	}
}

func TestBridgeForwardsPassthroughMethod(t *testing.T) {
	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler())

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestBridgeResponseSizeCapTripsResourceExhausted(t *testing.T) {
	bigDaemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
	})

	limits := DefaultLimits()
	limits.MaxMessageBytes = 8

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, bigDaemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the response starts successfully; the cap trips mid-stream)", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if got := resp.Trailer.Get("Grpc-Status"); got != strconv.Itoa(grpcCodeResourceExhausted) {
		t.Fatalf("Grpc-Status trailer = %q, want %d (RESOURCE_EXHAUSTED)", got, grpcCodeResourceExhausted)
	}
}

// TestLimitedReadCloserCap is table-driven over the three size relationships
// between a source and its cap. It pins the fix for CodeRabbit's off-by-one
// finding: a source of EXACTLY the cap's length must reach a clean io.EOF,
// never errMessageTooLarge — the cap's contract is "exceeds", not "reaches".
func TestLimitedReadCloserCap(t *testing.T) {
	cases := []struct {
		name      string
		srcLen    int
		limit     int64
		wantErr   error // nil means a clean io.EOF (io.ReadAll swallows it)
		wantBytes int
	}{
		{"source shorter than the cap reaches a clean EOF", 3, 5, nil, 3},
		{"source exactly at the cap reaches a clean EOF, not errMessageTooLarge", 5, 5, nil, 5},
		{"source longer than the cap trips errMessageTooLarge", 6, 5, errMessageTooLarge, 5},
		{"cap of math.MaxInt64 must not overflow the one-byte sentinel", 3, math.MaxInt64, nil, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := io.NopCloser(strings.NewReader(strings.Repeat("x", tc.srcLen)))
			lrc := newLimitedReadCloser(src, tc.limit)

			got, err := io.ReadAll(lrc)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ReadAll() error = %v, want nil", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadAll() error = %v, want %v", err, tc.wantErr)
			}
			if len(got) != tc.wantBytes {
				t.Fatalf("ReadAll() returned %d bytes, want %d", len(got), tc.wantBytes)
			}
		})
	}
}

func TestLimitedReadCloserDisabledWhenLimitIsZero(t *testing.T) {
	src := io.NopCloser(strings.NewReader("hello"))
	if got := newLimitedReadCloser(src, 0); got != io.ReadCloser(src) {
		t.Fatal("newLimitedReadCloser with limit <= 0 must return the original reader unchanged")
	}
}

func TestBridgeDeniedStreamBudgetTerminatesTunnel(t *testing.T) {
	limits := DefaultLimits()
	limits.DeniedStreamBudget = 1
	limits.DeniedStreamWindow = time.Minute

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, echoDaemonHandler())

	// First two denied streams: budget of 1 means the 2nd recordDenied()
	// call reports "exceeded" and the bridge tears the whole connection down.
	for range 2 {
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Prune", ""))
		if err != nil {
			// The connection may already be torn down by the time this
			// RoundTrip is attempted — acceptable, since that's exactly the
			// behavior under test.
			break
		}
		_, _ = grpcStatusOf(t, resp)
	}

	select {
	case <-tb.done:
		if tb.err == nil {
			t.Fatal("runBridge returned nil error after the denied-stream budget was exceeded, want a non-nil teardown error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runBridge did not terminate the tunnel after the denied-stream budget was exceeded")
	}
}

func TestBridgeSessionRegistryTracksOpenSession(t *testing.T) {
	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), echoDaemonHandler())

	if tb.registry.Len() != 1 {
		t.Fatalf("registry.Len() = %d while the bridge is running, want 1", tb.registry.Len())
	}
	got, ok := tb.registry.Get(tb.session.ID)
	if !ok || got.Profile != "test-profile" {
		t.Fatalf("registry.Get(%d) = (%+v, %v), want the frozen test-profile session", tb.session.ID, got, ok)
	}
}

func TestRunBridgeClientLegHandshakeFailure(t *testing.T) {
	// A dead client-leg connection makes clientTransport.NewClientConn's
	// initial preface/settings flush fail synchronously, before runBridge
	// ever starts serving the server leg — exercising runBridge's own
	// "establish client leg" error return, distinct from every other bridge
	// test in this file (which all reach a live client leg).
	serverLeg, driverConn := net.Pipe()
	defer func() { _ = driverConn.Close() }()

	clientLeg, clientPeer := net.Pipe()
	_ = clientPeer.Close()
	_ = clientLeg.Close()

	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointGRPC, "")

	err := runBridge(context.Background(), bridgeLegs{endpoint: EndpointGRPC, serverConn: serverLeg, clientConn: clientLeg}, session, allowAllPolicy, DefaultLimits(), noopLogger())
	if err == nil {
		t.Fatal("runBridge() with a dead client leg = nil error, want an error establishing the client leg")
	}
	if !strings.Contains(err.Error(), "establish client leg") {
		t.Fatalf("runBridge() error = %v, want it to mention establishing the client leg", err)
	}
}

// fakeClientLeg is a hand-rolled clientLegConn double used to drive
// bridge.forward's error-handling branches deterministically — a genuine
// RoundTrip failure, a response body whose Read fails with something other
// than errMessageTooLarge, and the outgoing request's Host — none of which
// are reproducible reliably by racing a real network connection's teardown
// against a live http2.ClientConn.
type fakeClientLeg struct {
	gotReq *http.Request
	resp   *http.Response
	err    error
}

func (f *fakeClientLeg) RoundTrip(r *http.Request) (*http.Response, error) {
	f.gotReq = r
	return f.resp, f.err
}

func (f *fakeClientLeg) Close() error { return nil }

// newUnitTestBridge builds a *bridge whose clientLeg is the given fake,
// wired with just enough real net.Conn plumbing (unused by forward itself,
// but required by closeAll, which every forward() error path may invoke) to
// let closeAll run without panicking.
func newUnitTestBridge(t *testing.T, clientLeg clientLegConn) *bridge {
	t.Helper()
	serverConn, serverPeer := net.Pipe()
	t.Cleanup(func() { _ = serverPeer.Close() })
	clientConn, clientPeer := net.Pipe()
	t.Cleanup(func() { _ = clientPeer.Close() })

	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointGRPC, "")

	return &bridge{
		legs:      bridgeLegs{endpoint: EndpointGRPC, serverConn: serverConn, clientConn: clientConn},
		session:   session,
		policy:    allowAllPolicy,
		limits:    DefaultLimits(),
		logger:    noopLogger(),
		guard:     newStreamAbuseGuard(DefaultLimits()),
		clientLeg: clientLeg,
	}
}

func TestBridgeForwardDefaultsHostWhenEmpty(t *testing.T) {
	fake := &fakeClientLeg{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
	}}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.buildkit.v1.Control/Info", nil)
	req.Host = ""
	rec := httptest.NewRecorder()

	b.forward(rec, req, "moby.buildkit.v1.Control", "Info")

	if fake.gotReq == nil {
		t.Fatal("forward() never called RoundTrip")
	}
	if fake.gotReq.Host != "buildkitd" {
		t.Fatalf("outgoing request Host = %q, want forward()'s default %q", fake.gotReq.Host, "buildkitd")
	}
	if fake.gotReq.URL.Host != "buildkitd" {
		t.Fatalf("outgoing request URL.Host = %q, want %q", fake.gotReq.URL.Host, "buildkitd")
	}
}

func TestBridgeForwardRequestSizeCapTripsResourceExhaustedWithoutClosingTunnel(t *testing.T) {
	// The request-body size cap (limitedReadCloser wrapping r.Body) surfaces
	// as errMessageTooLarge coming back OUT of RoundTrip itself, since it's
	// the outgoing body read that trips, not the response. Exercised here via
	// fakeClientLeg rather than a live http2.ClientConn: driving a real
	// oversized request through an actual RoundTrip races the client's
	// in-flight body write against the server's response, which is exactly
	// the flakiness this package's integration tests avoid elsewhere in
	// favor of isolated unit coverage of the two things that matter —
	// limitedReadCloser's own cap behavior (TestLimitedReadCloserCap)
	// and forward()'s handling of the error RoundTrip returns because of it.
	fake := &fakeClientLeg{err: errMessageTooLarge}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.buildkit.v1.Control/Solve", strings.NewReader("oversized"))
	rec := httptest.NewRecorder()

	b.forward(rec, req, "moby.buildkit.v1.Control", "Solve")

	if b.closeErr != nil {
		t.Fatalf("closeErr = %v, want nil — a request size-cap trip is stream-local, not a tunnel-ending failure", b.closeErr)
	}
	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (RESOURCE_EXHAUSTED)", code, grpcCodeResourceExhausted)
	}
}

func TestBridgeForwardGenericRoundTripErrorTerminatesTunnel(t *testing.T) {
	fake := &fakeClientLeg{err: errors.New("connection reset by peer")}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.buildkit.v1.Control/Solve", strings.NewReader(""))
	rec := httptest.NewRecorder()

	b.forward(rec, req, "moby.buildkit.v1.Control", "Solve")

	if b.closeErr == nil {
		t.Fatal("forward() with a genuine (non-size-cap) RoundTrip error must call closeAll with a non-nil error")
	}
	if !strings.Contains(b.closeErr.Error(), "connection reset by peer") {
		t.Fatalf("closeErr = %v, want it to wrap the RoundTrip error", b.closeErr)
	}
}

func TestBridgeForwardResponseCopyGenericErrorTerminatesTunnel(t *testing.T) {
	fake := &fakeClientLeg{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(iotest.ErrReader(errors.New("stream reset"))),
	}}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.buildkit.v1.Control/Solve", strings.NewReader(""))
	rec := httptest.NewRecorder()

	b.forward(rec, req, "moby.buildkit.v1.Control", "Solve")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (headers are written before the body copy fails)", rec.Code)
	}
	if b.closeErr == nil {
		t.Fatal("forward() with a generic response-copy error must call closeAll with a non-nil error")
	}
	if strings.Contains(b.closeErr.Error(), errMessageTooLarge.Error()) {
		t.Fatalf("closeErr = %v, want a genuine transport error, not the size-cap sentinel", b.closeErr)
	}
}
