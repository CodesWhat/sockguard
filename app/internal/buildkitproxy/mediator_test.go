package buildkitproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func newUpgradeRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "h2c")
	return r
}

func TestMediatorServeGRPCRejectsInvalidUpgrade(t *testing.T) {
	m := NewMediator(&fakeDialer{err: errors.New("must not be dialed")}, noopLogger())

	r := newUpgradeRequest(t, "/grpc")
	r.Method = http.MethodGet // invalid: not a POST
	rec := httptest.NewRecorder()

	m.ServeGRPC(rec, r, allowAllPolicy, SessionKey{ClientIdentity: "c", Profile: "p"})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if m.Registry.Len() != 0 {
		t.Fatalf("registry.Len() = %d after a rejected upgrade, want 0 (no session should ever be opened)", m.Registry.Len())
	}
}

func TestMediatorServeGRPCDaemonDialFailure(t *testing.T) {
	m := NewMediator(&fakeDialer{err: errors.New("connection refused")}, noopLogger())

	r := newUpgradeRequest(t, "/grpc")
	rec := httptest.NewRecorder()

	m.ServeGRPC(rec, r, allowAllPolicy, SessionKey{ClientIdentity: "c", Profile: "p"})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if m.Registry.Len() != 0 {
		t.Fatalf("registry.Len() = %d after a daemon dial failure, want 0", m.Registry.Len())
	}
}

func TestMediatorServeGRPCDaemonRejectsUpgrade(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()
	defer func() { _ = daemonSide.Close() }()
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(daemonSide))
		if err != nil {
			return
		}
		_ = req.Body.Close()
		_, _ = daemonSide.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"))
	}()

	m := NewMediator(&fakeDialer{conn: dialerSide}, noopLogger())
	r := newUpgradeRequest(t, "/grpc")
	rec := httptest.NewRecorder()

	m.ServeGRPC(rec, r, allowAllPolicy, SessionKey{ClientIdentity: "c", Profile: "p"})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

// fakeHijackResponseRecorder is httptest.NewRecorder augmented with
// http.Hijacker, backed by one end of a net.Pipe — used so
// Mediator.serve's real HTTP error paths (httptest.ResponseRecorder) and
// its real hijack path (this type) are each tested with the minimal double
// that actually satisfies the interfaces it needs.
type fakeHijackResponseRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *fakeHijackResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	br := bufio.NewReader(w.conn)
	bw := bufio.NewWriter(w.conn)
	return w.conn, bufio.NewReadWriter(br, bw), nil
}

// runDaemonH2CStub drives the daemon side of an h2c upgrade handshake to
// completion (read the POST request, reply 101), then serves handler as an
// h2c server over the same connection for the rest of the tunnel's life —
// standing in for buildkitd (EndpointGRPC) or, for EndpointSession tests,
// for "the daemon leg sockguard also dials" per the reversed-roles design.
func runDaemonH2CStub(t *testing.T, conn net.Conn, handler http.Handler) {
	t.Helper()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = req.Body.Close()
	if _, err := conn.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")); err != nil {
		return
	}
	srv := &http2.Server{}
	srv.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
}

func TestMediatorServeGRPCEndToEnd(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()
	defer func() { _ = daemonSide.Close() }()

	daemonHandlerDone := make(chan struct{})
	go func() {
		defer close(daemonHandlerDone)
		runDaemonH2CStub(t, daemonSide, echoDaemonHandler())
	}()

	clientTestSide, clientHijackSide := net.Pipe()
	defer func() { _ = clientTestSide.Close() }()

	m := NewMediator(&fakeDialer{conn: dialerSide}, noopLogger())
	r := newUpgradeRequest(t, "/grpc")
	w := &fakeHijackResponseRecorder{ResponseRecorder: httptest.NewRecorder(), conn: clientHijackSide}

	serveReturned := make(chan struct{})
	go func() {
		defer close(serveReturned)
		m.ServeGRPC(w, r, allowAllPolicy, SessionKey{ClientIdentity: "test-client", Profile: "ci"})
	}()

	// Read the 101 response sockguard replays to the "client" side.
	clientBr := bufio.NewReader(clientTestSide)
	resp, err := http.ReadResponse(clientBr, r)
	if err != nil {
		t.Fatalf("reading the 101 response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// The connection is now h2c: drive a request into it as the client leg
	// of the real gRPC tunnel and confirm it gets bridged all the way to the
	// echo daemon and back.
	tr := &http2.Transport{AllowHTTP: true}
	cc, err := tr.NewClientConn(&bufferedConn{Conn: clientTestSide, r: clientBr})
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	defer func() { _ = cc.Close() }()

	// Info (Passthrough), not Solve: this test exercises end-to-end h2c
	// tunnel wiring, not Phase 3's Solve-specific per-message mediation
	// (covered separately in bridge_test.go), and an arbitrary non-gRPC-framed
	// payload like this one would now be rejected by Solve's frame decode.
	grpcResp, err := cc.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", "payload"))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(grpcResp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != "payload" {
		t.Fatalf("response body = %q, want %q", body, "payload")
	}

	_ = cc.Close()
	_ = clientTestSide.Close()

	select {
	case <-serveReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Mediator.ServeGRPC did not return after the client connection closed")
	}
	if m.Registry.Len() != 0 {
		t.Fatalf("registry.Len() = %d after the tunnel closed, want 0 (session must be closed on exit)", m.Registry.Len())
	}
}

func TestMediatorServeSessionRewritesAdvertisementBeforeDialingDaemon(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()
	defer func() { _ = daemonSide.Close() }()

	var gotAdvertisement []string
	requestRead := make(chan struct{})
	go func() {
		defer close(requestRead)
		br := bufio.NewReader(daemonSide)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		gotAdvertisement = req.Header.Values(sessionGRPCMethodHeader)
		_ = req.Body.Close()
		// Reject the upgrade — this test only cares about what sockguard
		// sent, not about completing a full tunnel.
		_, _ = daemonSide.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"))
	}()

	m := NewMediator(&fakeDialer{conn: dialerSide}, noopLogger())
	r := newUpgradeRequest(t, "/session")
	r.Header.Add(sessionGRPCMethodHeader, "moby.filesync.v1.FileSync")
	r.Header.Add(sessionGRPCMethodHeader, "moby.buildkit.v1.frontend.LLBBridge") // must be stripped
	rec := httptest.NewRecorder()

	m.ServeSession(rec, r, allowAllPolicy, SessionKey{ClientIdentity: "c", Profile: "p"})

	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon never received a request")
	}

	want := []string{"moby.filesync.v1.FileSync"}
	if len(gotAdvertisement) != len(want) || gotAdvertisement[0] != want[0] {
		t.Fatalf("daemon saw advertisement %v, want %v (LLBBridge is fully denied and must be stripped before forwarding)", gotAdvertisement, want)
	}
}

func TestMediatorServeSessionReversedRoles(t *testing.T) {
	// EndpointSession: the daemon leg is the SERVER role (it dials calls in,
	// per the reversed-roles design), and the hijacked client leg is the
	// CLIENT role (the CLI runs a gRPC server there). Verify by having the
	// "daemon" (h2c client, once upgraded) call INTO the tunnel and
	// confirming the request reaches a handler served on the client leg.
	daemonSide, dialerSide := net.Pipe()
	defer func() { _ = daemonSide.Close() }()

	clientCalled := make(chan string, 1)
	clientHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientCalled <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	clientTestSide, clientHijackSide := net.Pipe()
	defer func() { _ = clientTestSide.Close() }()

	m := NewMediator(&fakeDialer{conn: dialerSide}, noopLogger())
	r := newUpgradeRequest(t, "/session")
	w := &fakeHijackResponseRecorder{ResponseRecorder: httptest.NewRecorder(), conn: clientHijackSide}

	serveReturned := make(chan struct{})
	go func() {
		defer close(serveReturned)
		m.ServeSession(w, r, allowAllPolicy, SessionKey{ClientIdentity: "c", Profile: "p"})
	}()

	// Complete the daemon-side upgrade handshake, then drive requests IN as
	// the h2c client — this is buildkitd's role on /session.
	daemonBr := bufio.NewReader(daemonSide)
	daemonReq, err := http.ReadRequest(daemonBr)
	if err != nil {
		t.Fatalf("reading daemon-bound request: %v", err)
	}
	_ = daemonReq.Body.Close()
	if _, err := daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")); err != nil {
		t.Fatalf("writing 101 to daemon side: %v", err)
	}

	// Drain the 101 sockguard replays to the client hijack side so the
	// h2c client preface that follows isn't mistaken for HTTP/1.1 by
	// anything downstream — the client leg here IS the raw connection
	// sockguard hijacked, read directly by the OTHER end (clientTestSide) as
	// the CLI's own gRPC server would.
	clientBr := bufio.NewReader(clientTestSide)
	if _, err := http.ReadResponse(clientBr, r); err != nil {
		t.Fatalf("reading 101 on the client leg: %v", err)
	}
	go func() {
		srv := &http2.Server{}
		srv.ServeConn(&bufferedConn{Conn: clientTestSide, r: clientBr}, &http2.ServeConnOpts{Handler: clientHandler})
	}()

	tr := &http2.Transport{AllowHTTP: true}
	daemonCC, err := tr.NewClientConn(&bufferedConn{Conn: daemonSide, r: daemonBr})
	if err != nil {
		t.Fatalf("NewClientConn (daemon acting as client): %v", err)
	}
	defer func() { _ = daemonCC.Close() }()

	// Uses FileSync/DiffCopy (still on the plain byte-verbatim forward path,
	// deferred to Phase 5) rather than Auth/Credentials: since Phase 4,
	// Credentials is per-message mediated and requires valid gRPC framing,
	// which this test's empty body deliberately is not — this test's only
	// concern is role-wiring, not message mediation.
	_, err = daemonCC.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.FileSync/DiffCopy", ""))
	if err != nil {
		t.Fatalf("RoundTrip from the daemon leg: %v", err)
	}

	select {
	case path := <-clientCalled:
		if path != "/moby.filesync.v1.FileSync/DiffCopy" {
			t.Fatalf("client-leg handler saw path %q, want /moby.filesync.v1.FileSync/DiffCopy", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the client-leg handler was never called — EndpointSession's reversed roles are not wired correctly")
	}

	_ = daemonCC.Close()
	_ = daemonSide.Close()
	select {
	case <-serveReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Mediator.ServeSession did not return after both connections closed")
	}
}

func TestMediatorServeGRPCHijackFailureClosesDaemonConn(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()
	daemonClosed := make(chan struct{})
	go func() {
		br := bufio.NewReader(daemonSide)
		req, err := http.ReadRequest(br)
		if err == nil {
			_ = req.Body.Close()
			_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"))
		}
		buf := make([]byte, 1)
		// Block on a read; it must return (peer closed) once sockguard
		// closes daemonConn after the hijack failure below.
		_, _ = daemonSide.Read(buf)
		close(daemonClosed)
	}()

	m := NewMediator(&fakeDialer{conn: dialerSide}, noopLogger())
	r := newUpgradeRequest(t, "/grpc")
	rec := httptest.NewRecorder() // NOT a Hijacker — forces the hijack failure path

	m.ServeGRPC(rec, r, allowAllPolicy, SessionKey{ClientIdentity: "c", Profile: "p"})

	select {
	case <-daemonClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon connection was not closed after the client hijack failed")
	}
	if m.Registry.Len() != 0 {
		t.Fatalf("registry.Len() = %d after a hijack failure, want 0", m.Registry.Len())
	}
}

func TestMediatorServeGRPCTerminatesOnBridgeError(t *testing.T) {
	// Sever the daemon connection immediately after completing the h2c
	// upgrade handshake, but BEFORE sockguard's own client-leg http2
	// handshake (runBridge's clientTransport.NewClientConn) gets to run.
	// That handshake's initial preface/settings flush then fails
	// synchronously and deterministically (the peer is already gone), giving
	// serve() a non-nil runBridge error without racing real network timing.
	daemonSide, dialerSide := net.Pipe()
	go func() {
		br := bufio.NewReader(daemonSide)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"))
		_ = daemonSide.Close()
	}()

	clientTestSide, clientHijackSide := net.Pipe()
	defer func() { _ = clientTestSide.Close() }()
	go func() {
		// Drain sockguard's replayed 101 response on the client side so
		// hijackClientH2C's Flush doesn't block forever on this unbuffered
		// pipe; nothing past that response is expected on this leg since
		// runBridge fails before ever calling http2.Server.ServeConn.
		buf := make([]byte, 4096)
		for {
			if _, err := clientTestSide.Read(buf); err != nil {
				return
			}
		}
	}()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := NewMediator(&fakeDialer{conn: dialerSide}, logger)
	r := newUpgradeRequest(t, "/grpc")
	w := &fakeHijackResponseRecorder{ResponseRecorder: httptest.NewRecorder(), conn: clientHijackSide}

	serveReturned := make(chan struct{})
	go func() {
		defer close(serveReturned)
		m.ServeGRPC(w, r, allowAllPolicy, SessionKey{ClientIdentity: "c", Profile: "p"})
	}()

	select {
	case <-serveReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeGRPC did not return after the daemon leg was severed before the client-leg handshake completed")
	}

	if !strings.Contains(logBuf.String(), "buildkit: tunnel terminated") {
		t.Fatalf("log output = %q, want it to contain the tunnel-terminated warning logged on a non-nil runBridge error", logBuf.String())
	}
	if m.Registry.Len() != 0 {
		t.Fatalf("registry.Len() = %d after the tunnel failed to establish, want 0", m.Registry.Len())
	}
}

func TestNewMediatorDefaultsLoggerWhenNil(t *testing.T) {
	m := NewMediator(&fakeDialer{err: errors.New("unused")}, nil)
	if m.Logger == nil {
		t.Fatal("NewMediator(dialer, nil).Logger is nil, want slog.Default()")
	}
}

func TestCloseConnLoggedTolerantOfDoubleClose(t *testing.T) {
	_, conn := net.Pipe()
	_ = conn.Close()
	// net.Pipe's Close is idempotent (a second call returns nil), so this
	// only exercises closeConnLogged's success path — it must not panic.
	// TestCloseConnLoggedLogsCloseError below covers the err != nil branch,
	// which needs a Close that actually reports failure.
	closeConnLogged(noopLogger(), conn, "test connection", "/grpc")
}

// failCloseConn is a net.Conn whose Close always fails, standing in for a
// real close error (e.g. an already-torn-down TCP connection at the OS
// level) since net.Pipe's own Close is idempotent and never returns one.
type failCloseConn struct {
	net.Conn
	err error
}

func (c *failCloseConn) Close() error { return c.err }

func TestCloseConnLoggedLogsCloseError(t *testing.T) {
	_, conn := net.Pipe()
	failing := &failCloseConn{Conn: conn, err: errors.New("close boom")}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	closeConnLogged(logger, failing, "daemon connection", "/grpc")

	if !strings.Contains(logBuf.String(), "close boom") {
		t.Fatalf("log output = %q, want it to contain the Close error", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "daemon connection") {
		t.Fatalf("log output = %q, want it to contain the connection label", logBuf.String())
	}
}
