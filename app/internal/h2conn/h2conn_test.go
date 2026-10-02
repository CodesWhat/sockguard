package h2conn

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testWait = 5 * time.Second

type contextKey struct{}

// startServer runs Serve on one end of a pipe and returns the other end plus
// a channel closed when Serve returns. The pipe is closed with the test.
func startServer(t *testing.T, ctx context.Context, config ServerConfig) (net.Conn, <-chan struct{}) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Serve(ctx, serverSide, config)
	}()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
		waitClosed(t, done, "Serve")
	})
	return clientSide, done
}

func waitClosed(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatalf("%s did not return within %v", what, testWait)
	}
}

func newClient(t *testing.T, conn net.Conn, config *http.HTTP2Config) *http.ClientConn {
	t.Helper()
	client, err := NewClientConn(conn, config)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func roundTrip(t *testing.T, client *http.ClientConn, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	_ = resp.Body.Close()
	return resp, string(body)
}

func newRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return req
}

func TestRoundTripSpeaksHTTP2OverTheGivenConn(t *testing.T) {
	type seen struct {
		protoMajor int
		value      any
		hasTLS     bool
	}
	got := make(chan seen, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{protoMajor: r.ProtoMajor, value: r.Context().Value(contextKey{}), hasTLS: r.TLS != nil}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(body)
		w.Header().Set("Grpc-Status", "0")
	})
	ctx := context.WithValue(context.Background(), contextKey{}, "base")
	conn, _ := startServer(t, ctx, ServerConfig{Handler: handler})
	client := newClient(t, conn, nil)

	resp, body := roundTrip(t, client, newRequest(t, http.MethodPost, "http://tunnel/echo", "payload"))

	if resp.ProtoMajor != 2 {
		t.Errorf("response ProtoMajor = %d, want 2", resp.ProtoMajor)
	}
	if body != "payload" {
		t.Errorf("body = %q, want %q", body, "payload")
	}
	if status := resp.Trailer.Get("Grpc-Status"); status != "0" {
		t.Errorf("Grpc-Status trailer = %q, want %q", status, "0")
	}
	request := <-got
	if request.protoMajor != 2 {
		t.Errorf("request ProtoMajor = %d, want 2", request.protoMajor)
	}
	if request.value != "base" {
		t.Errorf("request context value = %v, want the Serve base context's", request.value)
	}
	if request.hasTLS {
		t.Error("request.TLS is set on a cleartext tunnel")
	}
}

func TestServeReturnsAndClosesConnWhenPeerGoesAway(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Serve(context.Background(), serverSide, ServerConfig{Handler: http.NotFoundHandler()})
	}()
	client, err := NewClientConn(clientSide, nil)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	roundTrip(t, client, newRequest(t, http.MethodGet, "http://tunnel/", ""))

	select {
	case <-done:
		t.Fatal("Serve returned while the connection was still open")
	case <-time.After(50 * time.Millisecond):
	}

	if err := client.Close(); err != nil {
		t.Fatalf("closing the client connection: %v", err)
	}
	waitClosed(t, done, "Serve")

	if _, err := serverSide.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("write to the served conn after Serve returned: err = %v, want io.ErrClosedPipe", err)
	}
	if _, err := clientSide.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("write to the client conn after Close: err = %v, want io.ErrClosedPipe", err)
	}
}

// tlsLookingConn has the ConnectionState method net/http uses to decide a
// connection is TLS, the way a *tls.Conn hijacked from an HTTPS listener does.
type tlsLookingConn struct {
	net.Conn
}

func (tlsLookingConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
}

func TestServeTreatsATLSConnAsAnOrdinaryByteStream(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Serve(context.Background(), tlsLookingConn{serverSide}, ServerConfig{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "served")
		})})
	}()
	t.Cleanup(func() {
		_ = clientSide.Close()
		waitClosed(t, done, "Serve")
	})
	client := newClient(t, clientSide, nil)

	_, body := roundTrip(t, client, newRequest(t, http.MethodGet, "http://tunnel/", ""))
	if body != "served" {
		t.Fatalf("body = %q, want %q", body, "served")
	}
}

func TestServeHandsOptionsStarToTheHandler(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handled-By", "caller")
		w.WriteHeader(http.StatusForbidden)
	})
	conn, _ := startServer(t, context.Background(), ServerConfig{Handler: handler})
	client := newClient(t, conn, nil)

	req := &http.Request{
		Method: http.MethodOptions,
		URL:    &url.URL{Scheme: "http", Host: "tunnel", Path: "*"},
		Header: http.Header{},
		Host:   "tunnel",
	}
	resp, _ := roundTrip(t, client, req)

	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Handled-By") != "caller" {
		t.Fatalf("OPTIONS * answered with status %d and X-Handled-By %q, want the caller's handler to answer it",
			resp.StatusCode, resp.Header.Get("X-Handled-By"))
	}
}

func TestServeAdvertisesMaxConcurrentStreams(t *testing.T) {
	const limit = 3
	conn, _ := startServer(t, context.Background(), ServerConfig{Handler: http.NotFoundHandler(), MaxConcurrentStreams: limit})
	client := newClient(t, conn, nil)

	// The client only knows the server's limit once it has read the server's
	// SETTINGS, which a completed round trip guarantees.
	roundTrip(t, client, newRequest(t, http.MethodGet, "http://tunnel/", ""))

	if got := client.Available(); got != limit {
		t.Fatalf("client.Available() = %d after the server's SETTINGS, want %d", got, limit)
	}
}

func TestServeClosesAnIdleConn(t *testing.T) {
	conn, done := startServer(t, context.Background(), ServerConfig{Handler: http.NotFoundHandler(), IdleTimeout: 30 * time.Millisecond})
	newClient(t, conn, nil)

	waitClosed(t, done, "Serve with a 30ms IdleTimeout")
}

func TestServeClosesAConnThatNeverSendsThePreface(t *testing.T) {
	called := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called <- struct{}{} })
	conn, done := startServer(t, context.Background(), ServerConfig{Handler: handler, PrefaceTimeout: 30 * time.Millisecond})

	// Serve must not write anything before the preface arrives, so the first
	// thing a silent peer sees is the close.
	_ = conn.SetReadDeadline(time.Now().Add(testWait))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read from a conn Serve timed out = (%d, %v), want (0, io.EOF)", n, err)
	}
	waitClosed(t, done, "Serve with a 30ms PrefaceTimeout")
	select {
	case <-called:
		t.Fatal("handler ran on a connection that never sent the client preface")
	default:
	}
}

func TestServeClosesAConnThatDoesNotSpeakHTTP2(t *testing.T) {
	called := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called <- struct{}{} })
	conn, done := startServer(t, context.Background(), ServerConfig{Handler: handler})

	// The pipe is unbuffered, so this write fails partway once Serve has
	// read enough to know it is not the preface and hangs up.
	go func() { _, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: tunnel\r\n\r\n") }()

	_ = conn.SetReadDeadline(time.Now().Add(testWait))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after sending HTTP/1.1 = (%d, %v), want (0, io.EOF): Serve must not answer in HTTP/1", n, err)
	}
	waitClosed(t, done, "Serve")
	select {
	case <-called:
		t.Fatal("handler ran for an HTTP/1.1 request")
	default:
	}
}

// HTTP/2 frame types this test reads off the wire (RFC 9113 section 6).
const (
	frameTypeSettings = 0x4
	frameTypePing     = 0x6
)

// readFrameType reads one HTTP/2 frame from r and returns its type,
// discarding the payload.
func readFrameType(r io.Reader) (byte, error) {
	var header [9]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	length := int64(header[0])<<16 | int64(header[1])<<8 | int64(header[2])
	if _, err := io.CopyN(io.Discard, r, length); err != nil {
		return 0, err
	}
	return header[3], nil
}

func TestServePingsAPeerThatGoesQuiet(t *testing.T) {
	conn, _ := startServer(t, context.Background(), ServerConfig{Handler: http.NotFoundHandler(), ReadIdleTimeout: 30 * time.Millisecond})

	// A hand-rolled peer: the client preface and an empty SETTINGS frame,
	// then silence. Writes go on their own goroutine because the pipe is
	// unbuffered and Serve only reads the SETTINGS once it has started
	// writing its own.
	go func() {
		_, _ = io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		_, _ = conn.Write([]byte{0, 0, 0, frameTypeSettings, 0, 0, 0, 0, 0})
	}()

	_ = conn.SetReadDeadline(time.Now().Add(testWait))
	for {
		frameType, err := readFrameType(conn)
		if err != nil {
			t.Fatalf("no PING arrived from Serve with a 30ms ReadIdleTimeout: %v", err)
		}
		if frameType == frameTypePing {
			return
		}
	}
}

func TestNewClientConnFailsOnADeadConn(t *testing.T) {
	conn, peer := net.Pipe()
	_ = peer.Close()
	_ = conn.Close()

	client, err := NewClientConn(conn, nil)
	if err == nil {
		_ = client.Close()
		t.Fatal("NewClientConn on a closed conn returned no error")
	}
}

func TestNewClientConnAppliesTheHTTP2Config(t *testing.T) {
	const (
		settingMaxFrameSize = 0x5
		maxReadFrameSize    = 32 << 10
	)
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})

	// NewClientConn blocks on the unbuffered pipe until its preface and
	// SETTINGS are read, so it runs beside the reader below.
	type result struct {
		client *http.ClientConn
		err    error
	}
	created := make(chan result, 1)
	go func() {
		client, err := NewClientConn(conn, &http.HTTP2Config{MaxReadFrameSize: maxReadFrameSize})
		created <- result{client, err}
	}()

	_ = peer.SetReadDeadline(time.Now().Add(testWait))
	preface := make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if _, err := io.ReadFull(peer, preface); err != nil {
		t.Fatalf("reading the client preface: %v", err)
	}
	if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		t.Fatalf("client preface = %q", preface)
	}
	var header [9]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil {
		t.Fatalf("reading the client's SETTINGS header: %v", err)
	}
	if header[3] != frameTypeSettings {
		t.Fatalf("first client frame type = %#x, want SETTINGS", header[3])
	}
	payload := make([]byte, int(header[0])<<16|int(header[1])<<8|int(header[2]))
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("reading the client's SETTINGS payload: %v", err)
	}
	// Each setting is a 16-bit identifier and a 32-bit value.
	advertised := -1
	for ; len(payload) >= 6; payload = payload[6:] {
		if int(payload[0])<<8|int(payload[1]) == settingMaxFrameSize {
			advertised = int(payload[2])<<24 | int(payload[3])<<16 | int(payload[4])<<8 | int(payload[5])
		}
	}
	if advertised != maxReadFrameSize {
		t.Fatalf("client advertised SETTINGS_MAX_FRAME_SIZE %d, want the configured %d", advertised, maxReadFrameSize)
	}

	// Drain the WINDOW_UPDATE that follows so NewClientConn's flush completes.
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	select {
	case got := <-created:
		if got.err != nil {
			t.Fatalf("NewClientConn: %v", got.err)
		}
		_ = got.client.Close()
	case <-time.After(testWait):
		t.Fatal("NewClientConn did not return after its handshake was read")
	}
}

func TestDialOnceYieldsTheConnExactlyOnce(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})
	dial := dialOnce(conn)

	got, err := dial(context.Background(), "tcp", clientConnAddress)
	if err != nil || got != conn {
		t.Fatalf("first dial = (%v, %v), want the wrapped conn", got, err)
	}
	if got, err := dial(context.Background(), "tcp", clientConnAddress); got != nil || !errors.Is(err, errConnAlreadyUsed) {
		t.Fatalf("second dial = (%v, %v), want (nil, errConnAlreadyUsed)", got, err)
	}
}

func TestSingleConnListener(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})
	listener := &singleConnListener{conn: conn, done: make(chan struct{})}

	if got := listener.Addr(); got != conn.LocalAddr() {
		t.Errorf("Addr() = %v, want the conn's local address %v", got, conn.LocalAddr())
	}
	if got, err := listener.Accept(); err != nil || got != conn {
		t.Fatalf("first Accept = (%v, %v), want the conn", got, err)
	}

	second := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		second <- err
	}()
	select {
	case err := <-second:
		t.Fatalf("second Accept returned %v before the listener was closed", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case err := <-second:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(testWait):
		t.Fatal("second Accept stayed blocked after Close")
	}
}
