package buildkitproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestValidateUpgradeRequest(t *testing.T) {
	valid := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/session", nil)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "h2c")
		return r
	}

	cases := []struct {
		name    string
		mutate  func(r *http.Request)
		wantErr error // nil means "any non-nil error", checked via errors.Is when set
	}{
		{"valid request", func(r *http.Request) {}, nil},
		{"wrong method", func(r *http.Request) { r.Method = http.MethodGet }, ErrNotUpgradeRequest},
		{"missing Connection header", func(r *http.Request) { r.Header.Del("Connection") }, ErrNotUpgradeRequest},
		{"Connection without Upgrade token", func(r *http.Request) { r.Header.Set("Connection", "keep-alive") }, ErrNotUpgradeRequest},
		{"missing Upgrade header", func(r *http.Request) { r.Header.Del("Upgrade") }, ErrNotUpgradeRequest},
		{"wrong Upgrade token", func(r *http.Request) { r.Header.Set("Upgrade", "tcp") }, ErrNotUpgradeRequest},
		{"multiple Upgrade values", func(r *http.Request) { r.Header.Add("Upgrade", "websocket") }, ErrNotUpgradeRequest},
		{"Upgrade is case-insensitive h2c", func(r *http.Request) { r.Header.Set("Upgrade", "H2C") }, nil},
		{"has content length body", func(r *http.Request) { r.ContentLength = 10 }, ErrUpgradeHasBody},
		{"has transfer encoding", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, ErrConflictingFraming},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.mutate(r)
			err := ValidateUpgradeRequest(r)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateUpgradeRequest() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateUpgradeRequest() = %v, want error matching %v", err, tc.wantErr)
			}
		})
	}
}

func TestHeaderHasToken(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, Upgrade")

	cases := []struct {
		name  string
		h     http.Header
		token string
		want  bool
	}{
		{"case-insensitive, comma-separated match", h, "upgrade", true},
		{"absent token", h, "close", false},
		{"empty header", http.Header{}, "upgrade", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := headerHasToken(tc.h, "Connection", tc.token); got != tc.want {
				t.Errorf("headerHasToken() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRewriteSessionAdvertisement(t *testing.T) {
	h := http.Header{}
	h.Add(sessionGRPCMethodHeader, "moby.filesync.v1.FileSync")
	h.Add(sessionGRPCMethodHeader, "moby.buildkit.v1.frontend.LLBBridge") // fully denied
	h.Add(sessionGRPCMethodHeader, "moby.filesync.v1.Auth")
	h.Add(sessionGRPCMethodHeader, "  ") // blank after trim, must be dropped silently

	rewriteSessionAdvertisement(h, allowAllPolicy)

	got := h.Values(sessionGRPCMethodHeader)
	want := []string{"moby.filesync.v1.FileSync", "moby.filesync.v1.Auth"}
	if len(got) != len(want) {
		t.Fatalf("rewritten advertisement = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rewritten advertisement = %v, want %v", got, want)
		}
	}
}

func TestRewriteSessionAdvertisementNoHeaderIsNoop(t *testing.T) {
	h := http.Header{}
	h.Set("Other-Header", "unchanged")
	rewriteSessionAdvertisement(h, allowAllPolicy)
	if len(h.Values(sessionGRPCMethodHeader)) != 0 {
		t.Error("rewriteSessionAdvertisement invented a header that was never present")
	}
	if h.Get("Other-Header") != "unchanged" {
		t.Error("rewriteSessionAdvertisement touched an unrelated header")
	}
}

// TestRewriteSessionAdvertisementStripsPolicyDeniedService pins CodeRabbit's
// finding: moby.filesync.v1.Auth is registered Mediate under EndpointSession
// (so the registry admits it in principle), but a policy that
// never turns Session.Auth.Allow on must still see it stripped — advertising
// a registry-admitted-but-policy-denied service would invite a daemon
// callback the bridge only rejects after the fact.
func TestRewriteSessionAdvertisementStripsPolicyDeniedService(t *testing.T) {
	h := http.Header{}
	h.Add(sessionGRPCMethodHeader, "moby.filesync.v1.FileSync")
	h.Add(sessionGRPCMethodHeader, "moby.filesync.v1.Auth")

	p := Policy{Session: SessionPolicy{FileSync: FileSyncPolicy{Allow: true}}}
	rewriteSessionAdvertisement(h, p)

	got := h.Values(sessionGRPCMethodHeader)
	want := []string{"moby.filesync.v1.FileSync"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("rewritten advertisement = %v, want %v (Auth is registry-admitted but policy-denied, and must be stripped)", got, want)
	}
}

func TestBufferedConnReadsBufferedBytesFirst(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	written := make(chan struct{})
	go func() {
		_, _ = client.Write([]byte("hello-world"))
		close(written)
	}()

	br := bufio.NewReaderSize(server, 4096)
	if _, err := br.Peek(5); err != nil {
		t.Fatalf("Peek: %v", err)
	}
	<-written

	bc := &bufferedConn{Conn: server, r: br}
	buf := make([]byte, 32)
	n, err := bc.Read(buf)
	if err != nil {
		t.Fatalf("bufferedConn.Read: %v", err)
	}
	if got := string(buf[:n]); got != "hello-world" {
		t.Fatalf("bufferedConn.Read returned %q, want %q", got, "hello-world")
	}
}

// TestDialDaemonH2CDialAndWriteFailureModes tables the two failure points
// that happen before any bytes come back from the daemon at all: the dial
// itself, and writing the upgrade request onto an already-dead connection.
func TestDialDaemonH2CDialAndWriteFailureModes(t *testing.T) {
	wantErr := errors.New("boom")

	cases := []struct {
		name        string
		dialer      *fakeDialer
		wantErr     error  // checked via errors.Is when set
		wantErrText string // checked via strings.Contains when set
	}{
		{
			name:    "dial failure",
			dialer:  &fakeDialer{err: wantErr},
			wantErr: wantErr,
		},
		{
			name: "write request failure (dead conn)",
			dialer: func() *fakeDialer {
				_, conn := net.Pipe()
				_ = conn.Close() // both ends dead: any Write returns io.ErrClosedPipe immediately
				return &fakeDialer{conn: conn}
			}(),
			wantErrText: "write daemon upgrade request",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := dialDaemonH2C(context.Background(), tc.dialer, "/grpc", http.Header{})
			if err == nil {
				t.Fatal("dialDaemonH2C() = nil error, want non-nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("dialDaemonH2C() error = %v, want wrapping %v", err, tc.wantErr)
			}
			if tc.wantErrText != "" && !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("dialDaemonH2C() error = %v, want it to mention %q", err, tc.wantErrText)
			}
		})
	}
}

// TestDialDaemonH2CRejectsInvalidResponse tables every way the daemon's
// response to the upgrade request can fail to be a genuine h2c upgrade: no
// response at all, a non-101 status, and — pinning CodeRabbit's finding that
// a 101 status alone doesn't prove the upgrade — a 101 whose
// Connection/Upgrade headers don't actually say "h2c".
func TestDialDaemonH2CRejectsInvalidResponse(t *testing.T) {
	cases := []struct {
		name        string
		daemonReply func(daemonSide net.Conn)
		wantErrText string
	}{
		{
			name: "daemon closes without responding",
			daemonReply: func(daemonSide net.Conn) {
				// Close without ever writing a response: http.ReadResponse on
				// the dialer side must fail (EOF), not hang or succeed.
				_ = daemonSide.Close()
			},
			wantErrText: "read daemon upgrade response",
		},
		{
			name: "non-101 status",
			daemonReply: func(daemonSide net.Conn) {
				_, _ = daemonSide.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			},
			wantErrText: "403",
		},
		{
			name: "101 missing Connection: Upgrade",
			daemonReply: func(daemonSide net.Conn) {
				_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nUpgrade: h2c\r\n\r\n"))
			},
			wantErrText: "missing \"Connection: Upgrade\"",
		},
		{
			name: "101 with a non-h2c Upgrade token",
			daemonReply: func(daemonSide net.Conn) {
				_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
			},
			wantErrText: "Upgrade header must be exactly",
		},
		{
			name: "101 with multiple Upgrade values",
			daemonReply: func(daemonSide net.Conn) {
				_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nUpgrade: websocket\r\n\r\n"))
			},
			wantErrText: "Upgrade header must be exactly",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			daemonSide, dialerSide := net.Pipe()
			defer func() { _ = daemonSide.Close() }()

			go func() {
				req, err := http.ReadRequest(bufio.NewReader(daemonSide))
				if err != nil {
					return
				}
				_ = req.Body.Close()
				tc.daemonReply(daemonSide)
			}()

			_, _, err := dialDaemonH2C(context.Background(), &fakeDialer{conn: dialerSide}, "/session", http.Header{})
			if err == nil {
				t.Fatal("dialDaemonH2C() = nil error, want non-nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("dialDaemonH2C() error = %v, want it to mention %q", err, tc.wantErrText)
			}
		})
	}
}

// TestDialDaemonH2CSuccess is left as a single integration-style test rather
// than folded into the table above: unlike the failure modes, it asserts on
// the daemon-observed request headers AND the returned response/conn, which
// doesn't fit the table's single wantErrText shape.
func TestDialDaemonH2CSuccess(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()
	defer func() { _ = daemonSide.Close() }()

	var gotUpgrade, gotConnection, gotSessionUUID, gotRequestURI string
	requestRead := make(chan struct{})
	go func() {
		defer close(requestRead)
		req, err := http.ReadRequest(bufio.NewReader(daemonSide))
		if err != nil {
			return
		}
		gotUpgrade = req.Header.Get("Upgrade")
		gotConnection = req.Header.Get("Connection")
		gotSessionUUID = req.Header.Get(sessionUUIDHeader)
		gotRequestURI = req.RequestURI
		_ = req.Body.Close()
		_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"))
	}()

	hdr := http.Header{}
	hdr.Set(sessionUUIDHeader, "abc-123")
	conn, resp, err := dialDaemonH2C(context.Background(), &fakeDialer{
		conn:        dialerSide,
		basePath:    "/proxy/api",
		rawBasePath: "/proxy%2Fapi",
	}, "/session", hdr)
	if err != nil {
		t.Fatalf("dialDaemonH2C() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	<-requestRead

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("resp.StatusCode = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	if gotUpgrade != "h2c" {
		t.Errorf("daemon saw Upgrade = %q, want %q", gotUpgrade, "h2c")
	}
	if !strings.Contains(gotConnection, "Upgrade") {
		t.Errorf("daemon saw Connection = %q, want it to contain Upgrade", gotConnection)
	}
	if gotSessionUUID != "abc-123" {
		t.Errorf("daemon saw %s = %q, want %q (caller-supplied headers must be forwarded)", sessionUUIDHeader, gotSessionUUID, "abc-123")
	}
	if gotRequestURI != "/proxy%2Fapi/session" {
		t.Errorf("daemon saw RequestURI = %q, want endpoint base path", gotRequestURI)
	}
}

func TestDialDaemonH2CPreservesBasePathForBothDockerUpgradeEndpoints(t *testing.T) {
	for _, path := range []string{"/session", "/grpc"} {
		path := path
		t.Run(path, func(t *testing.T) {
			daemonSide, dialerSide := net.Pipe()
			defer func() { _ = daemonSide.Close() }()
			requestURI := make(chan string, 1)
			go func() {
				req, err := http.ReadRequest(bufio.NewReader(daemonSide))
				if err != nil {
					requestURI <- "read error: " + err.Error()
					return
				}
				requestURI <- req.RequestURI
				_ = req.Body.Close()
				_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"))
			}()

			conn, resp, err := dialDaemonH2C(context.Background(), &fakeDialer{
				conn:        dialerSide,
				basePath:    "/gateway/docker",
				rawBasePath: "/gateway%2Fdocker",
			}, path, http.Header{})
			if err != nil {
				t.Fatalf("dialDaemonH2C: %v", err)
			}
			_ = resp.Body.Close()
			_ = conn.Close()
			if got := <-requestURI; got != "/gateway%2Fdocker"+path {
				t.Fatalf("RequestURI = %q, want %q", got, "/gateway%2Fdocker"+path)
			}
		})
	}
}

// TestHijackClientH2CHijackFailureModes tables the two ways obtaining the
// hijacked connection itself can fail: the ResponseWriter never supported
// hijacking at all, and Hijack() being called but returning its own error.
func TestHijackClientH2CHijackFailureModes(t *testing.T) {
	hijackErr := errors.New("hijack not supported here")
	failingHijacker := newFakeHijackWriter(nil)
	failingHijacker.hijackErr = hijackErr

	cases := []struct {
		name    string
		w       http.ResponseWriter
		wantErr error // checked via errors.Is when set
	}{
		{"response writer does not support hijacking", httptest.NewRecorder(), nil},
		{"Hijack() itself fails", failingHijacker, hijackErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hijackClientH2C(tc.w, &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}})
			if err == nil {
				t.Fatal("hijackClientH2C() = nil error, want non-nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("hijackClientH2C() error = %v, want wrapping %v", err, tc.wantErr)
			}
		})
	}
}

func TestHijackClientH2CSuccess(t *testing.T) {
	testSide, hijackSide := net.Pipe()
	defer func() { _ = testSide.Close() }()

	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 UPGRADED",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Connection": {"Upgrade"}, "Upgrade": {"h2c"}},
	}

	w := newFakeHijackWriter(hijackSide)

	readDone := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := testSide.Read(buf)
		readDone <- string(buf[:n])
	}()

	conn, err := hijackClientH2C(w, resp)
	if err != nil {
		t.Fatalf("hijackClientH2C() error = %v", err)
	}
	if !w.hijacked {
		t.Fatal("hijackClientH2C() did not call Hijack()")
	}

	select {
	case got := <-readDone:
		if !strings.Contains(got, "101") || !strings.Contains(got, "Upgrade: h2c") {
			t.Fatalf("bytes written to hijacked conn = %q, want a 101 response with Upgrade: h2c", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the 101 response to be written to the hijacked connection")
	}

	// The returned conn must still be usable for further I/O (it's the raw
	// tunnel the bridge takes over next).
	go func() { _, _ = testSide.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading through the returned conn: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("read %q through the returned conn, want %q", buf, "ping")
	}
}

// TestHijackClientH2CWriteFailureModes tables the two ways replaying the
// 101 response to the hijacked connection can fail: a response body whose
// Read fails (net/http chunks the body into resp.Write itself when
// ContentLength < 0, so this fails inside Write), and the peer already being
// gone before Write/Flush is attempted at all.
func TestHijackClientH2CWriteFailureModes(t *testing.T) {
	cases := []struct {
		name        string
		setup       func() (http.ResponseWriter, *http.Response)
		wantErrText string
	}{
		{
			name: "response body read fails during Write",
			setup: func() (http.ResponseWriter, *http.Response) {
				_, hijackSide := net.Pipe()
				resp := &http.Response{
					StatusCode:    http.StatusSwitchingProtocols,
					Status:        "101 UPGRADED",
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        http.Header{"Connection": {"Upgrade"}, "Upgrade": {"h2c"}},
					Body:          io.NopCloser(iotest.ErrReader(errors.New("boom"))),
					ContentLength: -1,
				}
				return newFakeHijackWriter(hijackSide), resp
			},
			wantErrText: "write 101 to client",
		},
		{
			name: "peer gone before Write/Flush is attempted",
			setup: func() (http.ResponseWriter, *http.Response) {
				server, client := net.Pipe()
				_ = server.Close()
				return newFakeHijackWriter(client), &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, resp := tc.setup()
			_, err := hijackClientH2C(w, resp)
			if err == nil {
				t.Fatal("hijackClientH2C() = nil error, want non-nil")
			}
			if tc.wantErrText != "" && !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("hijackClientH2C() error = %v, want it to mention %q", err, tc.wantErrText)
			}
		})
	}
}
