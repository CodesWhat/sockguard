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
	if !headerHasToken(h, "Connection", "upgrade") {
		t.Error("headerHasToken() = false, want true (case-insensitive, comma-separated match)")
	}
	if headerHasToken(h, "Connection", "close") {
		t.Error("headerHasToken() = true for absent token, want false")
	}
	if headerHasToken(http.Header{}, "Connection", "upgrade") {
		t.Error("headerHasToken() on empty header = true, want false")
	}
}

func TestRewriteSessionAdvertisement(t *testing.T) {
	h := http.Header{}
	h.Add(sessionGRPCMethodHeader, "moby.filesync.v1.FileSync")
	h.Add(sessionGRPCMethodHeader, "moby.buildkit.v1.frontend.LLBBridge") // fully denied
	h.Add(sessionGRPCMethodHeader, "moby.filesync.v1.Auth")
	h.Add(sessionGRPCMethodHeader, "  ") // blank after trim, must be dropped silently

	rewriteSessionAdvertisement(h)

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
	rewriteSessionAdvertisement(h)
	if len(h.Values(sessionGRPCMethodHeader)) != 0 {
		t.Error("rewriteSessionAdvertisement invented a header that was never present")
	}
	if h.Get("Other-Header") != "unchanged" {
		t.Error("rewriteSessionAdvertisement touched an unrelated header")
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

func TestDialDaemonH2CDialError(t *testing.T) {
	wantErr := errors.New("boom")
	_, _, err := dialDaemonH2C(context.Background(), &fakeDialer{err: wantErr}, "/grpc", http.Header{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("dialDaemonH2C() error = %v, want wrapping %v", err, wantErr)
	}
}

func TestDialDaemonH2CRejectsNon101(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()
	defer func() { _ = daemonSide.Close() }()

	go func() {
		req, err := http.ReadRequest(bufio.NewReader(daemonSide))
		if err != nil {
			return
		}
		_ = req.Body.Close()
		_, _ = daemonSide.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	}()

	_, _, err := dialDaemonH2C(context.Background(), &fakeDialer{conn: dialerSide}, "/session", http.Header{})
	if err == nil {
		t.Fatal("dialDaemonH2C() with a 403 daemon response = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("dialDaemonH2C() error = %v, want it to mention the rejected status", err)
	}
}

func TestDialDaemonH2CWriteRequestFailure(t *testing.T) {
	_, conn := net.Pipe()
	_ = conn.Close() // both ends dead: any Write returns io.ErrClosedPipe immediately

	_, _, err := dialDaemonH2C(context.Background(), &fakeDialer{conn: conn}, "/grpc", http.Header{})
	if err == nil {
		t.Fatal("dialDaemonH2C() with a dead conn = nil error, want an error writing the upgrade request")
	}
	if !strings.Contains(err.Error(), "write daemon upgrade request") {
		t.Fatalf("dialDaemonH2C() error = %v, want it to mention writing the upgrade request", err)
	}
}

func TestDialDaemonH2CReadResponseFailure(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()

	go func() {
		req, err := http.ReadRequest(bufio.NewReader(daemonSide))
		if err != nil {
			return
		}
		_ = req.Body.Close()
		// Close without ever writing a response: http.ReadResponse on the
		// dialer side must fail (EOF), not hang or succeed.
		_ = daemonSide.Close()
	}()

	_, _, err := dialDaemonH2C(context.Background(), &fakeDialer{conn: dialerSide}, "/session", http.Header{})
	if err == nil {
		t.Fatal("dialDaemonH2C() with a daemon that closes without responding = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "read daemon upgrade response") {
		t.Fatalf("dialDaemonH2C() error = %v, want it to mention reading the upgrade response", err)
	}
}

func TestDialDaemonH2CSuccess(t *testing.T) {
	daemonSide, dialerSide := net.Pipe()
	defer func() { _ = daemonSide.Close() }()

	var gotUpgrade, gotConnection, gotSessionUUID string
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
		_ = req.Body.Close()
		_, _ = daemonSide.Write([]byte("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"))
	}()

	hdr := http.Header{}
	hdr.Set(sessionUUIDHeader, "abc-123")
	conn, resp, err := dialDaemonH2C(context.Background(), &fakeDialer{conn: dialerSide}, "/session", hdr)
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
}

func TestHijackClientH2CNotAHijacker(t *testing.T) {
	rec := httptest.NewRecorder()
	_, err := hijackClientH2C(rec, &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}})
	if err == nil {
		t.Fatal("hijackClientH2C() with a non-Hijacker ResponseWriter = nil error, want an error")
	}
}

func TestHijackClientH2CHijackError(t *testing.T) {
	w := newFakeHijackWriter(nil)
	w.hijackErr = errors.New("hijack not supported here")
	_, err := hijackClientH2C(w, &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}})
	if !errors.Is(err, w.hijackErr) {
		t.Fatalf("hijackClientH2C() error = %v, want wrapping %v", err, w.hijackErr)
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

func TestHijackClientH2CWriteResponseFailure(t *testing.T) {
	// A response whose Body read fails makes resp.Write(buf) itself return an
	// error (net/http chunks the body into the write when ContentLength < 0)
	// — a distinct failure point from TestHijackClientH2CWriteFailure below,
	// which exercises the subsequent buf.Flush() failing instead.
	_, hijackSide := net.Pipe()
	w := newFakeHijackWriter(hijackSide)

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

	if _, err := hijackClientH2C(w, resp); err == nil {
		t.Fatal("hijackClientH2C() with a response body that fails to read = nil error, want an error")
	} else if !strings.Contains(err.Error(), "write 101 to client") {
		t.Fatalf("hijackClientH2C() error = %v, want it to mention writing the 101 response", err)
	}
}

func TestHijackClientH2CWriteFailure(t *testing.T) {
	server, client := net.Pipe()
	_ = server.Close() // peer gone before Write/Flush is attempted

	w := newFakeHijackWriter(client)
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}}
	if _, err := hijackClientH2C(w, resp); err == nil {
		t.Fatal("hijackClientH2C() with a dead peer = nil error, want an error")
	}
}
