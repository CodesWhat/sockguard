package buildkitproxy

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
)

// fakeDialer implements Dialer over a pre-established net.Conn (typically
// one end of a net.Pipe), or returns a fixed error — used across this
// package's tests to stand in for the real *upstream.Resolver without
// importing internal/upstream (which would create an import cycle risk this
// leaf package's doc comments explicitly avoid).
type fakeDialer struct {
	conn        net.Conn
	err         error
	basePath    string
	rawBasePath string
}

func (d *fakeDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func (d *fakeDialer) DialRequest(ctx context.Context, req *http.Request) (net.Conn, *http.Request, error) {
	conn, err := d.DialContext(ctx, "", "")
	if err != nil {
		return nil, nil, err
	}
	clone := req.Clone(req.Context())
	urlCopy := *req.URL
	clone.URL = &urlCopy
	clone.URL.Path = d.basePath + req.URL.Path
	if d.rawBasePath != "" || req.URL.RawPath != "" {
		clone.URL.RawPath = d.rawBasePath + req.URL.EscapedPath()
	}
	return conn, clone, nil
}

// fakeHijackWriter is a minimal http.ResponseWriter + http.Hijacker test
// double backed by a pre-established net.Conn, standing in for the real
// *http.response the stdlib server hands handlers — which cannot be
// constructed directly outside net/http itself.
type fakeHijackWriter struct {
	header      http.Header
	status      int
	conn        net.Conn
	hijackErr   error
	hijacked    bool
	wroteHeader bool
}

func newFakeHijackWriter(conn net.Conn) *fakeHijackWriter {
	return &fakeHijackWriter{header: make(http.Header), conn: conn}
}

func (w *fakeHijackWriter) Header() http.Header { return w.header }

func (w *fakeHijackWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return len(p), nil
}

func (w *fakeHijackWriter) WriteHeader(status int) {
	w.wroteHeader = true
	w.status = status
}

func (w *fakeHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.hijackErr != nil {
		return nil, nil, w.hijackErr
	}
	w.hijacked = true
	br := bufio.NewReader(w.conn)
	bw := bufio.NewWriter(w.conn)
	return w.conn, bufio.NewReadWriter(br, bw), nil
}

// noopLogger returns a *slog.Logger that discards everything, so tests don't
// spam output while still exercising every log call for coverage/race
// purposes.
func noopLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
