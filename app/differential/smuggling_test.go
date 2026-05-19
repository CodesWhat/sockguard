package differential

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
)

// The HTTP request-smuggling axis of the differential. The ServeHTTP-based
// harness in differential_test.go feeds the chain a pre-parsed *http.Request,
// which skips the net/http wire parser entirely — but smuggling lives in that
// parser: it is the gap between how sockguard frames a byte stream into
// requests and how the daemon would. So this tier runs the production chain
// behind a real http.Server and dials it with raw, hand-crafted HTTP bytes.
//
// The governing invariant: the number of requests the daemon receives must
// equal the number sockguard parsed and allowed — never more. A client must
// not be able to frame bytes so that a request sockguard never judged still
// reaches the daemon.

// newRawChain runs the production chain behind a real http.Server on a fresh
// unix socket and returns the socket path. Unlike buildChain's handler, this
// puts the net/http request parser in the loop, which is the whole point of
// the smuggling tier.
func newRawChain(t *testing.T, daemon *recordingDaemon, rules ...filter.Rule) string {
	t.Helper()

	chain := buildChain(t, daemon.socketPath, rules...)

	sockPath := fmt.Sprintf("/tmp/sockguard-diff-fe-%d-%d.sock", os.Getpid(), diffSocketSeq.Add(1))
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket %q: %v", sockPath, err)
	}

	srv := &http.Server{
		Handler:           chain,
		ErrorLog:          slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})
	return sockPath
}

// sendRaw dials the chain's unix socket, writes raw HTTP bytes verbatim, and
// returns the raw response. A read-deadline timeout is not a failure: a
// malformed input can leave the server waiting for more bytes — what the test
// asserts on is what reached the daemon, not the client-side response.
func sendRaw(t *testing.T, sockPath, raw string) string {
	t.Helper()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial chain socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set conn deadline: %v", err)
	}
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read raw response: %v", err)
	}
	return string(resp)
}

// rawRequest assembles exact wire bytes: request line and headers joined by
// CRLF, the terminating blank line, then the body verbatim.
func rawRequest(lines []string, body string) string {
	return strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}

// TestSmugglingDefaultDenyForwardsNothing fires a corpus of smuggling payloads
// at a default-deny chain. Default-deny makes the invariant absolute: sockguard
// allows nothing, so no byte framing whatsoever may produce a request at the
// daemon. A single recorded request is a bypass.
func TestSmugglingDefaultDenyForwardsNothing(t *testing.T) {
	t.Parallel()

	// A complete, well-formed request used as the smuggled payload in the
	// content-length-body and pipelining cases.
	smuggled := "GET /containers/create HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"

	tests := []struct {
		name string
		raw  string
	}{
		{
			// Baseline: a clean request really does traverse the parser and
			// reach the filter — and default-deny stops it before the proxy.
			name: "well-formed request is denied not forwarded",
			raw: rawRequest([]string{
				"GET /containers/json HTTP/1.1",
				"Host: docker",
				"Connection: close",
			}, ""),
		},
		{
			// Conflicting Content-Length values: an attacker's lever for
			// desync. A correct server rejects rather than picking one.
			name: "duplicate content-length headers",
			raw: rawRequest([]string{
				"POST /containers/json HTTP/1.1",
				"Host: docker",
				"Content-Length: 3",
				"Content-Length: 4",
				"Connection: close",
			}, "abcd"),
		},
		{
			// Content-Length alongside Transfer-Encoding: chunked — the
			// classic CL.TE desync primitive.
			name: "content-length with transfer-encoding chunked",
			raw: rawRequest([]string{
				"POST /containers/json HTTP/1.1",
				"Host: docker",
				"Content-Length: 6",
				"Transfer-Encoding: chunked",
				"Connection: close",
			}, "0\r\n\r\n"),
		},
		{
			// A whole request smuggled inside a declared body. It must stay
			// body — never be re-parsed into a routable request.
			name: "request smuggled inside content-length body",
			raw: rawRequest([]string{
				"GET /containers/json HTTP/1.1",
				"Host: docker",
				fmt.Sprintf("Content-Length: %d", len(smuggled)),
				"Connection: close",
			}, smuggled),
		},
		{
			// Two genuine pipelined requests: both must be judged, and under
			// default-deny both denied — the second is not a free pass.
			name: "pipelined second request",
			raw: rawRequest([]string{
				"GET /containers/json HTTP/1.1",
				"Host: docker",
			}, "") + smuggled,
		},
		{
			// Bare-LF line terminators instead of CRLF — a parser-leniency
			// probe. Reject or deny, but never forward.
			name: "bare LF line terminators",
			raw:  "GET /containers/json HTTP/1.1\nHost: docker\nConnection: close\n\n",
		},
		{
			name: "negative content-length",
			raw: rawRequest([]string{
				"POST /containers/json HTTP/1.1",
				"Host: docker",
				"Content-Length: -1",
				"Connection: close",
			}, ""),
		},
		{
			// Bytes past a zero-length declared body: leftover that a
			// desync would replay as a prefix of the next request.
			name: "trailing bytes after zero-length body",
			raw: rawRequest([]string{
				"POST /containers/json HTTP/1.1",
				"Host: docker",
				"Content-Length: 0",
				"Connection: close",
			}, smuggled),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			daemon := newRecordingDaemon(t)
			sockPath := newRawChain(t, daemon) // no rules → default-deny

			_ = sendRaw(t, sockPath, tt.raw)

			if n := daemon.count(); n != 0 {
				t.Fatalf("BYPASS: default-deny chain forwarded %d request(s) to the daemon for payload %q",
					n, tt.name)
			}
		})
	}
}

// TestSmugglingAllowedRequestForwardedExactlyOnce checks the other half of the
// invariant: when sockguard does allow a request, exactly one request reaches
// the daemon, and any bytes a client tried to smuggle alongside it arrive as
// body content — not as a second, unjudged request.
func TestSmugglingAllowedRequestForwardedExactlyOnce(t *testing.T) {
	t.Parallel()

	// Permissive policy so the outer request is allowed and forwarded; the
	// test then proves the smuggled payload did not become its own request.
	permissive := []filter.Rule{
		allowRule(http.MethodGet, "/**"),
		allowRule(http.MethodPost, "/**"),
	}

	t.Run("request smuggled in body stays body", func(t *testing.T) {
		t.Parallel()

		daemon := newRecordingDaemon(t)
		sockPath := newRawChain(t, daemon, permissive...)

		smuggled := "GET /containers/create HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
		raw := rawRequest([]string{
			"POST /containers/json HTTP/1.1",
			"Host: docker",
			fmt.Sprintf("Content-Length: %d", len(smuggled)),
			"Connection: close",
		}, smuggled)

		_ = sendRaw(t, sockPath, raw)

		got := daemon.snapshot()
		if len(got) != 1 {
			t.Fatalf("daemon received %d requests, want exactly 1", len(got))
		}
		if got[0].Method != http.MethodPost || got[0].Path != "/containers/json" {
			t.Fatalf("daemon received %s %q, want POST /containers/json", got[0].Method, got[0].Path)
		}
		if string(got[0].Body) != smuggled {
			t.Fatalf("daemon body = %q, want the smuggled bytes carried verbatim as body", got[0].Body)
		}
	})

	t.Run("chunked body de-chunked and forwarded once", func(t *testing.T) {
		t.Parallel()

		daemon := newRecordingDaemon(t)
		sockPath := newRawChain(t, daemon, permissive...)

		// A chunked body terminated by 0\r\n\r\n, then a whole request as
		// trailing bytes. Connection: close means the server finishes this
		// request and closes — the trailing bytes must simply be dropped.
		body := "5\r\nhello\r\n0\r\n\r\n" +
			"GET /containers/create HTTP/1.1\r\nHost: docker\r\n\r\n"
		raw := rawRequest([]string{
			"POST /containers/json HTTP/1.1",
			"Host: docker",
			"Transfer-Encoding: chunked",
			"Connection: close",
		}, body)

		_ = sendRaw(t, sockPath, raw)

		got := daemon.snapshot()
		if len(got) != 1 {
			t.Fatalf("daemon received %d requests, want exactly 1 (trailing bytes must not smuggle)", len(got))
		}
		if got[0].Path != "/containers/json" {
			t.Fatalf("daemon received path %q, want /containers/json", got[0].Path)
		}
		if string(got[0].Body) != "hello" {
			t.Fatalf("daemon body = %q, want de-chunked %q", got[0].Body, "hello")
		}
	})
}
