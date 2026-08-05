package cmd

// TestServeHandlerRejectsH2CClientPreface is an integration test for the h2c
// (HTTP/2 cleartext) guard documented next to buildkitTunnelEndpoints in
// rules.go: sockguard's listener is a bare net/http.Server with no
// golang.org/x/net/http2/h2c handler wired in, so a client that opens a raw
// TCP connection and sends the HTTP/2 client connection preface
// ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") can never negotiate a real HTTP/2
// session or an opaque binary tunnel through sockguard. This test proves
// that gap is a closed door rather than an unverified assumption: the
// preface's request line parses as an ordinary (and policy-denied) HTTP/1.1
// request, and the connection never begins exchanging raw HTTP/2 frames.
//
// This is presently the only realistic way in that a native (non-BuildKit
// -session/-grpc-hijack) gRPC-over-h2c client could reach an
// operator-authored rule; verifying it fails closed keeps the
// moby.buildkit.v1.Control probe in validateBuildkitTunnelRules meaningful
// even though nothing today can dial it end-to-end.

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
)

// http2ClientPreface is the fixed 24-octet connection preface every HTTP/2
// client must send first, per RFC 7540 §3.5 / RFC 9113 §3.4. It is also the
// exact byte sequence h2c (cleartext HTTP/2) clients such as some gRPC and
// BuildKit control-plane libraries send without ever negotiating via
// Upgrade or ALPN.
const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func TestServeHandlerRejectsH2CClientPreface(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "missing-h2c-upstream")
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	srv := httptest.NewServer(handler)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := conn.Write([]byte(http2ClientPreface)); err != nil {
		t.Fatalf("writing HTTP/2 client preface: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		// A closed/reset connection in response to the preface is an
		// acceptable rejection outcome too — either way, no h2 session or
		// opaque tunnel was established.
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection reset") {
			return
		}
		t.Fatalf("http.ReadResponse: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatalf("server upgraded the connection (status %d); expected the h2c preface to be rejected, not tunneled", resp.StatusCode)
	}
	if resp.ProtoMajor == 2 {
		t.Fatalf("server responded over HTTP/2 (%s); expected the h2c preface to be rejected as a plain HTTP/1.x request", resp.Proto)
	}
	if resp.StatusCode < 400 {
		t.Fatalf("status = %d, want a 4xx rejection for the unmatched PRI method/deny-all policy", resp.StatusCode)
	}
}
