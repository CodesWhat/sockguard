package cmd

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

// unrootedRequestTargetCase is one raw HTTP/1.1 request line that Go's server
// parses into a request whose URL.Path is not rooted, together with what
// sockguard must answer.
//
// None of these can be built with http.NewRequest: net/http's client always
// writes origin-form or absolute-form with a path, so the only way to put an
// asterisk-form, authority-form or path-less absolute-form line on the wire is
// to write the request line by hand over net.Dial.
type unrootedRequestTargetCase struct {
	name string
	// requestLine is the full first line, without the trailing CRLF.
	requestLine string
	wantStatus  int
	// wantReasonCode is the reason_code the access log must carry, or "" when
	// the request never reaches sockguard's handler chain at all.
	wantReasonCode string
}

func unrootedRequestTargetCases() []unrootedRequestTargetCase {
	return []unrootedRequestTargetCase{
		// r.URL.Path == "*". Go's server routes only "OPTIONS *" to its own
		// globalOptionsHandler, so every other method's asterisk-form lands in
		// the handler chain.
		{
			name:           "asterisk form GET",
			requestLine:    "GET * HTTP/1.1",
			wantStatus:     http.StatusBadRequest,
			wantReasonCode: reasonCodeRequestTargetNotRooted,
		},
		{
			name:           "asterisk form POST",
			requestLine:    "POST * HTTP/1.1",
			wantStatus:     http.StatusBadRequest,
			wantReasonCode: reasonCodeRequestTargetNotRooted,
		},
		// r.URL.Path == "": absolute-form with an empty path. url.URL's
		// RequestURI substitutes "/" for an empty path, so had this been
		// forwarded the daemon would have seen "GET /" while policy evaluated
		// "".
		{
			name:           "absolute form with no path",
			requestLine:    "GET http://docker.invalid HTTP/1.1",
			wantStatus:     http.StatusBadRequest,
			wantReasonCode: reasonCodeRequestTargetNotRooted,
		},
		// r.URL.Path == "", URL.Opaque == "probe": a rootless RFC 3986 URI,
		// which url.ParseRequestURI accepts as opaque because it has a scheme.
		{
			name:           "opaque absolute form",
			requestLine:    "GET sockguard:probe HTTP/1.1",
			wantStatus:     http.StatusBadRequest,
			wantReasonCode: reasonCodeRequestTargetNotRooted,
		},
		// r.URL.Path == "", URL.Host == "docker.invalid:2375". Go reparses an
		// authority-form CONNECT target as "http://" + target and then strips
		// the scheme back off, so the handler sees a host and no path.
		{
			name:           "authority form CONNECT",
			requestLine:    "CONNECT docker.invalid:2375 HTTP/1.1",
			wantStatus:     http.StatusBadRequest,
			wantReasonCode: reasonCodeRequestTargetNotRooted,
		},
		// The documented exception. net/http answers "OPTIONS *" itself with
		// 200 and an empty body (http.globalOptionsHandler) unless
		// http.Server.DisableGeneralOptionsHandler is set, and sockguard
		// leaves that at its default — see
		// TestServerLeavesGoGeneralOptionsHandlerEnabled. The whole chain is
		// bypassed, so there is no access-log line and no reason code, but
		// nothing reaches the daemon either: the stdlib handler writes the
		// response and never calls sockguard's handler.
		{
			name:        "asterisk form OPTIONS answered by net/http",
			requestLine: "OPTIONS * HTTP/1.1",
			wantStatus:  http.StatusOK,
		},
	}
}

// TestUnrootedRequestTargetsAreRejectedOnTheWire drives the production handler
// chain with raw request lines net/http's client cannot produce, under the
// most permissive policy there is: a single catch-all "/**" allow.
//
// That rule is the point. "/**" compiles to the match-all matcher, which
// answered an unconditional true, so every one of these unrooted targets was
// allowed and proxied even though the regex the pattern stands for,
// "^(/(?s:.*))?$", matches neither "*" nor anything else these produce. The
// upstream here fails the test if it is reached at all.
func TestUnrootedRequestTargetsAreRejectedOnTheWire(t *testing.T) {
	var mu sync.Mutex
	var upstreamHits []string

	socketPath := shortSocketPath(t, "request-target")
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits = append(upstreamHits, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = true

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "allow"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	collector := &testhelp.CollectingHandler{}
	logger := testhelp.NewTeeLogger(slog.NewTextHandler(io.Discard, nil), collector)
	handler := buildServeHandler(t, &cfg, logger, nil, rules, newServeTestDeps())
	addr, _ := startProxyChainServer(t, handler)

	for _, tc := range unrootedRequestTargetCases() {
		t.Run(tc.name, func(t *testing.T) {
			before := len(collector.FindMessage("request_denied"))

			resp, body := writeRawRequestLine(t, addr, tc.requestLine)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("%q: status = %d, want %d; body: %s", tc.requestLine, resp.StatusCode, tc.wantStatus, body)
			}

			if tc.wantReasonCode == "" {
				if len(collector.FindMessage("request_denied")) != before {
					t.Fatalf("%q: the handler chain logged a denial, but net/http was expected to answer this request itself", tc.requestLine)
				}
				return
			}

			var payload map[string]string
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("%q: json.Unmarshal(%q): %v", tc.requestLine, body, err)
			}
			if got := payload["message"]; got != requestTargetNotRootedDenyMessage {
				t.Fatalf("%q: message = %q, want %q", tc.requestLine, got, requestTargetNotRootedDenyMessage)
			}

			denials := collector.FindMessage("request_denied")
			if len(denials) != before+1 {
				t.Fatalf("%q: got %d request_denied log records, want %d", tc.requestLine, len(denials), before+1)
			}
			last := denials[len(denials)-1]
			if got := last.Attrs["reason_code"]; got != tc.wantReasonCode {
				t.Fatalf("%q: reason_code = %#v, want %q", tc.requestLine, got, tc.wantReasonCode)
			}
			if got := last.Attrs["decision"]; got != "deny" {
				t.Fatalf("%q: decision = %#v, want %q", tc.requestLine, got, "deny")
			}
		})
	}

	mu.Lock()
	hits := append([]string(nil), upstreamHits...)
	mu.Unlock()
	if len(hits) != 0 {
		t.Fatalf("upstream was reached by %d unrooted request(s): %v", len(hits), hits)
	}
}

// TestRootedRequestTargetsStillReachTheUpstream is the negative control for
// the guard: the request forms a Docker client actually sends must be
// untouched by it. Origin-form is what every client uses over the socket, and
// absolute-form with a path is what a caller pointed at sockguard through a
// forward proxy sends — both carry a rooted URL.Path, so both must proxy.
func TestRootedRequestTargetsStillReachTheUpstream(t *testing.T) {
	var mu sync.Mutex
	var upstreamHits []string

	socketPath := shortSocketPath(t, "rooted-target")
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits = append(upstreamHits, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "allow"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	addr, _ := startProxyChainServer(t, handler)

	tests := []struct {
		name        string
		requestLine string
		wantHit     string
	}{
		{
			name:        "origin form",
			requestLine: "GET /_ping HTTP/1.1",
			wantHit:     "GET /_ping",
		},
		{
			name:        "absolute form with a path",
			requestLine: "GET http://docker.invalid/v1.45/_ping HTTP/1.1",
			wantHit:     "GET /v1.45/_ping",
		},
		{
			name:        "root path",
			requestLine: "GET / HTTP/1.1",
			wantHit:     "GET /",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := writeRawRequestLine(t, addr, tc.requestLine)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%q: status = %d, want %d; body: %s", tc.requestLine, resp.StatusCode, http.StatusOK, body)
			}

			mu.Lock()
			hits := append([]string(nil), upstreamHits...)
			mu.Unlock()
			if len(hits) == 0 || hits[len(hits)-1] != tc.wantHit {
				t.Fatalf("%q: upstream hits = %v, want last entry %q", tc.requestLine, hits, tc.wantHit)
			}
		})
	}
}

// TestServerLeavesGoGeneralOptionsHandlerEnabled pins the one carve-out the
// request-target guard has. net/http answers "OPTIONS *" from
// globalOptionsHandler before sh.srv.Handler runs, so that request never
// reaches sockguard's chain — no access log line, no policy evaluation, and no
// upstream call. Sockguard keeps the stdlib default rather than routing it
// into the chain: it is a server-wide capability probe that addresses no
// Docker endpoint, and the stdlib answer never touches the daemon.
//
// Flipping DisableGeneralOptionsHandler to true would send "OPTIONS *" through
// withRequestTargetGuard and turn the 200 into a 400, so this assertion is
// what makes that a deliberate change rather than a silent one.
func TestServerLeavesGoGeneralOptionsHandlerEnabled(t *testing.T) {
	if newHTTPServer(http.NotFoundHandler()).DisableGeneralOptionsHandler {
		t.Fatal("newHTTPServer disables Go's OPTIONS * handler; unrootedRequestTargetCases documents the opposite")
	}
	if newAdminHTTPServer(http.NotFoundHandler()).DisableGeneralOptionsHandler {
		t.Fatal("newAdminHTTPServer disables Go's OPTIONS * handler; unrootedRequestTargetCases documents the opposite")
	}
}

// writeRawRequestLine dials addr, writes requestLine verbatim followed by a
// Host header and the terminating CRLF, and reads back the response. The
// request line is never re-serialized by net/http, which is the whole point:
// an http.Client would rewrite every form this test cares about.
func writeRawRequestLine(t *testing.T, addr, requestLine string) (*http.Response, []byte) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	raw := requestLine + "\r\nHost: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write %q: %v", requestLine, err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response to %q: %v", requestLine, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body for %q: %v", requestLine, err)
	}
	return resp, body
}
