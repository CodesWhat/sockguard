// Package differential is the proxy-vs-daemon differential test harness
// (QA-1). The threat model for a Docker socket proxy is parser-differential:
// "can a client make the daemon do something policy forbids?" sockguard
// decides allow/deny on its normalized/parsed view of a request; the daemon
// acts on its own view. A bypass exists wherever the two views diverge.
//
// This harness drives the production middleware order — filter rule evaluator
// → hijack handler → reverse proxy — against a recording stand-in daemon, so a
// test can compare what sockguard's policy judged against the exact bytes the
// daemon received. It carries no build tag, so it runs in the per-PR CI test
// job. A real-dockerd tier (QA-1f, build-tagged in app/integration/) replays
// the same corpus against a live daemon.
package differential

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/proxy"
)

// recordedRequest captures one request as the stand-in daemon received it —
// i.e. exactly what sockguard forwarded upstream.
type recordedRequest struct {
	Method   string
	Path     string // r.URL.Path as the daemon's HTTP server parsed it
	RawPath  string // r.URL.RawPath — non-empty only when Path's encoding is ambiguous
	RawQuery string
	Header   http.Header
	Body     []byte
}

// recordingDaemon is the "daemon side" of the differential: a unix-socket HTTP
// server that records every request it receives and answers 200. It lets a
// test inspect precisely what sockguard forwarded, with no real Docker.
type recordingDaemon struct {
	socketPath string

	mu       sync.Mutex
	requests []recordedRequest
}

// newRecordingDaemon starts a recording daemon on a fresh unix socket and
// registers cleanup. The socket path is kept short (under /tmp) because macOS
// caps sun_path at 104 bytes, which t.TempDir() can exceed.
func newRecordingDaemon(t *testing.T) *recordingDaemon {
	t.Helper()

	socketPath := fmt.Sprintf("/tmp/sockguard-diff-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket %q: %v", socketPath, err)
	}

	d := &recordingDaemon{socketPath: socketPath}
	srv := &http.Server{Handler: http.HandlerFunc(d.handle)}
	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})
	return d
}

func (d *recordingDaemon) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()

	d.mu.Lock()
	d.requests = append(d.requests, recordedRequest{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
		Header:   r.Header.Clone(),
		Body:     body,
	})
	d.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("[]"))
}

// requestByID returns the request the daemon recorded carrying the given
// correlation id, or nil if none reached it — i.e. the request was denied
// before the proxy. Matching by id rather than arrival order keeps the harness
// correct when subtests run in parallel against a shared daemon.
func (d *recordingDaemon) requestByID(id string) *recordedRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.requests {
		if d.requests[i].Header.Get(diffIDHeader) == id {
			r := d.requests[i]
			return &r
		}
	}
	return nil
}

// buildChain assembles the production middleware order that governs path
// matching and proxying — filter rule evaluator → hijack handler → reverse
// proxy — pointed at the daemon socket. ownership/visibility are deliberately
// omitted: they are not on the path-normalization differential path and would
// add daemon side-channel calls. Passing no rules yields default-deny.
func buildChain(t *testing.T, socketPath string, rules ...filter.Rule) http.Handler {
	t.Helper()

	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i := range rules {
		rules[i].Index = i
		cr, err := filter.CompileRule(rules[i])
		if err != nil {
			t.Fatalf("compile rule %d (%+v): %v", i, rules[i], err)
		}
		compiled = append(compiled, cr)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var h http.Handler = proxy.New(socketPath, logger)
	h = proxy.HijackHandler(socketPath, logger, h)
	h = filter.MiddlewareWithOptions(compiled, logger, filter.Options{})(h)
	return h
}

func allowRule(method, pattern string) filter.Rule {
	return filter.Rule{Methods: []string{method}, Pattern: pattern, Action: filter.ActionAllow}
}

func denyRule(method, pattern string) filter.Rule {
	return filter.Rule{Methods: []string{method}, Pattern: pattern, Action: filter.ActionDeny}
}

// proxyResult is the outcome of one request through the sockguard chain.
type proxyResult struct {
	statusCode int
	body       string
	// allowed reports whether the request reached the upstream daemon. A
	// denial is written by the filter middleware before the proxy runs, so
	// it never reaches the daemon.
	allowed bool
}

// diffIDHeader correlates a request sent through the chain with the request
// the daemon recorded. It is an ordinary header, so sockguard forwards it
// untouched (it is not hop-by-hop).
const diffIDHeader = "X-Sockguard-Diff-Id"

var diffRequestSeq atomic.Int64

// sendRequest drives one request through the chain and reports both the
// client-visible result and, when the request was allowed through, the
// request the daemon actually received. httptest.NewRequest builds the
// *http.Request via http.ReadRequest — the same parser the net/http server
// uses — so r.URL.Path / RawPath are populated exactly as in production.
func sendRequest(t *testing.T, h http.Handler, daemon *recordingDaemon, method, target string, body []byte) (proxyResult, *recordedRequest) {
	t.Helper()

	id := fmt.Sprintf("diff-%d", diffRequestSeq.Add(1))

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set(diffIDHeader, id)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	forwarded := daemon.requestByID(id)
	return proxyResult{
		statusCode: rec.Code,
		body:       rec.Body.String(),
		allowed:    forwarded != nil,
	}, forwarded
}

func TestDifferentialHarnessRoundTrip(t *testing.T) {
	t.Parallel()
	daemon := newRecordingDaemon(t)

	// Allowed: a request matching an allow rule reaches the daemon, and the
	// daemon receives the method and path the client sent.
	allowed := buildChain(t, daemon.socketPath, allowRule(http.MethodGet, "/containers/**"))
	res, fwd := sendRequest(t, allowed, daemon, http.MethodGet, "/containers/json", nil)
	if !res.allowed {
		t.Fatalf("GET /containers/json was not forwarded (status %d, body %q)", res.statusCode, res.body)
	}
	if fwd.Method != http.MethodGet || fwd.Path != "/containers/json" {
		t.Fatalf("daemon received %s %q, want GET /containers/json", fwd.Method, fwd.Path)
	}

	// Denied: default-deny (no rules) blocks the request before the proxy,
	// so the daemon never sees it.
	denied := buildChain(t, daemon.socketPath)
	res, fwd = sendRequest(t, denied, daemon, http.MethodGet, "/containers/json", nil)
	if res.allowed || fwd != nil {
		t.Fatal("GET /containers/json under default-deny reached the daemon")
	}
	if res.statusCode != http.StatusForbidden {
		t.Fatalf("default-deny status = %d, want %d", res.statusCode, http.StatusForbidden)
	}
}

func TestDifferentialHarnessDenyRuleBlocksUpstream(t *testing.T) {
	t.Parallel()
	daemon := newRecordingDaemon(t)

	// An explicit deny rule ahead of a broad allow must block the request:
	// first-match-wins, and a denied request must not reach the daemon.
	h := buildChain(t, daemon.socketPath,
		denyRule(http.MethodPost, "/containers/create"),
		allowRule(http.MethodPost, "/**"),
	)
	res, fwd := sendRequest(t, h, daemon, http.MethodPost, "/containers/create", []byte(`{}`))
	if res.allowed || fwd != nil {
		t.Fatal("POST /containers/create reached the daemon despite a deny rule")
	}
	if res.statusCode != http.StatusForbidden {
		t.Fatalf("deny status = %d, want %d", res.statusCode, http.StatusForbidden)
	}
}
