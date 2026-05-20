package filter

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSlowlorisBodyReadDeadlineIsEnforced is the QA-3 regression that the
// inspector-side body-read deadline (middleware.go's bodyReadTimeout)
// actually fires on a stalled body. The mutation-kill test
// TestBodyReadTimeoutIs30Seconds pins the constant; this test pins the
// behavior. A 30s wall-clock deadline cannot be exercised in CI, so the
// test scopes bodyReadTimeout down to a few hundred ms via t.Cleanup —
// that is the whole reason it was converted from const to var in
// middleware.go.
//
// The shape of the exploit: a client opens a connection, promises a
// Content-Length the inspector will try to read in full, then never
// finishes the body. Without a deadline, the inspector's body read
// blocks forever and the connection is wedged. With the deadline,
// SetReadDeadline on the conn causes the next body Read to return
// os.ErrDeadlineExceeded, the inspector treats that as an error, and the
// middleware returns 403 with the "unable to inspect …" reason.
//
// The test drives raw TCP rather than http.Client because Client buffers
// the body before sending headers under some transports — we need the
// stall to land on the server's side of the conn, after the headers but
// before the body completes.
func TestSlowlorisBodyReadDeadlineIsEnforced(t *testing.T) {
	const testDeadline = 150 * time.Millisecond

	prev := bodyReadTimeout
	bodyReadTimeout = testDeadline
	t.Cleanup(func() { bodyReadTimeout = prev })

	allowCreate, err := CompileRule(Rule{
		Methods: []string{http.MethodPost},
		Pattern: "/containers/create",
		Action:  ActionAllow,
		Index:   0,
	})
	if err != nil {
		t.Fatalf("compile allow rule: %v", err)
	}
	denyAll, err := CompileRule(Rule{
		Methods: []string{"*"},
		Pattern: "/**",
		Action:  ActionDeny,
		Reason:  "no matching allow rule",
		Index:   1,
	})
	if err != nil {
		t.Fatalf("compile deny rule: %v", err)
	}

	// The upstream is unreachable by design: any test that reaches it has
	// already passed the inspector, which is the failure mode this test
	// detects. A successful slowloris stop returns the inspector's deny
	// before the request ever gets here.
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("slowloris body reached the upstream — inspector did not deny on a stalled body")
		w.WriteHeader(http.StatusInternalServerError)
	})

	mw := verboseMiddleware([]*CompiledRule{allowCreate, denyAll}, testLogger())
	server := httptest.NewServer(mw(upstream))
	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Promise a body the inspector will commit to reading; send none of it.
	// The container-create inspector's max body is several MB, so 1<<20 is
	// well under the 413 limit — this stalls inside the inspector, it does
	// not 413-out before the deadline.
	req := "POST /containers/create HTTP/1.1\r\n" +
		"Host: sockguard.test\r\n" +
		"Content-Type: application/json\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", 1<<20) +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request headers: %v", err)
	}

	// Allow up to bodyReadTimeout + generous CI-scheduling slack. The bound
	// is the upper boundary of "did the server respond in time?", not a
	// precise measurement — the production deadline is the real assertion.
	if err := conn.SetReadDeadline(time.Now().Add(testDeadline + 2*time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response (server probably never closed the body-read deadline path): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("status = %d, want 403; body: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "unable to inspect container create request body") {
		t.Fatalf("deny body = %q, want the inspector-error reason — a different 403 means the slowloris path is not the one that fired",
			strings.TrimSpace(string(body)))
	}
}
