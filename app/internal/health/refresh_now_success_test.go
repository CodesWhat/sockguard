package health

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

// TestRefreshNowSucceedsWithoutLoggingUnreachable pins refreshNow's `if err
// != nil` guard around the "health check failed: upstream unreachable" warn:
// the warn must fire only when the probe actually failed, never when it
// succeeds. A checker whose dial succeeds must let refreshNow become the
// leader, return a verdict with a nil error, and log nothing.
func TestRefreshNowSucceedsWithoutLoggingUnreachable(t *testing.T) {
	t.Parallel()
	collector := &testhelp.CollectingHandler{}
	checker := newUpstreamHealthChecker(
		2*time.Second,
		time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			return noopConn{}, nil
		},
	)
	monitor := newMonitorWithChecker("/tmp/upstream.sock", time.Now(), collector.Logger(), checker)

	v, leader := monitor.refreshNow()
	if !leader {
		t.Fatal("refreshNow() leader = false, want true (nothing else was refreshing)")
	}
	if v.err != nil {
		t.Fatalf("refreshNow() verdict.err = %v, want nil (the checker succeeded)", v.err)
	}
	if v.status != "connected" {
		t.Fatalf("refreshNow() verdict.status = %q, want %q", v.status, "connected")
	}
	if warns := collector.FindMessage("health check failed: upstream unreachable"); len(warns) != 0 {
		t.Fatalf("unreachable warnings = %d, want 0 on a successful probe; records: %#v", len(warns), collector.Records())
	}
}
