package cmd

import (
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/inbound"
)

// TestStatSocketIdentityGuardsAndSuccess covers statSocketIdentity's early
// returns (empty path, nil lstat func) and its success path (delegating to
// socketIdentityFromFileInfo) — none of which were reached by the existing
// bind-barrier tests, which only ever exercise the lstat-error branch via
// unmocked paths that don't exist on disk.
func TestStatSocketIdentityGuardsAndSuccess(t *testing.T) {
	lstat := func(string) (os.FileInfo, error) { return socketFileInfo(7), nil }

	if got := statSocketIdentity(lstat, ""); got.valid {
		t.Fatalf("statSocketIdentity(empty path) = %+v, want invalid", got)
	}
	if got := statSocketIdentity(nil, "/run/x.sock"); got.valid {
		t.Fatalf("statSocketIdentity(nil lstat) = %+v, want invalid", got)
	}

	got := statSocketIdentity(lstat, "/run/x.sock")
	if !got.valid || got.ino != 7 {
		t.Fatalf("statSocketIdentity() = %+v, want valid identity with ino=7", got)
	}

	errLstat := func(string) (os.FileInfo, error) { return nil, errors.New("stat boom") }
	if got := statSocketIdentity(errLstat, "/run/x.sock"); got.valid {
		t.Fatalf("statSocketIdentity(lstat error) = %+v, want invalid", got)
	}
}

// TestSocketIdentityFromFileInfoGuards covers the nil-info and
// non-syscall.Stat_t branches of socketIdentityFromFileInfo, which every
// existing caller only ever fed a real *syscall.Stat_t-backed FileInfo.
func TestSocketIdentityFromFileInfoGuards(t *testing.T) {
	if got := socketIdentityFromFileInfo(nil); got.valid {
		t.Fatalf("socketIdentityFromFileInfo(nil) = %+v, want invalid", got)
	}

	// listenerFeatureFileInfo.Sys() returns &i.stat, a *syscall.Stat_t; a
	// FileInfo whose Sys() returns something else entirely exercises the
	// type-assertion-fails branch.
	if got := socketIdentityFromFileInfo(fakeSysFileInfo{}); got.valid {
		t.Fatalf("socketIdentityFromFileInfo(non-Stat_t Sys()) = %+v, want invalid", got)
	}
}

type fakeSysFileInfo struct{}

func (fakeSysFileInfo) Name() string       { return "sock" }
func (fakeSysFileInfo) Size() int64        { return 0 }
func (fakeSysFileInfo) Mode() os.FileMode  { return os.ModeSocket | 0o600 }
func (fakeSysFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeSysFileInfo) IsDir() bool        { return false }
func (fakeSysFileInfo) Sys() any           { return "not a stat_t" }

// TestRemoveSocketIfOwnedEmptyPathNoop covers the empty-path early return,
// which no existing test reaches (shutdownMainListeners always guards on
// member.socketPath != "" before calling removeSocketIfOwned).
func TestRemoveSocketIfOwnedEmptyPathNoop(t *testing.T) {
	deps := newServeTestDeps()
	removeCalls := 0
	deps.removePath = func(string) error { removeCalls++; return nil }

	if err := removeSocketIfOwned(deps, "", socketIdentity{valid: true, ino: 1}); err != nil {
		t.Fatalf("removeSocketIfOwned(empty path) error = %v, want nil", err)
	}
	if removeCalls != 0 {
		t.Fatalf("removePath calls = %d, want 0 for empty path", removeCalls)
	}
}

// TestRemoveSocketIfOwnedInodeMatch covers the want.valid branch's happy
// path: the socket at path still resolves to the exact inode captured at
// bind time, so it is removed and the removePath result is propagated.
// Every existing test only exercises the want.valid==false fallback, so the
// statSocketIdentity call and comparison here were entirely uncovered.
func TestRemoveSocketIfOwnedInodeMatch(t *testing.T) {
	deps := newServeTestDeps()
	deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(42), nil }
	removeCalls := 0
	deps.removePath = func(string) error { removeCalls++; return nil }

	want := socketIdentity{valid: true, ino: 42}
	if err := removeSocketIfOwned(deps, "/run/ci.sock", want); err != nil {
		t.Fatalf("removeSocketIfOwned() error = %v, want nil", err)
	}
	if removeCalls != 1 {
		t.Fatalf("removePath calls = %d, want 1 for matching inode", removeCalls)
	}
}

// TestRemoveSocketIfOwnedInodeMismatchSkipsRemoval covers the "something
// else now occupies the path" guard: a mismatched (or gone) inode must never
// be removed, even though want.valid is true.
func TestRemoveSocketIfOwnedInodeMismatchSkipsRemoval(t *testing.T) {
	tests := []struct {
		name  string
		lstat func(string) (os.FileInfo, error)
	}{
		{name: "different inode now at path", lstat: func(string) (os.FileInfo, error) { return socketFileInfo(99), nil }},
		{name: "path gone", lstat: func(string) (os.FileInfo, error) { return nil, errors.New("no such file") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := newServeTestDeps()
			deps.lstatPath = tc.lstat
			removeCalls := 0
			deps.removePath = func(string) error { removeCalls++; return nil }

			want := socketIdentity{valid: true, ino: 42}
			if err := removeSocketIfOwned(deps, "/run/ci.sock", want); err != nil {
				t.Fatalf("removeSocketIfOwned() error = %v, want nil", err)
			}
			if removeCalls != 0 {
				t.Fatalf("removePath calls = %d, want 0 when inode does not match", removeCalls)
			}
		})
	}
}

// TestHijackedConnTrackerTransitionNilSafety covers transition's guard for a
// nil tracker or nil conn — trackHijackedConnections always installs a
// non-nil tracker so no existing test ever calls transition with either nil.
func TestHijackedConnTrackerTransitionNilSafety(t *testing.T) {
	var nilTracker *hijackedConnTracker
	nilTracker.transition(&serveTestConn{}, http.StateHijacked) // must not panic

	tracker := &hijackedConnTracker{conns: make(map[net.Conn]struct{})}
	tracker.transition(nil, http.StateHijacked) // must not panic
	if len(tracker.conns) != 0 {
		t.Fatalf("conns = %v, want empty after nil-conn transition", tracker.conns)
	}
}

type closeTrackingConn struct {
	serveTestConn
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.closed = true
	return nil
}

// TestHijackedConnTrackerTransitionClosedTrackerClosesNewHijacks covers the
// t.closed branch: once closeAll has run, any further StateHijacked
// transition must close the connection immediately instead of tracking it.
func TestHijackedConnTrackerTransitionClosedTrackerClosesNewHijacks(t *testing.T) {
	tracker := &hijackedConnTracker{conns: make(map[net.Conn]struct{})}
	tracker.closeAll()

	conn := &closeTrackingConn{}
	tracker.transition(conn, http.StateHijacked)

	if !conn.closed {
		t.Fatal("late hijack after closeAll was not closed")
	}
	if len(tracker.conns) != 0 {
		t.Fatalf("conns = %v, want empty (closed tracker must not retain new hijacks)", tracker.conns)
	}
}

// TestHijackedConnTrackerTransitionStateClosedRemoves covers the
// http.StateClosed case: a tracked connection reaching StateClosed through
// the normal net/http lifecycle (not a Close call routed through closeAll)
// must be removed from the tracked set.
func TestHijackedConnTrackerTransitionStateClosedRemoves(t *testing.T) {
	tracker := &hijackedConnTracker{conns: make(map[net.Conn]struct{})}
	conn := &serveTestConn{}
	tracker.transition(conn, http.StateHijacked)
	if _, tracked := tracker.conns[conn]; !tracked {
		t.Fatal("conn was not tracked after StateHijacked")
	}

	tracker.transition(conn, http.StateClosed)
	if _, tracked := tracker.conns[conn]; tracked {
		t.Fatal("conn still tracked after StateClosed")
	}
}

// TestListenerStatusBoardNilReceiverIsSafe covers the nil-board guards on
// register/setState/snapshot. board is nil whenever the legacy
// single-listener path runs without #149's listener board wired in — every
// existing test constructs a real board via newListenerStatusBoard.
func TestListenerStatusBoardNilReceiverIsSafe(t *testing.T) {
	var board *listenerStatusBoard

	board.register(inbound.Identity{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix}, "bound") // must not panic
	board.setState("ci", "serving")                                                                             // must not panic
	if got := board.snapshot(); got != nil {
		t.Fatalf("snapshot() on nil board = %v, want nil", got)
	}
}

// TestListenerStatusBoardSetStateUnregisteredNameNoop covers setState's
// !ok guard: a name that was never registered must not fabricate an entry.
func TestListenerStatusBoardSetStateUnregisteredNameNoop(t *testing.T) {
	board := newListenerStatusBoard()
	board.setState("never-registered", "serving")

	if got := board.snapshot(); len(got) != 0 {
		t.Fatalf("snapshot() = %+v, want empty (setState must not create entries)", got)
	}
}

// TestNetworkFor covers networkFor's own `listen.Socket != ""` branch
// (serve_listeners.go:218; not one of the mutants in scope here, but the
// sibling of listenerAddrFor immediately below it and otherwise untested).
func TestNetworkFor(t *testing.T) {
	if got := networkFor(config.ListenConfig{Socket: "/run/sockguard.sock"}); got != inbound.NetworkUnix {
		t.Fatalf("networkFor(socket set) = %v, want %v", got, inbound.NetworkUnix)
	}
	if got := networkFor(config.ListenConfig{Address: "127.0.0.1:2375"}); got != inbound.NetworkTCP {
		t.Fatalf("networkFor(socket empty) = %v, want %v", got, inbound.NetworkTCP)
	}
}

// ---------------------------------------------------------------------------
// serve_listeners.go:227 — CONDITIONALS_NEGATION: `if listen.Socket != ""`
// inside listenerAddrFor. Mutation flips != to ==, so a configured unix
// socket path would render as "tcp://" (and vice versa) in logs/banner text.
// ---------------------------------------------------------------------------

func TestListenerAddrFor(t *testing.T) {
	if got := listenerAddrFor(config.ListenConfig{Socket: "/run/sockguard.sock"}); got != "unix:/run/sockguard.sock" {
		t.Fatalf("listenerAddrFor(socket set) = %q, want %q", got, "unix:/run/sockguard.sock")
	}
	if got := listenerAddrFor(config.ListenConfig{Address: "127.0.0.1:2375"}); got != "tcp://127.0.0.1:2375" {
		t.Fatalf("listenerAddrFor(socket empty) = %q, want %q", got, "tcp://127.0.0.1:2375")
	}
}
