package cmd

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
)

// TestCreateNamedListenerImplUnixSocket covers the listeners[*] unix-socket
// bind path (#149) — createNamedListenerImpl was entirely unexercised
// directly (only its stubbed field is used by higher-level bind-barrier
// tests). Mirrors TestCreateListenerUnixSocket's real-bind assertions.
func TestCreateNamedListenerImplUnixSocket(t *testing.T) {
	socketPath := shortSocketPath(t, "named")
	entry := config.ListenerConfig{
		Name:         "ci",
		ListenConfig: config.ListenConfig{Socket: socketPath, SocketMode: "0600"},
	}

	ln, err := newServeDeps().createNamedListenerImpl(&config.Config{}, entry)
	if err != nil {
		t.Fatalf("createNamedListenerImpl() error = %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket path: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected socket file at %q, mode=%v", socketPath, info.Mode())
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 600", info.Mode().Perm())
	}
}

// TestCreateNamedListenerImplTCP covers the listeners[*] TCP bind path.
func TestCreateNamedListenerImplTCP(t *testing.T) {
	entry := config.ListenerConfig{
		Name:         "ops",
		ListenConfig: config.ListenConfig{Address: "127.0.0.1:0"},
	}

	ln, err := newServeDeps().createNamedListenerImpl(&config.Config{}, entry)
	if err != nil {
		t.Fatalf("createNamedListenerImpl() error = %v", err)
	}
	defer ln.Close()

	if ln.Addr().Network() != "tcp" {
		t.Fatalf("listener network = %q, want tcp", ln.Addr().Network())
	}
}

// TestCreateNamedListenerImplUsesEntryName confirms bind errors are reported
// against the specific listeners[*] entry (via the prefix threaded into
// createSocketListener), not a generic "listen"/"admin.listen" label.
func TestCreateNamedListenerImplUsesEntryName(t *testing.T) {
	entry := config.ListenerConfig{
		Name:         "ci",
		ListenConfig: config.ListenConfig{Socket: "/run/ci.sock", SocketMode: "bogus"},
	}

	_, err := newServeDeps().createNamedListenerImpl(&config.Config{}, entry)
	if err == nil || !strings.Contains(err.Error(), "listeners[ci].socket_mode") {
		t.Fatalf("createNamedListenerImpl() error = %v, want listeners[ci] prefix", err)
	}
}

// TestChownSocket covers chownSocket's uid/gid pointer-to-int resolution and
// error wrapping directly — it was entirely unexercised (createSocketListener
// never reached the chown call in any existing test).
func TestChownSocket(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name       string
		uid, gid   *int
		chownErr   error
		wantUID    int
		wantGID    int
		wantErrSub string
	}{
		{name: "both nil resolve to -1,-1", uid: nil, gid: nil, wantUID: -1, wantGID: -1},
		{name: "uid only", uid: intPtr(1000), gid: nil, wantUID: 1000, wantGID: -1},
		{name: "gid only", uid: nil, gid: intPtr(2000), wantUID: -1, wantGID: 2000},
		{name: "both set", uid: intPtr(1000), gid: intPtr(2000), wantUID: 1000, wantGID: 2000},
		{name: "chown error is wrapped", uid: intPtr(1000), gid: intPtr(2000), chownErr: errors.New("op not permitted"), wantUID: 1000, wantGID: 2000, wantErrSub: `chown socket "/run/x.sock": op not permitted`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := newServeTestDeps()
			var gotPath string
			var gotUID, gotGID int
			deps.chown = func(path string, uid, gid int) error {
				gotPath, gotUID, gotGID = path, uid, gid
				return tc.chownErr
			}

			err := deps.chownSocket("/run/x.sock", tc.uid, tc.gid)
			if tc.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("chownSocket() error = %v, want substring %q", err, tc.wantErrSub)
				}
			} else if err != nil {
				t.Fatalf("chownSocket() unexpected error: %v", err)
			}
			if gotPath != "/run/x.sock" || gotUID != tc.wantUID || gotGID != tc.wantGID {
				t.Fatalf("chown(%q, %d, %d), want (%q, %d, %d)", gotPath, gotUID, gotGID, "/run/x.sock", tc.wantUID, tc.wantGID)
			}
		})
	}
}

// TestCreateSocketListenerChownsOnSuccess covers createSocketListener's
// chown branch when SocketUID/SocketGID are set: the listener is chowned
// after bind and returned unclosed.
func TestCreateSocketListenerChownsOnSuccess(t *testing.T) {
	socketPath := shortSocketPath(t, "chown-ok")
	deps := newServeTestDeps()
	var chownCalls int
	deps.chown = func(string, int, int) error {
		chownCalls++
		return nil
	}
	uid, gid := 1000, 1000

	ln, err := deps.createSocketListener("listen", socketPath, "0660", &uid, &gid)
	if err != nil {
		t.Fatalf("createSocketListener() error = %v", err)
	}
	defer ln.Close()

	if chownCalls != 1 {
		t.Fatalf("chown calls = %d, want 1", chownCalls)
	}
}

// TestCreateSocketListenerClosesListenerWhenChownFails covers the rollback
// branch: a chown failure after a successful bind must close the freshly
// created listener (unlinking the unix socket) and propagate the error.
func TestCreateSocketListenerClosesListenerWhenChownFails(t *testing.T) {
	socketPath := shortSocketPath(t, "chown-fail")
	deps := newServeTestDeps()
	deps.chown = func(string, int, int) error { return errors.New("chown boom") }
	uid, gid := 1000, 1000

	ln, err := deps.createSocketListener("listen", socketPath, "0660", &uid, &gid)
	if err == nil || !strings.Contains(err.Error(), "chown boom") {
		t.Fatalf("createSocketListener() error = %v, want chown boom", err)
	}
	if ln != nil {
		t.Fatal("createSocketListener() returned non-nil listener alongside chown error")
	}
	if _, statErr := os.Stat(socketPath); !os.IsNotExist(statErr) {
		t.Fatalf("socket file %q still exists after Close on chown failure", socketPath)
	}
}

// TestDefaultProbeUnixSocket covers the unmocked probe used at runtime
// (newServeDeps wires probeUnixSocket to this by default; tests elsewhere
// only ever stub it). A live listener dials cleanly; a path with nothing
// listening fails.
func TestDefaultProbeUnixSocket(t *testing.T) {
	t.Run("live socket dials cleanly", func(t *testing.T) {
		socketPath := shortSocketPath(t, "probe-live")
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		if err := defaultProbeUnixSocket(socketPath); err != nil {
			t.Fatalf("defaultProbeUnixSocket() error = %v, want nil for live socket", err)
		}
	})

	t.Run("missing socket fails to dial", func(t *testing.T) {
		socketPath := shortSocketPath(t, "probe-missing")

		if err := defaultProbeUnixSocket(socketPath); err == nil {
			t.Fatal("defaultProbeUnixSocket() error = nil, want dial failure for missing socket")
		}
	})
}
