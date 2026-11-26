package sdnotify

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func listen(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen %q: %v", name, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func recv(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

func TestNewNoOpWhenUnsetOrInvalid(t *testing.T) {
	for _, v := range []string{"", "relative/path", "vsock:1:2"} {
		n := New(env(map[string]string{"NOTIFY_SOCKET": v}))
		if n != nil {
			t.Fatalf("New(%q) = %v, want nil", v, n)
		}
		if err := n.Ready(); err != nil {
			t.Fatalf("nil Ready() = %v", err)
		}
		if err := n.Watchdog(); err != nil {
			t.Fatalf("nil Watchdog() = %v", err)
		}
		if err := n.Stopping(); err != nil {
			t.Fatalf("nil Stopping() = %v", err)
		}
	}
}

func TestSendsStatesToPathSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sdn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "n.sock")
	conn := listen(t, sock)
	n := New(env(map[string]string{"NOTIFY_SOCKET": sock}))
	for _, tc := range []struct {
		send func() error
		want string
	}{
		{n.Ready, "READY=1"},
		{n.Watchdog, "WATCHDOG=1"},
		{n.Stopping, "STOPPING=1"},
	} {
		if err := tc.send(); err != nil {
			t.Fatalf("send %s: %v", tc.want, err)
		}
		if got := recv(t, conn); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
}

func TestSendsToAbstractSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract unix sockets are Linux only")
	}
	name := "@sockguard-sdnotify-test-" + time.Now().Format("150405.000000")
	conn := listen(t, name)
	n := New(env(map[string]string{"NOTIFY_SOCKET": name}))
	if err := n.Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if got := recv(t, conn); got != "READY=1" {
		t.Fatalf("got %q", got)
	}
}

func TestSendErrorWhenSocketGone(t *testing.T) {
	n := New(env(map[string]string{"NOTIFY_SOCKET": "/tmp/sockguard-sdnotify-missing.sock"}))
	if err := n.Ready(); err == nil {
		t.Fatal("Ready() = nil, want dial error")
	}
}

func TestWatchdogInterval(t *testing.T) {
	pid := os.Getpid()
	cases := []struct {
		name string
		env  map[string]string
		want time.Duration
		ok   bool
	}{
		{"unset", map[string]string{}, 0, false},
		{"half", map[string]string{"WATCHDOG_USEC": "30000000"}, 15 * time.Second, true},
		{"own pid", map[string]string{"WATCHDOG_USEC": "2000000", "WATCHDOG_PID": itoa(pid)}, time.Second, true},
		{"other pid", map[string]string{"WATCHDOG_USEC": "2000000", "WATCHDOG_PID": itoa(pid + 1)}, 0, false},
		{"bad pid", map[string]string{"WATCHDOG_USEC": "2000000", "WATCHDOG_PID": "x"}, 0, false},
		{"zero", map[string]string{"WATCHDOG_USEC": "0"}, 0, false},
		{"garbage", map[string]string{"WATCHDOG_USEC": "abc"}, 0, false},
	}
	for _, tc := range cases {
		got, ok := WatchdogInterval(env(tc.env), pid)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got (%v,%v), want (%v,%v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestKeepAlivePingsOnlyWhileHealthy(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sdn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "k.sock")
	conn := listen(t, sock)
	n := New(env(map[string]string{"NOTIFY_SOCKET": sock}))

	var healthy atomic.Bool
	healthy.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		n.KeepAlive(ctx, 10*time.Millisecond, healthy.Load, nil)
		close(done)
	}()

	if got := recv(t, conn); got != "WATCHDOG=1" {
		t.Fatalf("got %q", got)
	}
	healthy.Store(false)
	// Drain anything already in flight, then require silence.
	time.Sleep(50 * time.Millisecond)
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 64)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("received a ping while unhealthy")
	}
	healthy.Store(true)
	if got := recv(t, conn); got != "WATCHDOG=1" {
		t.Fatalf("after recovery got %q", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("KeepAlive did not stop on cancel")
	}
}

func TestKeepAliveReportsSendErrors(t *testing.T) {
	n := New(env(map[string]string{"NOTIFY_SOCKET": "/tmp/sockguard-sdnotify-missing.sock"}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go n.KeepAlive(ctx, time.Hour, nil, func(err error) {
		select {
		case errs <- err:
		default:
		}
	})
	select {
	case <-errs:
	case <-time.After(2 * time.Second):
		t.Fatal("no error reported")
	}
}
