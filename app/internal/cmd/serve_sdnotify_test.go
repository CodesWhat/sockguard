package cmd

import (
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// notifyCollector is a fake NOTIFY_SOCKET that records every datagram.
type notifyCollector struct {
	mu   sync.Mutex
	msgs []string
}

func newNotifyCollector(t *testing.T, name string) *notifyCollector {
	t.Helper()
	sock := shortSocketPath(t, name)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen notify socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", sock)
	c := &notifyCollector{}
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			c.mu.Lock()
			c.msgs = append(c.msgs, string(buf[:n]))
			c.mu.Unlock()
		}
	}()
	return c
}

func (c *notifyCollector) count(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

func (c *notifyCollector) first() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.msgs) == 0 {
		return ""
	}
	return c.msgs[0]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// withoutExitAfter turns off exit_after on the shared watchdog test config so
// the down-upstream case stays up and the test observes pings, not an exit.
func withoutExitAfter(deps *serveDeps) func(string) (*config.Config, error) {
	orig := deps.loadConfig
	return func(p string) (*config.Config, error) {
		cfg, err := orig(p)
		if cfg != nil {
			cfg.Health.Watchdog.ExitAfter = "0s"
		}
		return cfg, err
	}
}

func startServeForNotify(t *testing.T, deps *serveDeps) (chan<- os.Signal, <-chan error) {
	t.Helper()
	deps.loadConfig = withoutExitAfter(deps)
	sigReady := make(chan chan<- os.Signal, 1)
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) { sigReady <- c }
	done := make(chan error, 1)
	go func() { done <- runServeWithDeps(newServeCommand(), nil, deps) }()
	return <-sigReady, done
}

func TestRunServeNotifiesSystemdReadyWatchdogAndStopping(t *testing.T) {
	sock := shortSocketPath(t, "sdn-up")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	notes := newNotifyCollector(t, "sdn-up-n")
	t.Setenv("WATCHDOG_USEC", "40000")
	t.Setenv("WATCHDOG_PID", "")

	sigCh, done := startServeForNotify(t, newWatchdogExitDeps(sock))

	waitFor(t, "READY=1", func() bool { return notes.count("READY=1") == 1 })
	if got := notes.first(); got != "READY=1" {
		t.Fatalf("first notification = %q, want READY=1", got)
	}
	waitFor(t, "WATCHDOG=1 pings", func() bool { return notes.count("WATCHDOG=1") >= 2 })

	sigCh <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
	waitFor(t, "STOPPING=1", func() bool { return notes.count("STOPPING=1") == 1 })
}

func TestRunServeStopsWatchdogPingsWhileUpstreamDown(t *testing.T) {
	notes := newNotifyCollector(t, "sdn-down-n")
	t.Setenv("WATCHDOG_USEC", "40000")
	t.Setenv("WATCHDOG_PID", "")

	sigCh, done := startServeForNotify(t, newWatchdogExitDeps(shortSocketPath(t, "sdn-down")))

	waitFor(t, "READY=1", func() bool { return notes.count("READY=1") == 1 })
	// Let the watchdog record the outage, then require the pings to stop.
	time.Sleep(150 * time.Millisecond)
	before := notes.count("WATCHDOG=1")
	time.Sleep(200 * time.Millisecond)
	if after := notes.count("WATCHDOG=1"); after != before {
		t.Fatalf("WATCHDOG=1 kept arriving while the upstream was down: %d -> %d", before, after)
	}

	sigCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func TestRunServeWithoutNotifySocketIsQuiet(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "40000")
	sigCh, done := startServeForNotify(t, newWatchdogExitDeps(shortSocketPath(t, "sdn-off")))
	sigCh <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
}
