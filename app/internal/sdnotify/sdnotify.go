// Package sdnotify implements the small part of systemd's sd_notify protocol
// sockguard needs: READY=1, WATCHDOG=1 and STOPPING=1 sent as datagrams to the
// unix socket named by NOTIFY_SOCKET. It is stdlib only and a no-op when
// NOTIFY_SOCKET is unset, so it costs nothing outside a Type=notify unit.
package sdnotify

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	stateReady    = "READY=1"
	stateWatchdog = "WATCHDOG=1"
	stateStopping = "STOPPING=1"

	envNotifySocket = "NOTIFY_SOCKET"
	envWatchdogUSec = "WATCHDOG_USEC"
	envWatchdogPID  = "WATCHDOG_PID"
)

// Notifier sends sd_notify datagrams. The zero value and a nil *Notifier are
// valid no-ops.
type Notifier struct {
	addr string
}

// New returns a Notifier for the socket in NOTIFY_SOCKET, read through getenv.
// It returns nil (a no-op) when the variable is unset or empty. A leading "@"
// names an abstract-namespace socket and a leading "/" a filesystem path; any
// other form is not something systemd hands out and is ignored.
func New(getenv func(string) string) *Notifier {
	addr := getenv(envNotifySocket)
	if addr == "" || (addr[0] != '/' && addr[0] != '@') {
		return nil
	}
	return &Notifier{addr: addr}
}

// Ready tells systemd startup is finished and the proxy is serving.
func (n *Notifier) Ready() error { return n.send(stateReady) }

// Watchdog sends one liveness ping.
func (n *Notifier) Watchdog() error { return n.send(stateWatchdog) }

// Stopping tells systemd the service has begun its shutdown.
func (n *Notifier) Stopping() error { return n.send(stateStopping) }

func (n *Notifier) send(state string) error {
	if n == nil || n.addr == "" {
		return nil
	}
	// Go maps a leading "@" to the abstract namespace on Linux.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: n.addr, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("sd_notify dial %q: %w", n.addr, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("sd_notify write: %w", err)
	}
	return nil
}

// WatchdogInterval returns how often to ping: half of WATCHDOG_USEC, the
// cadence sd_watchdog_enabled(3) recommends. ok is false when the unit sets no
// watchdog, the value is not a positive integer, or WATCHDOG_PID names a
// different process than pid.
func WatchdogInterval(getenv func(string) string, pid int) (time.Duration, bool) {
	raw := getenv(envWatchdogUSec)
	if raw == "" {
		return 0, false
	}
	usec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || usec <= 1 {
		return 0, false
	}
	if p := getenv(envWatchdogPID); p != "" {
		if want, err := strconv.Atoi(p); err != nil || want != pid {
			return 0, false
		}
	}
	return time.Duration(usec) * time.Microsecond / 2, true
}

// KeepAlive pings systemd's watchdog every interval until ctx is canceled, but
// only while healthy reports true. A ping withheld because the upstream is down
// is what lets WatchdogSec= expire so systemd restarts the service. onError is
// called, when non-nil, for each failed send.
func (n *Notifier) KeepAlive(ctx context.Context, interval time.Duration, healthy func() bool, onError func(error)) {
	if n == nil || n.addr == "" || interval <= 0 {
		return
	}
	ping := func() {
		if healthy != nil && !healthy() {
			return
		}
		if err := n.Watchdog(); err != nil && onError != nil {
			onError(err)
		}
	}
	ping()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping()
		}
	}
}
