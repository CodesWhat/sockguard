package reload

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestDebouncerRearmCollapsesIntoOneFire(t *testing.T) {
	t.Parallel()
	d := newDebouncer(0)
	defer d.close()
	d.arm()
	d.arm() // re-arm inside the same window stops the pending timer first
	select {
	case <-d.fired():
		d.onFire()
	case <-time.After(2 * time.Second):
		t.Fatal("debouncer never fired")
	}
	if d.armed {
		t.Fatal("onFire must clear armed")
	}
	d.arm()
	<-d.fired() // fired but not yet drained when re-arming below
	d.armed = true
	d.arm()
	select {
	case <-d.fired():
	case <-time.After(2 * time.Second):
		t.Fatal("debouncer did not fire after re-arming a drained timer")
	}
}

func TestStatSnapshotMissingFile(t *testing.T) {
	t.Parallel()
	r := &Reloader{opts: Options{Path: filepath.Join(t.TempDir(), "absent.yaml")}}
	if snap, ok := r.statSnapshot(); ok || snap.known {
		t.Fatalf("statSnapshot of a missing file = (%+v, %v), want unknown/false", snap, ok)
	}
	present := filepath.Join(t.TempDir(), "present.yaml")
	if err := os.WriteFile(present, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.opts.Path = present
	if snap, ok := r.statSnapshot(); !ok || !snap.known || snap.size != 1 {
		t.Fatalf("statSnapshot of a present file = (%+v, %v)", snap, ok)
	}
}

func TestEventTargetsConfigIgnoresUnnamedEvents(t *testing.T) {
	t.Parallel()
	r := &Reloader{opts: Options{Path: "/etc/sockguard/sockguard.yaml"}}
	if r.eventTargetsConfig(fsnotify.Event{Op: fsnotify.Write}) {
		t.Fatal("an event with no name must not target the config")
	}
}

func TestSignalHandlerHooksFallBackToProcessSignals(t *testing.T) {
	t.Parallel()
	r := &Reloader{}
	ch := make(chan os.Signal, 1)
	r.installSignalHandler(ch)
	r.uninstallSignalHandler(ch)

	var notified, stopped bool
	r.opts.SignalNotify = func(chan<- os.Signal, ...os.Signal) { notified = true }
	r.opts.SignalStop = func(chan<- os.Signal) { stopped = true }
	r.installSignalHandler(ch)
	r.uninstallSignalHandler(ch)
	if !notified || !stopped {
		t.Fatalf("injected hooks not used: notified=%v stopped=%v", notified, stopped)
	}
}
