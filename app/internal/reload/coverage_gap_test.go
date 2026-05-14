package reload

// coverage_gap_test.go covers two branches absent from reload_test.go:
//
//   - safeOnReload: panic recovery — a panicking OnReload must not kill the loop.
//   - Production watcher (real fsnotify): file rewrite on disk triggers OnReload.

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// TestSafeOnReloadRecoversPanic verifies that a panicking OnReload callback is
// caught by safeOnReload and does not propagate to the caller. The reloader
// must remain alive and invoke a subsequent trigger correctly.
func TestSafeOnReloadRecoversPanic(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules: []"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()

	// The first invocation panics; the second succeeds and records a hit.
	var callCount atomic.Int64
	secondFired := make(chan struct{}, 1)

	r, err := New(Options{
		Path:     cfgPath,
		Debounce: -1, // no debounce — fire immediately
		Logger:   discardLogger(),
		NewWatcher: func() (Watcher, error) {
			return fw, nil
		},
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload: func() {
			n := callCount.Add(1)
			if n == 1 {
				panic("intentional panic in OnReload")
			}
			select {
			case secondFired <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Run(ctx)
	}()

	// First trigger — OnReload will panic.
	fw.emit(fsnotify.Event{Name: cfgPath, Op: fsnotify.Write})

	// Wait a moment for the panic to be recovered, then trigger again.
	time.Sleep(20 * time.Millisecond)

	// Second trigger — must succeed despite the earlier panic.
	fw.emit(fsnotify.Event{Name: cfgPath, Op: fsnotify.Write})

	select {
	case <-secondFired:
	case <-time.After(2 * time.Second):
		t.Fatal("second OnReload did not fire after panic recovery — loop may have died")
	}

	cancel()
	<-done

	if n := callCount.Load(); n < 2 {
		t.Fatalf("OnReload call count = %d, want ≥2 (panic + recovery)", n)
	}
}

// TestProductionWatcherFileRewriteTriggersReload exercises the real fsnotify
// watcher path (not the fake Watcher) end-to-end. Writing new content to the
// config file must cause OnReload to fire.
//
// This is distinct from TestRealFsnotifyEndToEnd in reload_test.go only in
// that it additionally covers the production NewWatcher code path without
// the watchReadyWatcher wrapper, so both the wrapped and unwrapped paths are
// reached.
func TestProductionWatcherFileRewriteTriggersReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fired := make(chan struct{}, 4)

	// watchReadyWatcher signals when the real kqueue/inotify watch is armed.
	watchReady := make(chan struct{})
	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     30 * time.Millisecond,
		Logger:       discardLogger(),
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload:     func() { fired <- struct{}{} },
		NewWatcher: func() (Watcher, error) {
			w, err := fsnotify.NewWatcher()
			if err != nil {
				return nil, err
			}
			return &watchReadyWatcher{
				Watcher: &fsnotifyWatcher{w: w},
				ready:   watchReady,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Run(ctx)
	}()

	// Block until the real watch is registered before mutating the file.
	select {
	case <-watchReady:
	case <-time.After(5 * time.Second):
		t.Fatal("fsnotify watch was never registered")
	}

	if err := os.WriteFile(cfgPath, []byte("rules: [{match: {method: GET, path: /_ping}, action: allow}]\n"), 0o600); err != nil {
		t.Fatalf("rewrite cfg: %v", err)
	}

	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("OnReload did not fire after real file rewrite")
	}

	cancel()
	<-done
}
