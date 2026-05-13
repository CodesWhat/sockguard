package reload

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// fakeWatcher implements Watcher for tests so we can drive event delivery
// deterministically without standing up a real inotify / kqueue watch.
type fakeWatcher struct {
	events chan fsnotify.Event
	errors chan error

	mu      sync.Mutex
	closed  bool
	watched map[string]struct{}
}

func newFakeWatcher() *fakeWatcher {
	return &fakeWatcher{
		events:  make(chan fsnotify.Event, 16),
		errors:  make(chan error, 8),
		watched: make(map[string]struct{}),
	}
}

func (f *fakeWatcher) Add(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("fake watcher closed")
	}
	f.watched[path] = struct{}{}
	return nil
}

func (f *fakeWatcher) Remove(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.watched, path)
	return nil
}

func (f *fakeWatcher) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	close(f.events)
	close(f.errors)
	return nil
}

func (f *fakeWatcher) Events() <-chan fsnotify.Event { return f.events }
func (f *fakeWatcher) Errors() <-chan error          { return f.errors }

// emit sends an event into the channel — blocking is fine for tests since
// the buffer is sized generously.
func (f *fakeWatcher) emit(ev fsnotify.Event) {
	f.events <- ev
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestNewRejectsMissingPath / OnReload covers the construction guards.
func TestNewRejectsMissingPath(t *testing.T) {
	_, err := New(Options{OnReload: func() {}})
	if err == nil {
		t.Fatal("expected error when Path is empty")
	}
}

func TestNewRejectsMissingOnReload(t *testing.T) {
	_, err := New(Options{Path: "/tmp/cfg.yaml"})
	if err == nil {
		t.Fatal("expected error when OnReload is nil")
	}
}

func TestNewAbsolvesPath(t *testing.T) {
	r, err := New(Options{Path: "cfg.yaml", OnReload: func() {}})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if !filepath.IsAbs(r.opts.Path) {
		t.Fatalf("Path = %q, want absolute", r.opts.Path)
	}
}

// TestTriggerInvokesOnReloadAfterDebounce verifies the manual trigger
// path: a single Trigger() should fire OnReload exactly once after the
// debounce window elapses.
func TestTriggerInvokesOnReloadAfterDebounce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules: []"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	reloadCount := atomic.Int64{}
	fired := make(chan struct{}, 4)

	r, err := New(Options{
		Path:     cfgPath,
		Debounce: 30 * time.Millisecond,
		Logger:   discardLogger(),
		NewWatcher: func() (Watcher, error) {
			return fw, nil
		},
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload: func() {
			reloadCount.Add(1)
			fired <- struct{}{}
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

	r.Trigger()
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnReload did not fire within 1s after Trigger")
	}

	cancel()
	<-done
	if got := reloadCount.Load(); got != 1 {
		t.Fatalf("OnReload count = %d, want 1", got)
	}
}

// TestMultipleTriggersCoalesce verifies the debounce contract — three
// triggers inside the window collapse to a single OnReload call.
func TestMultipleTriggersCoalesce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	reloadCount := atomic.Int64{}
	fired := make(chan struct{}, 8)

	r, err := New(Options{
		Path:     cfgPath,
		Debounce: 50 * time.Millisecond,
		Logger:   discardLogger(),
		NewWatcher: func() (Watcher, error) {
			return fw, nil
		},
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload: func() {
			reloadCount.Add(1)
			fired <- struct{}{}
		},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()

	r.Trigger()
	r.Trigger()
	r.Trigger()

	select {
	case <-fired:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("OnReload did not fire")
	}

	// Wait long enough for a second OnReload to land if one were going
	// to. 100ms is twice the debounce window with margin.
	select {
	case <-fired:
		t.Fatal("OnReload fired again — bursts did not coalesce")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	<-done
	if got := reloadCount.Load(); got != 1 {
		t.Fatalf("OnReload count = %d, want 1 (coalesced)", got)
	}
}

// TestFileWriteEventTriggersReload exercises the fsnotify path: a Write
// event targeting the configured file fires OnReload after debouncing.
func TestFileWriteEventTriggersReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	fired := make(chan struct{}, 4)

	r, err := New(Options{
		Path:     cfgPath,
		Debounce: 30 * time.Millisecond,
		Logger:   discardLogger(),
		NewWatcher: func() (Watcher, error) {
			return fw, nil
		},
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload:     func() { fired <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()

	fw.emit(fsnotify.Event{Name: cfgPath, Op: fsnotify.Write})

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnReload did not fire after file write event")
	}
	cancel()
	<-done
}

// TestFileEventForOtherFileIsIgnored verifies that events for sibling
// files in the watched dir don't trigger spurious reloads.
func TestFileEventForOtherFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	fired := make(chan struct{}, 4)

	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     30 * time.Millisecond,
		Logger:       discardLogger(),
		NewWatcher:   func() (Watcher, error) { return fw, nil },
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload:     func() { fired <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()

	fw.emit(fsnotify.Event{Name: filepath.Join(dir, "other.yaml"), Op: fsnotify.Write})

	select {
	case <-fired:
		t.Fatal("OnReload fired for unrelated file")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	<-done
}

// TestSignalTriggersReload checks the SIGHUP path through an injected
// signal source. The injected SignalNotify wires the reloader's channel
// to a test-controlled producer.
func TestSignalTriggersReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	fired := make(chan struct{}, 4)

	var captured chan<- os.Signal
	captureMu := sync.Mutex{}
	notify := func(c chan<- os.Signal, _ ...os.Signal) {
		captureMu.Lock()
		captured = c
		captureMu.Unlock()
	}
	stop := func(chan<- os.Signal) {}

	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     30 * time.Millisecond,
		Logger:       discardLogger(),
		NewWatcher:   func() (Watcher, error) { return fw, nil },
		SignalNotify: notify,
		SignalStop:   stop,
		OnReload:     func() { fired <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()

	// Wait for installSignalHandler to register the channel.
	deadline := time.Now().Add(time.Second)
	for {
		captureMu.Lock()
		c := captured
		captureMu.Unlock()
		if c != nil {
			c <- syscall.SIGHUP
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("signal channel was never registered")
		}
		time.Sleep(time.Millisecond)
	}

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnReload did not fire after signal")
	}
	cancel()
	<-done
}

// TestWatcherErrorDoesNotKillLoop confirms a transient watcher error is
// logged but the loop continues to serve subsequent triggers.
func TestWatcherErrorDoesNotKillLoop(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	fired := make(chan struct{}, 4)

	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     30 * time.Millisecond,
		Logger:       discardLogger(),
		NewWatcher:   func() (Watcher, error) { return fw, nil },
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(chan<- os.Signal) {},
		OnReload:     func() { fired <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()

	fw.errors <- errors.New("transient watcher hiccup")

	// Loop must still process triggers after surfacing the error.
	r.Trigger()
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnReload did not fire after watcher error")
	}
	cancel()
	<-done
}

// TestContextCancelExitsCleanly verifies the loop returns when ctx is
// canceled and that any in-flight OnReload completes first.
func TestContextCancelExitsCleanly(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	fw := newFakeWatcher()
	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     time.Millisecond,
		Logger:       discardLogger(),
		NewWatcher:   func() (Watcher, error) { return fw, nil },
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(chan<- os.Signal) {},
		OnReload:     func() {},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v, want nil after cancel", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after context cancel")
	}
}

// TestRealFsnotifyEndToEnd is a smoke test against the real fsnotify
// watcher. Touching the file should trigger a reload. Skipped on
// platforms where filesystem notifications are not available.
func TestRealFsnotifyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fired := make(chan struct{}, 4)
	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     30 * time.Millisecond,
		Logger:       discardLogger(),
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(chan<- os.Signal) {},
		OnReload:     func() { fired <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()

	// Tiny pause so fsnotify can set up the watch before we mutate.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(cfgPath, []byte("rules: [{match: {method: GET, path: /foo}, action: allow}]\n"), 0o600); err != nil {
		t.Fatalf("rewrite cfg: %v", err)
	}

	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("OnReload did not fire after real file write")
	}
	cancel()
	<-done
}
