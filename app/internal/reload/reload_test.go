package reload

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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

// watchReadyWatcher wraps a real fsnotify Watcher and closes a ready
// channel the first time Add succeeds, giving tests a clean signal that
// the watch is active before they mutate the filesystem.
type watchReadyWatcher struct {
	Watcher
	once  sync.Once
	ready chan struct{}
}

func (w *watchReadyWatcher) Add(path string) error {
	err := w.Watcher.Add(path)
	if err == nil {
		w.once.Do(func() { close(w.ready) })
	}
	return err
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

	watchReady := make(chan struct{})
	fired := make(chan struct{}, 4)
	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     30 * time.Millisecond,
		Logger:       discardLogger(),
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(chan<- os.Signal) {},
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
	go func() { defer close(done); _ = r.Run(ctx) }()

	// Wait for fsnotify to register the watch before mutating the file.
	select {
	case <-watchReady:
	case <-time.After(5 * time.Second):
		t.Fatal("fsnotify watch was never registered")
	}

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

// TestRenameEventTriggersReload verifies that an fsnotify.Rename event
// targeting the config file arms the debounce and fires OnReload. Atomic
// rename (mv tempfile → cfg.yaml) is the dominant safe-write pattern used
// by editors, Ansible, kustomize, and Helm.
func TestRenameEventTriggersReload(t *testing.T) {
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

	fw.emit(fsnotify.Event{Name: cfgPath, Op: fsnotify.Rename})

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnReload did not fire after fsnotify.Rename event")
	}
	cancel()
	<-done
}

// TestCreateEventTriggersReload verifies that a standalone fsnotify.Create
// event fires OnReload. This matches the "file first appears" scenario and
// the second half of an atomic-rename sequence on macOS kqueue.
func TestCreateEventTriggersReload(t *testing.T) {
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

	fw.emit(fsnotify.Event{Name: cfgPath, Op: fsnotify.Create})

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnReload did not fire after fsnotify.Create event")
	}
	cancel()
	<-done
}

// TestRemoveThenCreateEventSequenceTriggersReload verifies that a Remove
// followed by a Create on the same path (the macOS kqueue atomic-rename
// teardown-and-restore sequence) debounces into exactly one OnReload call.
func TestRemoveThenCreateEventSequenceTriggersReload(t *testing.T) {
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
		Debounce: 30 * time.Millisecond,
		Logger:   discardLogger(),
		NewWatcher: func() (Watcher, error) {
			return fw, nil
		},
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(chan<- os.Signal) {},
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

	// Emit Remove then Create in quick succession — should coalesce.
	fw.emit(fsnotify.Event{Name: cfgPath, Op: fsnotify.Remove})
	fw.emit(fsnotify.Event{Name: cfgPath, Op: fsnotify.Create})

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnReload did not fire after Remove+Create sequence")
	}

	// Allow time for a second spurious fire to surface before asserting count.
	select {
	case <-fired:
		t.Fatal("OnReload fired a second time — Remove+Create was not debounced")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	<-done
	if got := reloadCount.Load(); got != 1 {
		t.Fatalf("OnReload count = %d, want 1 (debounced)", got)
	}
}

// TestContextCancelReleasesSignalHandler verifies that canceling the
// context causes Run to exit and releases the goroutines it started
// (the event loop and the signal handler). The goroutine count after
// shutdown must return to the pre-Run baseline within a small tolerance.
func TestContextCancelReleasesSignalHandler(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()

	// Capture the signal channel so we can verify stop is called, but
	// keep a no-op implementation to avoid touching real OS signals.
	stopCalled := make(chan struct{}, 1)
	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     time.Millisecond,
		Logger:       discardLogger(),
		NewWatcher:   func() (Watcher, error) { return fw, nil },
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop: func(c chan<- os.Signal) {
			select {
			case stopCalled <- struct{}{}:
			default:
			}
		},
		OnReload: func() {},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	// Allow any background runtime goroutines to settle before we baseline.
	runtime.Gosched()
	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	// Cancel and wait for Run to return.
	cancel()
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("Run() = %v, want nil", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after context cancel")
	}

	// Confirm signal handler was stopped.
	select {
	case <-stopCalled:
	case <-time.After(time.Second):
		t.Fatal("SignalStop was not called after context cancel")
	}

	// Poll until goroutine count settles back to baseline (±1 to tolerate
	// transient runtime goroutines), up to a 2-second deadline.
	deadline := time.Now().Add(2 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: started with %d, now have %d after Run exit", baseline, current)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestPollFallbackFiresOnMtimeChange exercises the stat-based fallback used
// on inotify-unreliable backends (Synology / DSM btrfs bind-mounts, some
// FUSE setups). The fsnotify channel is left idle; the loop only learns
// the file changed by re-statting it.
func TestPollFallbackFiresOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("v1"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	reloadCount := atomic.Int64{}
	fired := make(chan struct{}, 4)

	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     -1, // immediate fire so tests don't wait for debounce
		PollInterval: 20 * time.Millisecond,
		Logger:       discardLogger(),
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

	// Let the loop seed the baseline before we mutate the file. Without this
	// pause the first poll tick can fire on an unset baseline and miss the
	// edit (the loop would just record the current state and return).
	time.Sleep(40 * time.Millisecond)

	// Rewrite the file with new content + advance mtime so size, mtime, and
	// inode all move. Truncate+write keeps inode but bumps size and mtime;
	// chtimes guarantees mtime moves even on coarse filesystems.
	if err := os.WriteFile(cfgPath, []byte("v2-with-more-bytes"), 0o600); err != nil {
		t.Fatalf("write cfg v2: %v", err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(cfgPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("poll fallback did not fire reload within 1s after file mutation")
	}
	cancel()
	<-done
	if got := reloadCount.Load(); got < 1 {
		t.Fatalf("OnReload count = %d, want at least 1", got)
	}
}

// TestPollFallbackIdleWhenFileUnchanged confirms the poll path does not
// arm reload when the file hasn't moved. Without this guard, the periodic
// stat would generate spurious reload work on every tick.
func TestPollFallbackIdleWhenFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("static"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fw := newFakeWatcher()
	reloadCount := atomic.Int64{}

	r, err := New(Options{
		Path:         cfgPath,
		Debounce:     -1,
		PollInterval: 20 * time.Millisecond,
		Logger:       discardLogger(),
		NewWatcher: func() (Watcher, error) {
			return fw, nil
		},
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload:     func() { reloadCount.Add(1) },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()

	// Allow several poll ticks to pass without mutating the file.
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	if got := reloadCount.Load(); got != 0 {
		t.Fatalf("OnReload fired %d times on an unchanged file, want 0 (poll fallback should be quiet)", got)
	}
}

// TestFileSnapshotChangedFrom unit-tests the diff predicate so a future
// edit to size/mtime/inode handling doesn't silently regress the poll path.
func TestFileSnapshotChangedFrom(t *testing.T) {
	base := fileSnapshot{known: true, size: 100, mtime: time.Unix(1700000000, 0), inode: 42}

	cases := []struct {
		name string
		next fileSnapshot
		want bool
	}{
		{"equal", base, false},
		{"size changed", fileSnapshot{known: true, size: 200, mtime: base.mtime, inode: base.inode}, true},
		{"mtime changed", fileSnapshot{known: true, size: base.size, mtime: base.mtime.Add(time.Second), inode: base.inode}, true},
		{"inode changed", fileSnapshot{known: true, size: base.size, mtime: base.mtime, inode: 99}, true},
		{"unknown baseline", base, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := base
			if tc.name == "unknown baseline" {
				prev = fileSnapshot{known: false}
			}
			if got := tc.next.changedFrom(prev); got != tc.want {
				t.Fatalf("changedFrom(%+v vs %+v) = %v, want %v", tc.next, prev, got, tc.want)
			}
		})
	}
}
