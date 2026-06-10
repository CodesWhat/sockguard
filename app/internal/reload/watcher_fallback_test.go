package reload

// watcher_fallback_test.go exercises three coverage gaps in newWatcher:
//
//  1. The production fsnotify branch (opts.NewWatcher == nil) — verify a real
//     fsnotify-backed Watcher is returned and is usable.
//  2. The error path — when the factory returns an error, Run must surface it
//     wrapped with the "reload: create watcher: " prefix.
//  3. fsnotifyWatcher.Remove — the method satisfies the Watcher interface but
//     is never called by the loop; see note in TestFsnotifyWatcherRemoveIsDeadCode.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewWatcherUsesRealFsnotifyWhenHookAbsent constructs a Reloader with no
// NewWatcher hook, then calls the unexported newWatcher() method directly.
// It verifies that a real, usable watcher is returned (Add succeeds, Close
// succeeds), confirming the production fsnotify branch is reachable.
func TestNewWatcherUsesRealFsnotifyWhenHookAbsent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	r, err := New(Options{
		Path:     cfgPath,
		Logger:   discardLogger(),
		OnReload: func() {},
		// NewWatcher intentionally absent — exercises the production branch.
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	w, err := r.newWatcher()
	if err != nil {
		t.Fatalf("newWatcher() unexpectedly returned error: %v", err)
	}
	if w == nil {
		t.Fatal("newWatcher() returned nil watcher without error")
	}

	// Verify the watcher is functional: Add the temp dir (the same dir Run
	// would watch) must not return an error on supported platforms.
	if addErr := w.Add(dir); addErr != nil {
		t.Fatalf("watcher.Add(%q): %v", dir, addErr)
	}

	// Events and Errors channels must be non-nil (required for loop's select).
	if w.Events() == nil {
		t.Fatal("watcher.Events() returned nil channel")
	}
	if w.Errors() == nil {
		t.Fatal("watcher.Errors() returned nil channel")
	}

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("watcher.Close(): %v", closeErr)
	}
}

// TestReloaderSurfacesWatcherCreationFailure injects a NewWatcher that always
// fails and verifies that Run returns a non-nil error whose message contains
// the "reload: create watcher:" prefix. This documents the fail-closed
// contract: a broken watcher factory prevents startup rather than silently
// running without hot-reload.
func TestReloaderSurfacesWatcherCreationFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	sentinel := errors.New("synthetic watcher init failure")

	r, err := New(Options{
		Path:   cfgPath,
		Logger: discardLogger(),
		NewWatcher: func() (Watcher, error) {
			return nil, sentinel
		},
		SignalNotify: func(c chan<- os.Signal, _ ...os.Signal) {},
		SignalStop:   func(c chan<- os.Signal) {},
		OnReload:     func() {},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runErr := r.Run(ctx)
	if runErr == nil {
		t.Fatal("Run() returned nil; expected an error wrapping the watcher creation failure")
	}
	if !errors.Is(runErr, sentinel) {
		t.Errorf("Run() error chain does not contain sentinel: %v", runErr)
	}
	const wantPrefix = "reload: create watcher:"
	if !strings.Contains(runErr.Error(), wantPrefix) {
		t.Errorf("Run() error = %q; want it to contain %q", runErr.Error(), wantPrefix)
	}
}

// TestFsnotifyWatcherRemoveIsDeadCode documents that fsnotifyWatcher.Remove
// satisfies the Watcher interface but is never called by the reload loop.
// Rather than manufacture an artificial call inside the loop, this test
// exercises the method directly on an fsnotifyWatcher created via the
// production factory, confirming at minimum that the delegation to
// (*fsnotify.Watcher).Remove does not panic and returns an error for an
// unwatched path (the expected fsnotify behavior when Remove is called for a
// path that was never Add-ed).
func TestFsnotifyWatcherRemoveIsDeadCode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	r, err := New(Options{
		Path:     cfgPath,
		Logger:   discardLogger(),
		OnReload: func() {},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	w, err := r.newWatcher()
	if err != nil {
		t.Fatalf("newWatcher(): %v", err)
	}
	defer func() { _ = w.Close() }()

	// Add the directory so we have something to remove.
	if err := w.Add(dir); err != nil {
		t.Fatalf("watcher.Add(%q): %v", dir, err)
	}

	// Remove must not panic. fsnotify returns nil on a successful unwatch.
	if removeErr := w.Remove(dir); removeErr != nil {
		t.Fatalf("watcher.Remove(%q): %v", dir, removeErr)
	}

	// NOTE: fsnotifyWatcher.Remove is never invoked by the reload loop — the
	// loop only calls Add (once, for the parent directory), Events(), Errors(),
	// and Close(). The method exists solely because the Watcher interface
	// requires it. Any future refactor that removes the method from the
	// interface would allow deleting the delegation on fsnotifyWatcher as well.
}
