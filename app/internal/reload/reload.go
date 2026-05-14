package reload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DefaultDebounce is the default coalescing window for back-to-back file
// events. Editors (vim, nvim, gofmt-on-save) commonly emit several events
// per save (chmod + write + rename + create); collapsing them into a
// single trigger avoids reloading mid-write.
const DefaultDebounce = 250 * time.Millisecond

// Options configures a Reloader.
type Options struct {
	// Path is the absolute path of the config file to watch. Required.
	Path string

	// Debounce coalesces a burst of fsnotify events into one OnReload call.
	// Zero defaults to DefaultDebounce. Negative values disable debouncing —
	// useful for deterministic tests but not recommended in production
	// because most editors emit multi-event saves.
	Debounce time.Duration

	// PollInterval optionally enables a stat-based fallback that periodically
	// checks the config file's size, modification time, and inode and arms a
	// reload when any of them have moved since the last check. Zero disables
	// polling — the default, because fsnotify is reliable on regular Linux
	// and macOS filesystems and a SIGHUP covers the rest. Synology / DSM
	// btrfs bind-mounts and some FUSE backends drop inotify events crossing
	// the host/container boundary; on those backends the operator can either
	// keep the canonical SIGHUP workflow or enable polling here (typical
	// values 5s–15s) so an unattended edit is still picked up.
	PollInterval time.Duration

	// OnReload is invoked when a reload trigger has fired and debouncing
	// has elapsed. Required. The Reloader serializes calls — there is at
	// most one OnReload in flight at any time.
	OnReload func()

	// Logger is used for watcher-error and reload-fired log lines. If nil,
	// slog.Default() is used.
	Logger *slog.Logger

	// SignalNotify lets tests bypass the OS signal subsystem. In production
	// it is signal.Notify-shaped and the Reloader registers SIGHUP. Tests
	// can supply a function that wires the provided channel to a
	// caller-controlled source. When nil, the production path is used.
	SignalNotify func(c chan<- os.Signal, sig ...os.Signal)

	// SignalStop mirrors SignalNotify for shutdown. When nil, signal.Stop
	// is used.
	SignalStop func(c chan<- os.Signal)

	// NewWatcher overrides fsnotify.NewWatcher. Mainly a test seam: a
	// test can return a fake watcher whose Events channel the test drives
	// directly. When nil, fsnotify.NewWatcher is called.
	NewWatcher func() (Watcher, error)

	// Now lets tests inject a deterministic clock for poll-fallback bookkeeping
	// and for unit tests of the file-stat snapshot. Production callers leave
	// this nil; the Reloader uses time.Now in that case. Mainly a test seam
	// for the poll-fallback path.
	Now func() time.Time
}

// Watcher is the small subset of *fsnotify.Watcher this package uses,
// extracted so tests can inject fakes without standing up real inotify /
// kqueue watches.
type Watcher interface {
	Add(path string) error
	Remove(path string) error
	Close() error
	Events() <-chan fsnotify.Event
	Errors() <-chan error
}

// Reloader watches the configured file path for changes and invokes
// OnReload after a debounce window. SIGHUP triggers an immediate reload
// (also subject to the same debounce, so a SIGHUP + simultaneous edit do
// not race into two reloads).
type Reloader struct {
	opts    Options
	trigger chan struct{}
}

// New constructs a Reloader from opts. It does not start watching; call
// Run to begin the event loop.
//
// Returns an error if Path is empty, OnReload is nil, or Path's parent
// directory cannot be resolved.
func New(opts Options) (*Reloader, error) {
	if opts.Path == "" {
		return nil, errors.New("reload: Path is required")
	}
	if opts.OnReload == nil {
		return nil, errors.New("reload: OnReload is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Debounce == 0 {
		opts.Debounce = DefaultDebounce
	}
	abs, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("reload: resolve config path: %w", err)
	}
	opts.Path = abs
	return &Reloader{opts: opts, trigger: make(chan struct{}, 1)}, nil
}

// Trigger asks the reloader to schedule a reload. Safe to call from any
// goroutine. Multiple Triggers between debounce ticks coalesce into one
// OnReload call. Mainly exposed for tests and for any future RPC-driven
// reload surface.
func (r *Reloader) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Run starts the reload event loop. It blocks until ctx is canceled.
//
// Errors creating the fsnotify watcher are returned synchronously so the
// caller can decide whether to start sockguard at all without hot-reload.
// Per-event errors (watcher.Errors channel, OnReload panics) are logged
// but do not stop the loop — sockguard keeps serving with the last good
// config.
func (r *Reloader) Run(ctx context.Context) error {
	watcher, err := r.newWatcher()
	if err != nil {
		return fmt.Errorf("reload: create watcher: %w", err)
	}
	defer func() {
		if closeErr := watcher.Close(); closeErr != nil {
			r.opts.Logger.Warn("reload: close watcher", "error", closeErr)
		}
	}()

	// Watch the parent directory rather than the file itself: editors
	// commonly write via rename (tempfile + atomic replace), which makes
	// a file-level watch go stale the moment the inode is swapped. The
	// parent-dir watch survives that.
	dir := filepath.Dir(r.opts.Path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("reload: watch %q: %w", dir, err)
	}

	signalCh := make(chan os.Signal, 1)
	r.installSignalHandler(signalCh)
	defer r.uninstallSignalHandler(signalCh)

	r.opts.Logger.Info("config hot-reload enabled",
		"path", r.opts.Path,
		"debounce", r.opts.Debounce.String(),
		"poll_interval", r.opts.PollInterval.String(),
	)

	return r.loop(ctx, watcher, signalCh)
}

// fileSnapshot captures the lightweight identity fields of the watched file
// used by the poll-fallback path. A change in any of these between two stats
// is treated as "the file moved" and arms a reload — the same posture as a
// fired fsnotify event. Inode changes catch atomic-replace flows (vim, gofmt,
// kustomize) on backends that drop inotify events.
type fileSnapshot struct {
	known bool
	size  int64
	mtime time.Time
	inode uint64
}

func (r *Reloader) loop(ctx context.Context, watcher Watcher, signalCh <-chan os.Signal) error {
	// debounceTimer is created stopped; arming it on the first relevant
	// event collapses subsequent events into the same window.
	debounceTimer := time.NewTimer(time.Hour)
	if !debounceTimer.Stop() {
		<-debounceTimer.C
	}
	defer debounceTimer.Stop()
	armed := false
	arm := func() {
		if r.opts.Debounce <= 0 {
			// No-debounce mode: fire immediately, used by tests that
			// want determinism. We still funnel through the timer channel
			// for code-path uniformity — reset to a near-zero interval.
			if armed && !debounceTimer.Stop() {
				select {
				case <-debounceTimer.C:
				default:
				}
			}
			debounceTimer.Reset(time.Microsecond)
			armed = true
			return
		}
		if armed && !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
				// Already fired and was drained — armed should already be false.
			}
		}
		debounceTimer.Reset(r.opts.Debounce)
		armed = true
	}

	// Stat-based fallback poller, opt-in via Options.PollInterval. Useful on
	// inotify-unreliable backends (Synology / DSM btrfs bind-mounts, some
	// FUSE setups, NFS): the host's IN_MODIFY does not always propagate
	// through to a container's inotify, so absent SIGHUP the reload watcher
	// would never see the edit. With polling on, the loop also re-stats the
	// file and arms a reload when size/mtime/inode have moved.
	var pollChan <-chan time.Time
	var pollTicker *time.Ticker
	var lastSnapshot fileSnapshot
	if r.opts.PollInterval > 0 {
		pollTicker = time.NewTicker(r.opts.PollInterval)
		defer pollTicker.Stop()
		pollChan = pollTicker.C
		// Seed the baseline so the first tick only fires on a genuine change.
		// If the initial stat fails (transient mount issue, file not yet
		// present), leave the snapshot unknown — the next tick that succeeds
		// will set the baseline rather than arming reload off a phantom diff.
		if snap, ok := r.statSnapshot(); ok {
			lastSnapshot = snap
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-watcher.Events():
			if !ok {
				return errors.New("reload: watcher events channel closed unexpectedly")
			}
			if r.eventTargetsConfig(ev) {
				arm()
			}
		case err, ok := <-watcher.Errors():
			if !ok {
				return errors.New("reload: watcher errors channel closed unexpectedly")
			}
			if err != nil {
				r.opts.Logger.Warn("config watcher error", "error", err)
			}
		case sig, ok := <-signalCh:
			if !ok {
				return nil
			}
			r.opts.Logger.Info("reload signal received", "signal", sig.String())
			arm()
		case <-r.trigger:
			arm()
		case <-pollChan:
			snap, ok := r.statSnapshot()
			if !ok {
				// stat failure is not fatal — the file may be mid-replace on
				// an atomic-rename editor; the next tick will either confirm
				// the change or restore the baseline.
				continue
			}
			if !lastSnapshot.known {
				lastSnapshot = snap
				continue
			}
			if snap.changedFrom(lastSnapshot) {
				r.opts.Logger.Info("config poll detected change", "path", r.opts.Path)
				lastSnapshot = snap
				arm()
			}
		case <-debounceTimer.C:
			armed = false
			r.safeOnReload()
		}
	}
}

// statSnapshot returns the watched file's current size / mtime / inode. The
// returned ok=false means the stat failed (file briefly missing during an
// atomic rename, transient mount issue) and the caller should leave the
// baseline untouched and try again on the next tick. Inode extraction is
// platform-specific and falls back to zero on backends that don't expose
// syscall.Stat_t — size + mtime are still enough to detect most edits there.
func (r *Reloader) statSnapshot() (fileSnapshot, bool) {
	info, err := os.Stat(r.opts.Path)
	if err != nil {
		return fileSnapshot{}, false
	}
	return fileSnapshot{
		known: true,
		size:  info.Size(),
		mtime: info.ModTime(),
		inode: inodeOf(info),
	}, true
}

func (s fileSnapshot) changedFrom(prev fileSnapshot) bool {
	if !prev.known {
		return false
	}
	if s.size != prev.size {
		return true
	}
	if !s.mtime.Equal(prev.mtime) {
		return true
	}
	if s.inode != prev.inode {
		return true
	}
	return false
}

func (r *Reloader) eventTargetsConfig(ev fsnotify.Event) bool {
	if ev.Name == "" {
		return false
	}
	// Compare absolute paths because fsnotify reports the path as it was
	// registered (we registered the parent dir, so events arrive with
	// absolute names).
	if filepath.Clean(ev.Name) != r.opts.Path {
		return false
	}
	// Treat any non-Remove event as "config may have new contents".
	// Atomic-replace flows on Linux fire Rename on the old path then
	// Create on the new path; on macOS kqueue it's typically Remove +
	// Create. Either way, the Create / Write that lands on the same
	// basename is the signal we care about.
	if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Chmod|fsnotify.Rename) != 0 {
		return true
	}
	return false
}

func (r *Reloader) installSignalHandler(ch chan os.Signal) {
	if r.opts.SignalNotify != nil {
		r.opts.SignalNotify(ch, syscall.SIGHUP)
		return
	}
	signalNotify(ch, syscall.SIGHUP)
}

func (r *Reloader) uninstallSignalHandler(ch chan os.Signal) {
	if r.opts.SignalStop != nil {
		r.opts.SignalStop(ch)
		return
	}
	signalStop(ch)
}

func (r *Reloader) newWatcher() (Watcher, error) {
	if r.opts.NewWatcher != nil {
		return r.opts.NewWatcher()
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &fsnotifyWatcher{w: w}, nil
}

// safeOnReload runs the caller-supplied reload callback, recovering from
// panics so a broken callback cannot kill the reloader goroutine. A panic
// in OnReload should be exceptional — it means a programming bug in
// internal/cmd's rebuild path — but sockguard's whole posture is "stay
// up", so we log it and keep watching.
func (r *Reloader) safeOnReload() {
	defer func() {
		if rec := recover(); rec != nil {
			r.opts.Logger.Error("config reload callback panicked",
				"panic", fmt.Sprintf("%v", rec),
			)
		}
	}()
	r.opts.OnReload()
}

// fsnotifyWatcher wraps a *fsnotify.Watcher to satisfy the Watcher
// interface (which uses methods returning channels rather than channel
// fields, so fakes can be implemented as plain structs).
type fsnotifyWatcher struct {
	w *fsnotify.Watcher
}

func (f *fsnotifyWatcher) Add(path string) error               { return f.w.Add(path) }
func (f *fsnotifyWatcher) Remove(path string) error            { return f.w.Remove(path) }
func (f *fsnotifyWatcher) Close() error                        { return f.w.Close() }
func (f *fsnotifyWatcher) Events() <-chan fsnotify.Event       { return f.w.Events }
func (f *fsnotifyWatcher) Errors() <-chan error                { return f.w.Errors }
