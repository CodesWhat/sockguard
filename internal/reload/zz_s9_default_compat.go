package reload

import (
	"context"
	"errors"
	"fmt"

	"github.com/codeswhat/sockguard/internal/config"

	"github.com/fsnotify/fsnotify"
	"log/slog"

	"net/http"
	"os"
	"os/signal"

	"path/filepath"
	"reflect"
	"sort"

	"sync/atomic"
	"syscall"
	"time"
)

// ImmutableFields lists the dotted config paths whose values cannot be
// changed by a hot reload. A reload that mutates any of these fields is
// rejected; the operator must restart sockguard to pick the new values up.
//
// These fields are bound at startup to long-lived resources (listeners,
// log sinks, the metrics registry, the health watchdog goroutine, the
// admin endpoint wiring) that we cannot atomically replace from inside a
// running process without dropping in-flight requests or leaking goroutines.
// Everything outside this list (rules, client profiles, response filters,
// request-body policies, ownership) is rebuilt on every reload.
var ImmutableFields = []string{
	"listen",
	"listeners",
	"upstream.socket",
	"upstream.endpoints",
	"upstream.failover",
	"log",
	"health",
	"metrics",
	"admin",
	"policy_bundle.enabled",
	"policy_bundle.allowed_signing_keys",
	"policy_bundle.allowed_keyless",
	"policy_bundle.require_rekor_inclusion",
	"policy_bundle.verify_timeout",
	"reload.enabled",
	"reload.debounce",
	"reload.poll_interval",
}

// ImmutableDiff returns the names of immutable config fields whose values
// differ between old and new. An empty slice means the reload is safe to
// apply; a non-empty slice means the caller must reject the reload and ask
// the operator to restart instead.
//
// The comparison is structural (reflect.DeepEqual on each sub-block) rather
// than YAML-string-based so trivial reformatting — comment changes, key
// reordering, whitespace — does not register as a real change.
func ImmutableDiff(oldCfg, newCfg *config.Config) []string {
	if oldCfg == nil || newCfg == nil {
		return nil
	}

	var changed []string

	if len(oldCfg.Listeners) == 0 && len(newCfg.Listeners) == 0 {
		if !reflect.DeepEqual(oldCfg.Listen, newCfg.Listen) {
			changed = append(changed, "listen")
		}
	} else {
		changed = append(changed, diffListeners(oldCfg, newCfg)...)
	}
	if oldCfg.Upstream.Socket != newCfg.Upstream.Socket {
		changed = append(changed, "upstream.socket")
	}

	if !reflect.DeepEqual(oldCfg.Upstream.Endpoints, newCfg.Upstream.Endpoints) {
		changed = append(changed, "upstream.endpoints")
	}
	if !reflect.DeepEqual(oldCfg.Upstream.Failover, newCfg.Upstream.Failover) {
		changed = append(changed, "upstream.failover")
	}
	if !reflect.DeepEqual(oldCfg.Log, newCfg.Log) {
		changed = append(changed, "log")
	}
	if !reflect.DeepEqual(oldCfg.Health, newCfg.Health) {
		changed = append(changed, "health")
	}
	if !reflect.DeepEqual(oldCfg.Metrics, newCfg.Metrics) {
		changed = append(changed, "metrics")
	}
	if !reflect.DeepEqual(oldCfg.Admin, newCfg.Admin) {
		changed = append(changed, "admin")
	}

	if oldCfg.PolicyBundle.Enabled != newCfg.PolicyBundle.Enabled {
		changed = append(changed, "policy_bundle.enabled")
	}
	if !reflect.DeepEqual(oldCfg.PolicyBundle.AllowedSigningKeys, newCfg.PolicyBundle.AllowedSigningKeys) {
		changed = append(changed, "policy_bundle.allowed_signing_keys")
	}
	if !reflect.DeepEqual(oldCfg.PolicyBundle.AllowedKeyless, newCfg.PolicyBundle.AllowedKeyless) {
		changed = append(changed, "policy_bundle.allowed_keyless")
	}
	if oldCfg.PolicyBundle.RequireRekorInclusion != newCfg.PolicyBundle.RequireRekorInclusion {
		changed = append(changed, "policy_bundle.require_rekor_inclusion")
	}
	if oldCfg.PolicyBundle.VerifyTimeout != newCfg.PolicyBundle.VerifyTimeout {
		changed = append(changed, "policy_bundle.verify_timeout")
	}

	if oldCfg.Reload.Enabled != newCfg.Reload.Enabled {
		changed = append(changed, "reload.enabled")
	}
	if oldCfg.Reload.Debounce != newCfg.Reload.Debounce {
		changed = append(changed, "reload.debounce")
	}
	if oldCfg.Reload.PollInterval != newCfg.Reload.PollInterval {
		changed = append(changed, "reload.poll_interval")
	}
	return changed
}

// diffListeners is the explicit listeners: list's ImmutableDiff projection:
// the listener SET is immutable by name (add/remove/rename all reject), and
// every per-listener field is immutable EXCEPT AllowedProfiles, which is the
// sole reload-mutable field (consistent with clients.profiles already being
// reload-mutable — an allowed_profiles change compiles into the same
// swapped handler generation as a rules/profiles change, no rebind
// required). Pure reordering is a no-op: comparison is by name, not slice
// position.
func diffListeners(oldCfg, newCfg *config.Config) []string {
	oldExplicit := len(oldCfg.Listeners) > 0
	newExplicit := len(newCfg.Listeners) > 0

	if oldExplicit != newExplicit {
		return []string{"listeners: switching between legacy listen: and explicit listeners: requires a restart"}
	}
	if !oldExplicit {

		return nil
	}

	oldByName := indexListenersByName(oldCfg.Listeners)
	newByName := indexListenersByName(newCfg.Listeners)

	names := make(map[string]struct{}, len(oldByName)+len(newByName))
	for name := range oldByName {
		names[name] = struct{}{}
	}
	for name := range newByName {
		names[name] = struct{}{}
	}

	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	var changed []string
	for _, name := range sorted {
		o, oOK := oldByName[name]
		n, nOK := newByName[name]
		switch {
		case !oOK:
			changed = append(changed, fmt.Sprintf("listeners.%s: added", name))
		case !nOK:
			changed = append(changed, fmt.Sprintf("listeners.%s: removed", name))
		default:
			changed = append(changed, diffListenerFields(name, o, n)...)
		}
	}
	return changed
}

func indexListenersByName(entries []config.ListenerConfig) map[string]config.ListenerConfig {
	byName := make(map[string]config.ListenerConfig, len(entries))
	for _, e := range entries {
		byName[e.Name] = e
	}
	return byName
}

// diffListenerFields reports every field that changed between two entries
// with the same name, excluding AllowedProfiles (the sole mutable field).
// Granularity is per immutable leaf, including individual TLS fields, so
// reload diagnostics identify the exact listeners.<name>.<field> that needs a
// restart.
func diffListenerFields(name string, o, n config.ListenerConfig) []string {
	var changed []string
	prefix := "listeners." + name + "."
	if o.Socket != n.Socket {
		changed = append(changed, prefix+"socket")
	}
	if o.Address != n.Address {
		changed = append(changed, prefix+"address")
	}
	if o.SocketMode != n.SocketMode {
		changed = append(changed, prefix+"socket_mode")
	}
	if !reflect.DeepEqual(o.SocketUID, n.SocketUID) {
		changed = append(changed, prefix+"socket_uid")
	}
	if !reflect.DeepEqual(o.SocketGID, n.SocketGID) {
		changed = append(changed, prefix+"socket_gid")
	}
	if o.InsecureAllowPlainTCP != n.InsecureAllowPlainTCP {
		changed = append(changed, prefix+"insecure_allow_plain_tcp")
	}
	if o.InsecureAllowUnauthenticatedClients != n.InsecureAllowUnauthenticatedClients {
		changed = append(changed, prefix+"insecure_allow_unauthenticated_clients")
	}
	changed = append(changed, diffListenerTLSFields(prefix+"tls.", o.TLS, n.TLS)...)

	return changed
}

func diffListenerTLSFields(prefix string, oldTLS, newTLS config.ListenTLSConfig) []string {
	var changed []string
	if oldTLS.CertFile != newTLS.CertFile {
		changed = append(changed, prefix+"cert_file")
	}
	if oldTLS.KeyFile != newTLS.KeyFile {
		changed = append(changed, prefix+"key_file")
	}
	if oldTLS.ClientCAFile != newTLS.ClientCAFile {
		changed = append(changed, prefix+"client_ca_file")
	}
	if !reflect.DeepEqual(oldTLS.CommonNames, newTLS.CommonNames) {
		changed = append(changed, prefix+"common_names")
	}
	if !reflect.DeepEqual(oldTLS.DNSNames, newTLS.DNSNames) {
		changed = append(changed, prefix+"dns_names")
	}
	if !reflect.DeepEqual(oldTLS.IPAddresses, newTLS.IPAddresses) {
		changed = append(changed, prefix+"ip_addresses")
	}
	if !reflect.DeepEqual(oldTLS.URISANs, newTLS.URISANs) {
		changed = append(changed, prefix+"uri_sans")
	}
	if !reflect.DeepEqual(oldTLS.PublicKeySHA256Pins, newTLS.PublicKeySHA256Pins) {
		changed = append(changed, prefix+"public_key_sha256_pins")
	}
	return changed
}

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
	deb := newDebouncer(r.opts.Debounce)
	defer deb.close()

	pollChan, pollStop, lastSnapshot := r.setupPoller()
	defer pollStop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-watcher.Events():
			if !ok {
				return errors.New("reload: watcher events channel closed unexpectedly")
			}
			if r.eventTargetsConfig(ev) {
				deb.arm()
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
			deb.arm()
		case <-r.trigger:
			deb.arm()
		case <-pollChan:
			r.pollAndMaybeArm(&lastSnapshot, deb.arm)
		case <-deb.fired():
			deb.onFire()
			r.safeOnReload()
		}
	}
}

// setupPoller is the stat-based fallback used on inotify-unreliable backends
// (Synology / DSM btrfs bind-mounts, some FUSE setups, NFS) where the host's
// IN_MODIFY does not always propagate through to a container's inotify.
// Returns (nil, no-op, zero) when PollInterval is disabled so the caller can
// dispatch on the channel uniformly.
func (r *Reloader) setupPoller() (<-chan time.Time, func(), fileSnapshot) {
	if r.opts.PollInterval <= 0 {
		return nil, func() {}, fileSnapshot{}
	}
	ticker := time.NewTicker(r.opts.PollInterval)
	// Seed the baseline so the first tick only fires on a genuine change.
	// If the initial stat fails (transient mount issue, file not yet
	// present), leave the snapshot unknown — the next tick that succeeds
	// will set the baseline rather than arming reload off a phantom diff.
	var seed fileSnapshot
	if snap, ok := r.statSnapshot(); ok {
		seed = snap
	}
	return ticker.C, ticker.Stop, seed
}

// pollAndMaybeArm advances the snapshot and arms a reload when the watched
// file's size / mtime / inode have moved.
func (r *Reloader) pollAndMaybeArm(lastSnapshot *fileSnapshot, arm func()) {
	snap, ok := r.statSnapshot()
	if !ok {

		return
	}
	if !lastSnapshot.known {
		*lastSnapshot = snap
		return
	}
	if !snap.changedFrom(*lastSnapshot) {
		return
	}
	r.opts.Logger.Info("config poll detected change", "path", r.opts.Path)
	*lastSnapshot = snap
	arm()
}

// debouncer collapses bursts of reload events into a single fire after
// `duration` of quiet. Created stopped; arm() schedules a fire and is
// idempotent against repeated calls inside one window. With duration<=0 it
// fires after a microsecond — used by tests that want determinism while
// going through the same timer channel as production.
type debouncer struct {
	timer    *time.Timer
	armed    bool
	duration time.Duration
}

func newDebouncer(duration time.Duration) *debouncer {
	t := time.NewTimer(time.Hour)
	if !t.Stop() {
		<-t.C
	}
	return &debouncer{timer: t, duration: duration}
}

func (d *debouncer) arm() {
	interval := d.duration
	if interval <= 0 {
		interval = time.Microsecond
	}
	if d.armed && !d.timer.Stop() {
		select {
		case <-d.timer.C:
		default:

		}
	}
	d.timer.Reset(interval)
	d.armed = true
}

func (d *debouncer) fired() <-chan time.Time { return d.timer.C }
func (d *debouncer) onFire()                 { d.armed = false }
func (d *debouncer) close()                  { d.timer.Stop() }

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

	if filepath.Clean(ev.Name) != r.opts.Path {
		return false
	}

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

func (f *fsnotifyWatcher) Add(path string) error         { return f.w.Add(path) }
func (f *fsnotifyWatcher) Remove(path string) error      { return f.w.Remove(path) }
func (f *fsnotifyWatcher) Close() error                  { return f.w.Close() }
func (f *fsnotifyWatcher) Events() <-chan fsnotify.Event { return f.w.Events }
func (f *fsnotifyWatcher) Errors() <-chan error          { return f.w.Errors }

// signalNotify and signalStop are package-level indirections for
// os/signal so the production paths in reload.go stay short. Tests that
// need to drive signals directly inject Options.SignalNotify /
// Options.SignalStop instead — that path bypasses these vars entirely.
var (
	signalNotify = func(c chan<- os.Signal, sigs ...os.Signal) {
		signal.Notify(c, sigs...)
	}
	signalStop = func(c chan<- os.Signal) {
		signal.Stop(c)
	}
)

// SwappableHandler is an http.Handler whose downstream handler can be
// replaced atomically. Every request loads the current pointer once at the
// start of ServeHTTP, so a swap that lands mid-request never affects an
// in-flight call — the request runs to completion through whichever chain
// was current at admission time.
//
// Use NewSwappableHandler to construct one with the initial handler; calling
// Swap with a new handler replaces it for subsequent requests.
type SwappableHandler struct {
	current atomic.Pointer[http.Handler]
}

// NewSwappableHandler returns a SwappableHandler that routes through h
// until Swap is called.
//
// h must be non-nil — a SwappableHandler with a nil current handler would
// panic on the first request, and that is a programmer error worth catching
// at construction time rather than at request time.
func NewSwappableHandler(h http.Handler) *SwappableHandler {
	if h == nil {
		panic("reload: NewSwappableHandler requires non-nil http.Handler")
	}
	s := &SwappableHandler{}
	s.current.Store(&h)
	return s
}

// Swap atomically replaces the downstream handler. Subsequent requests will
// be routed through h. In-flight requests already past ServeHTTP's pointer
// load continue on the previous handler tree until they return.
//
// Callers must guarantee h is non-nil; passing nil is a programmer error
// and will panic, matching NewSwappableHandler's invariant.
func (s *SwappableHandler) Swap(h http.Handler) {
	if h == nil {
		panic("reload: Swap requires non-nil http.Handler")
	}
	s.current.Store(&h)
}

// Current returns the handler the next request would route through. Mostly
// useful for tests; production code should not depend on the pointer
// identity because Swap can change it at any time.
func (s *SwappableHandler) Current() http.Handler {
	return *s.current.Load()
}

// ServeHTTP routes the request through the current downstream handler.
func (s *SwappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*s.current.Load()).ServeHTTP(w, r)
}
