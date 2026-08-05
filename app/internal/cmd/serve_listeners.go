package cmd

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"syscall"

	"github.com/codeswhat/sockguard/internal/clientacl"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/inbound"
	"github.com/codeswhat/sockguard/internal/metrics"
)

// listenerStatusBoard tracks each configured listener's lifecycle state
// (#149) for the /health response (health.ListenerStatus). Safe for
// concurrent use: writes come from the bind/publish/shutdown call sites
// below, reads come from whichever goroutine is currently serving a
// /health request — both can run concurrently with each other and with
// writes from other listeners' goroutines.
type listenerStatusBoard struct {
	mu      sync.Mutex
	entries map[string]health.ListenerStatus
}

func newListenerStatusBoard() *listenerStatusBoard {
	return &listenerStatusBoard{entries: make(map[string]health.ListenerStatus)}
}

// register creates (or overwrites) a board entry with identity's Name/Role/
// Network and the given state. Called once per listener when its full
// identity first becomes known — at bind time for main listeners, at
// startup for the admin listener.
func (b *listenerStatusBoard) register(identity inbound.Identity, state string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[identity.Name] = health.ListenerStatus{
		Name:    identity.Name,
		Role:    string(identity.Role),
		Network: string(identity.Network),
		State:   state,
	}
}

// setState updates only the State field of an already-registered entry,
// leaving Name/Role/Network untouched. A no-op if name was never
// registered — callers that only have a name (e.g. the error fan-in, which
// carries listenerResult, not a full inbound.Identity) can't accidentally
// fabricate an entry with an empty Network/Role.
func (b *listenerStatusBoard) setState(name, state string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[name]
	if !ok {
		return
	}
	entry.State = state
	b.entries[name] = entry
}

// snapshot returns every tracked listener's current state, sorted by name
// for deterministic /health output. Implements health.Monitor.ListenersFunc.
func (b *listenerStatusBoard) snapshot() []health.ListenerStatus {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]health.ListenerStatus, 0, len(b.entries))
	for _, entry := range b.entries {
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, c health.ListenerStatus) int {
		return cmp.Compare(a.Name, c.Name)
	})
	return out
}

// listenerMember is one bound-and-served main listener: the result of
// EffectiveListeners() (#149) turned into a live net.Listener plus the
// http.Server dedicated to it. Every main listener shares the same handler
// (reload.SwappableHandler) — only the identity stamped into ConnContext and
// the bind target differ between members.
type listenerMember struct {
	identity   inbound.Identity
	listener   net.Listener
	server     *http.Server
	hijacked   *hijackedConnTracker
	socketPath string
	// socketIdentity is the (dev, ino) pair captured immediately after bind,
	// for explicit listeners[*] entries only (see bindMainListeners). It
	// guards shutdown-time removal: a socket path is only unlinked if it
	// still resolves to the exact inode this process created.
	socketIdentity socketIdentity
}

// hijackedConnTracker owns connections removed from net/http's lifecycle by
// a successful Hijack (Docker attach/exec streaming). http.Server.Shutdown
// intentionally does not close them, so listener-group shutdown must do so
// explicitly to keep the single 30-second drain deadline meaningful.
type hijackedConnTracker struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func trackHijackedConnections(server *http.Server) *hijackedConnTracker {
	tracker := &hijackedConnTracker{conns: make(map[net.Conn]struct{})}
	previous := server.ConnState
	server.ConnState = func(conn net.Conn, state http.ConnState) {
		if previous != nil {
			previous(conn, state)
		}
		tracker.transition(conn, state)
	}
	return tracker
}

func (t *hijackedConnTracker) transition(conn net.Conn, state http.ConnState) {
	if t == nil || conn == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch state {
	case http.StateHijacked:
		if t.closed {
			_ = conn.Close()
			return
		}
		t.conns[conn] = struct{}{}
	case http.StateClosed:
		delete(t.conns, conn)
	}
}

func (t *hijackedConnTracker) closeAll() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.closed = true
	connections := make([]net.Conn, 0, len(t.conns))
	for conn := range t.conns {
		connections = append(connections, conn)
	}
	clear(t.conns)
	t.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

// socketIdentity is a unix filesystem identity (device + inode). The zero
// value is "unknown/not captured" (valid == false), which callers must treat
// conservatively — see removeSocketIfOwned.
type socketIdentity struct {
	dev, ino uint64
	valid    bool
}

func statSocketIdentity(lstat func(string) (os.FileInfo, error), path string) socketIdentity {
	if path == "" || lstat == nil {
		return socketIdentity{}
	}
	info, err := lstat(path)
	if err != nil {
		return socketIdentity{}
	}
	return socketIdentityFromFileInfo(info)
}

func socketIdentityFromFileInfo(info os.FileInfo) socketIdentity {
	if info == nil {
		return socketIdentity{}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketIdentity{}
	}
	//nolint:gosec // G115: Dev/Ino widths differ across GOOS (e.g. int32 Dev on darwin); both are non-negative kernel-assigned identifiers, never attacker-controlled input, so a widening/truncating conversion here is safe.
	return socketIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), valid: true}
}

// removeSocketIfOwned unlinks path only when it still identifies the same
// inode captured at bind time (want). An unknown identity (want.valid ==
// false — e.g. explicit listeners bound before this hardening, or a legacy
// member which does not record one) falls back to unconditional removal,
// matching pre-#149 behavior for those paths.
func removeSocketIfOwned(deps *serveDeps, path string, want socketIdentity) error {
	if path == "" {
		return nil
	}
	if !want.valid {
		return deps.removePath(path)
	}
	got := statSocketIdentity(deps.lstatPath, path)
	if !got.valid || got != want {
		// Gone, or something else now occupies the path — never remove a
		// file this process didn't create.
		return nil
	}
	return deps.removePath(path)
}

// networkFor reports the inbound.Network a ListenConfig binds to.
func networkFor(listen config.ListenConfig) inbound.Network {
	if listen.Socket != "" {
		return inbound.NetworkUnix
	}
	return inbound.NetworkTCP
}

// listenerAddrFor renders a human-readable "unix:<path>" / "tcp://<addr>"
// string for one effective listener entry, for logs and the startup banner.
func listenerAddrFor(listen config.ListenConfig) string {
	if listen.Socket != "" {
		return "unix:" + listen.Socket
	}
	return "tcp://" + listen.Address
}

// bindMainListeners binds every effective main listener (#149) — the legacy
// singular listen: block synthesized into one entry, or every listeners[*]
// entry — before any of them starts serving. Two-phase: prepare (this
// function) computes and binds every member; the caller starts Serve only
// after every member here (and the admin listener, bound separately) is
// live. Any bind failure closes every member already bound, in reverse
// order, and returns a wrapped error — there is never an instant where a
// strict non-empty subset of the configured main listeners is live.
func bindMainListeners(cfg *config.Config, deps *serveDeps, handler http.Handler, board *listenerStatusBoard) ([]*listenerMember, error) {
	effective := cfg.EffectiveListeners()
	explicit := len(cfg.Listeners) > 0

	members := make([]*listenerMember, 0, len(effective))
	for _, entry := range effective {
		var ln net.Listener
		var err error
		if explicit {
			ln, err = deps.createNamedListener(cfg, entry)
		} else {
			// Legacy path: preserve the createServeListener hook exactly so
			// its existing test doubles keep working unmodified.
			ln, err = deps.createServeListener(cfg)
		}
		if err != nil {
			closeMembersReverse(members)
			if explicit {
				return nil, fmt.Errorf("listener %q: %w", entry.Name, err)
			}
			// Legacy single-listener wrap kept byte-for-byte identical to
			// pre-#149 wording ("listener: %w") — pinned by
			// TestRunServeErrorPaths/listener.
			return nil, fmt.Errorf("listener: %w", err)
		}

		identity := inbound.Identity{
			Name:    entry.Name,
			Role:    inbound.RoleMain,
			Network: networkFor(entry.ListenConfig),
		}
		server := newHTTPServerForIdentity(handler, identity)
		member := &listenerMember{
			identity:   identity,
			listener:   ln,
			server:     server,
			hijacked:   trackHijackedConnections(server),
			socketPath: entry.Socket,
		}
		if explicit && entry.Socket != "" {
			member.socketIdentity = statSocketIdentity(deps.lstatPath, entry.Socket)
		}
		board.register(identity, health.ListenerStateBound)
		members = append(members, member)
	}
	return members, nil
}

// closeMembersReverse closes every bound member's listener in reverse bind
// order — the standard two-phase-bind rollback shape. Closing a
// *net.UnixListener also unlinks its socket file (Go's default
// SetUnlinkOnClose behavior), so no separate removePath call is needed here.
func closeMembersReverse(members []*listenerMember) {
	for i := len(members) - 1; i >= 0; i-- {
		_ = members[i].listener.Close()
	}
}

// publishMainListeners starts the Serve goroutine for every bound member,
// relaying each one's terminal error into fanIn tagged with the member's
// name. fanIn must be buffered to at least len(members) so a member's
// forwarder never blocks on a fanIn send that the caller isn't ready to
// receive yet (e.g. during shutdown, once the caller has already stopped
// selecting on it).
func publishMainListeners(deps *serveDeps, members []*listenerMember, fanIn chan<- listenerResult, board *listenerStatusBoard) {
	for _, member := range members {
		publishListenerMember(deps, member, fanIn, board)
	}
}

func publishListenerMember(deps *serveDeps, member *listenerMember, fanIn chan<- listenerResult, board *listenerStatusBoard) {
	memberErrCh := make(chan error, 1)
	go deps.startServing(member.server, member.listener, memberErrCh)
	board.setState(member.identity.Name, health.ListenerStateServing)
	go func() {
		err := <-memberErrCh
		fanIn <- listenerResult{name: member.identity.Name, role: member.identity.Role, err: err}
	}()
}

// setListenersUp publishes the sockguard_listener_up{listener,role,network}
// gauge (#149) for every member at once. Called with up=true immediately
// after publishMainListeners has started every member's Serve() goroutine,
// and with up=false at the start of shutdown — see Registry.SetListenerUp
// for why the series is created once and never removed.
func setListenersUp(registry *metrics.Registry, members []*listenerMember, up bool) {
	for _, member := range members {
		registry.SetListenerUp(member.identity.Name, string(member.identity.Role), string(member.identity.Network), up)
	}
}

// listenerResult is one member's terminal Serve() outcome, fanned into a
// shared channel so the caller's select statement has a single case to
// watch regardless of how many listeners are configured.
type listenerResult struct {
	name string
	role inbound.Role
	err  error
}

// shutdownMainListeners concurrently shuts down every member's http.Server
// within ctx's deadline, then removes any unix socket files this process
// owns (see removeSocketIfOwned). Log message text ("shutdown error" /
// "remove socket error") is kept identical to the pre-#149 single-listener
// wording — only the added "listener" attr is new — so existing log-based
// test assertions keep matching regardless of listener count.
func shutdownMainListeners(ctx context.Context, deps *serveDeps, members []*listenerMember, board *listenerStatusBoard, logger *slog.Logger) {
	for _, member := range members {
		board.setState(member.identity.Name, health.ListenerStateDraining)
	}

	var wg sync.WaitGroup
	for _, member := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := deps.shutdownServer(member.server, ctx); err != nil {
				logger.Error("shutdown error", "listener", member.identity.Name, "error", err)
				if ctx.Err() != nil {
					_ = member.server.Close()
					_ = member.listener.Close()
				}
			}
			member.hijacked.closeAll()
		}()
	}
	wg.Wait()

	for _, member := range members {
		board.setState(member.identity.Name, health.ListenerStateStopped)
	}

	for _, member := range members {
		if member.socketPath == "" {
			continue
		}
		if err := removeSocketIfOwned(deps, member.socketPath, member.socketIdentity); err != nil && !os.IsNotExist(err) {
			logger.Error("remove socket error", "listener", member.identity.Name, "socket", member.socketPath, "error", err)
		}
	}
}

// bannerListenerLines renders one banner.Info.Listeners entry per bound main
// listener in bind order, matching the "name unix:<path>" / "name
// tcp://<addr>" shape documented on banner.Info.Listeners.
func bannerListenerLines(members []*listenerMember, effective []config.ListenerConfig) []string {
	byName := make(map[string]config.ListenerConfig, len(effective))
	for _, e := range effective {
		byName[e.Name] = e
	}
	lines := make([]string, 0, len(members))
	for _, m := range members {
		entry := byName[m.identity.Name]
		lines = append(lines, fmt.Sprintf("%s %s", m.identity.Name, listenerAddrFor(entry.ListenConfig)))
	}
	return lines
}

// newHTTPServerForIdentity builds the http.Server for one listener member,
// composing inbound.ConnContext (stamped first, so it can never be spoofed
// by anything clientacl's own ConnContext reads later) with clientacl's
// existing per-connection identity capture. newHTTPServer keeps calling this
// with a synthesized main/default identity so every existing call site (and
// its tests, which only assert timeout/limit fields and ConnContext
// non-nil-ness) keeps compiling and passing unmodified.
func newHTTPServerForIdentity(handler http.Handler, identity inbound.Identity) *http.Server {
	srv := newHTTPServer(handler)
	srv.ConnContext = inbound.ConnContext(identity, clientacl.ConnContext)
	return srv
}
