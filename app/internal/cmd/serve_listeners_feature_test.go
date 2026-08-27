package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/health"
	"github.com/codeswhat/sockguard/app/internal/inbound"
	"github.com/codeswhat/sockguard/app/internal/metrics"
)

type listenerFeatureFileInfo struct {
	mode os.FileMode
	stat syscall.Stat_t
}

func (i *listenerFeatureFileInfo) Name() string       { return "sock" }
func (i *listenerFeatureFileInfo) Size() int64        { return 0 }
func (i *listenerFeatureFileInfo) Mode() os.FileMode  { return i.mode }
func (i *listenerFeatureFileInfo) ModTime() time.Time { return time.Time{} }
func (i *listenerFeatureFileInfo) IsDir() bool        { return false }
func (i *listenerFeatureFileInfo) Sys() any           { return &i.stat }

func socketFileInfo(ino uint64) os.FileInfo {
	info := &listenerFeatureFileInfo{mode: os.ModeSocket | 0o600}
	info.stat.Ino = ino
	return info
}

func TestListenUnixSocketStaleProbeSafetyMatrix(t *testing.T) {
	t.Parallel()

	addrInUse := fmt.Errorf("bind unix: %w", syscall.EADDRINUSE)
	tests := []struct {
		name            string
		mode            os.FileMode
		probeErr        error
		identities      []os.FileInfo
		wantSuccess     bool
		wantRemoved     bool
		wantListenCalls int
		wantError       string
	}{
		{
			name:            "dead refused socket is replaced",
			mode:            os.ModeSocket | 0o600,
			probeErr:        syscall.ECONNREFUSED,
			identities:      []os.FileInfo{socketFileInfo(10), socketFileInfo(10)},
			wantSuccess:     true,
			wantRemoved:     true,
			wantListenCalls: 2,
		},
		{
			name:            "live socket is preserved",
			mode:            os.ModeSocket | 0o600,
			probeErr:        nil,
			identities:      []os.FileInfo{socketFileInfo(20)},
			wantListenCalls: 1,
			wantError:       "actively serving another process",
		},
		{
			name:            "ambiguous timeout is preserved",
			mode:            os.ModeSocket | 0o600,
			probeErr:        context.DeadlineExceeded,
			identities:      []os.FileInfo{socketFileInfo(30), socketFileInfo(30)},
			wantListenCalls: 1,
			wantError:       "probe result is ambiguous",
		},
		{
			name:            "regular file is preserved",
			mode:            0o600,
			probeErr:        syscall.ECONNREFUSED,
			identities:      []os.FileInfo{&listenerFeatureFileInfo{mode: 0o600}},
			wantListenCalls: 1,
			wantError:       "is not a socket",
		},
		{
			name:            "inode replacement during probe is preserved",
			mode:            os.ModeSocket | 0o600,
			probeErr:        syscall.ECONNREFUSED,
			identities:      []os.FileInfo{socketFileInfo(40), socketFileInfo(41)},
			wantListenCalls: 1,
			wantError:       "changed during stale-socket probe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := newServeTestDeps()
			deps.umask = func(int) int { return 0 }
			deps.isAddrInUse = func(error) bool { return true }
			listenCalls := 0
			deps.listenNetwork = func(network, address string) (net.Listener, error) {
				listenCalls++
				if listenCalls == 1 {
					return nil, addrInUse
				}
				return &serveTestListener{}, nil
			}
			lstatCalls := 0
			deps.lstatPath = func(string) (os.FileInfo, error) {
				idx := lstatCalls
				lstatCalls++
				if idx >= len(tc.identities) {
					idx = len(tc.identities) - 1
				}
				return tc.identities[idx], nil
			}
			deps.probeUnixSocket = func(string) error { return tc.probeErr }
			removed := false
			deps.removePath = func(string) error {
				removed = true
				return nil
			}

			ln, err := deps.listenUnixSocketWithMode("/run/test.sock", tc.mode)
			if tc.wantSuccess {
				if err != nil || ln == nil {
					t.Fatalf("listenUnixSocketWithMode() = (%v, %v), want listener,nil", ln, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("listenUnixSocketWithMode() error = %v, want %q", err, tc.wantError)
			}
			if removed != tc.wantRemoved {
				t.Fatalf("removed = %v, want %v", removed, tc.wantRemoved)
			}
			if listenCalls != tc.wantListenCalls {
				t.Fatalf("listen calls = %d, want %d", listenCalls, tc.wantListenCalls)
			}
		})
	}
}

func TestUnixListenerClosePreservesReplacementPath(t *testing.T) {
	path := shortSocketPath(t, "replacement")
	ln, err := newServeTestDeps().listenUnixSocket(path)
	if err != nil {
		t.Fatalf("listenUnixSocket() error = %v", err)
	}

	originalPath := path + ".original"
	if err := os.Rename(path, originalPath); err != nil {
		_ = ln.Close()
		t.Fatalf("rename bound socket: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		_ = ln.Close()
		t.Fatalf("write replacement path: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement path was removed by listener close: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("replacement contents = %q, want replacement", got)
	}
}

func TestBindListenersCaptureUnixSocketIdentityForEveryRole(t *testing.T) {
	deps := newServeTestDeps()
	deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(77), nil }
	deps.createServeListener = func(*config.Config) (net.Listener, error) { return &serveTestListener{}, nil }
	deps.createNamedListener = func(*config.Config, config.ListenerConfig) (net.Listener, error) { return &serveTestListener{}, nil }
	deps.createAdminListener = func(*config.Config) (net.Listener, error) { return &serveTestListener{}, nil }

	legacyCfg := testServeConfig()
	legacyCfg.Listen.Socket = "/run/legacy.sock"
	legacyCfg.Listen.Address = ""
	legacy, err := bindMainListeners(legacyCfg, deps, http.NotFoundHandler(), newListenerStatusBoard())
	if err != nil {
		t.Fatalf("bind legacy listener: %v", err)
	}
	if len(legacy) != 1 || !legacy[0].socketIdentity.valid {
		t.Fatalf("legacy socket identity = %+v, want captured", legacy)
	}

	explicitCfg := testServeConfig()
	explicitCfg.Listeners = []config.ListenerConfig{{
		Name: "ci", ListenConfig: config.ListenConfig{Socket: "/run/ci.sock"}, AllowedProfiles: []string{"*"},
	}}
	explicit, err := bindMainListeners(explicitCfg, deps, http.NotFoundHandler(), newListenerStatusBoard())
	if err != nil {
		t.Fatalf("bind explicit listener: %v", err)
	}
	if len(explicit) != 1 || !explicit[0].socketIdentity.valid {
		t.Fatalf("explicit socket identity = %+v, want captured", explicit)
	}

	adminCfg := testServeConfig()
	adminCfg.Admin.Enabled = true
	adminCfg.Admin.Listen.Socket = "/run/admin.sock"
	admin, err := bindAdminServer(adminCfg, newDiscardLogger(), nil, nil, deps, newListenerStatusBoard())
	if err != nil {
		t.Fatalf("bind admin listener: %v", err)
	}
	if admin == nil || !admin.socketIdentity.valid {
		t.Fatalf("admin socket identity = %+v, want captured", admin)
	}
}

func TestBindMainListenersRollbackRemovesOwnedUnixSocket(t *testing.T) {
	cfg := testServeConfig()
	cfg.Listeners = []config.ListenerConfig{
		{Name: "ci", ListenConfig: config.ListenConfig{Socket: "/run/ci.sock"}, AllowedProfiles: []string{"*"}},
		{Name: "ops", ListenConfig: config.ListenConfig{Socket: "/run/ops.sock"}, AllowedProfiles: []string{"*"}},
	}
	deps := newServeTestDeps()
	binds := 0
	deps.createNamedListener = func(*config.Config, config.ListenerConfig) (net.Listener, error) {
		binds++
		if binds == 1 {
			return &serveTestListener{}, nil
		}
		return nil, errors.New("bind failed")
	}
	deps.lstatPath = func(string) (os.FileInfo, error) { return socketFileInfo(88), nil }
	var removed []string
	deps.removePath = func(path string) error {
		removed = append(removed, path)
		return nil
	}

	_, err := bindMainListeners(cfg, deps, http.NotFoundHandler(), newListenerStatusBoard())
	if err == nil {
		t.Fatal("bindMainListeners() error = nil, want second bind failure")
	}
	if fmt.Sprint(removed) != fmt.Sprint([]string{"/run/ci.sock"}) {
		t.Fatalf("rollback removals = %v, want owned /run/ci.sock", removed)
	}
}

type closeOrderListener struct {
	name  string
	mu    *sync.Mutex
	order *[]string
}

func (l *closeOrderListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *closeOrderListener) Addr() net.Addr            { return &net.UnixAddr{Name: l.name, Net: "unix"} }
func (l *closeOrderListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	*l.order = append(*l.order, l.name)
	return nil
}

func bindBarrierTestDeps(cfg *config.Config) *serveDeps {
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) { return cfg, nil }
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return newDiscardLogger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return stubCompiledRules(), nil }
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) { return &serveTestConn{}, nil }
	deps.notifySignals = func(chan<- os.Signal, ...os.Signal) {}
	return deps
}

func bindBarrierConfig() *config.Config {
	cfg := testServeConfig()
	cfg.Listeners = []config.ListenerConfig{
		{Name: "ci", ListenConfig: config.ListenConfig{Socket: "/run/ci.sock", SocketMode: "0600"}, AllowedProfiles: []string{"*"}},
		{Name: "ops", ListenConfig: config.ListenConfig{Socket: "/run/ops.sock", SocketMode: "0600"}, AllowedProfiles: []string{"*"}},
	}
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Socket = "/run/admin.sock"
	return cfg
}

func TestBindBarrierAdminFailureRollsBackMainsInReverseWithoutServing(t *testing.T) {
	t.Parallel()

	cfg := bindBarrierConfig()
	deps := bindBarrierTestDeps(cfg)
	var mu sync.Mutex
	var closed []string
	deps.createNamedListener = func(_ *config.Config, entry config.ListenerConfig) (net.Listener, error) {
		return &closeOrderListener{name: entry.Name, mu: &mu, order: &closed}, nil
	}
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		return nil, errors.New("admin path collision")
	}
	serveCalls := 0
	deps.startServing = func(*http.Server, net.Listener, chan<- error) { serveCalls++ }

	err := runServeWithDeps(newServeCommand(), nil, deps)
	if err == nil || !strings.Contains(err.Error(), "admin listener: admin path collision") {
		t.Fatalf("runServeWithDeps() error = %v, want admin bind failure", err)
	}
	if serveCalls != 0 {
		t.Fatalf("Serve calls = %d, want zero before full bind barrier", serveCalls)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"ops", "ci"}
	if fmt.Sprint(closed) != fmt.Sprint(want) {
		t.Fatalf("rollback order = %v, want %v", closed, want)
	}
}

func TestBindBarrierMainFailureNeverBindsOrServesAdmin(t *testing.T) {
	t.Parallel()

	cfg := bindBarrierConfig()
	deps := bindBarrierTestDeps(cfg)
	first := &serveTestListener{}
	mainCalls := 0
	deps.createNamedListener = func(_ *config.Config, _ config.ListenerConfig) (net.Listener, error) {
		mainCalls++
		if mainCalls == 1 {
			return first, nil
		}
		return nil, errors.New("second main collision")
	}
	adminBinds := 0
	deps.createAdminListener = func(*config.Config) (net.Listener, error) {
		adminBinds++
		return &serveTestListener{}, nil
	}
	serveCalls := 0
	deps.startServing = func(*http.Server, net.Listener, chan<- error) { serveCalls++ }

	err := runServeWithDeps(newServeCommand(), nil, deps)
	if err == nil || !strings.Contains(err.Error(), `listener "ops"`) {
		t.Fatalf("runServeWithDeps() error = %v, want named main bind failure", err)
	}
	if adminBinds != 0 || serveCalls != 0 {
		t.Fatalf("admin binds=%d Serve calls=%d, want both zero", adminBinds, serveCalls)
	}
	if first.closeCalls != 1 {
		t.Fatalf("first main Close calls = %d, want 1", first.closeCalls)
	}
}

func TestBindAdminServerStampsDedicatedAdminIdentity(t *testing.T) {
	t.Parallel()

	cfg := bindBarrierConfig()
	deps := newServeTestDeps()
	deps.createAdminListener = func(*config.Config) (net.Listener, error) { return &serveTestListener{}, nil }
	member, err := bindAdminServer(cfg, newDiscardLogger(), nil, nil, deps, newListenerStatusBoard())
	if err != nil {
		t.Fatalf("bindAdminServer: %v", err)
	}
	if member == nil || member.server.ConnContext == nil {
		t.Fatal("dedicated admin member has no ConnContext")
	}
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	ctx := member.server.ConnContext(context.Background(), serverConn)
	identity, ok := inbound.FromContext(ctx)
	want := inbound.Identity{Name: config.AdminListenerName, Role: inbound.RoleAdmin, Network: inbound.NetworkUnix}
	if !ok || identity != want {
		t.Fatalf("admin ConnContext identity = (%#v,%v), want (%#v,true)", identity, ok, want)
	}
}

func TestAnyPrematureListenerServeReturnFailsAndDrainsWholeGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		serveErr error
	}{
		{name: "nil", serveErr: nil},
		{name: "http server closed", serveErr: http.ErrServerClosed},
		{name: "other error", serveErr: errors.New("serve failed")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := bindBarrierConfig()
			cfg.Admin.Enabled = false
			deps := bindBarrierTestDeps(cfg)
			deps.createNamedListener = func(*config.Config, config.ListenerConfig) (net.Listener, error) {
				return &serveTestListener{}, nil
			}
			deps.startServing = func(_ *http.Server, _ net.Listener, result chan<- error) {
				result <- tc.serveErr
			}
			var mu sync.Mutex
			shutdowns := 0
			deps.shutdownServer = func(*http.Server, context.Context) error {
				mu.Lock()
				shutdowns++
				mu.Unlock()
				return nil
			}
			deps.removePath = func(string) error { return nil }

			err := runServeWithDeps(newServeCommand(), nil, deps)
			if err == nil || !strings.Contains(err.Error(), "server error") {
				t.Fatalf("runServeWithDeps() error = %v, want premature Serve failure", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if shutdowns != 2 {
				t.Fatalf("Shutdown calls = %d, want all 2 listeners", shutdowns)
			}
		})
	}
}

func TestListenerStatusBoardStateMachineAndFailedTransitions(t *testing.T) {
	t.Parallel()

	states := []string{
		health.ListenerStateBound,
		health.ListenerStateServing,
		health.ListenerStateDraining,
		health.ListenerStateStopped,
	}
	for _, from := range states {
		t.Run("failed_from_"+from, func(t *testing.T) {
			board := newListenerStatusBoard()
			identity := inbound.Identity{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix}
			board.register(identity, from)
			board.setState(identity.Name, health.ListenerStateFailed)
			got := board.snapshot()
			if len(got) != 1 || got[0].State != health.ListenerStateFailed || got[0].Role != "main" || got[0].Network != "unix" {
				t.Fatalf("snapshot = %#v, want failed identity preserved", got)
			}
		})
	}

	board := newListenerStatusBoard()
	board.register(inbound.Identity{Name: "ops", Role: inbound.RoleMain, Network: inbound.NetworkTCP}, health.ListenerStateBound)
	board.register(inbound.Identity{Name: "admin", Role: inbound.RoleAdmin, Network: inbound.NetworkUnix}, health.ListenerStateBound)
	for _, state := range []string{health.ListenerStateServing, health.ListenerStateDraining, health.ListenerStateStopped} {
		board.setState("ops", state)
	}
	got := board.snapshot()
	if len(got) != 2 || got[0].Name != "admin" || got[1].Name != "ops" || got[1].State != health.ListenerStateStopped {
		t.Fatalf("snapshot = %#v, want sorted full clean transition", got)
	}
}

func TestListenerStatusBoardConcurrentAccess(t *testing.T) {
	t.Parallel()

	board := newListenerStatusBoard()
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("listener-%02d", i)
		board.register(inbound.Identity{Name: name, Role: inbound.RoleMain, Network: inbound.NetworkTCP}, health.ListenerStateBound)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("listener-%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				board.setState(name, health.ListenerStateServing)
				_ = board.snapshot()
				board.setState(name, health.ListenerStateDraining)
			}
		}()
	}
	wg.Wait()
	if got := len(board.snapshot()); got != 16 {
		t.Fatalf("snapshot size = %d, want 16", got)
	}
}

func TestListenerGroupPreRegistersEveryConfiguredGaugeAtZero(t *testing.T) {
	t.Parallel()

	registry := metrics.NewRegistry()
	members := []*listenerMember{
		{identity: inbound.Identity{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix}},
		{identity: inbound.Identity{Name: "ops", Role: inbound.RoleMain, Network: inbound.NetworkTCP}},
		{identity: inbound.Identity{Name: config.AdminListenerName, Role: inbound.RoleAdmin, Network: inbound.NetworkUnix}},
	}
	setListenersUp(registry, members, false)
	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{
		`sockguard_listener_up{listener="admin",network="unix",role="admin"} 0`,
		`sockguard_listener_up{listener="ci",network="unix",role="main"} 0`,
		`sockguard_listener_up{listener="ops",network="tcp",role="main"} 0`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("pre-publish metrics missing %q:\n%s", want, rec.Body.String())
		}
	}
}

func TestShutdownServersUsesFreshContextAndStopsAllMembersConcurrently(t *testing.T) {
	t.Parallel()

	cfg := bindBarrierConfig()
	registry := metrics.NewRegistry()
	board := newListenerStatusBoard()
	members := []*listenerMember{
		{identity: inbound.Identity{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix}, listener: &serveTestListener{}, server: newHTTPServer(http.NotFoundHandler())},
		{identity: inbound.Identity{Name: "ops", Role: inbound.RoleMain, Network: inbound.NetworkTCP}, listener: &serveTestListener{}, server: newHTTPServer(http.NotFoundHandler())},
	}
	for _, member := range members {
		board.register(member.identity, health.ListenerStateServing)
		registry.SetListenerUp(member.identity.Name, string(member.identity.Role), string(member.identity.Network), true)
	}
	adminIdentity := inbound.Identity{Name: "admin", Role: inbound.RoleAdmin, Network: inbound.NetworkUnix}
	board.register(adminIdentity, health.ListenerStateServing)
	registry.SetListenerUp("admin", "admin", "unix", true)

	deps := newServeTestDeps()
	deps.shutdownGracePeriod = 30 * time.Second
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	ctxErrors := make(chan error, 3)
	deadlines := make(chan time.Duration, 3)
	deps.shutdownServer = func(_ *http.Server, ctx context.Context) error {
		ctxErrors <- ctx.Err()
		deadline, ok := ctx.Deadline()
		if !ok {
			deadlines <- 0
		} else {
			deadlines <- time.Until(deadline)
		}
		entered <- struct{}{}
		<-release
		return nil
	}
	deps.removePath = func(string) error { return nil }

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	adminMember := &listenerMember{
		identity: adminIdentity,
		listener: &serveTestListener{},
		server:   newAdminHTTPServer(http.NotFoundHandler()),
	}
	go func() {
		shutdownServers(parent, deps, cfg, members, adminMember, registry, board, newDiscardLogger())
		close(done)
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/3 Shutdown calls entered; shutdown is not concurrent", i)
		}
	}
	close(release)
	<-done
	close(ctxErrors)
	for err := range ctxErrors {
		if err != nil {
			t.Errorf("shutdown context was already canceled at entry: %v", err)
		}
	}
	close(deadlines)
	for remaining := range deadlines {
		if remaining < 29*time.Second || remaining > 30*time.Second {
			t.Errorf("shutdown deadline remaining = %v, want fresh 30s context", remaining)
		}
	}

	for _, status := range board.snapshot() {
		if status.State != health.ListenerStateStopped {
			t.Errorf("listener %s state = %q, want stopped", status.Name, status.State)
		}
	}
	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{
		`sockguard_listener_up{listener="admin",network="unix",role="admin"} 0`,
		`sockguard_listener_up{listener="ci",network="unix",role="main"} 0`,
		`sockguard_listener_up{listener="ops",network="tcp",role="main"} 0`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, rec.Body.String())
		}
	}
}

func TestShutdownServersForcesListenerClosedAtDeadline(t *testing.T) {
	t.Parallel()

	cfg := testServeConfig()
	listener := &serveTestListener{}
	identity := inbound.Identity{Name: "default", Role: inbound.RoleMain, Network: inbound.NetworkTCP}
	member := &listenerMember{identity: identity, listener: listener, server: newHTTPServer(http.NotFoundHandler())}
	board := newListenerStatusBoard()
	board.register(identity, health.ListenerStateServing)
	deps := newServeTestDeps()
	deps.shutdownGracePeriod = time.Millisecond
	deps.shutdownServer = func(_ *http.Server, ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	shutdownServers(context.Background(), deps, cfg, []*listenerMember{member}, nil, metrics.NewRegistry(), board, newDiscardLogger())
	if listener.closeCalls == 0 {
		t.Fatal("listener was not force-closed after graceful shutdown deadline")
	}
}

func TestShutdownServersClosesHijackedConnectionsWithinDeadline(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	identity := inbound.Identity{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix}
	server := newHTTPServerForIdentity(http.NotFoundHandler(), identity)
	tracker := trackHijackedConnections(server)
	server.ConnState(serverConn, http.StateHijacked)
	member := &listenerMember{
		identity: identity,
		listener: &serveTestListener{},
		server:   server,
		hijacked: tracker,
	}
	board := newListenerStatusBoard()
	board.register(identity, health.ListenerStateServing)
	deps := newServeTestDeps()
	deps.shutdownGracePeriod = 30 * time.Second
	deps.shutdownServer = func(*http.Server, context.Context) error { return nil }

	shutdownServers(context.Background(), deps, testServeConfig(), []*listenerMember{member}, nil, metrics.NewRegistry(), board, newDiscardLogger())

	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("hijacked peer remained open after listener shutdown")
	}
}
