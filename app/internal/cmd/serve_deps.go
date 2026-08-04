package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/policybundle"
)

type serveDeps struct {
	loadConfig          func(string) (*config.Config, error)
	loadConfigBytes     func([]byte) (*config.Config, error)
	readConfigBytes     func(string) ([]byte, error)
	newLogger           func(string, string, string) (*slog.Logger, io.Closer, error)
	newAuditLogger      func(string, string) (*logging.AuditLogger, io.Closer, error)
	validateRules       func(*config.Config) ([]*filter.CompiledRule, error)
	dialUpstream        func(string, string, time.Duration) (net.Conn, error)
	listenNetwork       func(string, string) (net.Listener, error)
	lstatPath           func(string) (os.FileInfo, error)
	isAddrInUse         func(error) bool
	createServeListener func(*config.Config) (net.Listener, error)
	createAdminListener func(*config.Config) (net.Listener, error)
	// createNamedListener binds one explicit listeners[*] entry (#149). Only
	// used when len(cfg.Listeners) > 0 — the legacy single-listener path
	// keeps going through createServeListener above so its existing test
	// doubles keep working unchanged.
	createNamedListener func(*config.Config, config.ListenerConfig) (net.Listener, error)
	// probeUnixSocketLive reports whether something is actively accepting
	// connections on a unix socket path found at bind time (EADDRINUSE).
	// A successful dial is the only signal that blocks stale-socket
	// removal (#149) — see listenUnixSocketWithMode.
	probeUnixSocketLive func(string) bool
	chown               func(string, int, int) error
	buildBundleVerifier func(config.PolicyBundleConfig) (policybundle.Verifier, error)
	loadBundleEntity    func(string) (verify.SignedEntity, error)
	notifySignals       func(chan<- os.Signal, ...os.Signal)
	startServing        func(*http.Server, net.Listener, chan<- error)
	shutdownServer      func(*http.Server, context.Context) error
	removePath          func(string) error
	now                 func() time.Time
	shutdownGracePeriod time.Duration
	umask               func(int) int
	umaskMu             *sync.Mutex
}

var processUmaskMu sync.Mutex

func newServeDeps() *serveDeps {
	deps := &serveDeps{
		loadConfig:          config.Load,
		loadConfigBytes:     config.LoadBytes,
		readConfigBytes:     os.ReadFile,
		newLogger:           logging.New,
		newAuditLogger:      logging.NewAudit,
		validateRules:       validateAndCompileRules,
		dialUpstream:        net.DialTimeout,
		listenNetwork:       net.Listen,
		lstatPath:           os.Lstat,
		isAddrInUse:         isAddrInUse,
		probeUnixSocketLive: defaultProbeUnixSocketLive,
		chown:               os.Chown,
		buildBundleVerifier: defaultBuildBundleVerifier,
		loadBundleEntity:    policybundle.LoadBundle,
		notifySignals:       signal.Notify,
		startServing:        defaultServeStart,
		shutdownServer:      defaultServeShutdown,
		removePath:          os.Remove,
		now:                 time.Now,
		shutdownGracePeriod: 30 * time.Second,
		umask:               syscall.Umask,
		umaskMu:             &processUmaskMu,
	}
	deps.createServeListener = deps.createListener
	deps.createAdminListener = deps.createAdminListenerImpl
	deps.createNamedListener = deps.createNamedListenerImpl
	return deps
}

// defaultBuildBundleVerifier compiles a policy_bundle config into a
// runtime Verifier. The result is bound at startup and reused across every
// reload because policy_bundle's trust material is reload-immutable.
//
// When pb.Enabled=false the returned Verifier rejects calls — wiring code
// must guard on Enabled before invoking Verify.
func defaultBuildBundleVerifier(pb config.PolicyBundleConfig) (policybundle.Verifier, error) {
	raw := policybundle.RawConfig{
		Enabled:               pb.Enabled,
		RequireRekorInclusion: pb.RequireRekorInclusion,
		VerifyTimeoutStr:      pb.VerifyTimeout,
	}
	for _, k := range pb.AllowedSigningKeys {
		raw.AllowedSigningKeys = append(raw.AllowedSigningKeys, policybundle.SigningKeyConfig{PEM: k.PEM})
	}
	for _, kl := range pb.AllowedKeyless {
		raw.AllowedKeyless = append(raw.AllowedKeyless, policybundle.KeylessConfig{
			Issuer:         kl.Issuer,
			SubjectPattern: kl.SubjectPattern,
		})
	}
	cfg, err := policybundle.BuildConfig(raw)
	if err != nil {
		return nil, err
	}
	// Keyless verification against the public sigstore TUF roots is not yet
	// wired; if the operator configured keyless identities we surface a
	// clear error rather than silently falling back to "no trust material".
	// Production TUF wiring is a follow-up; for now keyed is fully
	// supported and keyless paths live behind tests using VirtualSigstore.
	if len(cfg.AllowedKeyless) > 0 && cfg.TrustedMaterial == nil {
		return nil, errors.New("policy_bundle.allowed_keyless is configured but the production TUF trust root is not yet wired; configure allowed_signing_keys for now")
	}
	return policybundle.New(cfg)
}

func defaultServeStart(server *http.Server, ln net.Listener, errCh chan<- error) {
	errCh <- server.Serve(ln)
}

func defaultServeShutdown(server *http.Server, ctx context.Context) error {
	return server.Shutdown(ctx)
}

func (d *serveDeps) verifyUpstreamReachable(upstreamSocket string, logger *slog.Logger) error {
	conn, err := d.dialUpstream("unix", upstreamSocket, 5*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("upstream socket not found (%s): %w", upstreamSocket, err)
		case errors.Is(err, os.ErrPermission):
			return fmt.Errorf("permission denied on upstream socket (%s): %w", upstreamSocket, err)
		default:
			return fmt.Errorf("upstream socket unreachable (%s): %w", upstreamSocket, err)
		}
	}
	if closeErr := conn.Close(); closeErr != nil {
		logger.Debug("failed to close upstream check connection", "error", closeErr)
	}
	return nil
}

func (d *serveDeps) createListener(cfg *config.Config) (net.Listener, error) {
	if cfg.Listen.Socket != "" {
		return d.createSocketListener("listen", cfg.Listen.Socket, cfg.Listen.SocketMode, cfg.Listen.SocketUID, cfg.Listen.SocketGID)
	}

	return d.createTCPListener(cfg.Listen.Address, cfg.Listen.TLS)
}

// createAdminListenerImpl builds the dedicated admin listener described by
// cfg.Admin.Listen. It reuses createSocketListener / createTCPListener so the
// hardened socket-mode and mTLS posture stays in lockstep with the main
// listener — the only difference is which config sub-block feeds the inputs.
// Callers must guard with cfg.Admin.Listen.Configured(); calling this with
// an unconfigured Listen returns an error rather than silently binding 0.0.0.0.
func (d *serveDeps) createAdminListenerImpl(cfg *config.Config) (net.Listener, error) {
	listen := cfg.Admin.Listen
	if !listen.Configured() {
		return nil, fmt.Errorf("admin listener not configured")
	}
	if listen.Socket != "" {
		return d.createSocketListener("admin.listen", listen.Socket, listen.SocketMode, listen.SocketUID, listen.SocketGID)
	}
	return d.createTCPListener(listen.Address, listen.TLS)
}

// createNamedListenerImpl binds one explicit listeners[*] entry (#149). It is
// only reached when cfg.Listeners is non-empty — see EffectiveListeners and
// the createNamedListener field doc.
func (d *serveDeps) createNamedListenerImpl(cfg *config.Config, entry config.ListenerConfig) (net.Listener, error) {
	if entry.Socket != "" {
		return d.createSocketListener(fmt.Sprintf("listeners[%s]", entry.Name), entry.Socket, entry.SocketMode, entry.SocketUID, entry.SocketGID)
	}
	return d.createTCPListener(entry.Address, entry.TLS)
}

// createSocketListener binds a unix-socket listener under the hardened
// (0600, the default) or group-readable (0660, requires socket_gid) mode —
// see config.validateSocketOwnership, which is the authoritative validator;
// this is a defense-in-depth check that should never fire against a config
// that already passed config.Validate(). uid/gid, when non-nil, chown the
// freshly bound socket after listen succeeds.
func (d *serveDeps) createSocketListener(prefix, path, modeValue string, uid, gid *int) (net.Listener, error) {
	fileMode, err := socketListenFileMode(prefix, modeValue, gid)
	if err != nil {
		return nil, err
	}

	var ln net.Listener
	if fileMode == config.HardenedListenSocketFileMode {
		// Delegates to the unmodified default-mode path so its existing test
		// doubles (which call listenUnixSocket directly) keep working.
		ln, err = d.listenUnixSocket(path)
	} else {
		ln, err = d.listenUnixSocketWithMode(path, fileMode)
	}
	if err != nil {
		return nil, err
	}

	if uid == nil && gid == nil {
		return ln, nil
	}
	if err := d.chownSocket(path, uid, gid); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// socketListenFileMode maps a validated socket_mode string to its
// os.FileMode, requiring an explicit gid for the group-readable mode —
// mirrors config.validateSocketOwnership so the runtime check and the
// config-time validator can never disagree about which combinations are
// legal.
func socketListenFileMode(prefix, modeValue string, gid *int) (os.FileMode, error) {
	switch strings.TrimSpace(modeValue) {
	case config.HardenedListenSocketMode:
		return config.HardenedListenSocketFileMode, nil
	case config.GroupReadableListenSocketMode:
		if gid == nil {
			return 0, fmt.Errorf("%s.socket_mode %q requires %s.socket_gid to be set explicitly; omit socket_gid and use %q for the default owner-only mode",
				prefix, config.GroupReadableListenSocketMode, prefix, config.HardenedListenSocketMode)
		}
		return config.GroupReadableListenSocketFileMode, nil
	default:
		return 0, fmt.Errorf("%s.socket_mode must be %q or %q (the latter requires %s.socket_gid), got %q",
			prefix, config.HardenedListenSocketMode, config.GroupReadableListenSocketMode, prefix, modeValue)
	}
}

func (d *serveDeps) chownSocket(path string, uid, gid *int) error {
	resolvedUID, resolvedGID := -1, -1
	if uid != nil {
		resolvedUID = *uid
	}
	if gid != nil {
		resolvedGID = *gid
	}
	if err := d.chown(path, resolvedUID, resolvedGID); err != nil {
		return fmt.Errorf("chown socket %q: %w", path, err)
	}
	return nil
}

func (d *serveDeps) createTCPListener(address string, tlsCfg config.ListenTLSConfig) (net.Listener, error) {
	ln, err := d.listenNetwork("tcp", address)
	if err != nil {
		return nil, err
	}
	if !tlsCfg.Complete() {
		return ln, nil
	}

	return d.wrapListenerWithTLS(ln, tlsCfg)
}

func (d *serveDeps) wrapListenerWithTLS(ln net.Listener, tlsCfg config.ListenTLSConfig) (net.Listener, error) {
	tlsConfig, err := config.BuildMutualTLSServerConfig(tlsCfg)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}

	return tls.NewListener(ln, tlsConfig), nil
}

func (d *serveDeps) listenUnixSocket(path string) (net.Listener, error) {
	return d.listenUnixSocketWithMode(path, config.HardenedListenSocketFileMode)
}

// listenUnixSocketWithMode binds a unix socket at the given file mode,
// replacing a stale socket left behind by a crashed previous instance.
//
// "Stale" is no longer inferred from EADDRINUSE alone (#149): before
// unlinking anything, probeUnixSocketLive dials the path. A successful dial
// proves another process is actively serving on it, so removal is refused —
// stealing a live peer's socket is exactly the failure mode this guards
// against. Any dial failure (refused, no such file, timeout) is treated as
// "not live" and removal proceeds; this is a deliberate, documented
// simplification of "probe must observe connection-refused, else ambiguous
// fails startup" — ENOENT/timeout are ordinary benign races (e.g. the file
// vanished between Lstat and dial) that would otherwise fail startup for no
// safety benefit, since the property that actually matters — never steal a
// live listener — is fully covered by the connect-succeeded case.
func (d *serveDeps) listenUnixSocketWithMode(path string, fileMode os.FileMode) (net.Listener, error) {
	return d.withUmask(socketCreateUmask(fileMode), func() (net.Listener, error) {
		ln, err := d.listenNetwork("unix", path)
		if err == nil {
			return ln, nil
		}
		if !d.isAddrInUse(err) {
			return nil, err
		}

		info, statErr := d.lstatPath(path)
		if statErr != nil {
			return nil, fmt.Errorf("socket path already in use and could not inspect %q: %w", path, statErr)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path %q exists and is not a socket", path)
		}
		if d.probeUnixSocketLive(path) {
			return nil, fmt.Errorf("socket path %q is actively serving another process; refusing to steal a live listener", path)
		}
		if removeErr := d.removePath(path); removeErr != nil {
			if !os.IsNotExist(removeErr) {
				return nil, fmt.Errorf("remove stale socket: %w", removeErr)
			}
		}

		ln, err = d.listenNetwork("unix", path)
		if err != nil {
			return nil, err
		}
		return ln, nil
	})
}

// defaultProbeUnixSocketLive dials path with a short timeout to determine
// whether an existing socket file is actively being served. It is a plain
// local unix-domain connect — no network I/O — so it resolves immediately
// whether the answer is "accepted" or "refused/missing".
func defaultProbeUnixSocketLive(path string) bool {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (d *serveDeps) withUmask(mask int, fn func() (net.Listener, error)) (net.Listener, error) {
	d.umaskMu.Lock()
	defer d.umaskMu.Unlock()

	previous := d.umask(mask)
	ln, err := fn()
	d.umask(previous)

	return ln, err
}
