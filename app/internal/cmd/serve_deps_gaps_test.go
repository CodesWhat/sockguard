package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/codeswhat/sockguard/app/internal/boundedio"
	"github.com/codeswhat/sockguard/app/internal/config"
)

func testPolicyPublicKeyPEM(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate policy signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("marshal policy public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestBuildBundleVerifierTrustModes(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const issuer = "https://issuer.example"
	const subject = "ci@example.com"
	payload := []byte("rules: []\n")
	entity, err := virtualSigstore.Sign(subject, issuer, payload)
	if err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	loadErr := errors.New("TUF unavailable")
	wantSigner := "keyless:" + issuer + ":" + subject
	keyedTrust := []config.PolicyBundleSigningKey{{PEM: testPolicyPublicKeyPEM(t)}}
	keylessTrust := []config.PolicyBundleKeyless{{Issuer: issuer, SubjectPattern: `^ci@example\.com$`}}
	tests := []struct {
		name          string
		cfg           config.PolicyBundleConfig
		material      root.TrustedMaterial
		loadErr       error
		wantLoadCalls int
		wantErr       error
		wantErrText   string
		verifyKeyless bool
		wantSigner    string
	}{
		{
			name:          "keyless trust loads and verifies",
			cfg:           config.PolicyBundleConfig{Enabled: true, AllowedKeyless: keylessTrust, RequireRekorInclusion: true},
			material:      virtualSigstore,
			wantLoadCalls: 1,
			verifyKeyless: true,
			wantSigner:    wantSigner,
		},
		{
			name:          "trust load failure aborts startup",
			cfg:           config.PolicyBundleConfig{Enabled: true, AllowedKeyless: keylessTrust},
			loadErr:       loadErr,
			wantLoadCalls: 1,
			wantErr:       loadErr,
			wantErrText:   "load keyless trust root",
		},
		{
			name:          "keyed-only startup stays offline",
			cfg:           config.PolicyBundleConfig{Enabled: true, AllowedSigningKeys: keyedTrust},
			wantLoadCalls: 0,
		},
		{
			name: "mixed trust loads and falls back to keyless",
			cfg: config.PolicyBundleConfig{
				Enabled:            true,
				AllowedSigningKeys: keyedTrust,
				AllowedKeyless:     keylessTrust,
			},
			material:      virtualSigstore,
			wantLoadCalls: 1,
			verifyKeyless: true,
			wantSigner:    wantSigner,
		},
		{
			name: "disabled config does not load trust",
			cfg: config.PolicyBundleConfig{
				Enabled:        false,
				AllowedKeyless: []config.PolicyBundleKeyless{{Issuer: "stale", SubjectPattern: "[stale"}},
			},
			wantLoadCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadCalls := 0
			verifier, err := buildBundleVerifier(tt.cfg, func() (root.TrustedMaterial, error) {
				loadCalls++
				return tt.material, tt.loadErr
			})
			if tt.wantErr != nil {
				if err == nil || !errors.Is(err, tt.wantErr) {
					t.Fatalf("buildBundleVerifier() = verifier %v, error %v; want %v", verifier, err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("error = %q, want %q", err.Error(), tt.wantErrText)
				}
			} else {
				if err != nil {
					t.Fatalf("buildBundleVerifier: %v", err)
				}
				if verifier == nil {
					t.Fatal("buildBundleVerifier returned nil verifier")
				}
			}
			if loadCalls != tt.wantLoadCalls {
				t.Fatalf("trusted material load calls = %d, want %d", loadCalls, tt.wantLoadCalls)
			}
			if !tt.verifyKeyless {
				return
			}
			result, err := verifier.Verify(context.Background(), payload, entity)
			if err != nil {
				t.Fatalf("Verify keyless entity: %v", err)
			}
			if result.Signer != tt.wantSigner {
				t.Fatalf("Signer = %q, want %q", result.Signer, tt.wantSigner)
			}
		})
	}
}

func TestDefaultBuildBundleVerifierUsesProductionTrustLoader(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	originalLoader := loadBundleTrustedMaterial
	t.Cleanup(func() { loadBundleTrustedMaterial = originalLoader })
	loadCalls := 0
	loadBundleTrustedMaterial = func() (root.TrustedMaterial, error) {
		loadCalls++
		return virtualSigstore, nil
	}

	verifier, err := defaultBuildBundleVerifier(config.PolicyBundleConfig{
		Enabled: true,
		AllowedKeyless: []config.PolicyBundleKeyless{
			{Issuer: "https://issuer.example", SubjectPattern: `^ci@example\.com$`},
		},
	})
	if err != nil {
		t.Fatalf("defaultBuildBundleVerifier: %v", err)
	}
	if verifier == nil {
		t.Fatal("defaultBuildBundleVerifier returned nil verifier")
	}
	if loadCalls != 1 {
		t.Fatalf("production trusted material load calls = %d, want 1", loadCalls)
	}
}

func TestNewServeDepsUsesBoundedConfigReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.Truncate(config.MaxConfigFileBytes + 1); err != nil {
		f.Close()
		t.Fatalf("Truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := newServeDeps().readConfigBytes(path); !errors.Is(err, boundedio.ErrTooLarge) {
		t.Fatalf("default readConfigBytes error = %v, want ErrTooLarge", err)
	}
}

// TestCreateNamedListenerImplUnixSocket covers the listeners[*] unix-socket
// bind path (#149) — createNamedListenerImpl was entirely unexercised
// directly (only its stubbed field is used by higher-level bind-barrier
// tests). Mirrors TestCreateListenerUnixSocket's real-bind assertions.
func TestCreateNamedListenerImplUnixSocket(t *testing.T) {
	socketPath := shortSocketPath(t, "named")
	entry := config.ListenerConfig{
		Name:         "ci",
		ListenConfig: config.ListenConfig{Socket: socketPath, SocketMode: "0600"},
	}

	ln, err := newServeDeps().createNamedListenerImpl(&config.Config{}, entry)
	if err != nil {
		t.Fatalf("createNamedListenerImpl() error = %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket path: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected socket file at %q, mode=%v", socketPath, info.Mode())
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 600", info.Mode().Perm())
	}
}

// TestCreateNamedListenerImplTCP covers the listeners[*] TCP bind path.
func TestCreateNamedListenerImplTCP(t *testing.T) {
	entry := config.ListenerConfig{
		Name:         "ops",
		ListenConfig: config.ListenConfig{Address: "127.0.0.1:0"},
	}

	ln, err := newServeDeps().createNamedListenerImpl(&config.Config{}, entry)
	if err != nil {
		t.Fatalf("createNamedListenerImpl() error = %v", err)
	}
	defer ln.Close()

	if ln.Addr().Network() != "tcp" {
		t.Fatalf("listener network = %q, want tcp", ln.Addr().Network())
	}
}

// TestCreateNamedListenerImplUsesEntryName confirms bind errors are reported
// against the specific listeners[*] entry (via the prefix threaded into
// createSocketListener), not a generic "listen"/"admin.listen" label.
func TestCreateNamedListenerImplUsesEntryName(t *testing.T) {
	entry := config.ListenerConfig{
		Name:         "ci",
		ListenConfig: config.ListenConfig{Socket: "/run/ci.sock", SocketMode: "bogus"},
	}

	_, err := newServeDeps().createNamedListenerImpl(&config.Config{}, entry)
	if err == nil || !strings.Contains(err.Error(), "listeners[ci].socket_mode") {
		t.Fatalf("createNamedListenerImpl() error = %v, want listeners[ci] prefix", err)
	}
}

// TestChownSocket covers chownSocket's uid/gid pointer-to-int resolution and
// error wrapping directly — it was entirely unexercised (createSocketListener
// never reached the chown call in any existing test).
func TestChownSocket(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name       string
		uid, gid   *int
		chownErr   error
		wantUID    int
		wantGID    int
		wantErrSub string
	}{
		{name: "both nil resolve to -1,-1", uid: nil, gid: nil, wantUID: -1, wantGID: -1},
		{name: "uid only", uid: intPtr(1000), gid: nil, wantUID: 1000, wantGID: -1},
		{name: "gid only", uid: nil, gid: intPtr(2000), wantUID: -1, wantGID: 2000},
		{name: "both set", uid: intPtr(1000), gid: intPtr(2000), wantUID: 1000, wantGID: 2000},
		{name: "chown error is wrapped", uid: intPtr(1000), gid: intPtr(2000), chownErr: errors.New("op not permitted"), wantUID: 1000, wantGID: 2000, wantErrSub: `chown socket "/run/x.sock": op not permitted`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := newServeTestDeps()
			var gotPath string
			var gotUID, gotGID int
			deps.chown = func(path string, uid, gid int) error {
				gotPath, gotUID, gotGID = path, uid, gid
				return tc.chownErr
			}

			err := deps.chownSocket("/run/x.sock", tc.uid, tc.gid)
			if tc.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("chownSocket() error = %v, want substring %q", err, tc.wantErrSub)
				}
			} else if err != nil {
				t.Fatalf("chownSocket() unexpected error: %v", err)
			}
			if gotPath != "/run/x.sock" || gotUID != tc.wantUID || gotGID != tc.wantGID {
				t.Fatalf("chown(%q, %d, %d), want (%q, %d, %d)", gotPath, gotUID, gotGID, "/run/x.sock", tc.wantUID, tc.wantGID)
			}
		})
	}
}

// TestCreateSocketListenerChownsOnSuccess covers createSocketListener's
// chown branch when SocketUID/SocketGID are set: the listener is chowned
// after bind and returned unclosed.
func TestCreateSocketListenerChownsOnSuccess(t *testing.T) {
	socketPath := shortSocketPath(t, "chown-ok")
	deps := newServeTestDeps()
	var chownCalls int
	deps.chown = func(string, int, int) error {
		chownCalls++
		return nil
	}
	uid, gid := 1000, 1000

	ln, err := deps.createSocketListener("listen", socketPath, "0660", &uid, &gid)
	if err != nil {
		t.Fatalf("createSocketListener() error = %v", err)
	}
	defer ln.Close()

	if chownCalls != 1 {
		t.Fatalf("chown calls = %d, want 1", chownCalls)
	}
}

// TestCreateSocketListenerClosesListenerWhenChownFails covers the rollback
// branch: a chown failure after a successful bind must close the freshly
// created listener (unlinking the unix socket) and propagate the error.
func TestCreateSocketListenerClosesListenerWhenChownFails(t *testing.T) {
	socketPath := shortSocketPath(t, "chown-fail")
	deps := newServeTestDeps()
	deps.chown = func(string, int, int) error { return errors.New("chown boom") }
	uid, gid := 1000, 1000

	ln, err := deps.createSocketListener("listen", socketPath, "0660", &uid, &gid)
	if err == nil || !strings.Contains(err.Error(), "chown boom") {
		t.Fatalf("createSocketListener() error = %v, want chown boom", err)
	}
	if ln != nil {
		t.Fatal("createSocketListener() returned non-nil listener alongside chown error")
	}
	if _, statErr := os.Stat(socketPath); !os.IsNotExist(statErr) {
		t.Fatalf("socket file %q still exists after Close on chown failure", socketPath)
	}
}

// TestDefaultProbeUnixSocket covers the unmocked probe used at runtime
// (newServeDeps wires probeUnixSocket to this by default; tests elsewhere
// only ever stub it). A live listener dials cleanly; a path with nothing
// listening fails.
func TestDefaultProbeUnixSocket(t *testing.T) {
	t.Run("live socket dials cleanly", func(t *testing.T) {
		socketPath := shortSocketPath(t, "probe-live")
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		if err := defaultProbeUnixSocket(socketPath); err != nil {
			t.Fatalf("defaultProbeUnixSocket() error = %v, want nil for live socket", err)
		}
	})

	t.Run("missing socket fails to dial", func(t *testing.T) {
		socketPath := shortSocketPath(t, "probe-missing")

		if err := defaultProbeUnixSocket(socketPath); err == nil {
			t.Fatal("defaultProbeUnixSocket() error = nil, want dial failure for missing socket")
		}
	})
}

// TestDefaultProbeUnixSocketDialsWithBoundedTimeout kills the ARITHMETIC_BASE
// mutant on the probe's dial timeout (200*time.Millisecond ->
// 200/time.Millisecond, i.e. a Duration(0) "no timeout" instead of a 200ms
// bound).
//
// No real dial can kill it: net.DialTimeout to a missing or refusing unix
// socket path returns immediately regardless of the timeout value (there is
// nothing to wait on), and forcing a real connect to block past 200ms requires
// exhausting the kernel's listen accept-backlog. Measured on darwin, once that
// backlog fills, further connects return ECONNREFUSED immediately rather than
// blocking, and the exact backlog size differs across platforms and kernels
// regardless. The probeDial seam replaces the flaky timing observation with a
// direct one: the probe has to hand its dialer a positive, bounded timeout.
func TestDefaultProbeUnixSocketDialsWithBoundedTimeout(t *testing.T) {
	original := probeDial
	t.Cleanup(func() { probeDial = original })

	var (
		calls      int
		gotNetwork string
		gotAddress string
		gotTimeout time.Duration
	)
	probeDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		calls++
		gotNetwork, gotAddress, gotTimeout = network, address, timeout
		return nil, errors.New("probe dial refused")
	}

	const socketPath = "/tmp/sockguard-probe-bounded.sock"
	if err := defaultProbeUnixSocket(socketPath); err == nil {
		t.Fatal("defaultProbeUnixSocket() error = nil, want the dialer's error passed straight back")
	}
	if calls != 1 {
		t.Fatalf("probe dialed %d times, want exactly 1", calls)
	}
	if gotNetwork != "unix" || gotAddress != socketPath {
		t.Fatalf("probe dialed (%q, %q), want (%q, %q)", gotNetwork, gotAddress, "unix", socketPath)
	}
	if gotTimeout <= 0 {
		t.Fatalf("probe dialed with timeout %v; net.DialTimeout reads a non-positive Duration as no timeout at all, so a stale-socket probe could hang startup", gotTimeout)
	}
	if gotTimeout > time.Second {
		t.Fatalf("probe dialed with timeout %v, want a bind-time bound of at most 1s", gotTimeout)
	}
	if gotTimeout != probeDialTimeout {
		t.Fatalf("probe dialed with timeout %v, want probeDialTimeout %v", gotTimeout, probeDialTimeout)
	}
}

// ---------------------------------------------------------------------------
// serve_deps.go:218 — CONDITIONALS_NEGATION: `if fileMode ==
// config.HardenedListenSocketFileMode` inside createSocketListener. When
// fileMode is the hardened mode, the true branch calls listenUnixSocket,
// which itself forwards to listenUnixSocketWithMode(path,
// HardenedListenSocketFileMode) — byte-identical to what the false branch
// would do for that same fileMode value, so that direction is unobservable.
// The mutation IS observable in the other direction: for a non-hardened
// (group-readable) fileMode, the mutant takes the listenUnixSocket branch
// and silently binds the socket at the hardened 0600 mode instead of the
// requested 0660.
// Kill: request group-readable mode explicitly and assert the resulting
// socket file's permission bits are 0660, not 0600.
// ---------------------------------------------------------------------------

func TestCreateSocketListenerUsesRequestedNonHardenedMode(t *testing.T) {
	socketPath := shortSocketPath(t, "group-mode")
	deps := newServeTestDeps()
	gid := os.Getgid()

	ln, err := deps.createSocketListener("listen", socketPath, "0660", nil, &gid)
	if err != nil {
		t.Fatalf("createSocketListener() error = %v", err)
	}
	defer ln.Close()

	info, statErr := os.Lstat(socketPath)
	if statErr != nil {
		t.Fatalf("Lstat(%q) error = %v", socketPath, statErr)
	}
	if got, want := info.Mode().Perm(), config.GroupReadableListenSocketFileMode; got != want {
		t.Fatalf("socket perm = %v, want %v (a mutant that always takes the hardened-mode branch would produce %v)",
			got, want, config.HardenedListenSocketFileMode)
	}
}

// ---------------------------------------------------------------------------
// serve_deps.go:230 — CONDITIONALS_NEGATION (x2): `if uid == nil && gid ==
// nil { return ln, nil }` inside createSocketListener. Negating either
// comparison makes the "skip chown entirely" fast path require a
// self-contradictory pair of conditions (e.g. uid != nil && gid == nil while
// both are actually nil), so it's never taken: an unrequested chown(path,
// -1, -1) call fires even when the caller passed no uid/gid at all.
// Kill: call createSocketListener with uid == nil && gid == nil and assert
// deps.chown is never invoked.
// ---------------------------------------------------------------------------

func TestCreateSocketListenerSkipsChownWhenBothNil(t *testing.T) {
	socketPath := shortSocketPath(t, "no-chown")
	deps := newServeTestDeps()
	chownCalls := 0
	deps.chown = func(string, int, int) error {
		chownCalls++
		return nil
	}

	ln, err := deps.createSocketListener("listen", socketPath, "0600", nil, nil)
	if err != nil {
		t.Fatalf("createSocketListener() error = %v", err)
	}
	defer ln.Close()

	if chownCalls != 0 {
		t.Fatalf("chown calls = %d, want 0 when both uid and gid are nil", chownCalls)
	}
}
