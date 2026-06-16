package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/codeswhat/sockguard/internal/admin"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/metrics"
	"github.com/codeswhat/sockguard/internal/policybundle"
	"github.com/codeswhat/sockguard/internal/reload"
)

// stubBundleVerifier implements policybundle.Verifier with a static result
// so tests can assert reload outcomes without standing up sigstore or
// VirtualSigstore. Trust material is exercised end-to-end by the
// policybundle package's own tests.
type stubBundleVerifier struct {
	res policybundle.VerifyResult
	err error
}

func (s *stubBundleVerifier) Verify(_ context.Context, _ []byte, _ verify.SignedEntity) (policybundle.VerifyResult, error) {
	return s.res, s.err
}

// newPolicyBundleFixture mirrors reloadCoordinatorFixture but wires a stub
// bundle verifier + a fake sigstore-bundle loader so the policy_bundle
// reload paths can be exercised in isolation.
type policyBundleFixture struct {
	coordinator  *reloadCoordinator
	registry     *metrics.Registry
	versioner    *admin.PolicyVersioner
	swappable    *reload.SwappableHandler
	cfgPath      string
	sigPath      string
	verifier     *stubBundleVerifier
	yamlBytes    []byte
	loadErr      error
	loadCfg      *config.Config
	loadBytesArg []byte
}

func newPolicyBundleFixture(t *testing.T, initial *config.Config, verifier *stubBundleVerifier) *policyBundleFixture {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules:\n  - match: {method: GET, path: /_ping}\n    action: allow\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	sigPath := filepath.Join(dir, "cfg.bundle.json")
	if err := os.WriteFile(sigPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	registry := metrics.NewRegistry()
	runtime := &serveRuntime{metrics: registry}
	versioner := admin.NewPolicyVersioner()

	deps := newServeTestDeps()
	fixture := &policyBundleFixture{
		registry:  registry,
		versioner: versioner,
		cfgPath:   cfgPath,
		sigPath:   sigPath,
		verifier:  verifier,
		yamlBytes: []byte("rules: []\n"),
	}
	deps.readConfigBytes = func(_ string) ([]byte, error) {
		return fixture.yamlBytes, nil
	}
	deps.loadBundleEntity = func(_ string) (verify.SignedEntity, error) {
		return &stubEntity{}, nil
	}
	deps.loadConfig = func(_ string) (*config.Config, error) {
		if fixture.loadErr != nil {
			return nil, fixture.loadErr
		}
		if fixture.loadCfg != nil {
			return fixture.loadCfg, nil
		}
		clone := *initial
		return &clone, nil
	}
	// With a bundle enabled, the reload parses the verified bytes via
	// loadConfigBytes rather than re-reading the file. Mirror loadConfig so the
	// fixture's loadErr/loadCfg knobs still drive the bundle path; also record
	// the bytes handed in so a test can assert they are the verified ones.
	deps.loadConfigBytes = func(b []byte) (*config.Config, error) {
		fixture.loadBytesArg = append([]byte(nil), b...)
		if fixture.loadErr != nil {
			return nil, fixture.loadErr
		}
		if fixture.loadCfg != nil {
			return fixture.loadCfg, nil
		}
		clone := *initial
		return &clone, nil
	}
	deps.validateRules = func(_ *config.Config) ([]*filter.CompiledRule, error) {
		return nil, nil
	}

	originalHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "v1")
	})
	swappable := reload.NewSwappableHandler(originalHandler)
	fixture.swappable = swappable

	fixture.coordinator = newReloadCoordinator(reloadCoordinatorParams{
		RootCtx:         context.Background(),
		Cfg:             initial,
		CfgFile:         cfgPath,
		Swappable:       swappable,
		InitialTeardown: func() {},
		Logger:          newDiscardLogger(),
		Deps:            deps,
		Runtime:         runtime,
		Versioner:       versioner,
		BundleVerifier:  verifier,
	})
	return fixture
}

// stubEntity is a no-op verify.SignedEntity stand-in returned by the fake
// loadBundleEntity. The stub verifier never inspects it.
type stubEntity struct{}

func (s *stubEntity) VerificationContent() (verify.VerificationContent, error) { return nil, nil }
func (s *stubEntity) SignatureContent() (verify.SignatureContent, error)       { return nil, nil }
func (s *stubEntity) HasInclusionPromise() bool                                { return false }
func (s *stubEntity) HasInclusionProof() bool                                  { return false }
func (s *stubEntity) Version() (string, error)                                 { return "v0.1", nil }
func (s *stubEntity) Timestamps() ([][]byte, error)                            { return nil, nil }
func (s *stubEntity) TlogEntries() ([]*tlog.Entry, error)                      { return nil, nil }

func policyBundleInitialConfig() *config.Config {
	cfg := config.Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/tmp/sig.bundle.json"
	cfg.PolicyBundle.AllowedSigningKeys = []config.PolicyBundleSigningKey{{PEM: "stub"}}
	return &cfg
}

func TestPolicyBundleReload_AcceptsSignedYAML(t *testing.T) {
	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{
		Signer:    "keyed:abcd",
		DigestHex: "deadbeef",
	}}
	f := newPolicyBundleFixture(t, policyBundleInitialConfig(), verifier)

	f.coordinator.reload()

	if got, ok := metricsReloadCount(t, f.registry, "ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1", got, ok)
	}
	if got, ok := metricsReloadCount(t, f.registry, "reject_signature"); ok && got != 0 {
		t.Fatalf("reject_signature count = %d, want 0", got)
	}
	snap := f.versioner.Snapshot()
	if snap == nil {
		t.Fatal("no snapshot published")
		return
	}
	if snap.BundleSigner != "keyed:abcd" {
		t.Fatalf("BundleSigner = %q, want keyed:abcd", snap.BundleSigner)
	}
	if snap.BundleDigest != "deadbeef" {
		t.Fatalf("BundleDigest = %q, want deadbeef", snap.BundleDigest)
	}
}

func TestPolicyBundleReload_RejectsBadSignature(t *testing.T) {
	verifier := &stubBundleVerifier{err: errors.New("signature did not verify")}
	f := newPolicyBundleFixture(t, policyBundleInitialConfig(), verifier)

	f.coordinator.reload()

	if got, ok := metricsReloadCount(t, f.registry, "reject_signature"); !ok || got != 1 {
		t.Fatalf("reject_signature count = %d (found=%v), want 1", got, ok)
	}
	if got, ok := metricsReloadCount(t, f.registry, "ok"); ok && got != 0 {
		t.Fatalf("ok count = %d, want 0 (rejected reload must not record success)", got)
	}
	if snap := f.versioner.Snapshot(); snap != nil {
		t.Fatalf("expected no snapshot publish on rejected reload, got %+v", snap)
	}
}

func TestPolicyBundleReload_SkipsWhenDisabled(t *testing.T) {
	cfg := config.Defaults()
	verifier := &stubBundleVerifier{err: errors.New("MUST NOT BE CALLED")}
	f := newPolicyBundleFixture(t, &cfg, verifier)
	// Force the verifier to be wired even though policy_bundle.enabled=false
	// — verifyBundle must early-return on the Enabled flag.

	f.coordinator.reload()

	if got, ok := metricsReloadCount(t, f.registry, "ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1 (disabled bundle must not block reload)", got, ok)
	}
	if got, ok := metricsReloadCount(t, f.registry, "reject_signature"); ok && got != 0 {
		t.Fatalf("reject_signature count = %d, want 0", got)
	}
	if snap := f.versioner.Snapshot(); snap != nil && snap.BundleSigner != "" {
		t.Fatalf("disabled bundle must not stamp BundleSigner, got %q", snap.BundleSigner)
	}
}

func TestPolicyBundleReload_VerifyRunsBeforeConfigLoad(t *testing.T) {
	verifier := &stubBundleVerifier{err: errors.New("signature mismatch")}
	f := newPolicyBundleFixture(t, policyBundleInitialConfig(), verifier)
	// Wire loadConfig to fail; the bundle verifier should already have
	// rejected the reload, so loadConfig must never be invoked.
	loadCalled := false
	f.coordinator.deps.loadConfig = func(_ string) (*config.Config, error) {
		loadCalled = true
		return nil, errors.New("MUST NOT BE CALLED")
	}

	f.coordinator.reload()

	if loadCalled {
		t.Fatal("loadConfig must not be called after a failed signature verification")
	}
	if got, ok := metricsReloadCount(t, f.registry, "reject_signature"); !ok || got != 1 {
		t.Fatalf("reject_signature count = %d (found=%v), want 1", got, ok)
	}
}

// TestPolicyBundleReload_ParsesVerifiedBytesNotFile pins the #8/#16 reload fix:
// when a bundle is enabled the reload parses the EXACT bytes it verified (via
// loadConfigBytes) and never re-reads the file with loadConfig — so a concurrent
// file swap or SOCKGUARD_* env vars cannot divert the applied config.
func TestPolicyBundleReload_ParsesVerifiedBytesNotFile(t *testing.T) {
	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:1"}}
	f := newPolicyBundleFixture(t, policyBundleInitialConfig(), verifier)
	f.yamlBytes = []byte("rules: []\n# signed-marker\n")

	loadCalled := false
	f.coordinator.deps.loadConfig = func(_ string) (*config.Config, error) {
		loadCalled = true
		return nil, errors.New("file re-read MUST NOT happen on the bundle path")
	}

	f.coordinator.reload()

	if loadCalled {
		t.Fatal("loadConfig (file re-read) must not run on the signed-bundle path")
	}
	if string(f.loadBytesArg) != string(f.yamlBytes) {
		t.Fatalf("loadConfigBytes parsed %q, want the verified bytes %q", f.loadBytesArg, f.yamlBytes)
	}
	if got, ok := metricsReloadCount(t, f.registry, "ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1", got, ok)
	}
}

func TestPolicyBundleReload_ResolvesSignaturePathFromCandidate(t *testing.T) {
	// Regression: verifyBundle must load the bundle entity from the CANDIDATE
	// config's signature_path, not the last-applied config's. signature_path is
	// reload-mutable so an operator can rotate the bundle; reading it from
	// activeCfg loaded the wrong (old) bundle for the new YAML and — because
	// activeCfg only advances on success — wedged every subsequent reload.
	initial := policyBundleInitialConfig()
	initial.PolicyBundle.SignaturePath = "/old/sig.bundle.json"

	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:x", DigestHex: "ab"}}
	f := newPolicyBundleFixture(t, initial, verifier)

	// The candidate (parsed from the verified bytes) points at the rotated path.
	candidate := config.Defaults()
	candidate.PolicyBundle.Enabled = true
	candidate.PolicyBundle.SignaturePath = "/new/sig.bundle.json"
	candidate.PolicyBundle.AllowedSigningKeys = []config.PolicyBundleSigningKey{{PEM: "stub"}}
	f.loadCfg = &candidate

	var gotPath string
	f.coordinator.deps.loadBundleEntity = func(p string) (verify.SignedEntity, error) {
		gotPath = p
		return &stubEntity{}, nil
	}

	f.coordinator.reload()

	if gotPath != "/new/sig.bundle.json" {
		t.Fatalf("loadBundleEntity path = %q, want the candidate's /new/sig.bundle.json (not active /old)", gotPath)
	}
	if got, ok := metricsReloadCount(t, f.registry, "ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1", got, ok)
	}
}

// ---------------------------------------------------------------------------
// verifyPolicyBundleAtStartup — exhaustive branch coverage.
// Every failure branch of the signature gate aborts startup, so each one
// must have an explicit regression test. The default constructor only
// exercised the !Enabled early return; the failures previously had none.
// ---------------------------------------------------------------------------

func newStartupCfg() *config.Config {
	cfg := config.Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/tmp/sig.bundle.json"
	cfg.PolicyBundle.AllowedSigningKeys = []config.PolicyBundleSigningKey{{PEM: "stub"}}
	return &cfg
}

func TestVerifyPolicyBundleAtStartup_Disabled(t *testing.T) {
	cfg := config.Defaults()
	deps := newServeTestDeps()
	res, signedCfg, err := verifyPolicyBundleAtStartup(context.Background(), &cfg, "/tmp/cfg.yaml", deps, &stubBundleVerifier{}, newDiscardLogger())
	if err != nil {
		t.Fatalf("err = %v, want nil for disabled", err)
	}
	if res != nil {
		t.Fatalf("res = %+v, want nil for disabled", res)
	}
	if signedCfg != nil {
		t.Fatalf("signedCfg = %+v, want nil for disabled", signedCfg)
	}
}

func TestVerifyPolicyBundleAtStartup_NoCfgFile(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()
	res, _, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "", deps, &stubBundleVerifier{}, newDiscardLogger())
	if err == nil {
		t.Fatal("err = nil, want failure when --config is empty")
	}
	if res != nil {
		t.Fatalf("res = %+v, want nil", res)
	}
}

func TestVerifyPolicyBundleAtStartup_NoSignaturePath(t *testing.T) {
	cfg := newStartupCfg()
	cfg.PolicyBundle.SignaturePath = ""
	deps := newServeTestDeps()
	_, _, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "/tmp/cfg.yaml", deps, &stubBundleVerifier{}, newDiscardLogger())
	if err == nil {
		t.Fatal("err = nil, want failure when signature_path is empty")
	}
}

func TestVerifyPolicyBundleAtStartup_ReadError(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()
	sentinel := errors.New("read failed")
	deps.readConfigBytes = func(string) ([]byte, error) { return nil, sentinel }
	_, _, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "/tmp/cfg.yaml", deps, &stubBundleVerifier{}, newDiscardLogger())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped %v", err, sentinel)
	}
}

func TestVerifyPolicyBundleAtStartup_LoadEntityError(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()
	deps.readConfigBytes = func(string) ([]byte, error) { return []byte("rules: []\n"), nil }
	sentinel := errors.New("load entity failed")
	deps.loadBundleEntity = func(string) (verify.SignedEntity, error) { return nil, sentinel }
	_, _, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "/tmp/cfg.yaml", deps, &stubBundleVerifier{}, newDiscardLogger())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}

func TestVerifyPolicyBundleAtStartup_VerifyError(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()
	deps.readConfigBytes = func(string) ([]byte, error) { return []byte("rules: []\n"), nil }
	deps.loadBundleEntity = func(string) (verify.SignedEntity, error) { return &stubEntity{}, nil }
	sentinel := errors.New("signature mismatch")
	verifier := &stubBundleVerifier{err: sentinel}
	_, _, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "/tmp/cfg.yaml", deps, verifier, newDiscardLogger())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}

func TestVerifyPolicyBundleAtStartup_Success(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()
	deps.readConfigBytes = func(string) ([]byte, error) { return []byte("rules: []\n"), nil }
	deps.loadBundleEntity = func(string) (verify.SignedEntity, error) { return &stubEntity{}, nil }
	want := policybundle.VerifyResult{Signer: "keyed:1234", DigestHex: "abcd", ElapsedMS: 42}
	verifier := &stubBundleVerifier{res: want}

	got, signedCfg, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "/tmp/cfg.yaml", deps, verifier, newDiscardLogger())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("got = nil, want VerifyResult")
		return
	}
	if got.Signer != want.Signer || got.DigestHex != want.DigestHex {
		t.Fatalf("got = %+v, want %+v", got, want)
	}
	if signedCfg == nil {
		t.Fatal("signedCfg = nil, want config parsed from verified bytes")
	}
}

// TestVerifyPolicyBundleAtStartup_ParsesVerifiedBytesNotFile pins the #8/#16
// fix: the returned config is parsed from the exact bytes that were verified
// (via loadConfigBytes), never a fresh file read, and the SOCKGUARD_* env
// overlay is not applied to signed policy.
func TestVerifyPolicyBundleAtStartup_ParsesVerifiedBytesNotFile(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()

	const verifiedYAML = "upstream:\n  socket: /verified/docker.sock\n"
	var verifiedBytes []byte
	deps.readConfigBytes = func(string) ([]byte, error) {
		verifiedBytes = []byte(verifiedYAML)
		return verifiedBytes, nil
	}
	deps.loadBundleEntity = func(string) (verify.SignedEntity, error) { return &stubEntity{}, nil }
	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:1"}}

	// loadConfigBytes must receive the exact bytes that were verified — not a
	// re-read of the file (which a TOCTOU attacker could have swapped).
	var gotBytes []byte
	deps.loadConfigBytes = func(b []byte) (*config.Config, error) {
		gotBytes = b
		return config.LoadBytes(b)
	}

	_, signedCfg, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "/tmp/cfg.yaml", deps, verifier, newDiscardLogger())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if string(gotBytes) != verifiedYAML {
		t.Fatalf("loadConfigBytes received %q, want the verified bytes %q", gotBytes, verifiedYAML)
	}
	if signedCfg == nil || signedCfg.Upstream.Socket != "/verified/docker.sock" {
		t.Fatalf("signedCfg = %+v, want config parsed from the verified bytes", signedCfg)
	}
}

// TestVerifyPolicyBundleAtStartup_ParseError surfaces a malformed verified body
// as a startup failure rather than silently applying a partial config.
func TestVerifyPolicyBundleAtStartup_ParseError(t *testing.T) {
	cfg := newStartupCfg()
	deps := newServeTestDeps()
	deps.readConfigBytes = func(string) ([]byte, error) { return []byte("rules: [:"), nil }
	deps.loadBundleEntity = func(string) (verify.SignedEntity, error) { return &stubEntity{}, nil }
	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:1"}}

	_, _, err := verifyPolicyBundleAtStartup(context.Background(), cfg, "/tmp/cfg.yaml", deps, verifier, newDiscardLogger())
	if err == nil || !strings.Contains(err.Error(), "parse verified config") {
		t.Fatalf("err = %v, want parse-verified-config failure", err)
	}
}

// metricsReloadCount returns the value of sockguard_config_reload_total{result}
// and a boolean indicating whether the metric line was present. The boolean
// guards against the silent-zero ambiguity: a missing metric line is (0, false)
// while a genuine zero counter is (0, true).
func metricsReloadCount(t *testing.T, r *metrics.Registry, result string) (uint64, bool) {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	needle := fmt.Sprintf("sockguard_config_reload_total{result=\"%s\"} ", result)
	idx := indexAfter(body, needle)
	if idx < 0 {
		return 0, false
	}
	var value uint64
	if _, err := fmt.Sscanf(body[idx:], "%d", &value); err != nil {
		return 0, false
	}
	return value, true
}
