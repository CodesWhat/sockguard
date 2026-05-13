package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	coordinator *reloadCoordinator
	registry    *metrics.Registry
	versioner   *admin.PolicyVersioner
	swappable   *reload.SwappableHandler
	cfgPath     string
	sigPath     string
	verifier    *stubBundleVerifier
	yamlBytes   []byte
	loadErr     error
	loadCfg     *config.Config
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
	deps.validateRules = func(_ *config.Config) ([]*filter.CompiledRule, error) {
		return nil, nil
	}

	originalHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "v1")
	})
	swappable := reload.NewSwappableHandler(originalHandler)
	fixture.swappable = swappable

	fixture.coordinator = newReloadCoordinator(
		initial,
		cfgPath,
		swappable,
		func() {},
		newDiscardLogger(),
		nil,
		deps,
		runtime,
		versioner,
		verifier,
	)
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
