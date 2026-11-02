package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/policybundle"
)

func junkKeysYAML(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "junk_%02d: 1\n", i)
	}
	return []byte(b.String())
}

func TestWarnUnknownConfigKeysCapsAtFifty(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	warnUnknownConfigKeys(logger, "/etc/sockguard.yaml", junkKeysYAML(60))

	if got := strings.Count(buf.String(), "unrecognized configuration key"); got != 50 {
		t.Fatalf("want 50 key warnings, got %d", got)
	}
	if got := strings.Count(buf.String(), "and 10 more unrecognized keys"); got != 1 {
		t.Fatalf("want one summary line for 10 more, got %d:\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), "key=junk_50") {
		t.Fatalf("key past the cap was listed:\n%s", buf.String())
	}

	buf.Reset()
	warnUnknownConfigKeys(logger, "/etc/sockguard.yaml", junkKeysYAML(50))
	if strings.Contains(buf.String(), "more unrecognized") {
		t.Fatalf("exactly 50 keys must not print a summary:\n%s", buf.String())
	}
}

func TestValidateCapsUnknownKeysAndReadsOnce(t *testing.T) {
	clearSockguardEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(cfgPath, []byte("onDisk_only: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldCfg, oldLoad, oldStrict := cfgFile, validateLoadConfig, validateStrict
	cfgFile, validateStrict = cfgPath, false
	t.Cleanup(func() { cfgFile, validateLoadConfig, validateStrict = oldCfg, oldLoad, oldStrict })

	calls := 0
	validateLoadConfig = func(path string) (*config.Config, []byte, error) {
		calls++
		cfg, err := config.Load("")
		// The bytes the loader reports differ from what is on disk: the
		// warning must come from these, not a second read of the file.
		return cfg, junkKeysYAML(60), err
	}

	var out, errOut bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)
	command.SetErr(&errOut)
	if err := runValidate(command, nil); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if calls != 1 {
		t.Fatalf("config loads = %d, want 1", calls)
	}
	if strings.Contains(errOut.String(), "ondisk_only") {
		t.Fatalf("validate re-read the file:\n%s", errOut.String())
	}
	if got := strings.Count(errOut.String(), "unrecognized configuration key"); got != 50 {
		t.Fatalf("want 50 warnings, got %d", got)
	}
	if !strings.Contains(errOut.String(), "and 10 more unrecognized keys") {
		t.Fatalf("missing summary line:\n%s", errOut.String())
	}
}

func TestValidateDetectionErrorDoesNotFailValidation(t *testing.T) {
	clearSockguardEnv(t)
	oldCfg, oldLoad, oldStrict := cfgFile, validateLoadConfig, validateStrict
	cfgFile, validateStrict = filepath.Join(t.TempDir(), "sockguard.yaml"), false
	if err := os.WriteFile(cfgFile, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cfgFile, validateLoadConfig, validateStrict = oldCfg, oldLoad, oldStrict })

	validateLoadConfig = func(string) (*config.Config, []byte, error) {
		cfg, err := config.Load("")
		return cfg, []byte("rules: [:"), err // unparseable for the detector
	}
	var out bytes.Buffer
	command := &cobra.Command{Use: "validate"}
	command.SetOut(&out)
	command.SetErr(io.Discard)
	if err := runValidate(command, nil); err != nil {
		t.Fatalf("detection error must not fail validation: %v", err)
	}
	if !strings.Contains(out.String(), "validation passed") {
		t.Fatalf("expected validation passed:\n%s", out.String())
	}
}

func TestReloadWarnsOnLoadedBytesOnce(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	var buf bytes.Buffer
	f.coordinator.logger = slog.New(slog.NewTextHandler(&buf, nil))
	calls := 0
	f.coordinator.deps.loadConfig = func(string) (*config.Config, error) {
		t.Fatal("loadConfig must not run when loadConfigData is set")
		return nil, nil
	}
	f.coordinator.deps.loadConfigData = func(string) (*config.Config, []byte, error) {
		calls++
		clone := initial
		return &clone, []byte("reload_junk: 1\n"), nil
	}
	f.coordinator.reload()

	if calls != 1 {
		t.Fatalf("config loads = %d, want 1", calls)
	}
	if got := strings.Count(buf.String(), "key=reload_junk"); got != 1 {
		t.Fatalf("want one warning from the loaded bytes, got %d:\n%s", got, buf.String())
	}
}

func TestPolicyBundleReloadWarnsOnlyFromVerifiedBytes(t *testing.T) {
	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:1"}}
	f := newPolicyBundleFixture(t, policyBundleInitialConfig(), verifier)
	if err := os.WriteFile(f.cfgPath, []byte("unverified_junk: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.yamlBytes = []byte("rules: []\nverified_junk: 1\n")
	var buf bytes.Buffer
	f.coordinator.logger = slog.New(slog.NewTextHandler(&buf, nil))
	f.coordinator.reload()

	if !strings.Contains(buf.String(), "key=verified_junk") {
		t.Fatalf("expected warning from verified bytes:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "unverified_junk") {
		t.Fatalf("warned from unverified file:\n%s", buf.String())
	}

	// Verification failure: nothing is inspected or warned.
	buf.Reset()
	verifier.err = errors.New("bad signature")
	f.coordinator.reload()
	if strings.Contains(buf.String(), "unrecognized configuration key") {
		t.Fatalf("warned despite failed verification:\n%s", buf.String())
	}
}

func signedServeFixture(t *testing.T, verifyErr error) (stderr string, runErr error) {
	t.Helper()
	const trustPath = "/operator/policy-trust.yaml"
	const candidateYAML = "policy_bundle:\n  signature_path: /candidate/cfg.bundle.json\ncandidate_junk: 1\n"
	const verifiedYAML = "policy_bundle:\n  signature_path: /candidate/cfg.bundle.json\nverified_junk: 1\n"
	const trustYAML = "policy_bundle:\n  enabled: true\n  allowed_signing_keys:\n    - pem: pinned-key\n"

	cmd := newServeCommand()
	cmd.Flags().String("policy-bundle-trust-config", "", "")
	if err := cmd.Flags().Set("policy-bundle-trust-config", trustPath); err != nil {
		t.Fatal(err)
	}
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)

	deps := newServeTestDeps()
	deps.loadConfigData = func(string) (*config.Config, []byte, error) {
		cfg, err := config.LoadBytes([]byte(candidateYAML))
		return cfg, []byte(candidateYAML), err
	}
	deps.readConfigBytes = func(path string) ([]byte, error) {
		switch path {
		case trustPath:
			return []byte(trustYAML), nil
		default:
			return []byte(verifiedYAML), nil
		}
	}
	deps.loadConfigBytes = config.LoadBytes
	deps.loadBundleEntity = func(string) (verify.SignedEntity, error) { return &stubEntity{}, nil }
	deps.buildBundleVerifier = func(config.PolicyBundleConfig) (policybundle.Verifier, error) {
		return &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:pinned"}, err: verifyErr}, nil
	}
	stop := errors.New("stop")
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return nil, stop }

	runErr = runServeWithDeps(cmd, nil, deps)
	return errBuf.String(), runErr
}

func TestServeSignedModeWarnsOnlyFromVerifiedBytes(t *testing.T) {
	stderr, err := signedServeFixture(t, nil)
	if err == nil || !strings.Contains(err.Error(), "stop") {
		t.Fatalf("runServeWithDeps() error = %v, want stop", err)
	}
	if !strings.Contains(stderr, "key=verified_junk") {
		t.Fatalf("expected warning from verified bytes:\n%s", stderr)
	}
	if strings.Contains(stderr, "candidate_junk") {
		t.Fatalf("warned from the unverified candidate:\n%s", stderr)
	}
}

func TestServeSignedModeFailedVerificationWarnsNothing(t *testing.T) {
	stderr, err := signedServeFixture(t, errors.New("bad signature"))
	if err == nil || !strings.Contains(err.Error(), "policy bundle") {
		t.Fatalf("runServeWithDeps() error = %v, want policy bundle failure", err)
	}
	if strings.Contains(stderr, "unrecognized configuration key") {
		t.Fatalf("warned before/without verification:\n%s", stderr)
	}
}

func TestServeUnsignedWarnsOnLoadedBytes(t *testing.T) {
	cmd := newServeCommand()
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	deps := newServeTestDeps()
	loads := 0
	deps.loadConfigData = func(string) (*config.Config, []byte, error) {
		loads++
		cfg := config.Defaults()
		return &cfg, []byte("loaded_junk: 1\n"), nil
	}
	stop := errors.New("stop")
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return nil, stop }
	if err := runServeWithDeps(cmd, nil, deps); !errors.Is(err, stop) {
		t.Fatalf("error = %v, want stop", err)
	}
	if loads != 1 || strings.Count(errBuf.String(), "key=loaded_junk") != 1 {
		t.Fatalf("loads=%d stderr:\n%s", loads, errBuf.String())
	}
}
