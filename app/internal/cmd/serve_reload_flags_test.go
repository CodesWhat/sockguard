package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/policybundle"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

// flagOverridesFor builds the same closure runServeWithDeps hands the reload
// coordinator: the real applyFlagOverrides bound to a cobra command whose
// flags have already been marked as explicitly set. Using the production
// function rather than a hand-rolled stub keeps these tests honest about what
// "the flags the operator passed" actually means.
func flagOverridesFor(t *testing.T, nameValue ...string) func(*config.Config) error {
	t.Helper()
	if len(nameValue)%2 != 0 {
		t.Fatalf("flagOverridesFor needs name/value pairs, got %d args", len(nameValue))
	}
	cmd := newServeCommand()
	for i := 0; i < len(nameValue); i += 2 {
		if err := cmd.Flags().Set(nameValue[i], nameValue[i+1]); err != nil {
			t.Fatalf("set --%s=%s: %v", nameValue[i], nameValue[i+1], err)
		}
	}
	return func(cfg *config.Config) error {
		return applyFlagOverrides(cmd, cfg)
	}
}

// TestReloadCoordinatorReappliesMutableFlagOverride covers symptom 1 of the
// dropped-flag bug. response.deny_verbosity is NOT in reload.ImmutableFields,
// so a successful reload rebuilds the handler chain straight from the YAML
// value and --deny-verbosity minimal evaporates on the first reload, quietly
// widening deny-response detail from the generic message to method + path +
// reason. Against the pre-fix code the candidate's "verbose" wins and the
// denial body leaks the configured reason.
func TestReloadCoordinatorReappliesMutableFlagOverride(t *testing.T) {
	const denyReason = "reloaded deny policy"

	// activeCfg as startup left it: YAML said verbose, the flag said minimal.
	initial := config.Defaults()
	initial.Response.DenyVerbosity = "minimal"
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)
	f.coordinator.applyFlagOverrides = flagOverridesFor(t, "deny-verbosity", "minimal")

	candidate := initial
	candidate.Response.DenyVerbosity = "verbose"
	candidate.Rules = []config.RuleConfig{{
		Match:  config.MatchConfig{Method: "GET", Path: "/x"},
		Action: "deny",
		Reason: denyReason,
	}}
	f.loadCfg = &candidate
	f.coordinator.deps.validateRules = validateAndCompileRules

	f.coordinator.reload()

	if got, ok := f.reloadCount("ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1; log: %s", got, ok, f.logBuf.String())
	}
	if got := f.coordinator.activeCfg.Response.DenyVerbosity; got != "minimal" {
		t.Fatalf("activeCfg.Response.DenyVerbosity = %q after reload, want the --deny-verbosity flag value minimal", got)
	}

	// The chain the reload actually swapped in is the authority, not the
	// struct field: assert the denial body carries no request detail.
	rec := httptest.NewRecorder()
	f.swappable.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("post-reload status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, denyReason) {
		t.Fatalf("denial body = %q, want no reason: --deny-verbosity minimal was dropped by the reload", body)
	}
	if !strings.Contains(body, "request denied by sockguard policy") {
		t.Fatalf("denial body = %q, want the generic minimal-verbosity message", body)
	}
}

// TestReloadCoordinatorFlagOverriddenImmutableFieldDoesNotRejectImmutable
// covers symptom 2, the worse of the two. c.activeCfg is the flag-overridden
// startup config and listen is an immutable field, so a --listen-socket that
// differs from the YAML made ImmutableDiff report a change on EVERY reload:
// the reload was rejected with reject_immutable for the whole process
// lifetime and the operator was told "restart required to apply" for a config
// that never changed. Nothing about the file changes between startup and this
// reload; the coordinator only ever sees the post-override activeCfg, so this
// equally covers "the YAML value churned but the flag pins the effective one".
func TestReloadCoordinatorFlagOverriddenImmutableFieldDoesNotRejectImmutable(t *testing.T) {
	const flagSocket = "/run/sockguard-from-flag.sock"

	initial := config.Defaults()
	initial.Listen.Socket = flagSocket
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)
	f.coordinator.applyFlagOverrides = flagOverridesFor(t, "listen-socket", flagSocket)

	// What the file+env load produces: the YAML's own socket, which the flag
	// outranks per the documented flags > env > file > defaults precedence.
	candidate := initial
	candidate.Listen.Socket = "/run/sockguard-from-yaml.sock"
	f.loadCfg = &candidate

	f.coordinator.reload()

	if got, ok := f.reloadCount("reject_immutable"); ok && got != 0 {
		t.Fatalf("reject_immutable count = %d, want 0: an unchanged config was rejected because the flag override was not re-applied; log: %s", got, f.logBuf.String())
	}
	if got, ok := f.reloadCount("ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1; log: %s", got, ok, f.logBuf.String())
	}
	if got := f.coordinator.activeCfg.Listen.Socket; got != flagSocket {
		t.Fatalf("activeCfg.Listen.Socket = %q after reload, want the flag value %q", got, flagSocket)
	}
}

// TestReloadCoordinatorStillRejectsGenuineImmutableChangeWithFlagOverrides is
// the counterweight: re-applying flags must not defeat the immutability gate.
// Every case wires the same --listen-socket override as the test above and
// then makes a real immutable change the flags do not cover.
func TestReloadCoordinatorStillRejectsGenuineImmutableChangeWithFlagOverrides(t *testing.T) {
	const flagSocket = "/run/sockguard-from-flag.sock"

	tests := []struct {
		name        string
		mutate      func(*config.Config)
		wantChanged string
	}{
		{
			// Same block the flag writes into, different field: the override
			// pins Listen.Socket, so only a real Address edit is left, and it
			// must still reject.
			name:        "sibling field in the flag-overridden block",
			mutate:      func(c *config.Config) { c.Listen.Address = "0.0.0.0:1234" },
			wantChanged: "changed_fields=listen",
		},
		{
			// An immutable field that has a flag, but that flag was not passed.
			name:        "immutable field whose flag was not set",
			mutate:      func(c *config.Config) { c.Upstream.Socket = "/var/run/other-docker.sock" },
			wantChanged: "changed_fields=upstream.socket",
		},
		{
			name:        "immutable block no flag touches",
			mutate:      func(c *config.Config) { c.Admin.Path = "/admin/check" },
			wantChanged: "changed_fields=admin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			initial := config.Defaults()
			initial.Admin.Enabled = true
			initial.Listen.Socket = flagSocket
			initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
			f := newReloadCoordinatorFixture(t, &initial)
			f.coordinator.applyFlagOverrides = flagOverridesFor(t, "listen-socket", flagSocket)

			candidate := initial
			candidate.Listen.Socket = "/run/sockguard-from-yaml.sock"
			tc.mutate(&candidate)
			f.loadCfg = &candidate

			before := f.coordinator.activeCfg
			f.coordinator.reload()

			if got, ok := f.reloadCount("reject_immutable"); !ok || got != 1 {
				t.Fatalf("reject_immutable count = %d (found=%v), want 1; log: %s", got, ok, f.logBuf.String())
			}
			if got, ok := f.reloadCount("ok"); ok && got != 0 {
				t.Fatalf("ok count = %d, want 0", got)
			}
			if f.coordinator.activeCfg != before {
				t.Fatal("rejected reload advanced activeCfg")
			}
			if logOutput := f.logBuf.String(); !strings.Contains(logOutput, tc.wantChanged) {
				t.Fatalf("rejection log missing %s: %s", tc.wantChanged, logOutput)
			}
		})
	}
}

// TestReloadCoordinatorRejectsWhenFlagOverridesFail covers the error return.
// applyFlagOverrides only fails when a flag is declared as a non-string type,
// which startup would already have refused, so this is defense in depth: the
// candidate could not be fully constructed, so the reload must not apply.
func TestReloadCoordinatorRejectsWhenFlagOverridesFail(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	// Redeclare deny-verbosity as an int so applyFlagOverrides' GetString
	// fails, exactly as TestApplyFlagOverridesErrorBranches does.
	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().Int("deny-verbosity", 0, "")
	if err := cmd.Flags().Set("deny-verbosity", "1"); err != nil {
		t.Fatalf("set deny-verbosity: %v", err)
	}
	f.coordinator.applyFlagOverrides = func(cfg *config.Config) error {
		return applyFlagOverrides(cmd, cfg)
	}

	clone := initial
	f.loadCfg = &clone
	before := f.coordinator.activeCfg
	beforeHandler := fmt.Sprintf("%p", f.swappable.Current())

	f.coordinator.reload()

	if got, ok := f.reloadCount("reject_load"); !ok || got != 1 {
		t.Fatalf("reject_load count = %d (found=%v), want 1; log: %s", got, ok, f.logBuf.String())
	}
	if got, ok := f.reloadCount("ok"); ok && got != 0 {
		t.Fatalf("ok count = %d, want 0", got)
	}
	if f.coordinator.activeCfg != before {
		t.Fatal("failed flag-override reload advanced activeCfg")
	}
	if fmt.Sprintf("%p", f.swappable.Current()) != beforeHandler {
		t.Fatal("failed flag-override reload swapped the handler")
	}
	if logOutput := f.logBuf.String(); !strings.Contains(logOutput, "applying CLI flag overrides failed") {
		t.Fatalf("rejection log missing the flag-override cause: %s", logOutput)
	}
}

// TestNewReloadCoordinatorDefaultsFlagOverridesToNoop pins the constructor
// contract the fixtures rely on: a coordinator built without an
// ApplyCoordinator override still has a callable non-nil applier, so reload()
// can invoke it unconditionally.
func TestNewReloadCoordinatorDefaultsFlagOverridesToNoop(t *testing.T) {
	c := newReloadCoordinator(reloadCoordinatorParams{
		RootCtx: context.Background(),
		Cfg:     &config.Config{},
		CfgFile: "unused",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if c.applyFlagOverrides == nil {
		t.Fatal("applyFlagOverrides = nil; reload() calls it unconditionally and would panic")
	}
	cfg := config.Defaults()
	if err := c.applyFlagOverrides(&cfg); err != nil {
		t.Fatalf("default applyFlagOverrides() error = %v, want nil", err)
	}
	if got := cfg.Response.DenyVerbosity; got != config.Defaults().Response.DenyVerbosity {
		t.Fatalf("default applyFlagOverrides mutated the config: DenyVerbosity = %q", got)
	}
}

// TestPolicyBundleReloadReappliesFlagOverrides pins the signed-bundle
// conclusion: CLI flags ARE re-applied on top of the verified bytes, because
// startup does exactly that at serve.go's applyFlagOverrides(cmd, signedCfg)
// and a reload must not diverge from startup. The "parse the EXACT verified
// bytes" guarantee defends against a file swapped between verify and load
// (#8) and SOCKGUARD_* env vars re-read on every reload (#16) — both channels
// an attacker can move at runtime. os.Args is not one of them: cobra parsed it
// once before RunE and it is frozen for the process lifetime, so the reload
// replays byte-identical values to the ones startup applied. Skipping them
// would be the divergence, not the safety.
func TestPolicyBundleReloadReappliesFlagOverrides(t *testing.T) {
	const flagSocket = "/run/sockguard-signed-flag.sock"

	initial := policyBundleInitialConfig()
	initial.Listen.Socket = flagSocket
	initial.Response.DenyVerbosity = "minimal"

	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:abcd"}}
	f := newPolicyBundleFixture(t, initial, verifier)
	f.coordinator.applyFlagOverrides = flagOverridesFor(t,
		"listen-socket", flagSocket,
		"deny-verbosity", "minimal",
	)

	// The config parsed from the verified bytes carries the signed YAML's own
	// values for both fields.
	candidate := *policyBundleInitialConfig()
	candidate.Listen.Socket = "/run/sockguard-signed-yaml.sock"
	candidate.Response.DenyVerbosity = "verbose"
	f.loadCfg = &candidate

	f.coordinator.reload()

	if got, ok := metricsReloadCount(t, f.registry, "reject_immutable"); ok && got != 0 {
		t.Fatalf("reject_immutable count = %d, want 0 on the signed path", got)
	}
	if got, ok := metricsReloadCount(t, f.registry, "ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1", got, ok)
	}
	if got := f.coordinator.activeCfg.Listen.Socket; got != flagSocket {
		t.Fatalf("activeCfg.Listen.Socket = %q, want the flag value %q on the signed path", got, flagSocket)
	}
	if got := f.coordinator.activeCfg.Response.DenyVerbosity; got != "minimal" {
		t.Fatalf("activeCfg.Response.DenyVerbosity = %q, want the flag value minimal on the signed path", got)
	}
	// The pinned trust root still wins over anything the candidate claims —
	// flags are layered on top of the pin, never underneath it.
	active := f.coordinator.activeCfg.PolicyBundle
	if !active.Enabled || len(active.AllowedSigningKeys) != 1 || active.AllowedSigningKeys[0].PEM != "stub" {
		t.Fatalf("active trust = %+v, want the startup-pinned trust preserved", active)
	}
}

// TestPolicyBundleReloadStillRejectsImmutableChangeWithFlagOverrides is the
// signed-path counterweight to the unsigned one above: a real immutable edit
// inside signed bytes is still rejected once flags are re-applied.
func TestPolicyBundleReloadStillRejectsImmutableChangeWithFlagOverrides(t *testing.T) {
	const flagSocket = "/run/sockguard-signed-flag.sock"

	initial := policyBundleInitialConfig()
	initial.Listen.Socket = flagSocket

	verifier := &stubBundleVerifier{res: policybundle.VerifyResult{Signer: "keyed:abcd"}}
	f := newPolicyBundleFixture(t, initial, verifier)
	f.coordinator.applyFlagOverrides = flagOverridesFor(t, "listen-socket", flagSocket)

	candidate := *policyBundleInitialConfig()
	candidate.Listen.Socket = "/run/sockguard-signed-yaml.sock"
	candidate.Upstream.Socket = "/var/run/other-docker.sock"
	f.loadCfg = &candidate

	f.coordinator.reload()

	if got, ok := metricsReloadCount(t, f.registry, "reject_immutable"); !ok || got != 1 {
		t.Fatalf("reject_immutable count = %d (found=%v), want 1", got, ok)
	}
	if got, ok := metricsReloadCount(t, f.registry, "ok"); ok && got != 0 {
		t.Fatalf("ok count = %d, want 0", got)
	}
}

// TestRunServe_ReloadReappliesStartupFlagOverrides is the wiring test: every
// other test in this file sets coordinator.applyFlagOverrides directly, so
// none of them would notice runServeWithDeps forgetting to pass
// ApplyFlagOverrides. This one drives the real serve path with
// --listen-socket set to something the (stubbed) file+env load never
// produces, touches the config file to trigger a real reload, and asserts the
// reload applied. Pre-fix, this reload is rejected with reject_immutable
// forever.
func TestRunServe_ReloadReappliesStartupFlagOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	tmpCfg := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(tmpCfg, []byte("listen:\n  address: 127.0.0.1:0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	flagSocket := filepath.Join(tmpDir, "from-flag.sock")

	originalCfgFile := cfgFile
	cfgFile = tmpCfg
	t.Cleanup(func() { cfgFile = originalCfgFile })

	deps := newServeTestDeps()
	// Never returns Listen.Socket, so the only source of it is the CLI flag.
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Reload.Enabled = true
		cfg.Reload.Debounce = "10ms"
		cfg.Reload.PollInterval = "50ms"
		return cfg, nil
	}
	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{}, nil
	}
	deps.startServing = func(*http.Server, net.Listener, chan<- error) {}
	deps.shutdownServer = func(*http.Server, context.Context) error { return nil }
	deps.removePath = func(string) error { return nil }
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
		go func() {
			if !collector.WaitForMessage("config hot-reload enabled", 5*time.Second) {
				c <- syscall.SIGINT
				return
			}
			// Touch the watched file so the reloader fires a real pass.
			if err := os.WriteFile(tmpCfg, []byte("listen:\n  address: 127.0.0.1:0\n# touched\n"), 0o600); err != nil {
				c <- syscall.SIGINT
				return
			}
			collector.WaitForMessage("config reload applied", 5*time.Second)
			c <- syscall.SIGINT
		}()
	}

	cmd := newServeCommand()
	if err := cmd.Flags().Set("listen-socket", flagSocket); err != nil {
		t.Fatalf("set listen-socket: %v", err)
	}

	if err := runServeWithDeps(cmd, nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}

	if collector.HasMessage("config reload rejected: immutable fields changed; restart required to apply") {
		t.Fatalf("reload rejected as immutable although only the CLI flag differs from the loaded config — runServeWithDeps is not passing ApplyFlagOverrides; records: %#v", collector.Records())
	}
	if !collector.HasMessage("config reload applied") {
		t.Fatalf("no reload was applied; records: %#v", collector.Records())
	}
}
