package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/internal/admin"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/metrics"
	"github.com/codeswhat/sockguard/internal/reload"
)

// reloadCoordinatorFixture builds a coordinator wired up to a swappable
// handler over a benign initial config, so individual tests can poke at
// reload outcomes without standing up the whole HTTP server. The test
// metrics registry is also returned for outcome assertions.
type reloadCoordinatorFixture struct {
	coordinator *reloadCoordinator
	swappable   *reload.SwappableHandler
	registry    *metrics.Registry
	versioner   *admin.PolicyVersioner
	cfgPath     string
	loadErr     error
	loadCfg     *config.Config
	validateErr error
}

func newReloadCoordinatorFixture(t *testing.T, initial *config.Config) *reloadCoordinatorFixture {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	registry := metrics.NewRegistry()
	runtime := &serveRuntime{metrics: registry}
	versioner := admin.NewPolicyVersioner()

	deps := newServeTestDeps()
	fixture := &reloadCoordinatorFixture{
		registry:  registry,
		versioner: versioner,
		cfgPath:   cfgPath,
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
		if fixture.validateErr != nil {
			return nil, fixture.validateErr
		}
		return nil, nil
	}

	originalTag := "v1"
	originalHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, originalTag)
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
		nil, // bundleVerifier — fixture covers the policy_bundle.enabled=false path
	)
	return fixture
}

// reloadCount returns the value of sockguard_config_reload_total{result} and
// a boolean indicating whether the metric line was present in the output. The
// boolean guards against the silent-zero ambiguity: a missing metric line
// returns (0, false) while a genuine zero counter returns (0, true).
func (f *reloadCoordinatorFixture) reloadCount(result string) (uint64, bool) {
	rec := httptest.NewRecorder()
	f.registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
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

func indexAfter(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i + len(sub)
		}
	}
	return -1
}

func TestReloadCoordinatorRejectsLoadError(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	f.loadErr = errors.New("simulated parse error")
	f.coordinator.reload()

	if got, ok := f.reloadCount("reject_load"); !ok || got != 1 {
		t.Fatalf("reject_load count = %d (found=%v), want 1", got, ok)
	}
	if got, ok := f.reloadCount("ok"); ok && got != 0 {
		t.Fatalf("ok count = %d, want 0 after rejected reload", got)
	}
}

func TestReloadCoordinatorRejectsImmutableChange(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	changed := initial
	changed.Listen.Address = "0.0.0.0:1234"
	f.loadCfg = &changed

	f.coordinator.reload()

	if got, ok := f.reloadCount("reject_immutable"); !ok || got != 1 {
		t.Fatalf("reject_immutable count = %d (found=%v), want 1", got, ok)
	}
	if got, ok := f.reloadCount("ok"); ok && got != 0 {
		t.Fatalf("ok count = %d, want 0", got)
	}
}

func TestReloadCoordinatorRejectsValidationError(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	f.validateErr = errors.New("rule 2 is malformed")
	f.coordinator.reload()

	if got, ok := f.reloadCount("reject_validation"); !ok || got != 1 {
		t.Fatalf("reject_validation count = %d (found=%v), want 1", got, ok)
	}
}

func TestReloadCoordinatorSwapsOnSuccess(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	// Push the coordinator through a successful reload. The fixture's
	// loadCfg is a structurally-equal copy of initial (no immutable
	// changes), and validateRules returns no error.
	clone := initial
	f.loadCfg = &clone

	// Capture the pre-reload swappable target so we can assert it changed.
	preReloadIdentity := fmt.Sprintf("%p", f.swappable.Current())

	f.coordinator.reload()

	if got, ok := f.reloadCount("ok"); !ok || got != 1 {
		t.Fatalf("ok count = %d (found=%v), want 1", got, ok)
	}

	postReloadIdentity := fmt.Sprintf("%p", f.swappable.Current())
	if preReloadIdentity == postReloadIdentity {
		t.Fatal("swappable handler identity unchanged after successful reload")
	}
}

func TestReloadCoordinatorStopIsIdempotent(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	teardownCalls := 0
	f.coordinator.chainTeardown = func() { teardownCalls++ }

	f.coordinator.stop()
	f.coordinator.stop()

	if teardownCalls != 1 {
		t.Fatalf("teardown invoked %d times, want exactly 1", teardownCalls)
	}
}

func TestReloadCoordinatorReloadAfterStopIsNoop(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	f.coordinator.stop()
	// reload() after stop() must not bump any counter and must not panic.
	f.coordinator.reload()

	for _, result := range []string{"ok", "reject_load", "reject_validation", "reject_immutable"} {
		if got, ok := f.reloadCount(result); ok && got != 0 {
			t.Fatalf("reload after stop bumped %s = %d, want 0", result, got)
		}
	}
}

func TestReloadCoordinatorBumpsPolicyVersionOnSuccess(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	// Seed the versioner with a startup snapshot so the test reload becomes
	// version 2 — matching the production wiring in runServeWithDeps.
	f.versioner.Update(admin.PolicySnapshot{Source: "startup", Rules: len(initial.Rules)})

	clone := initial
	f.loadCfg = &clone
	f.coordinator.reload()

	snap := f.versioner.Snapshot()
	if snap == nil {
		t.Fatalf("Snapshot() = nil after successful reload")
	}
	if snap.Version != 2 {
		t.Fatalf("Version = %d, want 2 (startup=1, reload=2)", snap.Version)
	}
	if snap.Source != "reload" {
		t.Fatalf("Source = %q, want reload", snap.Source)
	}

	// Metrics registry should also reflect the bump.
	rec := httptest.NewRecorder()
	f.registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if idx := indexAfter(rec.Body.String(), "sockguard_policy_version "); idx < 0 {
		t.Fatalf("sockguard_policy_version gauge not emitted: %s", rec.Body.String())
	}
}

func TestReloadCoordinatorPreservesPolicyVersionOnReject(t *testing.T) {
	cases := []struct {
		name string
		set  func(f *reloadCoordinatorFixture, initial config.Config)
	}{
		{
			name: "reject_load",
			set: func(f *reloadCoordinatorFixture, _ config.Config) {
				f.loadErr = errors.New("simulated parse error")
			},
		},
		{
			name: "reject_validation",
			set: func(f *reloadCoordinatorFixture, _ config.Config) {
				f.validateErr = errors.New("rule 2 is malformed")
			},
		},
		{
			name: "reject_immutable",
			set: func(f *reloadCoordinatorFixture, initial config.Config) {
				changed := initial
				changed.Listen.Address = "0.0.0.0:1234"
				f.loadCfg = &changed
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initial := config.Defaults()
			initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
			f := newReloadCoordinatorFixture(t, &initial)

			// Seed startup snapshot.
			startVersion := f.versioner.Update(admin.PolicySnapshot{Source: "startup", Rules: len(initial.Rules)})

			tc.set(f, initial)
			f.coordinator.reload()

			if got := f.versioner.Snapshot().Version; got != startVersion {
				t.Fatalf("Version = %d after %s, want startup version %d preserved", got, tc.name, startVersion)
			}
			if got := f.versioner.Snapshot().Source; got != "startup" {
				t.Fatalf("Source = %q after %s, want startup preserved", got, tc.name)
			}
		})
	}
}
