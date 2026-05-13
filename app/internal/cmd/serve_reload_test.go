package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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

	deps := newServeTestDeps()
	fixture := &reloadCoordinatorFixture{
		registry: registry,
		cfgPath:  cfgPath,
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
	)
	return fixture
}

func (f *reloadCoordinatorFixture) reloadCount(result string) uint64 {
	rec := httptest.NewRecorder()
	f.registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	needle := fmt.Sprintf("sockguard_config_reload_total{result=\"%s\"} ", result)
	idx := indexAfter(body, needle)
	if idx < 0 {
		return 0
	}
	var value uint64
	if _, err := fmt.Sscanf(body[idx:], "%d", &value); err != nil {
		return 0
	}
	return value
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

	if got := f.reloadCount("reject_load"); got != 1 {
		t.Fatalf("reject_load count = %d, want 1", got)
	}
	if got := f.reloadCount("ok"); got != 0 {
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

	if got := f.reloadCount("reject_immutable"); got != 1 {
		t.Fatalf("reject_immutable count = %d, want 1", got)
	}
	if got := f.reloadCount("ok"); got != 0 {
		t.Fatalf("ok count = %d, want 0", got)
	}
}

func TestReloadCoordinatorRejectsValidationError(t *testing.T) {
	initial := config.Defaults()
	initial.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/x"}, Action: "allow"}}
	f := newReloadCoordinatorFixture(t, &initial)

	f.validateErr = errors.New("rule 2 is malformed")
	f.coordinator.reload()

	if got := f.reloadCount("reject_validation"); got != 1 {
		t.Fatalf("reject_validation count = %d, want 1", got)
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

	if got := f.reloadCount("ok"); got != 1 {
		t.Fatalf("ok count = %d, want 1", got)
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
		if got := f.reloadCount(result); got != 0 {
			t.Fatalf("reload after stop bumped %s = %d, want 0", result, got)
		}
	}
}
