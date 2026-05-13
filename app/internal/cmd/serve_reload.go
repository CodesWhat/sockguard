package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/metrics"
	"github.com/codeswhat/sockguard/internal/reload"
)

// reloadCoordinator owns the hot-reload state for a running sockguard
// process: the current chain teardown, the active config snapshot, and
// the swappable handler the http.Server routes through. It serializes
// reloads with a mutex — at most one OnReload is in flight at any time —
// and updates the metrics registry with the outcome.
type reloadCoordinator struct {
	mu sync.Mutex

	// chainTeardown halts goroutines belonging to the CURRENT chain
	// (rate-limit sampler, per-profile Limiter eviction). The reload
	// path replaces it with the new chain's teardown and invokes the
	// old one. The shutdown path invokes whatever is current.
	chainTeardown func()
	activeCfg     *config.Config

	// Bindings that live for the whole process lifetime. None of these
	// change across reloads — the immutable-field gate rejects any
	// reload whose YAML would mutate these inputs.
	swappable   *reload.SwappableHandler
	cfgFile     string
	logger      *slog.Logger
	auditLogger *logging.AuditLogger
	deps        *serveDeps
	runtime     *serveRuntime
	registry    *metrics.Registry
}

// newReloadCoordinator returns a coordinator wired up with the initial
// chain teardown and current config snapshot. The caller must arrange for
// stop to be invoked once at process shutdown.
func newReloadCoordinator(
	cfg *config.Config,
	cfgFile string,
	swappable *reload.SwappableHandler,
	initialTeardown func(),
	logger *slog.Logger,
	auditLogger *logging.AuditLogger,
	deps *serveDeps,
	runtime *serveRuntime,
) *reloadCoordinator {
	if initialTeardown == nil {
		initialTeardown = func() {}
	}
	return &reloadCoordinator{
		chainTeardown: initialTeardown,
		activeCfg:     cfg,
		swappable:     swappable,
		cfgFile:       cfgFile,
		logger:        logger,
		auditLogger:   auditLogger,
		deps:          deps,
		runtime:       runtime,
		registry:      runtime.metrics,
	}
}

// stop halts the current chain's goroutines. Idempotent so it is safe
// to call from a defer at shutdown.
func (c *reloadCoordinator) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.chainTeardown == nil {
		return
	}
	c.chainTeardown()
	c.chainTeardown = nil
}

// reload runs one full reload pass: load → ApplyCompat → validate →
// immutable-diff → swap. Outcomes are surfaced via the metrics registry
// and the slog logger; the running config is never replaced on failure.
//
// Called from the reload.Reloader goroutine. The mutex serializes against
// shutdown and against future reload triggers that race during a long
// validation.
func (c *reloadCoordinator) reload() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.chainTeardown == nil {
		// stop() already ran — process is shutting down; ignore.
		return
	}

	newCfg, err := c.deps.loadConfig(c.cfgFile)
	if err != nil {
		c.logger.Warn("config reload rejected: load failed",
			"path", c.cfgFile,
			"error", err.Error(),
		)
		c.registry.ObserveConfigReload("reject_load")
		return
	}

	if changed := reload.ImmutableDiff(c.activeCfg, newCfg); len(changed) > 0 {
		c.logger.Warn("config reload rejected: immutable fields changed; restart required to apply",
			"path", c.cfgFile,
			"changed_fields", strings.Join(changed, ","),
		)
		c.registry.ObserveConfigReload("reject_immutable")
		return
	}

	// ApplyCompat expands Tecnativa env aliases on the new cfg. Use a
	// discard logger here so reload-time compat noise doesn't drown out
	// the operator's real reload signal; the compat-active state is
	// reflected in the candidate's rules, which validation will judge.
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	config.ApplyCompat(newCfg, discard)

	newRules, err := c.deps.validateRules(newCfg)
	if err != nil {
		c.logger.Warn("config reload rejected: validation failed",
			"path", c.cfgFile,
			"error", err.Error(),
		)
		c.registry.ObserveConfigReload("reject_validation")
		return
	}

	newHandler, newTeardown := buildServeHandlerChainWithRuntime(
		newCfg, c.logger, c.auditLogger, newRules, c.deps, c.runtime,
	)

	oldTeardown := c.chainTeardown
	c.chainTeardown = newTeardown
	c.activeCfg = newCfg

	// Swap the handler pointer BEFORE tearing down the old chain's
	// goroutines: new requests immediately route through the new chain;
	// requests already past the swappable's pointer load complete on
	// the old chain. The old sampler/eviction goroutines are still alive
	// during that window — tearing them down after the swap is safe
	// because they perform no per-request work for in-flight calls.
	c.swappable.Swap(newHandler)
	oldTeardown()

	c.logger.Info("config reload applied",
		"path", c.cfgFile,
		"rules", len(newRules),
		"profiles", len(newCfg.Clients.Profiles),
	)
	c.registry.ObserveConfigReload("ok")
}

// startReloader wires the coordinator into a reload.Reloader and runs it
// in a goroutine. Returns a stop function that cancels the watcher loop
// and returns once it has exited. Callers must invoke stop before
// invoking coordinator.stop() so a reload-in-progress can't race the
// teardown.
func startReloader(ctx context.Context, cfgFile string, debounce time.Duration, coordinator *reloadCoordinator, logger *slog.Logger) (func(), error) {
	if cfgFile == "" {
		return nil, errors.New("reload: cfgFile is required")
	}
	rl, err := reload.New(reload.Options{
		Path:     cfgFile,
		Debounce: debounce,
		OnReload: coordinator.reload,
		Logger:   logger,
	})
	if err != nil {
		return nil, err
	}

	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if runErr := rl.Run(loopCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
			logger.Warn("config reloader stopped with error", "error", runErr)
		}
	}()

	stop := func() {
		cancel()
		<-done
	}
	return stop, nil
}

