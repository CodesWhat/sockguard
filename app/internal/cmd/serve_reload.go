package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/admin"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/metrics"
	"github.com/codeswhat/sockguard/internal/policybundle"
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
	// versioner is shared with the admin policy-version handler. Updating it
	// after a successful swap is what makes the new generation visible to
	// GET /admin/policy/version and to sockguard_policy_version. Nil-safe so
	// tests can construct a coordinator without one.
	versioner *admin.PolicyVersioner
	// bundleVerifier is the reload-immutable signed-bundle verifier. Nil
	// means policy_bundle.enabled=false; the reload path skips verification
	// in that case. When non-nil and policy_bundle.enabled=true, every
	// reload must clear the verifier before any other work — otherwise the
	// trust gate would be bypassable by anyone with write access to the
	// YAML file.
	bundleVerifier policybundle.Verifier
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
	versioner *admin.PolicyVersioner,
	bundleVerifier policybundle.Verifier,
) *reloadCoordinator {
	if initialTeardown == nil {
		initialTeardown = func() {}
	}
	return &reloadCoordinator{
		chainTeardown:  initialTeardown,
		activeCfg:      cfg,
		swappable:      swappable,
		cfgFile:        cfgFile,
		logger:         logger,
		auditLogger:    auditLogger,
		deps:           deps,
		runtime:        runtime,
		registry:       runtime.metrics,
		versioner:      versioner,
		bundleVerifier: bundleVerifier,
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

	// Bundle verification runs FIRST so an unsigned or tampered YAML can
	// never reach the config parser. The verifier was bound at startup
	// from reload-immutable trust material; an enabled gate at startup is
	// an enabled gate forever.
	bundleResult, err := c.verifyBundle()
	if err != nil {
		c.logger.Warn("config reload rejected: signature verification failed",
			"result", "reject_signature",
			"path", c.cfgFile,
			"signature_path", c.activeCfg.PolicyBundle.SignaturePath,
			"error", err.Error(),
		)
		c.registry.ObserveConfigReload("reject_signature")
		return
	}

	newCfg, err := c.deps.loadConfig(c.cfgFile)
	if err != nil {
		c.logger.Warn("config reload rejected: load failed",
			"result", "reject_load",
			"path", c.cfgFile,
			"error", err.Error(),
		)
		c.registry.ObserveConfigReload("reject_load")
		return
	}

	if changed := reload.ImmutableDiff(c.activeCfg, newCfg); len(changed) > 0 {
		// Stamp result= and changed_fields= as discrete keys so a SIEM grep
		// on result=reject_immutable lines up with the metric label exactly.
		// Pre-v0.8.1 this rejection emitted the metric but the operator-visible
		// log lacked the result key, making the rejection easy to miss in the
		// NAS soak where an admin.path edit looked applied to the operator.
		c.logger.Warn("config reload rejected: immutable fields changed; restart required to apply",
			"result", "reject_immutable",
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
	compatActive := config.ApplyCompat(newCfg, discard)

	newRules, err := c.deps.validateRules(newCfg)
	if err != nil {
		c.logger.Warn("config reload rejected: validation failed",
			"result", "reject_validation",
			"path", c.cfgFile,
			"error", err.Error(),
		)
		c.registry.ObserveConfigReload("reject_validation")
		return
	}

	newHandler, newTeardown := buildServeHandlerChainWithRuntime(
		newCfg, c.logger, c.auditLogger, newRules, c.deps, c.runtime, c.versioner,
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

	// Publish the new generation AFTER the swap so an admin GET to
	// /admin/policy/version that races with a reload either sees the
	// pre-reload version (handler still pointing at the old chain) or
	// the post-reload version (handler is the new chain) — never a half
	// state where the version ticked but the active handler is stale.
	var newVersion int64
	if c.versioner != nil {
		snap := admin.PolicySnapshot{
			LoadedAt:     c.deps.now(),
			Rules:        len(newRules),
			Profiles:     len(newCfg.Clients.Profiles),
			CompatActive: compatActive,
			Source:       "reload",
			ConfigSHA256: policyConfigHash(newCfg),
		}
		if bundleResult != nil {
			snap.BundleSource = filepath.Base(newCfg.PolicyBundle.SignaturePath)
			snap.BundleSigner = bundleResult.Signer
			snap.BundleDigest = bundleResult.DigestHex
		}
		newVersion = c.versioner.Update(snap)
		c.registry.SetPolicyVersion(newVersion)
	}

	c.logger.Info("config reload applied",
		"result", "ok",
		"path", c.cfgFile,
		"rules", len(newRules),
		"profiles", len(newCfg.Clients.Profiles),
		"policy_version", newVersion,
	)
	c.registry.ObserveConfigReload("ok")
}

// verifyBundle returns (nil, nil) when bundle verification is disabled,
// (*VerifyResult, nil) on a clean accept, or (nil, err) on any failure
// (missing file, malformed bundle, signature mismatch). The bound verifier
// is the same instance produced at startup and reused across every reload
// because policy_bundle's trust material is reload-immutable.
func (c *reloadCoordinator) verifyBundle() (*policybundle.VerifyResult, error) {
	if c.bundleVerifier == nil || !c.activeCfg.PolicyBundle.Enabled {
		return nil, nil
	}
	if c.activeCfg.PolicyBundle.SignaturePath == "" {
		return nil, errors.New("policy_bundle.signature_path is empty")
	}
	yamlBytes, err := c.deps.readConfigBytes(c.cfgFile)
	if err != nil {
		return nil, err
	}
	entity, err := c.deps.loadBundleEntity(c.activeCfg.PolicyBundle.SignaturePath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), bundleVerifyDeadline(c.activeCfg.PolicyBundle))
	defer cancel()
	res, err := c.bundleVerifier.Verify(ctx, yamlBytes, entity)
	if err != nil {
		return nil, err
	}
	return &res, nil
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

