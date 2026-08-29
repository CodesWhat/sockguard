package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/dockerclient"
	"github.com/codeswhat/sockguard/app/internal/upstream"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// upstreamReachableTimeout bounds the startup reachability probe across all
// endpoints so a hung TLS handshake to one remote daemon cannot stall boot.
const upstreamReachableTimeout = 10 * time.Second

// resolveUpstreamSpecs determines the ordered endpoint specs for the upstream
// and whether this is the legacy single-local-socket case (which keeps the
// original fail-fast reachability check and log/banner wording). Precedence:
// explicit upstream.endpoints > DOCKER_HOST (tcp) env > upstream.socket.
func resolveUpstreamSpecs(cfg *config.Config, getenv func(string) string, logger *slog.Logger) (specs []upstream.EndpointSpec, legacySocket bool) {
	if len(cfg.Upstream.Endpoints) > 0 {
		specs = make([]upstream.EndpointSpec, len(cfg.Upstream.Endpoints))
		for i, ep := range cfg.Upstream.Endpoints {
			specs[i] = upstream.EndpointSpec{
				Address:               ep.Address,
				CAFile:                ep.TLS.CAFile,
				CertFile:              ep.TLS.CertFile,
				KeyFile:               ep.TLS.KeyFile,
				ServerName:            ep.TLS.ServerName,
				InsecureAllowPlainTCP: ep.InsecureAllowPlainTCP,
				InsecureSkipTLSVerify: ep.InsecureSkipTLSVerify,
			}
		}
		warnInsecureUpstreamSpecs(logger, specs, "upstream.endpoints config")
		return specs, false
	}
	if spec, ok := upstream.SpecsFromDockerEnv(getenv); ok {
		logger.Info("using remote upstream from DOCKER_HOST environment", "address", spec.Address)
		warnInsecureUpstreamSpecs(logger, []upstream.EndpointSpec{spec}, "DOCKER_HOST environment")
		return []upstream.EndpointSpec{spec}, false
	}
	return []upstream.EndpointSpec{{Address: cfg.Upstream.Socket}}, true
}

// warnInsecureUpstreamSpecs logs a startup warning for each endpoint that
// transports Docker API traffic without proper TLS — plaintext TCP, or TLS with
// certificate verification disabled. Both leave exec streams, secrets, and
// container data exposed (unencrypted, or encrypted but MITM-susceptible), so an
// operator who reaches them via a DOCKER_HOST drop-in (not just explicit config)
// gets a visible breadcrumb rather than a silent downgrade.
func warnInsecureUpstreamSpecs(logger *slog.Logger, specs []upstream.EndpointSpec, source string) {
	if logger == nil {
		return
	}
	for _, spec := range specs {
		switch {
		case spec.InsecureAllowPlainTCP:
			logger.Warn("upstream Docker endpoint uses plaintext TCP with no TLS; "+
				"Docker API traffic (exec streams, secrets, container data) is unencrypted and unauthenticated on the wire",
				"address", spec.Address, "source", source)
		case spec.InsecureSkipTLSVerify:
			logger.Warn("upstream Docker endpoint skips TLS certificate verification; "+
				"the connection is encrypted but the daemon's identity is not checked (MITM-susceptible)",
				"address", spec.Address, "source", source)
		}
	}
}

// buildUpstreamResolver constructs the shared upstream resolver from config,
// loading any per-endpoint TLS material. It returns the resolver, whether the
// legacy single-socket path was taken, and an error for any unbuildable
// endpoint (bad address, missing/invalid TLS files).
func buildUpstreamResolver(cfg *config.Config, logger *slog.Logger, getenv func(string) string) (*upstream.Resolver, bool, error) {
	specs, legacy := resolveUpstreamSpecs(cfg, getenv, logger)
	endpoints := make([]upstream.Endpoint, 0, len(specs))
	for _, spec := range specs {
		ep, err := upstream.BuildEndpoint(spec)
		if err != nil {
			return nil, legacy, err
		}
		endpoints = append(endpoints, ep)
	}
	res, err := upstream.New(endpoints, upstream.Options{
		Interval: durationOrZero(cfg.Upstream.Failover.HealthInterval),
		Timeout:  durationOrZero(cfg.Upstream.Failover.HealthTimeout),
		Logger:   logger,
	})
	return res, legacy, err
}

// durationOrZero parses a Go duration, returning 0 for empty or invalid input
// so the resolver falls back to its built-in defaults. Validation has already
// rejected malformed values by the time this runs in production.
func durationOrZero(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

// upstreamResolverFor returns res when non-nil, otherwise a single-socket
// resolver built from cfg. It lets request-chain helpers accept an optional
// shared resolver (production threads the real one; tests can pass nil to get
// the legacy single-socket behavior without constructing a resolver).
func upstreamResolverFor(res *upstream.Resolver, cfg *config.Config) *upstream.Resolver {
	if res != nil {
		return res
	}
	return upstream.NewSingleSocket(cfg.Upstream.Socket)
}

// runtimeResolver returns the runtime's shared resolver, falling back to a
// single-socket resolver built from cfg when the runtime (or its resolver) is
// absent — the latter only happens in tests that construct a bare serveRuntime.
func runtimeResolver(runtime *serveRuntime, cfg *config.Config) *upstream.Resolver {
	if runtime == nil {
		return upstreamResolverFor(nil, cfg)
	}
	return upstreamResolverFor(runtime.resolver, cfg)
}

// verifyUpstreamReachableForRuntime runs the startup reachability probe against
// the resolved upstream. The legacy single-local-socket path keeps the original
// fail-fast unix-dial check (which classifies not-found / permission errors for
// a precise operator message); the endpoints / DOCKER_HOST path probes every
// configured endpoint, seeds their health state, and fails only when none are
// reachable, so a multi-endpoint failover set can boot with one daemon down.
func verifyUpstreamReachableForRuntime(ctx context.Context, deps *serveDeps, runtime *serveRuntime, cfg *config.Config, logger *slog.Logger) error {
	if runtime == nil || runtime.legacyUpstreamSocket || runtime.resolver == nil {
		return deps.verifyUpstreamReachable(cfg.Upstream.Socket, logger)
	}
	probeCtx, cancel := context.WithTimeout(ctx, upstreamReachableTimeout)
	defer cancel()
	return runtime.resolver.CheckReachable(probeCtx)
}

// resolveUpstreamFlavor determines which engine the upstream is, from
// upstream.flavor and — for "auto" — a single GET /version probe.
//
// Three properties, in the order they matter:
//
//   - An explicit "docker" or "podman" short-circuits before any client is
//     built, so nothing on the network can move an operator's stated answer
//     and no request leaves the process. The test for this asserts zero HTTP
//     requests, not merely the right return value.
//   - An "auto" probe that fails for ANY reason returns an error, which the
//     caller turns into a startup failure. There is no fallback flavor. The
//     two candidate fallbacks are wrong in opposite directions — "docker"
//     silently reopens the Podman /events disclosure, "podman" silently
//     refuses /events for a Docker deployment that was working — and a probe
//     result cached for the process lifetime means a single transient failure
//     at boot would carry the wrong answer until the next restart. Failing
//     startup is the only outcome that is both safe and visible, and its
//     remedy is one config line, named in the message.
//   - The result is logged either way, with `probed` recording which path
//     produced it, so an operator reading the startup log can tell a detected
//     flavor from a declared one without diffing the config.
//
// The probe runs once per process. A daemon does not change engines at
// runtime, upstream.socket and upstream.endpoints are reload-immutable so a
// reload cannot repoint sockguard at a different daemon, and upstream.flavor
// is immutable alongside them — a reload that edits it is rejected with
// "restart required" rather than silently ignored.
func resolveUpstreamFlavor(ctx context.Context, deps *serveDeps, cfg *config.Config, rt http.RoundTripper, logger *slog.Logger) (upstreamflavor.Flavor, error) {
	configured, ok := upstreamflavor.Configured(cfg.Upstream.Flavor)
	if !ok {
		// Unreachable through `sockguard serve`, which validates the config
		// first; kept so a future caller that skips validation still fails
		// closed instead of probing on a nonsense value.
		return "", fmt.Errorf("upstream.flavor must be %q, %q or %q, got %q",
			upstreamflavor.Auto, upstreamflavor.Docker, upstreamflavor.Podman, cfg.Upstream.Flavor)
	}
	if configured != upstreamflavor.Auto {
		logger.Info("upstream flavor resolved", "flavor", string(configured), "probed", false)
		return configured, nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, upstreamflavor.DetectTimeout)
	defer cancel()
	detected, err := deps.detectUpstreamFlavor(probeCtx, dockerclient.NewWithRoundTripper(rt))
	if err != nil {
		logger.Error("upstream flavor probe failed", "error", err, "timeout", upstreamflavor.DetectTimeout.String())
		return "", fmt.Errorf(
			"%w; sockguard cannot tell whether this daemon filters GET /events conjunctively (Docker) or disjunctively (Podman), and guessing either way is unsafe — set upstream.flavor to %q or %q explicitly",
			err, upstreamflavor.Docker, upstreamflavor.Podman)
	}
	logger.Info("upstream flavor resolved", "flavor", string(detected), "probed", true)
	return detected, nil
}

// resolveUpstreamFlavorForRuntime resolves the flavor against the runtime's
// shared resolver — the same transport the proxy and every other side channel
// use, so the probe follows the active endpoint under failover — and records
// it on the runtime for the handler chain to read.
func resolveUpstreamFlavorForRuntime(ctx context.Context, deps *serveDeps, runtime *serveRuntime, cfg *config.Config, logger *slog.Logger) error {
	flavor, err := resolveUpstreamFlavor(ctx, deps, cfg, runtimeResolver(runtime, cfg), logger)
	if err != nil {
		return err
	}
	if runtime != nil {
		runtime.upstreamFlavor = flavor
	}
	return nil
}

// runtimeUpstreamFlavor reads the resolved flavor back out for the chain
// builders.
//
// An absent runtime, or one whose flavor was never resolved, reports Docker:
// that is the behavior every construction site had before this package
// existed, and it keeps a test that builds a bare serveRuntime from silently
// acquiring Podman semantics. It is not a production path —
// resolveUpstreamFlavorForRuntime runs before the chain is built and fails
// startup rather than leaving the field empty — and
// TestServeChainPassesResolvedFlavorToVisibility pins that.
func runtimeUpstreamFlavor(runtime *serveRuntime) upstreamflavor.Flavor {
	if runtime == nil || runtime.upstreamFlavor == "" {
		return upstreamflavor.Docker
	}
	return runtime.upstreamFlavor
}

// upstreamDisplayFromConfig renders the upstream for human-facing output (the
// validate header) directly from config, without constructing a resolver.
// Configured endpoints take precedence over the legacy socket and show a
// failover count when more than one is listed; DOCKER_* env resolution is a
// serve-time fallback and is intentionally not reflected here.
func upstreamDisplayFromConfig(cfg *config.Config) string {
	eps := cfg.Upstream.Endpoints
	switch len(eps) {
	case 0:
		return cfg.Upstream.Socket
	case 1:
		return eps[0].Address
	default:
		return fmt.Sprintf("%s (+%d failover)", eps[0].Address, len(eps)-1)
	}
}

// upstreamLabel is the short identifier used in health logs/metrics for the
// upstream: the sole endpoint's name, or the primary with a failover count.
func upstreamLabel(res *upstream.Resolver) string {
	eps := res.Endpoints()
	switch len(eps) {
	case 0:
		return "upstream"
	case 1:
		return eps[0].Name
	default:
		return eps[0].Name + " (+failover)"
	}
}
