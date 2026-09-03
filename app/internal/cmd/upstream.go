package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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
// explicit upstream.endpoints > DOCKER_HOST env > upstream.socket.
func resolveUpstreamSpecs(cfg *config.Config, lookupEnv func(string) (string, bool), logger *slog.Logger) (specs []upstream.EndpointSpec, legacySocket bool, err error) {
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
				//nolint:staticcheck // SA1019: v2.1 keeps the deprecated setting functional until its v3.0.0 removal
				InsecureSkipTLSVerify: ep.InsecureSkipTLSVerify,
			}
		}
		warnInsecureUpstreamSpecs(logger, specs, "upstream.endpoints config")
		return specs, false, nil
	}
	spec, ok, err := upstream.SpecsFromDockerEnv(lookupEnv)
	if err != nil {
		return nil, false, err
	}
	if ok {
		logger.Info("using upstream from DOCKER_HOST environment", "address", spec.Address)
		warnInsecureUpstreamSpecs(logger, []upstream.EndpointSpec{spec}, "DOCKER_HOST environment")
		return []upstream.EndpointSpec{spec}, false, nil
	}
	return []upstream.EndpointSpec{{Address: cfg.Upstream.Socket}}, true, nil
}

// warnInsecureUpstreamSpecs logs startup warnings for insecure endpoint
// settings. TCP warnings follow the transport selected by BuildEndpoint. Unix
// endpoints instead warn that TCP-only insecure settings have no effect.
func warnInsecureUpstreamSpecs(logger *slog.Logger, specs []upstream.EndpointSpec, source string) {
	if logger == nil {
		return
	}
	for _, spec := range specs {
		unixEndpoint := upstreamSpecUsesUnixTransport(spec)
		if spec.InsecureAllowPlainTCP {
			message := "upstream Docker endpoint uses plaintext TCP with no TLS; " +
				"Docker API traffic (exec streams, secrets, container data) is unencrypted and unauthenticated on the wire"
			if unixEndpoint {
				message = "upstream Docker endpoint uses a Unix socket; " +
					"insecure_allow_plain_tcp only applies to TCP endpoints and has no effect"
			} else if upstreamSpecSelectsTLS(spec) {
				message = "upstream Docker endpoint has insecure_allow_plain_tcp enabled, but TLS is selected; " +
					"remove insecure_allow_plain_tcp because it has no effect while TLS is configured"
			}
			logger.Warn(message,
				"address", spec.Address, "source", source)
		}
		if spec.InsecureSkipTLSVerify {
			deprecatedSetting := "upstream.endpoints[].insecure_skip_tls_verify"
			replacement := "upstream.endpoints[].tls.ca_file"
			message := "upstream Docker endpoint skips TLS certificate verification; " +
				"upstream.endpoints[].insecure_skip_tls_verify is deprecated and will be removed in v3.0.0; " +
				"configure upstream.endpoints[].tls.ca_file to verify the daemon"
			if source == "DOCKER_HOST environment" {
				deprecatedSetting = "DOCKER_TLS without DOCKER_TLS_VERIFY"
				replacement = "DOCKER_TLS_VERIFY=1"
				message = "upstream Docker endpoint skips TLS certificate verification because DOCKER_TLS is set without DOCKER_TLS_VERIFY; " +
					"this Docker environment fallback is deprecated and will be removed in v3.0.0; set DOCKER_TLS_VERIFY=1 to verify the daemon"
			}
			if unixEndpoint {
				message = "upstream Docker endpoint uses a Unix socket; " +
					"insecure_skip_tls_verify only applies to TCP endpoints and has no effect; " +
					deprecatedSetting + " is deprecated and will be removed in v3.0.0; configure " + replacement + " for TCP endpoints"
			}
			logger.Warn(message,
				"address", spec.Address,
				"source", source,
				"deprecated_setting", deprecatedSetting,
				"replacement", replacement,
				"removal_version", "v3.0.0",
			)
		}
	}
}

// upstreamSpecUsesUnixTransport asks the endpoint builder to classify only the
// address, avoiding TLS file loads while keeping warning behavior aligned with
// the actual transport parser.
func upstreamSpecUsesUnixTransport(spec upstream.EndpointSpec) bool {
	endpoint, err := upstream.BuildEndpoint(upstream.EndpointSpec{Address: spec.Address})
	return err == nil && endpoint.Network == "unix"
}

// upstreamSpecSelectsTLS mirrors the transport selection in
// upstream.BuildEndpoint without loading certificate files.
func upstreamSpecSelectsTLS(spec upstream.EndpointSpec) bool {
	return spec.CAFile != "" || spec.CertFile != "" || spec.KeyFile != "" ||
		spec.InsecureSkipTLSVerify
}

// buildUpstreamResolver constructs the shared upstream resolver from config,
// loading any per-endpoint TLS material. It returns the resolver, whether the
// legacy single-socket path was taken, and an error for any unbuildable
// endpoint (bad address, missing/invalid TLS files).
func buildUpstreamResolver(cfg *config.Config, logger *slog.Logger, lookupEnv func(string) (string, bool)) (*upstream.Resolver, bool, error) {
	specs, legacy, err := resolveUpstreamSpecs(cfg, lookupEnv, logger)
	if err != nil {
		return nil, false, err
	}
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
// upstream.flavor and — for "auto" — a GET /version probe of every
// configured endpoint.
//
// Four properties, in the order they matter:
//
//   - An explicit "docker" or "podman" short-circuits before any client is
//     built, so nothing on the network can move an operator's stated answer
//     and no request leaves the process. The test for this asserts zero HTTP
//     requests, not merely the right return value.
//   - "auto" probes EVERY endpoint in res, not just the active one. A
//     Docker-primary/Podman-secondary failover pair would otherwise cache
//     whichever engine happened to answer the startup probe — usually the
//     primary — and keep applying that engine's filter semantics after a
//     failover moved traffic to the other one. Podman's disjunctive /events
//     filter evaluated against Docker's semantics widens the stream instead
//     of narrowing it, so a wrong cached flavor is not a benign guess.
//   - A probe that fails for ANY endpoint, or that succeeds but disagrees
//     with another endpoint's answer, returns an error, which the caller
//     turns into a startup failure. There is no fallback flavor. The two
//     candidate fallbacks are wrong in opposite directions — "docker"
//     silently reopens the Podman /events disclosure, "podman" silently
//     refuses /events for a Docker deployment that was working — and a probe
//     result cached for the process lifetime means a single transient
//     failure or mismatch at boot would carry the wrong answer until the
//     next restart. Failing startup is the only outcome that is both safe
//     and visible, and its remedy is one config line, named in the message.
//   - The result is logged either way, with `probed` recording which path
//     produced it and `endpoints` recording how many were involved, so an
//     operator reading the startup log can tell a detected flavor from a
//     declared one without diffing the config.
//
// The probe runs once per process, against every endpoint at that moment.
// A daemon does not change engines at runtime, upstream.socket and
// upstream.endpoints are reload-immutable so a reload cannot repoint
// sockguard at a different daemon, and upstream.flavor is immutable
// alongside them — a reload that edits it is rejected with "restart
// required" rather than silently ignored.
func resolveUpstreamFlavor(ctx context.Context, deps *serveDeps, cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) (upstreamflavor.Flavor, error) {
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

	endpoints := res.Endpoints()
	if len(endpoints) == 0 {
		return "", fmt.Errorf("upstream flavor: %w", upstream.ErrNoEndpoints)
	}
	detected := make([]upstreamflavor.Flavor, len(endpoints))
	for i, ep := range endpoints {
		rt, err := res.EndpointRoundTripper(i)
		if err != nil {
			// Unreachable: i comes from ranging over res.Endpoints(), which
			// is built from the same states EndpointRoundTripper indexes.
			return "", fmt.Errorf("upstream flavor: %w", err)
		}
		probeCtx, cancel := context.WithTimeout(ctx, upstreamflavor.DetectTimeout)
		flavor, err := deps.detectUpstreamFlavor(probeCtx, dockerclient.NewWithRoundTripper(rt))
		cancel()
		if err != nil {
			logger.Error("upstream flavor probe failed", "error", err, "endpoint", ep.String(), "timeout", upstreamflavor.DetectTimeout.String())
			return "", fmt.Errorf(
				"%w; sockguard cannot tell whether upstream endpoint %s filters GET /events conjunctively (Docker) or disjunctively (Podman), and guessing either way is unsafe — set upstream.flavor to %q or %q explicitly",
				err, ep.String(), upstreamflavor.Docker, upstreamflavor.Podman)
		}
		detected[i] = flavor
	}

	for i := 1; i < len(detected); i++ {
		if detected[i] != detected[0] {
			return "", fmt.Errorf(
				"upstream endpoints disagree on engine flavor (%s); sockguard cannot apply a single GET /events filter semantics across a failover set that mixes engines — set upstream.flavor to %q or %q explicitly",
				describeEndpointFlavors(endpoints, detected), upstreamflavor.Docker, upstreamflavor.Podman)
		}
	}

	logger.Info("upstream flavor resolved", "flavor", string(detected[0]), "probed", true, "endpoints", len(endpoints))
	return detected[0], nil
}

// describeEndpointFlavors renders each endpoint's address alongside its
// detected flavor, in probe order, for the mismatch error message — so an
// operator sees exactly which endpoint reported which engine rather than
// just "they disagree".
func describeEndpointFlavors(endpoints []upstream.Endpoint, flavors []upstreamflavor.Flavor) string {
	parts := make([]string, len(endpoints))
	for i, ep := range endpoints {
		parts[i] = fmt.Sprintf("%s=%s", ep.String(), flavors[i])
	}
	return strings.Join(parts, ", ")
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
