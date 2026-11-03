package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/dockerclient"
	"github.com/codeswhat/sockguard/v3/app/internal/upstream"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
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
	return spec.CAFile != "" || spec.CertFile != "" || spec.KeyFile != ""
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
		// Zero keeps the resolver's 30s default; a negative value disables it.
		ResponseHeaderTimeout: effectiveResponseHeaderTimeout(cfg),
	})
	return res, legacy, err
}

// effectiveResponseHeaderTimeout resolves upstream.response_header_timeout to
// the resolver's convention: negative disables the deadline, zero means the
// built-in default (also the fallback for an unparseable value, which
// validation has already rejected in normal operation).
func effectiveResponseHeaderTimeout(cfg *config.Config) time.Duration {
	if cfg.Upstream.ResponseHeaderTimeoutDisabled() {
		return -1
	}
	return durationOrZero(cfg.Upstream.ResponseHeaderTimeout)
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

// resolveUpstreamFlavor supplies the engine identity to verification callers.
func resolveUpstreamFlavor(ctx context.Context, deps *serveDeps, cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) (upstreamflavor.Flavor, error) {
	capabilities, err := resolveUpstreamCapabilities(ctx, deps, cfg, res, logger)
	return capabilities.Flavor, err
}

// resolveUpstreamCapabilities probes every endpoint before enabling semantics
// that would be unsafe on an older failover target. Explicit configuration can
// resolve an unknown engine, but cannot declare an identified Podman as Docker.
func resolveUpstreamCapabilities(ctx context.Context, deps *serveDeps, cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) (upstreamflavor.Capabilities, error) {
	configured, ok := upstreamflavor.Configured(cfg.Upstream.Flavor)
	if !ok {
		return upstreamflavor.Capabilities{}, fmt.Errorf("upstream.flavor must be %q, %q or %q, got %q", upstreamflavor.Auto, upstreamflavor.Docker, upstreamflavor.Podman, cfg.Upstream.Flavor)
	}
	endpoints := res.Endpoints()
	if len(endpoints) == 0 {
		return upstreamflavor.Capabilities{}, fmt.Errorf("upstream flavor: %w", upstream.ErrNoEndpoints)
	}
	detected := make([]upstreamflavor.Flavor, len(endpoints))
	conjunctiveVolumes := true
	cgroupV1 := cgroupV1OptInConfigured(cfg)
	cgroupV1ProbeFailed := false
	allProbedDocker := true
	for i, ep := range endpoints {
		rt, err := res.EndpointRoundTripper(i)
		if err != nil {
			return upstreamflavor.Capabilities{}, fmt.Errorf("upstream flavor: %w", err)
		}
		probeCtx, cancel := context.WithTimeout(ctx, upstreamflavor.DetectTimeout)
		observed, err := deps.probeUpstream(probeCtx, dockerclient.NewWithRoundTripper(rt))
		cancel()
		if configured == upstreamflavor.Docker && (observed.Flavor == upstreamflavor.Podman || errors.Is(err, upstreamflavor.ErrAmbiguous)) {
			return upstreamflavor.Capabilities{}, fmt.Errorf("upstream.flavor docker contradicts Podman identity at %s; use auto or podman", ep.String())
		}
		if err != nil {
			if configured == upstreamflavor.Auto {
				logger.Error("upstream flavor probe failed", "error", err, "endpoint", ep.String(), "timeout", upstreamflavor.DetectTimeout.String())
				return upstreamflavor.Capabilities{}, fmt.Errorf("%w; sockguard cannot tell whether upstream endpoint %s filters GET /events conjunctively (Docker) or disjunctively (Podman), and guessing either way is unsafe; set upstream.flavor to %q or %q explicitly for an unrecognized engine", err, ep.String(), upstreamflavor.Docker, upstreamflavor.Podman)
			}
			logger.Warn("upstream capability probe unavailable; using configured flavor conservatively", "error", err, "endpoint", ep.String(), "flavor", string(configured))
			observed = upstreamflavor.Capabilities{Flavor: configured}
		}
		detected[i] = observed.Flavor
		allProbedDocker = allProbedDocker && observed.ProbedDocker
		conjunctiveVolumes = conjunctiveVolumes && observed.Flavor == upstreamflavor.Podman && observed.PodmanConjunctiveVolumeFilters
		if cgroupV1 {
			outcome := probeEndpointCgroup(ctx, deps, rt, ep, logger)
			cgroupV1 = outcome == cgroupProbeV1
			cgroupV1ProbeFailed = outcome == cgroupProbeFailed
		}
	}
	if configured != upstreamflavor.Auto {
		logger.Info("upstream flavor resolved", "flavor", string(configured), "probed", true, "endpoints", len(endpoints), "podman_conjunctive_volume_filters", configured == upstreamflavor.Podman && conjunctiveVolumes)
		return upstreamflavor.Capabilities{Flavor: configured, PodmanConjunctiveVolumeFilters: configured == upstreamflavor.Podman && conjunctiveVolumes, CgroupV1: cgroupV1, CgroupV1ProbeFailed: cgroupV1ProbeFailed, ProbedDocker: configured == upstreamflavor.Docker && allProbedDocker}, nil
	}
	for i := 1; i < len(detected); i++ {
		if detected[i] != detected[0] {
			return upstreamflavor.Capabilities{}, fmt.Errorf("upstream endpoints disagree on engine flavor (%s); sockguard cannot apply a single GET /events filter semantics across a failover set that mixes engines; set upstream.flavor to %q explicitly only if conservative Podman semantics are intended", describeEndpointFlavors(endpoints, detected), upstreamflavor.Podman)
		}
	}
	logger.Info("upstream flavor resolved", "flavor", string(detected[0]), "probed", true, "endpoints", len(endpoints), "podman_conjunctive_volume_filters", conjunctiveVolumes)
	return upstreamflavor.Capabilities{Flavor: detected[0], PodmanConjunctiveVolumeFilters: conjunctiveVolumes, CgroupV1: cgroupV1, CgroupV1ProbeFailed: cgroupV1ProbeFailed, ProbedDocker: detected[0] == upstreamflavor.Docker && allProbedDocker}, nil
}

// cgroupV1OptInConfigured reports whether the global request_body or any
// client profile sets container_create.allow_host_cgroupns_on_cgroup_v1. The
// GET /info probe only runs when it does, so a deployment that never opts in
// sends the daemon nothing new.
func cgroupV1OptInConfigured(cfg *config.Config) bool {
	if cfg.RequestBody.ContainerCreate.AllowHostCgroupNSOnCgroupV1 {
		return true
	}
	for _, profile := range cfg.Clients.Profiles {
		if profile.RequestBody.ContainerCreate.AllowHostCgroupNSOnCgroupV1 {
			return true
		}
	}
	return false
}

// cgroupProbeOutcome separates "the daemon answered and is not v1" (final)
// from "the probe itself failed" (worth retrying shortly).
type cgroupProbeOutcome int

const (
	cgroupProbeNotV1 cgroupProbeOutcome = iota
	cgroupProbeV1
	cgroupProbeFailed
)

func probeEndpointCgroup(ctx context.Context, deps *serveDeps, rt http.RoundTripper, ep upstream.Endpoint, logger *slog.Logger) cgroupProbeOutcome {
	if deps.probeCgroupVersion == nil {
		logger.Warn("cgroup version probe unavailable; allow_host_cgroupns_on_cgroup_v1 stays closed", "endpoint", ep.String())
		return cgroupProbeNotV1
	}
	probeCtx, cancel := context.WithTimeout(ctx, upstreamflavor.DetectTimeout)
	defer cancel()
	version, err := deps.probeCgroupVersion(probeCtx, dockerclient.NewWithRoundTripper(rt))
	if err != nil {
		logger.Warn("cgroup version probe failed; allow_host_cgroupns_on_cgroup_v1 stays closed", "error", err, "endpoint", ep.String())
		return cgroupProbeFailed
	}
	if version != "1" {
		logger.Info("upstream endpoint is not cgroup v1; allow_host_cgroupns_on_cgroup_v1 stays closed", "cgroup_version", version, "endpoint", ep.String())
		return cgroupProbeNotV1
	}
	return cgroupProbeV1
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
	capabilities, err := resolveUpstreamCapabilities(ctx, deps, cfg, runtimeResolver(runtime, cfg), logger)
	if err != nil {
		return err
	}
	if runtime != nil {
		runtime.upstreamFlavor = capabilities.Flavor
		runtime.upstreamPodmanConjunctiveVolumeFilters = capabilities.PodmanConjunctiveVolumeFilters
		runtime.cgroupV1.seed(cgroupV1OptInConfigured(cfg), capabilities.CgroupV1)
		if capabilities.CgroupV1ProbeFailed {
			// kickCh is buffered, so this survives until startCgroupV1Refresh
			// launches the loop, which then re-probes and starts the backoff.
			runtime.cgroupV1.kick()
		}
		runtime.upstreamProbedDocker = capabilities.ProbedDocker
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

// runtimeCgroupV1Func returns the live cgroup v1 reader for the filter, nil
// (static false) for a runtime without a tracker.
func runtimeCgroupV1Func(runtime *serveRuntime) func() bool {
	if runtime == nil {
		return nil
	}
	return runtime.cgroupV1.isV1Func()
}

func runtimeUpstreamCapabilities(runtime *serveRuntime) upstreamflavor.Capabilities {
	capabilities := upstreamflavor.Capabilities{Flavor: runtimeUpstreamFlavor(runtime)}
	if runtime != nil {
		capabilities.PodmanConjunctiveVolumeFilters = runtime.upstreamPodmanConjunctiveVolumeFilters
		capabilities.CgroupV1 = runtime.cgroupV1.isV1()
		capabilities.ProbedDocker = runtime.upstreamProbedDocker
	}
	return capabilities
}
