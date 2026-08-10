package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/internal/buildkitproxy"
)

// BuildkitOptions carries the ONE signal Phase 1 of issue #185 (BuildKit
// gRPC mediation) needs at the request-handling hot path: whether
// request_body.buildkit is configured for the active policy (global or a
// named client profile). It deliberately does NOT carry the richer
// buildkitproxy.Policy translation — Phase 1 ships no transport/mediator,
// so there is nothing here yet to make a per-field decision with. See
// buildkitPolicy.inspect below and cmd/rules.go's
// validateBuildkitTunnelRulesForPolicy for the startup-time half of this.
type BuildkitOptions struct {
	// TunnelConfigured is true when the operator configured
	// request_body.buildkit (top-level or on this client profile) — see
	// config.BuildkitRequestBodyConfig and buildkitproxy.Policy.Configured.
	TunnelConfigured bool
}

// buildkitTunnelPaths are the three opaque, unversioned BuildKit endpoints
// (see cmd/rules.go's buildkitTunnelEndpoints doc comment for the full
// rationale): POST /session, the frontend/session bridge; POST /grpc, the
// moby.buildkit.v1.Control service tunneled over an HTTP/1.1 hijack; and any
// direct moby.buildkit.v1.Control/<Method> path (e.g.
// /moby.buildkit.v1.Control/Solve, /moby.buildkit.v1.Control/Status) —
// cmd/rules.go's buildkitTunnelEndpoints probes these too, and once
// request_body.buildkit is configured, startup validation admits rules that
// match them, so this inspector must deny them here or they would reach the
// Docker socket completely unmediated. Matched against the ALREADY
// version-stripped normalized path, exactly like every other
// matches*Inspection function in this package.
func matchesBuildkitTunnelInspection(normalizedPath string) bool {
	return normalizedPath == "/session" || normalizedPath == "/grpc" ||
		strings.HasPrefix(normalizedPath, "/moby.buildkit.v1.Control/")
}

// IsBuildkitTunnelPath reports whether normalizedPath is one of the two
// REAL h2c-upgrade-bearing BuildKit tunnel endpoints — POST /session or
// POST /grpc, the only two paths sockguard ever hijacks (see
// internal/buildkitproxy.Mediator and cmd/serve.go's withBuildkitMediator).
// Deliberately narrower than matchesBuildkitTunnelInspection above, which
// also matches the literal /moby.buildkit.v1.Control/* probe path: that path
// carries no upgrade at all (see buildkit.go's inspect doc comment below)
// and is never handed to the mediator, so it must not be reported here.
func IsBuildkitTunnelPath(normalizedPath string) bool {
	return normalizedPath == "/session" || normalizedPath == "/grpc"
}

// buildkitPolicy is the request-time inspector for the BuildKit tunnel
// endpoints. Unlike every other inspector in this package it never reads
// the request body — there is nothing to decode at this layer even now that
// a real mediator exists; that mediator (internal/buildkitproxy) runs
// downstream, in the hijack tier of cmd/serve.go's handler chain, on
// whatever this inspector admits.
//
// Why this exists at all: cmd/rules.go's validateBuildkitTunnelRulesForPolicy
// treats a configured request_body.buildkit block as satisfying the same
// startup admission check insecure_accept_opaque_buildkit_tunnels does, so a
// rule allowing POST /session or POST /grpc no longer fails config
// validation once request_body.buildkit is set. Phase 1 (deny-only) ran
// before any mediator existed, so it denied both endpoints unconditionally
// once TunnelConfigured; Phase 2 replaces that with real admission — POST
// /session and POST /grpc pass through here (buildkitproxy.Mediator
// enforces Classify + Policy.Allowed per gRPC method downstream, once the
// h2c tunnel is actually terminated) — but the literal
// /moby.buildkit.v1.Control/<Method> probe path stays hard-denied
// regardless of TunnelConfigured: it carries no h2c upgrade for any mediator
// to terminate (sockguard's listener has no bare-h2c support outside the
// two hijack-capable endpoints — see cmd/rules.go's buildkitTunnelEndpoints
// doc comment), so there is nothing to bridge, only a bare HTTP/1.1 request
// shaped like a gRPC path.
//
// When TunnelConfigured is false (the overwhelmingly common case — no
// request_body.buildkit block at all), inspect is a no-op and the request
// falls through to whatever insecure_accept_opaque_buildkit_tunnels already
// allowed, unchanged from pre-#185 behavior.
type buildkitPolicy struct {
	tunnelConfigured bool
}

func newBuildkitPolicy(cfg BuildkitOptions) buildkitPolicy {
	return buildkitPolicy{tunnelConfigured: cfg.TunnelConfigured}
}

func (p buildkitPolicy) inspect(_ *slog.Logger, r *http.Request, _ string) (string, error) {
	if !p.tunnelConfigured {
		return "", nil
	}

	normPath := NormalizePath(r.URL.Path)
	if IsBuildkitTunnelPath(normPath) {
		// Admitted: internal/buildkitproxy.Mediator (wired in via cmd/serve.go's
		// withBuildkitMediator, downstream in the hijack tier) terminates the
		// h2c tunnel and enforces per-gRPC-method policy from here.
		return "", nil
	}

	service, method, ok := buildkitproxy.ParseGRPCPath(normPath)
	if !ok {
		return fmt.Sprintf("request_body.buildkit is configured, but %q could not be parsed as a gRPC method path", normPath), nil
	}
	disposition := buildkitproxy.Classify(buildkitproxy.EndpointGRPC, service, method)
	return fmt.Sprintf(
		"request_body.buildkit is configured; a literal moby.buildkit.v1.Control method path carries no h2c upgrade for sockguard's mediator to terminate, so %s/%s is denied regardless of its own %s classification — use the mediated POST /grpc tunnel instead",
		service, method, disposition,
	), nil
}
