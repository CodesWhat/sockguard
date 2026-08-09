package filter

import (
	"log/slog"
	"net/http"
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

// buildkitTunnelPaths are the two opaque, unversioned BuildKit endpoints
// (see cmd/rules.go's buildkitTunnelEndpoints doc comment for the full
// rationale): POST /session, the frontend/session bridge, and POST /grpc,
// the moby.buildkit.v1.Control service tunneled over an HTTP/1.1 hijack.
// Matched against the ALREADY version-stripped normalized path, exactly
// like every other matches*Inspection function in this package.
func matchesBuildkitTunnelInspection(normalizedPath string) bool {
	return normalizedPath == "/session" || normalizedPath == "/grpc"
}

// buildkitPolicy is Phase 1's deny-only "inspector" for the BuildKit tunnel
// endpoints. Unlike every other inspector in this package it never reads
// the request body — there is nothing to mediate yet.
//
// Why this exists at all: cmd/rules.go's validateBuildkitTunnelRulesForPolicy
// treats a configured request_body.buildkit block as satisfying the same
// startup admission check insecure_accept_opaque_buildkit_tunnels does, so a
// rule allowing POST /session or POST /grpc no longer fails config
// validation once request_body.buildkit is set. But #185's mediator (h2c
// termination, per-RPC decode, the method-classification registry) doesn't
// exist until later phases — so without this inspector, an admitted rule
// would fall through to the ordinary ReverseProxy path and tunnel the
// connection completely opaquely, silently defeating the entire point of
// requiring request_body.buildkit in the first place. This inspector runs
// on every allowed request to either endpoint and denies unconditionally
// whenever TunnelConfigured is true, regardless of what any individual
// control/session sub-policy allows — Phase 1 is deny-only by design (see
// PolicyConfig.Buildkit's doc comment).
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

func (p buildkitPolicy) inspect(_ *slog.Logger, _ *http.Request, _ string) (string, error) {
	if !p.tunnelConfigured {
		return "", nil
	}
	return "request_body.buildkit is configured, but sockguard's BuildKit gRPC mediator is not implemented yet (issue #185 phase 1 ships the schema/policy foundation only) — the opaque tunnel is denied rather than proxied uninspected", nil
}
