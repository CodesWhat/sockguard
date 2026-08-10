package buildkitproxy

import (
	"sync"
	"time"
)

// Limits bounds resource use on a single mediated BuildKit tunnel (one
// hijacked /session or /grpc connection). Terminating a client-driven HTTP/2
// connection reopens the Rapid Reset class (CVE-2023-44487): a malicious
// client can open many streams and reset them before sockguard finishes
// classifying/forwarding, forcing repeated work per stream. golang.org/x/net
// v0.57.0 (this package's pinned version) already carries upstream's
// connection-level Rapid Reset mitigation inside http2.Server itself; Limits
// adds sockguard-specific, defense-in-depth caps on top: a hard concurrent
// stream ceiling and a budget on how many denied/errored streams a single
// connection may produce before sockguard tears the whole tunnel down,
// because a legitimate BuildKit client essentially never calls a Deny'd
// method at all — a burst of denials is itself an abuse signal, not just
// each individual denial being fine in isolation.
//
// There are no operator-facing config knobs for these values (issue #185
// Phase 2 sign-off: "no new knobs" — the request_body.buildkit block gates
// mediation as a whole, not its internal DoS budget), so the concrete
// numbers below are sockguard's own judgment call, not synthesized from the
// #185 design docs, which describe the categories of cap needed
// (MaxConcurrentStreams, stream-reset rate limiting, byte caps, idle
// timeouts) without prescribing values. They are deliberately generous
// relative to a real `docker buildx build` session (which opens at most a
// handful of concurrent streams — Solve, Status, FileSync, Auth, occasional
// Secrets/SSH) while still bounding the worst case an abusive client could
// impose.
type Limits struct {
	// MaxConcurrentStreams caps concurrent HTTP/2 streams sockguard will
	// accept on the server leg of a bridged tunnel (see bridge.go). Passed
	// straight through to http2.Server.MaxConcurrentStreams.
	MaxConcurrentStreams uint32

	// MaxMessageBytes caps the cumulative bytes sockguard will relay for a
	// single stream's request body and, separately, its response body.
	// Phase 2 forwards original bytes without decoding protobuf framing (see
	// registry.go's package doc), so this is a coarse per-stream cap, not a
	// per-length-prefixed-message one — later phases that actually decode
	// Mediate methods can tighten this per field.
	MaxMessageBytes int64

	// DeniedStreamBudget is the number of Deny-classified or
	// protocol-invalid streams sockguard tolerates on one tunnel connection
	// within DeniedStreamWindow before closing the whole connection. Zero
	// disables the budget (unlimited denials tolerated) — DefaultLimits
	// never does this.
	DeniedStreamBudget int

	// DeniedStreamWindow is the rolling window DeniedStreamBudget is counted
	// over.
	DeniedStreamWindow time.Duration

	// IdleTimeout closes a bridged tunnel connection that has carried no
	// stream activity for this long. Matches the value sockguard's existing
	// attach/exec hijack path uses (internal/proxy's hijackInactivityTimeout)
	// so operators see one consistent inactivity convention across every
	// long-lived connection sockguard terminates.
	IdleTimeout time.Duration

	// ReadIdleTimeout, when non-zero, makes http2.Server proactively PING an
	// otherwise-quiet connection to detect a half-dead peer faster than
	// IdleTimeout alone would (IdleTimeout only fires on total silence;
	// ReadIdleTimeout catches a peer that ACKs TCP but stopped speaking
	// HTTP/2).
	ReadIdleTimeout time.Duration

	// MaxRefsPerSession bounds how many distinct Control/Solve refs a single
	// mediated session (see session.go's SessionRegistry.PutRef) may admit
	// before sockguard starts refusing new Solve calls with
	// RESOURCE_EXHAUSTED — the #185 Phase 3 sign-off's "bound the per-session
	// ref count (DoS)" requirement: without a cap, a client could keep
	// calling Solve with a fresh Ref forever, growing the ref-ownership index
	// without limit for the lifetime of the connection. A real `docker
	// buildx build` session admits one Solve (occasionally a handful, for
	// multi-target bake); this is deliberately generous relative to that
	// while still bounding the worst case. Zero or negative disables the
	// bound — DefaultLimits never does this.
	MaxRefsPerSession int

	// MaxCredentialCallsPerSession bounds how many EndpointSession
	// credential-mediated calls — moby.filesync.v1.Auth's four RPCs,
	// Secrets/GetSecret, and SSH's CheckAgent/ForwardAgent — a single
	// mediated session may make before sockguard starts refusing further
	// ones with RESOURCE_EXHAUSTED — the #185 Phase 4 sign-off's per-session
	// credential-request quota. Unlike MaxRefsPerSession, an admitted call
	// here doesn't grow any registry-wide state; the risk it bounds is
	// different: every one of these RPCs unlocks live credential material (a
	// registry token, a secret payload, SSH agent access), and a client that
	// keeps calling an ADMITTED method never trips the denied-stream abuse
	// budget (recordDeniedAndMaybeClose only counts denials/errors), so
	// without this cap that traffic would otherwise be unbounded. A real
	// `docker buildx build` session makes at most a handful of these per
	// unique registry/secret/SSH mount; this is deliberately generous
	// relative to that while still bounding the worst case. Zero or negative
	// disables the bound — DefaultLimits never does this.
	MaxCredentialCallsPerSession int
}

// DefaultLimits returns sockguard's Phase 2 DoS budget. See Limits' doc
// comment for why these are hardcoded rather than configurable.
func DefaultLimits() Limits {
	return Limits{
		MaxConcurrentStreams: 100,
		MaxMessageBytes:      64 << 20, // 64 MiB
		DeniedStreamBudget:   20,
		DeniedStreamWindow:   10 * time.Second,
		IdleTimeout:          10 * time.Minute,
		ReadIdleTimeout:      30 * time.Second,
		MaxRefsPerSession:    256,

		MaxCredentialCallsPerSession: 512,
	}
}

// streamAbuseGuard tracks Deny/error events on one tunnel connection and
// reports when DeniedStreamBudget has been exceeded within
// DeniedStreamWindow, so the caller can close the whole connection rather
// than keep paying per-stream classification cost for an abusive client.
type streamAbuseGuard struct {
	mu     sync.Mutex
	budget int
	window time.Duration
	events []time.Time
	nowFn  func() time.Time
}

func newStreamAbuseGuard(limits Limits) *streamAbuseGuard {
	return &streamAbuseGuard{
		budget: limits.DeniedStreamBudget,
		window: limits.DeniedStreamWindow,
		nowFn:  time.Now,
	}
}

// recordDenied records one denied/errored stream and reports whether the
// connection-level budget has now been exceeded. A zero or negative budget
// disables the guard (always returns false).
func (g *streamAbuseGuard) recordDenied() bool {
	if g.budget <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFn()
	cutoff := now.Add(-g.window)
	kept := g.events[:0]
	for _, t := range g.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	g.events = kept

	return len(g.events) > g.budget
}
