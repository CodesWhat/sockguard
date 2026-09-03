package cmd

// upstream_test.go — focused tests for upstream.go's resolver-selection and
// startup-reachability helpers, targeting gremlins mutation-testing survivors.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

// ---------------------------------------------------------------------------
// upstream.go:160 — CONDITIONALS_NEGATION: `if res != nil { return res }`
// inside upstreamResolverFor. Mutation flips != to ==, so a caller-supplied
// resolver would be discarded and a brand-new single-socket resolver
// returned in its place.
// Kill: assert the exact same *upstream.Resolver pointer comes back when a
// non-nil one is supplied.
// ---------------------------------------------------------------------------

func TestUpstreamResolverFor(t *testing.T) {
	t.Run("non-nil res is returned unchanged", func(t *testing.T) {
		res := upstream.NewSingleSocket("/tmp/whatever.sock")
		cfg := &config.Config{}
		cfg.Upstream.Socket = "/different.sock"

		got := upstreamResolverFor(res, cfg)
		if got != res {
			t.Fatalf("upstreamResolverFor(non-nil, cfg) returned a different resolver, want the same pointer")
		}
	})

	t.Run("nil res falls back to a single-socket resolver from cfg", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Upstream.Socket = "/legacy.sock"

		got := upstreamResolverFor(nil, cfg)
		if got == nil {
			t.Fatal("upstreamResolverFor(nil, cfg) = nil, want a constructed resolver")
		}
		eps := got.Endpoints()
		if len(eps) != 1 || eps[0].Address != "/legacy.sock" {
			t.Fatalf("upstreamResolverFor(nil, cfg).Endpoints() = %+v, want single endpoint at /legacy.sock", eps)
		}
	})
}

// ---------------------------------------------------------------------------
// upstream.go:170 — CONDITIONALS_NEGATION: `if runtime == nil` inside
// runtimeResolver. Mutation flips == to !=, so a non-nil runtime with a real
// resolver would be routed through upstreamResolverFor(nil, cfg) instead of
// its own resolver, silently discarding the shared resolver in the common
// case.
// Kill: assert runtime.resolver (identity) is returned unchanged when
// runtime and runtime.resolver are both non-nil.
// ---------------------------------------------------------------------------

func TestRuntimeResolver(t *testing.T) {
	cfg := &config.Config{}
	cfg.Upstream.Socket = "/legacy.sock"

	t.Run("non-nil runtime returns its own resolver", func(t *testing.T) {
		res := upstream.NewSingleSocket("/shared.sock")
		rt := &serveRuntime{resolver: res}

		got := runtimeResolver(rt, cfg)
		if got != res {
			t.Fatalf("runtimeResolver(non-nil runtime, cfg) returned a different resolver than runtime.resolver, want the same pointer")
		}
	})

	t.Run("nil runtime falls back to cfg-derived resolver", func(t *testing.T) {
		got := runtimeResolver(nil, cfg)
		if got == nil {
			t.Fatal("runtimeResolver(nil, cfg) = nil, want a constructed resolver")
		}
		eps := got.Endpoints()
		if len(eps) != 1 || eps[0].Address != "/legacy.sock" {
			t.Fatalf("runtimeResolver(nil, cfg).Endpoints() = %+v, want single endpoint at /legacy.sock", eps)
		}
	})
}

// ---------------------------------------------------------------------------
// upstream.go:183 — CONDITIONALS_NEGATION (x2): `if runtime == nil ||
// runtime.legacyUpstreamSocket || runtime.resolver == nil` inside
// verifyUpstreamReachableForRuntime, selecting between the legacy
// deps.verifyUpstreamReachable dial and the resolver's own CheckReachable.
// Negating `runtime == nil` makes the legacy path fire whenever runtime is
// non-nil (the common multi-endpoint case never reaches the resolver probe).
// Negating `runtime.resolver == nil` makes the legacy path fire whenever
// runtime.resolver is non-nil (same effect, opposite trigger).
// Kill: for each disjunct, construct the scenario where only that disjunct
// should determine the path, and assert exactly one of the two probes ran.
// ---------------------------------------------------------------------------

func TestVerifyUpstreamReachableForRuntime_PathSelection(t *testing.T) {
	cfg := &config.Config{}
	cfg.Upstream.Socket = "/legacy.sock"

	newCountingDeps := func() (*serveDeps, *int) {
		deps := newServeTestDeps()
		calls := 0
		deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) {
			calls++
			return &serveTestConn{}, nil
		}
		return deps, &calls
	}

	newCountingResolver := func(t *testing.T) (*upstream.Resolver, *int) {
		t.Helper()
		probeCalls := 0
		res, err := upstream.New([]upstream.Endpoint{
			{Name: "e", Network: "unix", Address: "/endpoint.sock"},
		}, upstream.Options{
			Probe: func(context.Context, upstream.Endpoint) error {
				probeCalls++
				return nil
			},
		})
		if err != nil {
			t.Fatalf("upstream.New() error = %v", err)
		}
		return res, &probeCalls
	}

	t.Run("nil runtime uses the legacy dial", func(t *testing.T) {
		deps, legacyCalls := newCountingDeps()
		if err := verifyUpstreamReachableForRuntime(context.Background(), deps, nil, cfg, newDiscardLogger()); err != nil {
			t.Fatalf("verifyUpstreamReachableForRuntime() error = %v", err)
		}
		if *legacyCalls != 1 {
			t.Fatalf("legacy dialUpstream calls = %d, want 1", *legacyCalls)
		}
	})

	t.Run("legacyUpstreamSocket true uses the legacy dial even with a resolver", func(t *testing.T) {
		deps, legacyCalls := newCountingDeps()
		res, probeCalls := newCountingResolver(t)
		rt := &serveRuntime{legacyUpstreamSocket: true, resolver: res}
		if err := verifyUpstreamReachableForRuntime(context.Background(), deps, rt, cfg, newDiscardLogger()); err != nil {
			t.Fatalf("verifyUpstreamReachableForRuntime() error = %v", err)
		}
		if *legacyCalls != 1 {
			t.Fatalf("legacy dialUpstream calls = %d, want 1", *legacyCalls)
		}
		if *probeCalls != 0 {
			t.Fatalf("resolver probe calls = %d, want 0", *probeCalls)
		}
	})

	t.Run("nil resolver uses the legacy dial", func(t *testing.T) {
		deps, legacyCalls := newCountingDeps()
		rt := &serveRuntime{}
		if err := verifyUpstreamReachableForRuntime(context.Background(), deps, rt, cfg, newDiscardLogger()); err != nil {
			t.Fatalf("verifyUpstreamReachableForRuntime() error = %v", err)
		}
		if *legacyCalls != 1 {
			t.Fatalf("legacy dialUpstream calls = %d, want 1", *legacyCalls)
		}
	})

	t.Run("non-legacy runtime with a resolver uses CheckReachable, not the legacy dial", func(t *testing.T) {
		deps, legacyCalls := newCountingDeps()
		res, probeCalls := newCountingResolver(t)
		rt := &serveRuntime{resolver: res}
		if err := verifyUpstreamReachableForRuntime(context.Background(), deps, rt, cfg, newDiscardLogger()); err != nil {
			t.Fatalf("verifyUpstreamReachableForRuntime() error = %v", err)
		}
		if *legacyCalls != 0 {
			t.Fatalf("legacy dialUpstream calls = %d, want 0 (resolver path should have been used)", *legacyCalls)
		}
		if *probeCalls == 0 {
			t.Fatal("resolver probe calls = 0, want at least 1 (CheckReachable never ran)")
		}
	})
}
