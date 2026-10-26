package buildkitproxy

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestGatewayRegistryLimitsAndCleanup(t *testing.T) {
	r := NewSessionRegistry()
	key := SessionKey{"client", "profile"}
	s := r.Open(key, EndpointGRPC, "")
	t.Cleanup(func() { r.Close(s.ID) })
	var builds []*gatewayBuild
	for i := 0; i < maxGatewayBuildsPerPrincipal; i++ {
		ref := fmt.Sprintf("build-%d", i)
		g, d := r.beginGatewayBuild(context.Background(), s, ref, "session", allowAllPolicy)
		if d != nil {
			t.Fatal(d)
		}
		if result := r.admitSolve(s, "session", ref, nil, 0, 0); result != solveAdmissionSucceeded {
			t.Fatal(result)
		}
		builds = append(builds, g)
	}
	if _, d := r.beginGatewayBuild(context.Background(), s, "excess", "session", allowAllPolicy); d == nil {
		t.Fatal("active build cap was bypassed")
	}
	if _, d := r.beginGatewayBuild(context.Background(), s, builds[0].ref, "session", allowAllPolicy); d == nil {
		t.Fatal("duplicate root replaced an active policy")
	}
	g := builds[0]
	for range maxGatewaySolvesPerBuild {
		if !r.admitGatewaySolve(g) {
			t.Fatal("solve cap fired early")
		}
	}
	if r.admitGatewaySolve(g) {
		t.Fatal("solve cap was bypassed")
	}
	r.endGatewayBuild(g)
	if r.gatewayBuild(key, g.ref) != nil || !errors.Is(context.Cause(g.ctx), errGatewayComplete) {
		t.Fatal("completed gateway remained active")
	}
	replacement, d := r.beginGatewayBuild(context.Background(), s, g.ref, "session", allowAllPolicy)
	if d != nil {
		t.Fatal(d)
	}
	r.endGatewayBuild(g)
	if r.gatewayBuild(key, g.ref) != replacement {
		t.Fatal("old cleanup removed the replacement build")
	}
	r.Close(s.ID)
	if replacement.ctx.Err() == nil || r.gatewayBuild(key, replacement.ref) != nil || len(r.gatewayBuilds) != 0 {
		t.Fatal("closing a tunnel retained a gateway capability or timer")
	}
}

func TestFrontendGatewayRequiresBothGrants(t *testing.T) {
	for _, allowSolve := range []bool{false, true} {
		for _, allowGateway := range []bool{false, true} {
			p := Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: allowSolve, AllowFrontendGateway: allowGateway}}}
			if p.Allowed(EndpointGRPC, gatewayService, "Solve") != (allowSolve && allowGateway) {
				t.Fatal("gateway granted without both opt-ins")
			}
			if p.Allowed(EndpointSession, gatewayService, "Solve") || p.Allowed(EndpointGRPC, gatewayService, "NewContainer") {
				t.Fatal("gateway grant enabled another execution path")
			}
		}
	}
}
