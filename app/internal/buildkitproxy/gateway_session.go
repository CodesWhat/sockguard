package buildkitproxy

import (
	"context"
	"errors"
	"time"
)

const (
	maxGatewayBuildsPerPrincipal = 8
	maxGatewaySolvesPerBuild     = 256
	maxGatewayBuildDuration      = 30 * time.Minute
)

var errGatewayComplete = errors.New("frontend build finished")

type gatewayBuild struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	stopTimer context.CancelFunc
	session   *Session
	sessionID string
	ref       string
	policy    Policy
	solves    int
}

func (r *SessionRegistry) beginGatewayBuild(ctx context.Context, s *Session, ref, sessionID string, policy Policy) (*gatewayBuild, *mediationDenial) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[s.ID] != s {
		return nil, deny(grpcCodePermissionDenied, "buildkit_ref_not_owned", "build session is closed")
	}
	builds := r.gatewayBuilds[s.Key]
	if builds[ref] != nil {
		return nil, deny(grpcCodePermissionDenied, "buildkit_ref_not_owned", "frontend build ref is already active")
	}
	if len(builds) >= maxGatewayBuildsPerPrincipal {
		return nil, deny(grpcCodeResourceExhausted, "buildkit_ref_limit_exceeded", "too many active frontend builds")
	}
	deadlineCtx, stopTimer := context.WithTimeout(ctx, maxGatewayBuildDuration)
	buildCtx, cancel := context.WithCancelCause(deadlineCtx)
	g := &gatewayBuild{ctx: buildCtx, cancel: cancel, stopTimer: stopTimer, session: s, sessionID: sessionID, ref: ref, policy: policy}
	if r.gatewayBuilds == nil {
		r.gatewayBuilds = make(map[SessionKey]map[string]*gatewayBuild)
	}
	if builds == nil {
		builds = make(map[string]*gatewayBuild)
		r.gatewayBuilds[s.Key] = builds
	}
	builds[ref] = g
	return g, nil
}

func (r *SessionRegistry) endGatewayBuild(g *gatewayBuild) {
	r.mu.Lock()
	defer r.mu.Unlock()
	builds := r.gatewayBuilds[g.session.Key]
	if builds[g.ref] == g {
		delete(builds, g.ref)
		if len(builds) == 0 {
			delete(r.gatewayBuilds, g.session.Key)
		}
	}
	g.cancel(errGatewayComplete)
	g.stopTimer()
}

func (r *SessionRegistry) gatewayBuild(key SessionKey, ref string) *gatewayBuild {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := r.gatewayBuilds[key][ref]
	if g == nil || g.ctx.Err() != nil || r.sessions[g.session.ID] != g.session || r.refOwners[key][ref] == 0 || r.solveSessions[buildkitSessionKey{Principal: key, ID: g.sessionID}] == 0 {
		return nil
	}
	return g
}

func (r *SessionRegistry) admitGatewaySolve(g *gatewayBuild) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gatewayBuilds[g.session.Key][g.ref] != g || g.ctx.Err() != nil || g.solves >= maxGatewaySolvesPerBuild {
		return false
	}
	g.solves++
	return true
}
