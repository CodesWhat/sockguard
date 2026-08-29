// Package buildkitproxy also carries Phase 2 of issue #185: the h2c
// termination/bridging transport (this file, bridge.go, upgrade.go,
// limits.go, session.go, grpcpath.go, grpcstatus.go) that Classify's method
// registry (registry.go) exists to be consulted by. See each file's doc
// comment for its slice of the design; Mediator below is the entry point
// cmd/serve.go's request-handling chain calls into.
package buildkitproxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// Dialer is the minimal upstream-dialing seam the mediator needs to reach
// the Docker daemon for the daemon-side leg of a bridged tunnel.
// *upstream.Resolver satisfies this interface structurally; this package
// deliberately does not import internal/upstream (or internal/clientacl, for
// the caller-supplied SessionKey — see its doc comment) to stay the
// dependency-light leaf package registry.go's doc comment describes.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Mediator terminates and bridges the two opaque BuildKit HTTP tunnels
// (POST /session, POST /grpc) once request_body.buildkit is configured for
// the request's active policy. One Mediator is shared across every request
// on a listener; it holds no per-request state beyond what SessionRegistry
// tracks.
type Mediator struct {
	Dialer   Dialer
	Logger   *slog.Logger
	Limits   Limits
	Registry *SessionRegistry
}

// NewMediator returns a Mediator with Phase 2's default DoS budget (see
// DefaultLimits) and a fresh, empty SessionRegistry.
func NewMediator(dialer Dialer, logger *slog.Logger) *Mediator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Mediator{
		Dialer:   dialer,
		Logger:   logger,
		Limits:   DefaultLimits(),
		Registry: NewSessionRegistry(),
	}
}

// ServeGRPC mediates a POST /grpc upgrade: the Docker client is the gRPC
// client, buildkitd is the server. key identifies the session for the
// registry (see SessionKey's doc comment) and policy is the already-resolved
// effective policy for this request (global or client-profile) — the caller
// resolves both before calling, e.g. from internal/clientacl's client-
// profile selection plus a stable verified principal signal.
func (m *Mediator) ServeGRPC(w http.ResponseWriter, r *http.Request, policy Policy, key SessionKey) {
	m.serve(EndpointGRPC, w, r, policy, key)
}

// ServeSession mediates a POST /session upgrade. Per the #185 synthesis,
// roles are reversed from ServeGRPC: buildkitd becomes the gRPC client,
// dialing calls back over the SAME hijacked connection into the Docker
// client's session server (Auth, Secrets, SSH, FileSync, FileSend, Upload).
func (m *Mediator) ServeSession(w http.ResponseWriter, r *http.Request, policy Policy, key SessionKey) {
	m.serve(EndpointSession, w, r, policy, key)
}

func (m *Mediator) serve(endpoint Endpoint, w http.ResponseWriter, r *http.Request, policy Policy, key SessionKey) {
	logPath := r.URL.Path

	if err := ValidateUpgradeRequest(r); err != nil {
		m.Logger.Warn("buildkit: rejecting malformed h2c upgrade request",
			"error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath), "endpoint", endpoint.String())
		_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: "invalid BuildKit tunnel upgrade request"})
		return
	}
	clientUUID := ""
	if endpoint == EndpointSession {
		var ok bool
		clientUUID, ok = buildkitSessionID(r)
		if !ok {
			m.Logger.Warn("buildkit: rejecting session tunnel without one valid session id",
				"path", logging.SafeString(logPath), "endpoint", endpoint.String())
			_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: "invalid BuildKit session identifier"})
			return
		}
	}

	outHeader := r.Header.Clone()
	if endpoint == EndpointSession {
		rewriteSessionAdvertisement(outHeader, policy)
	}

	dialCtx, cancel := context.WithTimeout(r.Context(), h2cDialTimeout)
	defer cancel()
	daemonConn, daemonResp, err := dialDaemonH2C(dialCtx, m.Dialer, r.URL.Path, outHeader)
	if err != nil {
		m.Logger.Error("buildkit: daemon h2c upgrade failed",
			"error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath), "endpoint", endpoint.String())
		_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "upstream BuildKit daemon unreachable or refused h2c upgrade"})
		return
	}
	_ = daemonResp.Body.Close()

	clientConn, err := hijackClientH2C(w, daemonResp)
	if err != nil {
		m.Logger.Error("buildkit: client hijack failed",
			"error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath), "endpoint", endpoint.String())
		closeConnLogged(m.Logger, daemonConn, "daemon connection", logPath)
		return
	}

	session := m.Registry.Open(key, endpoint, clientUUID)
	defer m.Registry.Close(session.ID)

	legs := bridgeLegs{endpoint: endpoint}
	switch endpoint {
	case EndpointGRPC:
		legs.serverConn, legs.clientConn = clientConn, daemonConn
	case EndpointSession:
		legs.serverConn, legs.clientConn = daemonConn, clientConn
	}

	m.Logger.Info("buildkit: tunnel opened",
		"endpoint", endpoint.String(), "session_id", session.ID, "profile", logging.SafeString(key.Profile), "path", logging.SafeString(logPath))

	if err := runBridge(r.Context(), legs, session, policy, effectiveLimits(m.Limits, policy), m.Logger, m.Registry, nil); err != nil {
		m.Logger.Warn("buildkit: tunnel terminated",
			"error", logging.SafeString(err.Error()), "endpoint", endpoint.String(), "session_id", session.ID)
		return
	}
	m.Logger.Info("buildkit: tunnel closed", "endpoint", endpoint.String(), "session_id", session.ID)
}

func buildkitSessionID(r *http.Request) (string, bool) {
	values := r.Header.Values(sessionUUIDHeader)
	if len(values) != 1 {
		return "", false
	}
	return canonicalBuildkitSessionID(values[0])
}

// effectiveLimits merges Phase 5 (issue #185)'s per-profile FileSync/
// FileSend/Upload cap overrides (policy.Session.{FileSync,FileSend,Upload})
// on top of base (m.Limits, one value shared by every profile — see
// Mediator's doc comment) for the single tunnel about to be bridged. A
// configured, positive per-profile value replaces the corresponding base
// field; zero (the default when a profile's request_body.buildkit.session
// cap block sets nothing) leaves base's hardcoded secure default in place —
// see limits.go's Phase 5 field doc comments and FileSyncPolicy's doc
// comment for this zero-means-default convention. Every other Limits field
// (the Phase 2 DoS budget) is untouched: those have no per-profile knob by
// design (Limits' own doc comment) and stay exactly base's value.
func effectiveLimits(base Limits, policy Policy) Limits {
	out := base
	if v := policy.Session.FileSync.MaxFiles; v > 0 {
		out.MaxFileSyncFiles = v
	}
	if v := policy.Session.FileSync.MaxTotalBytes; v > 0 {
		out.MaxFileSyncTotalBytes = v
	}
	if v := policy.Session.FileSync.MaxPathLength; v > 0 {
		out.MaxFileSyncPathLength = v
	}
	if v := policy.Session.FileSync.MaxFileBytes; v > 0 {
		out.MaxFileSyncFileBytes = v
	}
	if v := policy.Session.FileSend.MaxBytes; v > 0 {
		out.MaxFileSendBytes = v
	}
	if v := policy.Session.Upload.MaxBytes; v > 0 {
		out.MaxUploadBytes = v
	}
	return out
}

func closeConnLogged(logger *slog.Logger, conn net.Conn, label, path string) {
	if err := conn.Close(); err != nil {
		logger.Debug("buildkit: failed to close "+label, "error", logging.SafeString(err.Error()), "path", logging.SafeString(path))
	}
}
