package buildkitproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"

	"github.com/codeswhat/sockguard/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/internal/logging"
)

// errMessageTooLarge is returned by limitedReadCloser once a stream's
// cumulative bytes exceed its configured cap. It is a stream-local
// condition, never grounds for tearing down the whole tunnel — see
// bridge.forward's handling.
var errMessageTooLarge = errors.New("buildkitproxy: message exceeds configured size cap")

// bridgeLegs names the two connections a mediated tunnel bridges, already
// assigned to their h2c ROLE (not their client/daemon identity, which
// differs by endpoint — see the doc comments on Mediator.ServeGRPC/
// ServeSession): serverConn is where sockguard runs http2.Server.ServeConn
// (accepting incoming streams as one *http.Request per stream), and
// clientConn is the connection sockguard dials outbound requests on via an
// http2.Transport-backed http2.ClientConn.
//
// For EndpointGRPC (POST /grpc): serverConn is the hijacked Docker-client
// connection (the client is the gRPC client dialing IN to sockguard),
// clientConn is sockguard's own dial to the daemon (the daemon is the gRPC
// server sockguard dials OUT to).
//
// For EndpointSession (POST /session), per the #185 synthesis's reversed
// roles: serverConn is sockguard's own dial to the daemon (buildkitd
// becomes the gRPC CLIENT, dialing calls in over that connection),
// clientConn is the hijacked Docker-client connection (the CLI runs the
// gRPC SERVER for Auth/Secrets/SSH/FileSync/FileSend/Upload on its side of
// that same hijacked connection).
type bridgeLegs struct {
	endpoint   Endpoint
	serverConn net.Conn
	clientConn net.Conn
}

// clientLegConn is the minimal surface bridge.forward and bridge.closeAll
// need from the client leg's HTTP/2 connection. *http2.ClientConn satisfies
// this structurally in production; tests exercising forward()'s error
// handling (a genuine RoundTrip failure vs. a response-body copy failure vs.
// the size-cap path) use a hand-rolled fake instead of driving a real
// network round trip end to end, since those specific failure modes aren't
// reproducible deterministically over a live http2.ClientConn.
type clientLegConn interface {
	RoundTrip(*http.Request) (*http.Response, error)
	Close() error
}

// bridge holds the per-tunnel state the routing handler (handleStream)
// closes over: which session this is, what policy/limits govern it, and the
// single client-leg connection every admitted stream is relayed through.
type bridge struct {
	legs     bridgeLegs
	session  *Session
	policy   Policy
	limits   Limits
	logger   *slog.Logger
	guard    *streamAbuseGuard
	registry *SessionRegistry

	clientLeg clientLegConn

	// credentialCalls is Phase 4's per-session credential-call counter — see
	// Limits.MaxCredentialCallsPerSession and forwardSessionMediated
	// (bridge_session.go) for what it bounds. atomic.Int64 rather than a
	// mutex-guarded int since concurrent http2.Server handler goroutines (one
	// per stream) may all be admitting Auth/Secrets/SSH calls at once.
	credentialCalls atomic.Int64

	closeOnce sync.Once
	closeMu   sync.Mutex
	closeErr  error
}

// runBridge terminates legs.serverConn as h2c, dials legs.clientConn as an
// h2c client, and relays every admitted stream between them until the
// connection ends (gracefully or otherwise). It blocks until done. A
// non-nil return means the tunnel was torn down because of a protocol/
// transport-level failure — a Deny'd stream or a size-cap trip on an
// otherwise-healthy connection is NOT such a failure and does not produce a
// non-nil return (see bridge.forward and bridge.recordDeniedAndMaybeClose,
// which close early only once the DeniedStreamBudget itself is exceeded).
// registry is the same SessionRegistry session was opened from — Phase 3's
// forwardControlMediated consults it (via SessionKey, not session.ID; see
// SessionRegistry.OwnsRef's doc comment) to admit Control/Solve refs and
// check Control/Status ref ownership.
func runBridge(ctx context.Context, legs bridgeLegs, session *Session, policy Policy, limits Limits, logger *slog.Logger, registry *SessionRegistry) error {
	b := &bridge{
		legs:     legs,
		session:  session,
		policy:   policy,
		limits:   limits,
		logger:   logger,
		guard:    newStreamAbuseGuard(limits),
		registry: registry,
	}
	defer b.closeAll(nil)

	clientTransport := &http2.Transport{AllowHTTP: true}
	cc, err := clientTransport.NewClientConn(legs.clientConn)
	if err != nil {
		// Route this through closeAll/finalErr too, rather than returning
		// fmt.Errorf(...) directly: closeOnce still gives at-most-once
		// semantics (the deferred closeAll(nil) above is a no-op once this
		// call has already fired), and it keeps runBridge's error return
		// flowing through the single synchronized path finalErr provides —
		// see closeAll's doc comment for why a direct field read isn't safe.
		b.closeAll(fmt.Errorf("buildkitproxy: establish client leg: %w", err))
		return b.finalErr()
	}
	b.clientLeg = cc

	srv := &http2.Server{
		MaxConcurrentStreams: limits.MaxConcurrentStreams,
		IdleTimeout:          limits.IdleTimeout,
		ReadIdleTimeout:      limits.ReadIdleTimeout,
	}
	srv.ServeConn(legs.serverConn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: http.HandlerFunc(b.handleStream),
	})

	return b.finalErr()
}

// closeAll closes both legs of the tunnel exactly once. err, if non-nil, is
// recorded as runBridge's return value — used for genuine protocol/transport
// failures per the #185 Phase 2 scope's fail-closed requirement ("any error
// in the bridge... must terminate the tunnel, never fall back to opaque
// proxying"). A nil err (the normal path, via runBridge's deferred call)
// just performs cleanup after a graceful end.
//
// closeAll is called from both runBridge's own goroutine (the deferred
// cleanup, and the early client-leg-handshake-failure path) and stream
// handler goroutines http2.Server spawns (recordDeniedAndMaybeClose, forward)
// — closeErr is guarded by closeMu, not just closeOnce, because closing
// legs.serverConn here and runBridge's ServeConn call noticing that closure
// and returning are NOT themselves a synchronization point the Go memory
// model recognizes: without closeMu, runBridge reading closeErr after
// ServeConn returns would be a data race with a handler goroutine's write
// inside this closure. See finalErr, which every closeErr read must go
// through instead of touching the field directly.
func (b *bridge) closeAll(err error) {
	b.closeOnce.Do(func() {
		b.closeMu.Lock()
		b.closeErr = err
		b.closeMu.Unlock()
		if b.clientLeg != nil {
			_ = b.clientLeg.Close()
		}
		_ = b.legs.clientConn.Close()
		_ = b.legs.serverConn.Close()
	})
}

// finalErr returns the error closeAll recorded (nil if closeAll was never
// called, or was called with nil) — the only safe way to read closeErr once
// more than one goroutine may have touched it. See closeAll's doc comment.
func (b *bridge) finalErr() error {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()
	return b.closeErr
}

// handleStream is the http.Handler golang.org/x/net/http2.Server invokes
// once per HTTP/2 stream on the server leg — one *http.Request per gRPC
// call, per the #185 synthesis's chosen bridging granularity (see
// registry.go's package doc). It classifies the call's fully-qualified
// method through the Phase 1 registry, then — for a Mediate or Passthrough
// category — checks whether this request's Policy actually turned that
// category on (Policy.Allowed; see its doc comment for why this is a
// separate, necessary gate). A call that clears both checks is, for every
// method EXCEPT moby.buildkit.v1.Control's Solve/Status, relayed
// byte-for-byte to the client leg with no message-content decision (Phase
// 2's scope; the remaining Session-endpoint Mediate methods — Auth, Secrets,
// SSH, FileSync, FileSend, Upload — get their own per-message mediation in
// Phases 4-5). Solve/Status route through forwardControlMediated instead —
// see isControlMediatedMethod.
func (b *bridge) handleStream(w http.ResponseWriter, r *http.Request) {
	service, method, ok := ParseGRPCPath(r.URL.Path)
	if !ok {
		writeGRPCStatus(w, grpcCodeUnimplemented, "malformed gRPC method path")
		b.audit("", "", Deny, "buildkit_protocol_error")
		b.recordDeniedAndMaybeClose()
		return
	}

	disposition := Classify(b.legs.endpoint, service, method)
	switch disposition {
	case Mediate, Passthrough:
		if !b.policy.Allowed(b.legs.endpoint, service, method) {
			// The method's CATEGORY is eligible for mediation (Classify), but
			// this operator's policy never turned it on (Policy.Allowed) —
			// see policy.go's Allowed doc comment for why this is a separate,
			// necessary gate rather than duplicate denial.
			writeGRPCStatus(w, grpcCodePermissionDenied, fmt.Sprintf("%s/%s is not enabled by this profile's request_body.buildkit policy", service, method))
			b.audit(service, method, Deny, "buildkit_policy_denied")
			b.recordDeniedAndMaybeClose()
			return
		}
		if isControlMediatedMethod(b.legs.endpoint, service, method) {
			// Phase 3: Control/Solve and Control/Status get per-message
			// decode/policy mediation instead of Phase 2's byte-verbatim
			// relay — forwardControlMediated audits its own outcome (Mediate
			// on admit, Deny with a specific reason on any check failure),
			// so it is NOT also audited generically below.
			b.forwardControlMediated(w, r, service, method)
			return
		}
		if isSessionMediatedMethod(b.legs.endpoint, service, method) {
			// Phase 4: Auth/Secrets/SSH get their own per-message decode/
			// policy mediation instead of the plain byte-verbatim relay below
			// — forwardSessionMediated audits its own outcome, so it is NOT
			// also audited generically here. FileSync/FileSend/Upload are NOT
			// in isSessionMediatedMethod's true set (Phase 5's scope) and
			// fall through to the plain forward exactly as before.
			b.forwardSessionMediated(w, r, service, method)
			return
		}
		b.audit(service, method, disposition, "")
		b.forward(w, r, service, method)
	default:
		// Deny, and (defensively) anything Classify might ever return that
		// isn't Mediate/Passthrough — fail closed rather than assume a new
		// Disposition value is safe to forward.
		writeGRPCStatus(w, grpcCodePermissionDenied, fmt.Sprintf("%s/%s is denied by sockguard's BuildKit mediation policy", service, method))
		b.audit(service, method, Deny, "buildkit_method_denied")
		b.recordDeniedAndMaybeClose()
	}
}

// recordDeniedAndMaybeClose records a Deny/protocol-error stream against the
// connection's abuse budget and tears the whole tunnel down once that budget
// is exceeded — see Limits' doc comment for why a burst of denials is
// itself an abuse signal on a connection that should almost never produce
// one.
func (b *bridge) recordDeniedAndMaybeClose() {
	if b.guard.recordDenied() {
		b.logger.Warn("buildkit: denied-stream budget exceeded; terminating tunnel",
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.closeAll(errors.New("buildkitproxy: denied-stream abuse budget exceeded"))
	}
}

// forward relays one admitted (Mediate or Passthrough) stream to the client
// leg, preserving original request/response bytes verbatim — no protobuf
// decode/re-encode on this path (Phase 2 scope, and still true for every
// Phase 3+ method that isn't Control/Solve or Control/Status). It is a thin
// wrapper over forwardWithBody using the stream's own r.Body unmodified;
// forwardControlMediated instead supplies an already-buffered, already
// policy-checked body (the exact bytes readUnaryGRPCMessage read) once its
// own decode/policy checks pass.
func (b *bridge) forward(w http.ResponseWriter, r *http.Request, service, method string) {
	b.forwardWithBody(w, r, service, method, r.Body)
}

// forwardWithBody does forward's actual relay work against an explicit body
// rather than always r.Body — see forward's doc comment for why.  A genuine
// RoundTrip/transport failure tears the whole tunnel down (fail-closed); a
// size-cap trip on either direction ends only this stream with a
// RESOURCE_EXHAUSTED gRPC status, since an oversized single message is a
// per-RPC condition, not evidence the connection itself is compromised.
func (b *bridge) forwardWithBody(w http.ResponseWriter, r *http.Request, service, method string, body io.ReadCloser) {
	host := r.Host
	if host == "" {
		host = "buildkitd"
	}

	outReq := &http.Request{
		Method:        r.Method,
		URL:           &url.URL{Scheme: "http", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery},
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        r.Header.Clone(),
		Host:          host,
		Body:          newLimitedReadCloser(body, b.limits.MaxMessageBytes),
		ContentLength: -1,
	}

	resp, err := b.clientLeg.RoundTrip(outReq)
	if err != nil {
		if errors.Is(err, errMessageTooLarge) {
			writeGRPCStatus(w, grpcCodeResourceExhausted, "request message exceeds sockguard's size cap")
			b.audit(service, method, Deny, "buildkit_message_too_large")
			return
		}
		b.logger.Warn("buildkit: forwarding stream failed; terminating tunnel",
			"error", logging.SafeString(err.Error()), "service", logging.SafeString(service), "method", logging.SafeString(method),
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.closeAll(fmt.Errorf("buildkitproxy: forward %s/%s: %w", service, method, err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	limitedBody := newLimitedReadCloser(resp.Body, b.limits.MaxMessageBytes)
	_, copyErr := io.Copy(flushWriter{w}, limitedBody)

	switch {
	case errors.Is(copyErr, errMessageTooLarge):
		writeGRPCTrailerStatus(w, grpcCodeResourceExhausted, "response message exceeds sockguard's size cap")
		b.audit(service, method, Deny, "buildkit_message_too_large")
	case copyErr != nil:
		b.logger.Warn("buildkit: relaying stream response failed; terminating tunnel",
			"error", logging.SafeString(copyErr.Error()), "service", logging.SafeString(service), "method", logging.SafeString(method),
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.closeAll(fmt.Errorf("buildkitproxy: relay %s/%s response: %w", service, method, copyErr))
	default:
		for k, vv := range resp.Trailer {
			for _, v := range vv {
				w.Header().Add(http.TrailerPrefix+k, v)
			}
		}
	}
}

// isControlMediatedMethod reports whether service/method on endpoint is one
// of Phase 3's two per-message-mediated Control RPCs — the only methods
// handleStream routes through forwardControlMediated instead of the plain
// byte-verbatim forward. Both are already Classify()'d Mediate and (by the
// time this is consulted) already passed Policy.Allowed — this function
// only decides which forwarding STRATEGY an already-admitted call uses.
func isControlMediatedMethod(endpoint Endpoint, service, method string) bool {
	if endpoint != EndpointGRPC || service != "moby.buildkit.v1.Control" {
		return false
	}
	return method == "Solve" || method == "Status"
}

// forwardControlMediated is Phase 3 (issue #185)'s per-message mediation
// path for Control/Solve and Control/Status: buffer the client's single gRPC
// request message (readUnaryGRPCMessage), decode it with the vendored
// buildkitproto stubs, run policy checks (evaluateSolveRequest /
// evaluateStatusRequest, plus Status's ref-ownership check below), and only
// on admission forward the exact original frame bytes via forwardWithBody —
// never a re-encoded message, per the #185 Phase 3 constraint. Every denial
// path here ends the STREAM only (a per-stream gRPC status plus
// recordDeniedAndMaybeClose's soft connection-abuse budget), matching the
// task's fail-closed granularity: "per-stream policy/decode failure -> gRPC
// status on that stream only, session survives."
func (b *bridge) forwardControlMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	frame, payload, err := readUnaryGRPCMessage(r.Body, b.limits.MaxMessageBytes)
	if err != nil {
		if errors.Is(err, errMessageTooLarge) {
			// Mirrors forward()'s own size-cap handling: a size-cap trip is a
			// per-RPC condition, not evidence of connection-level abuse, so
			// it is audited but not counted against recordDeniedAndMaybeClose
			// (see Limits' doc comment).
			writeGRPCStatus(w, grpcCodeResourceExhausted, "request message exceeds sockguard's size cap")
			b.audit(service, method, Deny, "buildkit_message_too_large")
			return
		}
		writeGRPCStatus(w, grpcCodeInvalidArgument, "malformed BuildKit gRPC request framing")
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.recordDeniedAndMaybeClose()
		return
	}

	var (
		d   *mediationDenial
		ref string
	)
	switch method {
	case "Solve":
		var req *control.SolveRequest
		req, d = evaluateSolveRequest(payload, b.policy)
		if req != nil {
			ref = req.GetRef()
		}
	case "Status":
		var req *control.StatusRequest
		req, d = evaluateStatusRequest(payload)
		if d == nil && !b.registry.OwnsRef(b.session.Key, req.GetRef()) {
			d = deny(grpcCodePermissionDenied, "buildkit_ref_not_owned", "this ref does not belong to an admitted Solve for this client/profile")
		}
	default:
		// Unreachable today — isControlMediatedMethod only routes Solve and
		// Status here — but if it and this switch ever drift (a method added
		// to one and not the other), fail CLOSED rather than fall through
		// with d and ref left at their zero values, which would forward the
		// message with ZERO policy evaluation in a package whose entire
		// identity is default-deny. See grpcCodeInternal's doc comment.
		d = deny(grpcCodeInternal, "buildkit_internal_error", "internal routing error")
	}

	if d != nil {
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
		return
	}

	if method == "Solve" {
		if !b.registry.PutRef(b.session, ref, b.limits.MaxRefsPerSession) {
			writeGRPCStatus(w, grpcCodeResourceExhausted, "too many concurrent BuildKit solve refs admitted for this client")
			b.audit(service, method, Deny, "buildkit_ref_limit_exceeded")
			b.recordDeniedAndMaybeClose()
			return
		}
	}

	b.audit(service, method, Mediate, "")
	b.forwardWithBody(w, r, service, method, io.NopCloser(bytes.NewReader(frame)))
}

// audit emits the #185 synthesis's buildkit_rpc audit event: one line per
// gRPC call carried inside the mediated tunnel. reasonCode is empty for an
// admitted (Mediate/Passthrough) call — only denials and errors carry one of
// the synthesis's low-cardinality reason codes. Never logs message content,
// credentials, or secret/SSH identifiers raw — this event carries only
// method identity and the routing decision, plus whatever extra attrs a
// caller supplies. extra is Phase 4's addition (bridge_session.go's
// forwardAuthMediated/forwardSecretsMediated/forwardCheckAgent/
// forwardSSHAgentStream): a registry host (low-cardinality, safe to log raw)
// or a secret/SSH agent ID hashed via shortHash (never raw) — every other
// caller in this package passes none, which is a no-op append.
func (b *bridge) audit(service, method string, disposition Disposition, reasonCode string, extra ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("event", "buildkit_rpc"),
		slog.String("endpoint", b.legs.endpoint.String()),
		slog.Uint64("session_id", b.session.ID),
		slog.String("profile", logging.SafeString(b.session.Profile)),
		slog.String("service", logging.SafeString(service)),
		slog.String("method", logging.SafeString(method)),
		slog.String("disposition", disposition.String()),
	}
	if reasonCode != "" {
		attrs = append(attrs, slog.String("reason_code", reasonCode))
	}
	attrs = append(attrs, extra...)
	level := slog.LevelDebug
	if disposition == Deny {
		level = slog.LevelInfo
	}
	b.logger.LogAttrs(context.Background(), level, "buildkit gRPC call routed", attrs...)
}

// flushWriter wraps an http.ResponseWriter so every Write flushes
// immediately, matching sockguard's existing FlushInterval:-1 convention
// (internal/proxy.NewWithTransport) for streaming endpoints — a mediated
// BuildKit stream is exactly that, and gRPC's framing already provides its
// own message boundaries so buffering here would only add latency, never
// throughput.
type flushWriter struct {
	w http.ResponseWriter
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

// limitedReadCloser caps the cumulative bytes read from r at limit,
// returning errMessageTooLarge once that many bytes are EXCEEDED — a body of
// exactly limit bytes must still reach the underlying reader's own io.EOF
// cleanly, never errMessageTooLarge. remaining tracks bytes still allowed,
// but Read buffers one byte past it (following the same technique as the
// stdlib's http.MaxBytesReader) so a single Read can distinguish "the
// underlying reader stopped at exactly the cap" from "there was at least one
// more byte beyond it" without needing a lookahead Read of its own. A limit
// <= 0 disables the cap (returns r unchanged).
type limitedReadCloser struct {
	r         io.ReadCloser
	remaining int64
}

func newLimitedReadCloser(r io.ReadCloser, limit int64) io.ReadCloser {
	if limit <= 0 || r == nil {
		return r
	}
	return &limitedReadCloser{r: r, remaining: limit}
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	// Compare by subtraction: l.remaining+1 overflows to math.MinInt64 when
	// the cap is math.MaxInt64, and p[:l.remaining+1] would panic. The slice
	// below is only reached when len(p)-1 > remaining, which bounds
	// remaining+1 <= len(p), so the addition there cannot overflow.
	if int64(len(p))-1 > l.remaining {
		p = p[:l.remaining+1]
	}
	n, err := l.r.Read(p)

	if int64(n) <= l.remaining {
		l.remaining -= int64(n)
		return n, err
	}

	// n is the one-byte-past-the-cap sentinel: the body is strictly larger
	// than limit, not merely equal to it. Report exactly limit bytes read
	// (never the sentinel byte itself) and errMessageTooLarge instead of err.
	n = int(l.remaining)
	l.remaining = 0
	return n, errMessageTooLarge
}

func (l *limitedReadCloser) Close() error {
	return l.r.Close()
}
