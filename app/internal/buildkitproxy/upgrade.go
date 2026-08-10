package buildkitproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// h2cDialTimeout bounds sockguard's own dial-and-upgrade to the daemon side
// of a bridged tunnel. Matches internal/proxy's hijackDialTimeout convention
// (5s) — this package intentionally doesn't import internal/proxy (a leaf
// package should not depend on another leaf package's internals), so the
// value is restated rather than shared.
const h2cDialTimeout = 5 * time.Second

// sessionUUIDHeader is the client-supplied session correlation ID. Recorded
// on Session as advisory metadata only — see SessionKey's doc comment.
const sessionUUIDHeader = "X-Docker-Expose-Session-Uuid"

// sessionGRPCMethodHeader advertises, on a POST /session upgrade request,
// which gRPC services the client's session server has registered (e.g.
// "moby.filesync.v1.FileSync", "moby.filesync.v1.Auth") so buildkitd knows
// what it can call back into. rewriteSessionAdvertisement narrows this to
// the intersection of "advertised" and "permitted" before sockguard forwards
// the upgrade to the daemon.
const sessionGRPCMethodHeader = "X-Docker-Expose-Session-Grpc-Method"

var (
	// ErrNotUpgradeRequest is returned by ValidateUpgradeRequest when the
	// request isn't attempting an h2c upgrade at all.
	ErrNotUpgradeRequest = errors.New("buildkitproxy: not an h2c upgrade request")
	// ErrUpgradeHasBody is returned when the client sent body bytes on the
	// upgrade request itself — BuildKit's h2c upgrade (mirroring the
	// existing attach/exec hijack convention in internal/proxy) never
	// carries a request body; anything present is either a confused client
	// or an attempt to smuggle bytes past sockguard's inspection before the
	// connection becomes an opaque byte pipe.
	ErrUpgradeHasBody = errors.New("buildkitproxy: h2c upgrade request must not carry a body")
	// ErrConflictingFraming is returned when the request declares
	// Transfer-Encoding alongside an upgrade — a request can't simultaneously
	// be chunked-framed HTTP/1.1 and about to stop being HTTP/1.1 at all.
	ErrConflictingFraming = errors.New("buildkitproxy: h2c upgrade request must not declare Transfer-Encoding")
)

// ValidateUpgradeRequest strictly validates an incoming POST /session or
// POST /grpc request before sockguard attempts to bridge it: exactly
// method POST, a Connection header naming "Upgrade", an Upgrade header of
// exactly "h2c" (case-insensitive, no other protocol tokens), no request
// body, and no conflicting Transfer-Encoding. Per the #185 synthesis this
// strict validation happens BEFORE any dial to the daemon or hijack of the
// client connection — a request that fails here is rejected as an ordinary
// HTTP response, never partially bridged.
func ValidateUpgradeRequest(r *http.Request) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("%w: method %s", ErrNotUpgradeRequest, r.Method)
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") {
		return fmt.Errorf("%w: missing \"Connection: Upgrade\"", ErrNotUpgradeRequest)
	}
	upgrade := r.Header.Values("Upgrade")
	if len(upgrade) != 1 || !strings.EqualFold(strings.TrimSpace(upgrade[0]), "h2c") {
		return fmt.Errorf("%w: Upgrade header must be exactly \"h2c\", got %q", ErrNotUpgradeRequest, upgrade)
	}
	if r.ContentLength > 0 {
		return ErrUpgradeHasBody
	}
	if len(r.TransferEncoding) > 0 {
		return ErrConflictingFraming
	}
	return nil
}

// headerHasToken reports whether any comma-separated value of header h[name]
// contains token, matched case-insensitively per RFC 9110's list-header
// syntax. Mirrors internal/proxy's removeHopByHopHeaders parsing of the
// Connection header.
func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h[textproto.CanonicalMIMEHeaderKey(name)] {
		for part := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(textproto.TrimString(part), token) {
				return true
			}
		}
	}
	return false
}

// rewriteSessionAdvertisement narrows the client's sessionGRPCMethodHeader
// advertisement (read from dst) down to services ServiceAdmittedByPolicy
// reports as having at least one method that is BOTH non-Deny per Classify
// AND allowed by p, replacing the header's values on dst in place. Consulting
// p here — not just the static registry — matters: a service can be
// registered Mediate/Passthrough in principle while this operator's resolved
// policy still leaves it off (e.g. Auth advertised while
// p.Session.Auth.Allow is false), and advertising it anyway would invite a
// daemon callback the bridge only rejects after the fact instead of the
// daemon never being told the service is available at all. If dst carries no
// advertisement at all, dst is left untouched.
func rewriteSessionAdvertisement(dst http.Header, p Policy) {
	advertised := dst.Values(sessionGRPCMethodHeader)
	if len(advertised) == 0 {
		return
	}
	dst.Del(sessionGRPCMethodHeader)
	for _, service := range advertised {
		service = strings.TrimSpace(service)
		if service == "" {
			continue
		}
		if ServiceAdmittedByPolicy(EndpointSession, service, p) {
			dst.Add(sessionGRPCMethodHeader, service)
		}
	}
}

// bufferedConn wraps a net.Conn whose initial bytes were already consumed
// into a *bufio.Reader by HTTP/1.1 request/response parsing (the upgrade
// request/response itself), so any client or daemon bytes that arrived
// immediately after — e.g. a client that starts writing the HTTP/2 client
// preface without waiting a full round-trip for the 101 response bytes to
// drain — are read back out before falling through to the raw connection.
// Per the #185 synthesis: "preserve parser-buffered bytes via a bufferedConn
// wrapper." Every other net.Conn method (Write, Close, deadlines) passes
// through via the embedded net.Conn unchanged.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// dialDaemonH2C dials the Docker daemon via dialer and performs the SAME
// h2c-upgrade handshake sockguard's own client just performed against it:
// write a POST request to path with header carrying exactly one
// "Connection: Upgrade" / "Upgrade: h2c" pair, then read and validate a 101
// response. A 101 status code alone doesn't prove a genuine h2c upgrade — a
// daemon could send 101 without "Connection: Upgrade", or with an Upgrade
// header naming some other protocol — so the response headers are validated
// the same way ValidateUpgradeRequest validates the incoming request, before
// anything downstream (including clearing the dial-scoped deadline) treats
// the connection as a live h2c tunnel. Returns the raw (buffered-wrapped)
// connection and the daemon's 101 response so the caller can replay it
// verbatim to the hijacked client connection — required ordering per the
// synthesis: "require a valid upstream 101 before hijacking downstream."
func dialDaemonH2C(ctx context.Context, dialer Dialer, path string, header http.Header) (net.Conn, *http.Response, error) {
	conn, err := dialer.DialContext(ctx, "", "")
	if err != nil {
		return nil, nil, fmt.Errorf("buildkitproxy: dial daemon: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := &http.Request{
		Method:     http.MethodPost,
		URL:        &url.URL{Scheme: "http", Host: "docker", Path: path},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header.Clone(),
		Host:       "docker",
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")
	req.ContentLength = 0

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: write daemon upgrade request: %w", err)
	}

	br := bufio.NewReaderSize(conn, 64<<10)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: read daemon upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: daemon refused h2c upgrade: status %d", resp.StatusCode)
	}
	if !headerHasToken(resp.Header, "Connection", "upgrade") {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: daemon's 101 response missing \"Connection: Upgrade\": got Connection %q", resp.Header.Values("Connection"))
	}
	respUpgrade := resp.Header.Values("Upgrade")
	if len(respUpgrade) != 1 || !strings.EqualFold(strings.TrimSpace(respUpgrade[0]), "h2c") {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: daemon's 101 response Upgrade header must be exactly \"h2c\", got %q", respUpgrade)
	}

	// Clear the dial-scoped deadline now that the handshake is done; the
	// bridge itself owns idle/read timeouts on the live tunnel (see
	// bridge.go's use of Limits.IdleTimeout/ReadIdleTimeout).
	_ = conn.SetDeadline(time.Time{})

	return &bufferedConn{Conn: conn, r: br}, resp, nil
}

// hijackClientH2C hijacks the client connection behind w and replays resp —
// the daemon's own 101 response, obtained via dialDaemonH2C — verbatim,
// INCLUDING its Connection/Upgrade headers, mirroring
// internal/proxy/hijack.go's finalizeHijackUpgrade: after a 101 the
// connection is a raw byte tunnel with no next hop those headers could
// confuse, and buildkitd's exact 101 status line/headers are what the
// client's own gRPC transport expects to see.
func hijackClientH2C(w http.ResponseWriter, resp *http.Response) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("buildkitproxy: response writer does not support hijacking")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("buildkitproxy: hijack client connection: %w", err)
	}
	if err := resp.Write(buf); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("buildkitproxy: write 101 to client: %w", err)
	}
	if err := buf.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("buildkitproxy: flush 101 to client: %w", err)
	}
	return &bufferedConn{Conn: conn, r: buf.Reader}, nil
}
