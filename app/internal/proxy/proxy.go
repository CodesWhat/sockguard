package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/responsefilter"
	"github.com/codeswhat/sockguard/internal/upstream"
)

const (
	reasonCodeUpstreamSocketUnreachable = "upstream_socket_unreachable"
	reasonCodeUpstreamResponseRejected  = "upstream_response_rejected_by_policy"
	reasonCodeUpstreamRequestTimeout    = "upstream_request_timeout"
)

// Options configures reverse-proxy behavior beyond the fixed upstream socket.
type Options struct {
	ModifyResponse func(*http.Response) error
}

// NewWithOptions creates a reverse proxy that forwards requests to the upstream
// Docker socket and optionally enforces response-side policy. It is the
// single-local-socket shorthand: callers with a plain socket path get a
// one-endpoint resolver. The multi-endpoint/remote path uses NewWithTransport.
func NewWithOptions(upstreamSocket string, logger *slog.Logger, opts Options) *httputil.ReverseProxy {
	return NewWithTransport(upstream.NewSingleSocket(upstreamSocket), logger, opts)
}

// NewWithTransport creates a reverse proxy that forwards requests through rt —
// typically an *upstream.Resolver, which owns endpoint selection, per-endpoint
// connection pooling (MaxIdleConns 100, IdleConnTimeout 90s, ResponseHeader
// timeout 30s, matching the historical single-socket transport), client TLS,
// and automatic failover. Streaming endpoints (logs follow, events, stats) send
// headers promptly and stream the body, so the header timeout does not cap
// long-lived responses; hijacked attach/exec-start connections bypass this
// pooled transport entirely.
func NewWithTransport(rt http.RoundTripper, logger *slog.Logger, opts Options) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
		},
		Transport:      rt,
		ModifyResponse: opts.ModifyResponse,
		FlushInterval:  -1, // immediate flush for streaming endpoints
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
			attrs = append(attrs, slog.Any("error", err))
			logger.LogAttrs(r.Context(), slog.LevelError, "upstream request failed", attrs...)

			message := "upstream Docker socket unreachable"
			reasonCode := reasonCodeUpstreamSocketUnreachable
			status := http.StatusBadGateway
			switch {
			case errors.Is(err, responsefilter.ErrResponseRejected):
				message = "upstream Docker response rejected by sockguard policy"
				reasonCode = reasonCodeUpstreamResponseRejected
			case errors.Is(err, context.DeadlineExceeded):
				// The per-request upstream deadline (WithRequestTimeout) fired:
				// the daemon accepted the request but did not finish it in time.
				// Surface it as a Gateway Timeout, distinct from an unreachable
				// socket, so callers and access logs can tell a hung daemon apart
				// from a dead one. Client-initiated cancellation surfaces as
				// context.Canceled and stays on the 502 path.
				message = "upstream request timed out"
				reasonCode = reasonCodeUpstreamRequestTimeout
				status = http.StatusGatewayTimeout
			}
			if meta := logging.MetaForRequest(w, r); meta != nil {
				meta.ReasonCode = reasonCode
				meta.Reason = message
			}

			if encErr := httpjson.Write(w, status, httpjson.ErrorResponse{Message: message}); encErr != nil {
				attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
				attrs = append(attrs, slog.Any("error", encErr))
				logger.LogAttrs(r.Context(), slog.LevelWarn, "failed to encode error response", attrs...)
			}
		},
	}
}
