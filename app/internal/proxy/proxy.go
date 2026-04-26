package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/responsefilter"
)

const (
	reasonCodeUpstreamSocketUnreachable = "upstream_socket_unreachable"
	reasonCodeUpstreamResponseRejected  = "upstream_response_rejected_by_policy"
)

// Options configures reverse-proxy behavior beyond the fixed upstream socket.
type Options struct {
	ModifyResponse func(*http.Response) error
}

// New creates a reverse proxy that forwards requests to the upstream Docker socket.
func New(upstreamSocket string, logger *slog.Logger) *httputil.ReverseProxy {
	return NewWithOptions(upstreamSocket, logger, Options{})
}

// NewWithOptions creates a reverse proxy that forwards requests to the upstream
// Docker socket and optionally enforces response-side policy.
func NewWithOptions(upstreamSocket string, logger *slog.Logger, opts Options) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", upstreamSocket)
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
		},
		Transport:      transport,
		ModifyResponse: opts.ModifyResponse,
		FlushInterval:  -1, // immediate flush for streaming endpoints
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
			attrs = append(attrs, slog.Any("error", err))
			logger.LogAttrs(r.Context(), slog.LevelError, "upstream request failed", attrs...)

			message := "upstream Docker socket unreachable"
			reasonCode := reasonCodeUpstreamSocketUnreachable
			if errors.Is(err, responsefilter.ErrResponseRejected) {
				message = "upstream Docker response rejected by sockguard policy"
				reasonCode = reasonCodeUpstreamResponseRejected
			}
			if meta := logging.MetaForRequest(w, r); meta != nil {
				meta.ReasonCode = reasonCode
				meta.Reason = message
			}

			if encErr := httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: message}); encErr != nil {
				attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
				attrs = append(attrs, slog.Any("error", encErr))
				logger.LogAttrs(r.Context(), slog.LevelWarn, "failed to encode error response", attrs...)
			}
		},
	}
}
