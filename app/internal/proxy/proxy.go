package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

// New creates a reverse proxy that forwards requests to the upstream Docker socket.
func New(upstreamSocket string, logger *slog.Logger) *httputil.ReverseProxy {
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
		Transport:     transport,
		FlushInterval: -1, // immediate flush for streaming endpoints
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
			attrs = append(attrs, slog.Any("error", err))
			logger.LogAttrs(r.Context(), slog.LevelError, "upstream request failed", attrs...)

			if encErr := httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{
				Message: "upstream Docker socket unreachable",
			}); encErr != nil {
				attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
				attrs = append(attrs, slog.Any("error", encErr))
				logger.LogAttrs(r.Context(), slog.LevelWarn, "failed to encode error response", attrs...)
			}
		},
	}
}
