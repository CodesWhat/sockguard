package logging

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type contextKey int

const contextKeyMeta contextKey = iota

// RequestMeta holds mutable decision metadata, shared between middlewares
// via a pointer in the request context. The access log middleware creates it,
// and the filter middleware writes to it.
type RequestMeta struct {
	Decision string
	Rule     int
	Reason   string
	NormPath string
}

// WithMeta stores a RequestMeta pointer in the context.
func WithMeta(ctx context.Context, m *RequestMeta) context.Context {
	return context.WithValue(ctx, contextKeyMeta, m)
}

// Meta retrieves the RequestMeta pointer from the context, or nil.
func Meta(ctx context.Context) *RequestMeta {
	m, _ := ctx.Value(contextKeyMeta).(*RequestMeta)
	return m
}

// responseCapture wraps http.ResponseWriter to capture status and bytes written.
type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int
}

var _ http.Flusher = (*responseCapture)(nil)

func (rc *responseCapture) WriteHeader(code int) {
	rc.status = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	n, err := rc.ResponseWriter.Write(b)
	rc.bytes += n
	return n, err
}

// Flush delegates to the underlying ResponseWriter if it implements http.Flusher.
func (rc *responseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying ResponseWriter if it implements http.Hijacker.
func (rc *responseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rc.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// AccessLogMiddleware returns middleware that logs every request with structured fields.
// It injects a mutable RequestMeta into context so downstream middleware (filter) can
// record decision data that flows back up to the log entry.
func AccessLogMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			meta := &RequestMeta{}
			r = r.WithContext(WithMeta(r.Context(), meta))

			rc := &responseCapture{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rc, r)

			latency := time.Since(start)

			// Determine client address
			client := r.RemoteAddr
			if client == "" {
				client = "unix"
			}

			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("normalized_path", meta.NormPath),
				slog.Int("status", rc.status),
				slog.String("decision", meta.Decision),
				slog.Int("rule", meta.Rule),
				slog.Float64("latency_ms", float64(latency.Microseconds())/1000.0),
				slog.Int("bytes", rc.bytes),
				slog.String("client", client),
			}

			if meta.Reason != "" {
				attrs = append(attrs, slog.String("reason", meta.Reason))
			}

			if meta.Decision == "deny" {
				logger.LogAttrs(r.Context(), slog.LevelWarn, "request_denied", attrs...)
			} else {
				logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
			}
		})
	}
}
