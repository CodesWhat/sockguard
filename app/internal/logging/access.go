package logging

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
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

var requestMetaPool = sync.Pool{
	New: func() any {
		return &RequestMeta{}
	},
}

type accessLogAttrs [10]slog.Attr

var accessLogAttrPool = sync.Pool{
	New: func() any {
		return &accessLogAttrs{}
	},
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

func getRequestMeta() *RequestMeta {
	meta, _ := requestMetaPool.Get().(*RequestMeta)
	if meta == nil {
		return &RequestMeta{}
	}
	return meta
}

func putRequestMeta(meta *RequestMeta) {
	if meta == nil {
		return
	}
	*meta = RequestMeta{}
	requestMetaPool.Put(meta)
}

func getAccessLogAttrs() *accessLogAttrs {
	attrs, _ := accessLogAttrPool.Get().(*accessLogAttrs)
	if attrs == nil {
		return &accessLogAttrs{}
	}
	return attrs
}

func putAccessLogAttrs(attrs *accessLogAttrs) {
	if attrs == nil {
		return
	}
	clear(attrs[:])
	accessLogAttrPool.Put(attrs)
}

// responseCapture wraps http.ResponseWriter to capture status and bytes written.
type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int
}

var _ http.Flusher = (*responseCapture)(nil)
var _ http.Hijacker = (*responseCapture)(nil)

var responseCapturePool = sync.Pool{
	New: func() any {
		return &responseCapture{}
	},
}

func getResponseCapture(w http.ResponseWriter) *responseCapture {
	rc, _ := responseCapturePool.Get().(*responseCapture)
	if rc == nil {
		rc = &responseCapture{}
	}
	rc.ResponseWriter = w
	rc.status = http.StatusOK
	rc.bytes = 0
	return rc
}

func putResponseCapture(rc *responseCapture) {
	if rc == nil {
		return
	}
	rc.ResponseWriter = nil
	rc.status = 0
	rc.bytes = 0
	responseCapturePool.Put(rc)
}

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

			meta := getRequestMeta()
			defer putRequestMeta(meta)
			r = r.WithContext(WithMeta(r.Context(), meta))

			rc := getResponseCapture(w)
			defer putResponseCapture(rc)
			next.ServeHTTP(rc, r)

			latency := time.Since(start)

			// Determine client address
			client := r.RemoteAddr
			if client == "" {
				client = "unix"
			}
			latencyMS := float64(latency.Microseconds()) / 1000.0

			attrBuf := getAccessLogAttrs()
			attrs := attrBuf[:0]
			attrs = append(
				attrs,
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("normalized_path", meta.NormPath),
				slog.Int("status", rc.status),
				slog.String("decision", meta.Decision),
				slog.Int("rule", meta.Rule),
				slog.Float64("latency_ms", latencyMS),
				slog.Int("bytes", rc.bytes),
				slog.String("client", client),
			)
			if meta.Reason != "" {
				attrs = append(attrs, slog.String("reason", meta.Reason))
			}
			defer putAccessLogAttrs(attrBuf)

			if meta.Decision == "deny" {
				logger.LogAttrs(r.Context(), slog.LevelWarn, "request_denied", attrs...)
			} else {
				logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
			}
		})
	}
}
