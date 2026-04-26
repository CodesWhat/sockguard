package logging

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type contextKey int

const (
	contextKeyMeta contextKey = iota
	contextKeyClientRequestID
)

const (
	requestIDBytes           = 16
	requestIDEncodedBytes    = requestIDBytes * 2
	requestIDPoolSize        = 256
	requestIDRefillThreshold = requestIDPoolSize / 2
)

// RequestMeta holds mutable decision metadata shared between middlewares. The
// access log middleware creates it and attaches it to the wrapped
// ResponseWriter; tests and non-access-log callers can also pass it through
// request context via WithMeta.
type RequestMeta struct {
	Decision        string
	Rule            int
	Reason          string
	ReasonCode      string
	NormPath        string
	Profile         string
	ClientRequestID string
}

type requestMetaCarrier interface {
	RequestMeta() *RequestMeta
}

var requestMetaPool = sync.Pool{
	New: func() any {
		return &RequestMeta{}
	},
}

const requestIDHeader = "X-Request-Id"

var requestIDFallbackCounter uint64
var defaultRequestIDGenerator = newRequestIDGenerator(requestIDPoolSize, requestIDRefillThreshold, rand.Read)

type requestIDGenerator struct {
	ids             chan [requestIDBytes]byte
	refillCh        chan struct{}
	stopCh          chan struct{}
	wg              sync.WaitGroup
	refillThreshold int
	fill            func([]byte) (int, error)
}

func newRequestIDGenerator(poolSize, refillThreshold int, fill func([]byte) (int, error)) *requestIDGenerator {
	if poolSize < 1 {
		poolSize = 1
	}
	if refillThreshold < 0 {
		refillThreshold = 0
	}
	if refillThreshold >= poolSize {
		refillThreshold = poolSize - 1
	}

	generator := &requestIDGenerator{
		ids:             make(chan [requestIDBytes]byte, poolSize),
		refillCh:        make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		refillThreshold: refillThreshold,
		fill:            fill,
	}
	generator.wg.Add(1)
	go generator.run()
	generator.signalRefill()
	return generator
}

func (g *requestIDGenerator) Next() string {
	if g == nil {
		return encodeRequestID(fallbackRequestIDRaw())
	}

	select {
	case raw := <-g.ids:
		if len(g.ids) <= g.refillThreshold {
			g.signalRefill()
		}
		return encodeRequestID(raw)
	default:
		g.signalRefill()
		return encodeRequestID(fallbackRequestIDRaw())
	}
}

func (g *requestIDGenerator) run() {
	defer g.wg.Done()

	for {
		select {
		case <-g.refillCh:
			g.refillSync()
		case <-g.stopCh:
			return
		}
	}
}

func (g *requestIDGenerator) refillSync() {
	if g == nil || g.fill == nil || len(g.ids) > g.refillThreshold {
		return
	}

	needed := cap(g.ids) - len(g.ids)
	if needed == 0 {
		return
	}

	slab := make([]byte, needed*requestIDBytes)
	n, err := g.fill(slab)
	if err != nil || n != len(slab) {
		return
	}

	enqueueRequestIDs(g.ids, slab)
}

func enqueueRequestIDs(ids chan [requestIDBytes]byte, slab []byte) {
	for i := 0; i < len(slab)/requestIDBytes; i++ {
		var raw [requestIDBytes]byte
		copy(raw[:], slab[i*requestIDBytes:(i+1)*requestIDBytes])
		if !enqueueRequestID(ids, raw) {
			return
		}
	}
}

func enqueueRequestID(ids chan [requestIDBytes]byte, raw [requestIDBytes]byte) bool {
	select {
	case ids <- raw:
		return true
	default:
		return false
	}
}

func (g *requestIDGenerator) signalRefill() {
	if g == nil {
		return
	}
	select {
	case g.refillCh <- struct{}{}:
	default:
	}
}

func (g *requestIDGenerator) close() {
	if g == nil {
		return
	}
	close(g.stopCh)
	g.wg.Wait()
}

// accessLogAttrs leaves headroom beyond today's max log field count so adding
// one or two attrs later does not force a new backing slice allocation.
type accessLogAttrs [16]slog.Attr

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

// MetaFromResponseWriter retrieves the RequestMeta pointer from a wrapped
// ResponseWriter when access logging has attached one, or nil.
func MetaFromResponseWriter(w http.ResponseWriter) *RequestMeta {
	carrier, _ := w.(requestMetaCarrier)
	if carrier == nil {
		return nil
	}
	return carrier.RequestMeta()
}

// MetaForRequest prefers ResponseWriter-attached request metadata and falls
// back to request context when no access-log wrapper is present.
func MetaForRequest(w http.ResponseWriter, r *http.Request) *RequestMeta {
	if meta := MetaFromResponseWriter(w); meta != nil {
		return meta
	}
	if r == nil {
		return nil
	}
	return Meta(r.Context())
}

// SetDenied stamps a deny verdict onto the request metadata so the access
// log records the decision and reason. If the matching meta is missing its
// NormPath (which happens when a middleware that runs before `filter`
// evaluates the deny) and `normalize` is non-nil, the callback is used to
// populate NormPath so the access log still carries a clean path. Keeping
// the normalization as a callback avoids an import cycle between `logging`
// and `filter`.
func SetDenied(w http.ResponseWriter, r *http.Request, reason string, normalize func(string) string) {
	SetDeniedWithCode(w, r, "", reason, normalize)
}

// SetDeniedWithCode stamps a deny verdict plus a stable machine-readable
// reason code onto the request metadata so access and audit logs can correlate
// human-readable reasons with a bounded schema.
func SetDeniedWithCode(w http.ResponseWriter, r *http.Request, reasonCode, reason string, normalize func(string) string) {
	meta := MetaForRequest(w, r)
	if meta == nil {
		return
	}
	meta.Decision = "deny"
	meta.ReasonCode = reasonCode
	meta.Reason = reason
	if meta.NormPath == "" && normalize != nil && r != nil {
		meta.NormPath = normalize(r.URL.Path)
	}
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

// AppendCorrelationAttrs appends request correlation attributes that should match
// across access logs and subsystem error logs for the same request.
func AppendCorrelationAttrs(attrs []slog.Attr, r *http.Request) []slog.Attr {
	var meta *RequestMeta
	if r != nil {
		meta = Meta(r.Context())
	}
	return appendCorrelationAttrs(attrs, r, meta)
}

// AppendCorrelationAttrsForResponseWriter appends request correlation
// attributes, preferring ResponseWriter-attached metadata from the access log
// middleware and falling back to request context.
func AppendCorrelationAttrsForResponseWriter(attrs []slog.Attr, r *http.Request, w http.ResponseWriter) []slog.Attr {
	return appendCorrelationAttrs(attrs, r, MetaForRequest(w, r))
}

func appendCorrelationAttrs(attrs []slog.Attr, r *http.Request, meta *RequestMeta) []slog.Attr {
	if r == nil {
		return attrs
	}

	// path intentionally preserves the raw client URL path for forensic replay.
	// Policy decisions use meta.NormPath, emitted below as normalized_path.
	attrs = append(attrs,
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	)

	if values := r.Header[requestIDHeader]; len(values) > 0 && values[0] != "" {
		attrs = append(attrs, slog.String("request_id", values[0]))
	}
	if clientRequestID := clientRequestIDForRequest(r, meta); clientRequestID != "" {
		attrs = append(attrs, slog.String("client_request_id", clientRequestID))
	}

	if meta != nil {
		attrs = append(attrs,
			slog.String("normalized_path", meta.NormPath),
			slog.String("decision", meta.Decision),
			slog.Int("rule", meta.Rule),
		)
		if meta.Profile != "" {
			attrs = append(attrs, slog.String("profile", meta.Profile))
		}
		if meta.ReasonCode != "" {
			attrs = append(attrs, slog.String("reason_code", meta.ReasonCode))
		}
		if meta.Reason != "" {
			attrs = append(attrs, slog.String("reason", meta.Reason))
		}
	}

	return attrs
}

// RequestIDMiddleware stamps every request with a canonical, proxy-generated
// request ID so log correlation never relies on a caller-controlled header.
// Any caller-supplied ID is preserved separately for auditing.
func RequestIDMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientRequestID := r.Header.Get(requestIDHeader)
			if clientRequestID != "" {
				if meta := MetaForRequest(w, r); meta != nil {
					meta.ClientRequestID = clientRequestID
				}
				r = r.WithContext(context.WithValue(r.Context(), contextKeyClientRequestID, clientRequestID))
			}

			requestID := newRequestID()
			r.Header.Set(requestIDHeader, requestID)
			w.Header().Set(requestIDHeader, requestID)

			next.ServeHTTP(w, r)
		})
	}
}

// responseCapture wraps http.ResponseWriter to capture status and bytes written.
type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int
	meta   *RequestMeta
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
	rc.meta = nil
	return rc
}

func wrapResponseCapture(w http.ResponseWriter) (*responseCapture, bool) {
	if rc, ok := w.(*responseCapture); ok {
		return rc, false
	}
	return getResponseCapture(w), true
}

func putResponseCapture(rc *responseCapture) {
	if rc == nil {
		return
	}
	rc.ResponseWriter = nil
	rc.status = 0
	rc.bytes = 0
	rc.meta = nil
	responseCapturePool.Put(rc)
}

func (rc *responseCapture) RequestMeta() *RequestMeta {
	return rc.meta
}

func ensureRequestMeta(rc *responseCapture) (*RequestMeta, bool) {
	if rc == nil {
		return nil, false
	}
	if rc.meta != nil {
		return rc.meta, false
	}
	meta := getRequestMeta()
	rc.meta = meta
	return meta, true
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
// It attaches a pooled RequestMeta to the wrapped ResponseWriter so downstream
// middleware can record decision data without allocating a derived request context.
func AccessLogMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			rc, ownRC := wrapResponseCapture(w)
			meta, ownMeta := ensureRequestMeta(rc)
			// LogAttrs and downstream middlewares still read meta through rc, so
			// the pool return must stay deferred until after the log entry is emitted.
			if ownMeta {
				defer putRequestMeta(meta)
			}
			if ownRC {
				defer putResponseCapture(rc)
			}
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
			attrs = appendCorrelationAttrs(attrs, r, meta)
			attrs = append(
				attrs,
				slog.Int("status", rc.status),
				slog.Float64("latency_ms", latencyMS),
				slog.Int("bytes", rc.bytes),
				slog.String("client", client),
			)
			defer putAccessLogAttrs(attrBuf)

			if meta.Decision == "deny" {
				logger.LogAttrs(r.Context(), slog.LevelWarn, "request_denied", attrs...)
			} else {
				logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
			}
		})
	}
}

func clientRequestIDForRequest(r *http.Request, meta *RequestMeta) string {
	if meta != nil && meta.ClientRequestID != "" {
		return meta.ClientRequestID
	}
	if r == nil {
		return ""
	}
	clientRequestID, _ := r.Context().Value(contextKeyClientRequestID).(string)
	return clientRequestID
}

func newRequestID() string {
	return defaultRequestIDGenerator.Next()
}

func fallbackRequestIDRaw() [requestIDBytes]byte {
	var raw [requestIDBytes]byte
	binary.BigEndian.PutUint64(raw[:8], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(raw[8:], atomic.AddUint64(&requestIDFallbackCounter, 1))
	return raw
}

func encodeRequestID(raw [requestIDBytes]byte) string {
	var encoded [requestIDEncodedBytes]byte
	hex.Encode(encoded[:], raw[:])
	return string(encoded[:])
}
