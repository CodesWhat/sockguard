package logging

import (
	"bufio"
	"context"
	"crypto/rand"

	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/codeswhat/sockguard/internal/inbound"
	"io"
	"log/slog"

	"net"
	"net/http"

	"os"
	"path/filepath"
	"strings"
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
	Decision   string
	Rule       int
	Reason     string
	ReasonCode string
	NormPath   string
	Profile    string
	// RolloutMode carries the resolved profile's rollout posture
	// (enforce / warn / audit). Empty string is equivalent to "enforce".
	// Set by clientacl when a profile is matched; read by every deny site
	// to decide whether to actually block or pass through.
	RolloutMode     string
	ClientRequestID string
	TraceID         string
	TraceParentID   string
	TraceSpanID     string
	TraceFlags      string
	// ResourcePolicy carries #152's resource-limit-guard outcome for this
	// request. nil for every request the guard passed through untouched (no
	// applicable require_* flag) — that is the common case, so this stays a
	// pointer rather than an embedded struct to avoid paying for it on every
	// request. Set only by filter.ResourceLimitGuard; see
	// internal/filter/resource_limit_guard.go.
	ResourcePolicy *ResourcePolicyMeta
	// ListenerName is the operator-configured listener name (#149) — "default"
	// for the legacy singular listen: block, an explicit listeners[*].name, or
	// "admin" for the dedicated admin listener. Populated from the connection's
	// inbound.Identity, not request-controllable.
	ListenerName string
	// Mutation carries the admission-mutation engine's per-rule outcome
	// trace for this request (#151), set by filter's mutation.go via
	// recordMutationOutcome. nil when no configured mutation rule matched
	// the request's surface.
	Mutation *MutationRecord
}

// Decision values written into RequestMeta.Decision. Allow is not stamped
// explicitly today — the access logger treats an empty decision as allow.
const (
	DecisionDeny      = "deny"
	DecisionWouldDeny = "would_deny"
)

// AllowsPassThrough reports whether the resolved profile's rollout posture
// lets a deny decision pass through to the upstream rather than block. Called
// at every deny site to choose between SetDeniedWithCode + 4xx (enforce) and
// SetWouldDenyWithCode + next.ServeHTTP (warn / audit).
func (m *RequestMeta) AllowsPassThrough() bool {
	if m == nil {
		return false
	}
	return m.RolloutMode == "warn" || m.RolloutMode == "audit"
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
	// ids holds hex-encoded request IDs pre-stringified by the refill
	// goroutine, so Next() pays only for a channel receive — no allocation
	// per request. The hot path was previously hex.Encode + string copy on
	// every call, which showed up as a measurable per-request alloc.
	ids             chan string
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
		ids:             make(chan string, poolSize),
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
	case id := <-g.ids:
		if len(g.ids) <= g.refillThreshold {
			g.signalRefill()
		}
		return id
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

func enqueueRequestIDs(ids chan string, slab []byte) {
	for i := 0; i < len(slab)/requestIDBytes; i++ {
		var raw [requestIDBytes]byte
		copy(raw[:], slab[i*requestIDBytes:(i+1)*requestIDBytes])
		if !enqueueRequestID(ids, encodeRequestID(raw)) {
			return
		}
	}
}

func enqueueRequestID(ids chan string, raw string) bool {
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

// SetDeniedWithCode stamps a deny verdict plus a stable machine-readable
// reason code onto the request metadata so access and audit logs can correlate
// human-readable reasons with a bounded schema.
func SetDeniedWithCode(w http.ResponseWriter, r *http.Request, reasonCode, reason string, normalize func(string) string) {
	setDecisionWithCode(w, r, DecisionDeny, reasonCode, reason, normalize)
}

// SetWouldDenyWithCode stamps a "would have denied" verdict for warn / audit
// rollout-mode pass-through paths. The proxy must still call next.ServeHTTP
// after invoking this; the marker exists so the access log, audit log, and
// deny counter can attribute the would-be-deny to the gate that triggered it.
func SetWouldDenyWithCode(w http.ResponseWriter, r *http.Request, reasonCode, reason string, normalize func(string) string) {
	setDecisionWithCode(w, r, DecisionWouldDeny, reasonCode, reason, normalize)
}

func setDecisionWithCode(w http.ResponseWriter, r *http.Request, decision, reasonCode, reason string, normalize func(string) string) {
	meta := MetaForRequest(w, r)
	if meta == nil {
		return
	}
	meta.Decision = decision
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
	putResourcePolicyMeta(meta.ResourcePolicy)
	PutMutationRecord(meta.Mutation)
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

	attrs = append(attrs,
		slog.String("method", SafeString(r.Method)),
		slog.String("path", SafeString(r.URL.Path)),
	)

	if values := r.Header[requestIDHeader]; len(values) > 0 && values[0] != "" {
		attrs = append(attrs, slog.String("request_id", SafeString(values[0])))
	}
	if clientRequestID := clientRequestIDForRequest(r, meta); clientRequestID != "" {
		attrs = append(attrs, slog.String("client_request_id", SafeString(clientRequestID)))
	}
	if identity, ok := inbound.FromContext(r.Context()); ok && identity.Name != "" {
		attrs = append(attrs, slog.String("listener_name", SafeString(identity.Name)))
	}

	if meta != nil {
		attrs = append(attrs,
			slog.String("normalized_path", SafeString(meta.NormPath)),
			slog.String("decision", SafeString(meta.Decision)),
			slog.Int("rule", meta.Rule),
		)
		if meta.Profile != "" {
			attrs = append(attrs, slog.String("profile", SafeString(meta.Profile)))
		}
		if meta.RolloutMode != "" && meta.RolloutMode != "enforce" {
			attrs = append(attrs, slog.String("rollout_mode", SafeString(meta.RolloutMode)))
		}
		if meta.ReasonCode != "" {
			attrs = append(attrs, slog.String("reason_code", SafeString(meta.ReasonCode)))
		}
		if meta.Reason != "" {
			attrs = append(attrs, slog.String("reason", SafeString(meta.Reason)))
		}
		if meta.TraceID != "" {
			attrs = append(attrs, slog.String("trace_id", SafeString(meta.TraceID)))
		}
		if meta.TraceParentID != "" {
			attrs = append(attrs, slog.String("trace_parent_id", SafeString(meta.TraceParentID)))
		}
		if meta.TraceSpanID != "" {
			attrs = append(attrs, slog.String("trace_span_id", SafeString(meta.TraceSpanID)))
		}
		if meta.TraceFlags != "" {
			attrs = append(attrs, slog.Bool("trace_sampled", traceSampled(meta.TraceFlags)))
		}
		attrs = appendResourcePolicyAttrs(attrs, meta.ResourcePolicy)
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

			if ownMeta {
				defer putRequestMeta(meta)
			}
			if ownRC {
				defer putResponseCapture(rc)
			}
			if identity, ok := inbound.FromContext(r.Context()); ok {
				meta.ListenerName = identity.Name
			}
			next.ServeHTTP(rc, r)

			latency := time.Since(start)

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
				slog.String("client", SafeString(client)),
			)
			if meta.Mutation != nil && len(meta.Mutation.Rules) > 0 {
				attrs = append(attrs,
					slog.String("mutation_rule_ids", joinMutationRuleIDs(meta.Mutation.Rules)),
					slog.Bool("mutation_changed", meta.Mutation.ActualChanged),
				)
			}
			defer putAccessLogAttrs(attrBuf)

			switch meta.Decision {
			case DecisionDeny:
				logger.LogAttrs(r.Context(), slog.LevelWarn, "request_denied", attrs...)
			case DecisionWouldDeny:

				if meta.RolloutMode == "warn" {
					logger.LogAttrs(r.Context(), slog.LevelWarn, "request_would_deny", attrs...)
				} else {
					logger.LogAttrs(r.Context(), slog.LevelInfo, "request_would_deny", attrs...)
				}
			default:

				if meta.Mutation != nil && meta.Mutation.HasWarnEvaluation {
					logger.LogAttrs(r.Context(), slog.LevelWarn, "request", attrs...)
				} else {
					logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
				}
			}
		})
	}
}

// joinMutationRuleIDs renders a request's mutation rule trace as a single
// comma-separated field for the access log, avoiding a nested/array log
// value the rest of this structured logger's flat attr schema doesn't use
// elsewhere.
func joinMutationRuleIDs(rules []MutationRuleOutcome) string {
	ids := make([]string, len(rules))
	for i, rule := range rules {
		ids[i] = rule.ID
	}
	return strings.Join(ids, ",")
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

// AuditOptions configures dedicated audit-event fields that come from proxy
// runtime configuration rather than a single request.
type AuditOptions struct {
	// Listener identifies the inbound listener type ("tcp" or "unix").
	// Empty defaults to "tcp" for direct middleware use in tests and embedders.
	Listener          string
	OwnershipOwner    string
	OwnershipLabelKey string
}

// AuditLogger writes stable JSON audit events to a dedicated sink.
type AuditLogger struct {
	events    chan auditEvent
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	enc       *json.Encoder
	now       func() string
	dropped   atomic.Uint64
	lastWarn  atomic.Int64
}

const auditLogBufferSize = 1024
const auditDropWarningInterval = time.Minute

// NewAuditLogger constructs a dedicated JSON audit logger.
func NewAuditLogger(w io.Writer) *AuditLogger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	logger := &AuditLogger{
		events: make(chan auditEvent, auditLogBufferSize),
		done:   make(chan struct{}),
		enc:    enc,
		now: func() string {
			return time.Now().UTC().Format(time.RFC3339Nano)
		},
	}
	logger.wg.Add(1)
	go logger.run()
	return logger
}

// NewAudit opens a dedicated audit sink and returns a stable JSON audit logger.
func NewAudit(format, output string) (*AuditLogger, io.Closer, error) {
	if format != "json" {
		return nil, nil, fmt.Errorf("unsupported audit log format %q", format)
	}
	writer, closer, err := outputWriter(output)
	if err != nil {
		return nil, nil, err
	}
	logger := NewAuditLogger(writer)
	return logger, auditLogCloser{logger: logger, output: closer}, nil
}

type auditLogCloser struct {
	logger *AuditLogger
	output io.Closer
}

func (c auditLogCloser) Close() error {
	var err error
	if c.logger != nil {
		err = c.logger.Close()
	}
	if c.output != nil {
		if closeErr := c.output.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

type auditEvent struct {
	EventType         string                `json:"event_type"`
	Timestamp         string                `json:"timestamp"`
	RequestID         string                `json:"request_id"`
	ClientRequestID   string                `json:"client_request_id"`
	TraceID           string                `json:"trace_id"`
	TraceParentID     string                `json:"trace_parent_id"`
	TraceSpanID       string                `json:"trace_span_id"`
	TraceSampled      bool                  `json:"trace_sampled"`
	Method            string                `json:"method"`
	RawPath           string                `json:"raw_path"`        // Raw client URL path, for forensic replay.
	NormalizedPath    string                `json:"normalized_path"` // Canonical policy path, for SIEM correlation.
	Decision          string                `json:"decision"`
	ReasonCode        string                `json:"reason_code"`
	Reason            string                `json:"reason"`
	MatchedRule       int                   `json:"matched_rule"`
	SelectedProfile   string                `json:"selected_profile"`
	RolloutMode       string                `json:"rollout_mode,omitempty"`
	Status            int                   `json:"status"`
	ActorRemoteAddr   string                `json:"actor_remote_addr"`
	ActorSourceIP     string                `json:"actor_source_ip"`
	TransportListener string                `json:"transport_listener"`
	TransportScheme   string                `json:"transport_scheme"`
	TransportProtocol string                `json:"transport_protocol"`
	OwnershipContext  auditOwnershipContext `json:"ownership"`
	// ResourcePolicy is nil (omitted) for every request the #152 resource-limit
	// guard passed through untouched. It is a fresh value built by
	// auditResourcePolicyContextFrom below, never the pooled
	// *logging.ResourcePolicyMeta pointer RequestMeta carries — that pointer
	// is returned to its pool (and zeroed) by the deferred putRequestMeta
	// before this event reaches AuditLogger.run's goroutine, so the audit
	// event must hold its own deep copy taken synchronously here, not an
	// alias into pooled state.
	ResourcePolicy *auditResourcePolicyContext `json:"resource_policy,omitempty"`
	// ListenerName is the operator-configured listener name (#149) —
	// "default" for the legacy singular listen: block, an explicit
	// listeners[*].name, or "admin" for the dedicated admin listener.
	// Additive; TransportListener keeps its pre-existing "unix"/"tcp"
	// transport-kind meaning unchanged.
	ListenerName string `json:"listener_name,omitempty"`
	// Mutation is nil unless the admission-mutation engine evaluated at
	// least one rule against this request (#151). It is built by
	// newAuditMutationRecord as an independent deep copy of the pooled
	// logging.MutationRecord that RequestMeta.Mutation points to — never
	// the pooled pointer/slice itself — because this event is enqueued
	// onto AuditLogger's channel and encoded asynchronously, potentially
	// after the request handler's deferred putRequestMeta has already
	// recycled that pooled record back into mutationRecordPool for reuse
	// by an unrelated request.
	Mutation *auditMutationRecord `json:"mutation,omitempty"`
}

type auditOwnershipContext struct {
	Enabled  bool   `json:"enabled"`
	Owner    string `json:"owner"`
	LabelKey string `json:"label_key"`
}

// auditResourcePolicyContext is the audit-log shape of ResourcePolicyMeta.
// Never carries raw current/effective resource values, inspect JSON,
// PreviousSpec content, labels, or identifiers — classification fields only.
type auditResourcePolicyContext struct {
	Kind         string `json:"kind,omitempty"`
	Operation    string `json:"operation,omitempty"`
	StateSource  string `json:"state_source,omitempty"`
	Requirements string `json:"requirements,omitempty"`
	Result       string `json:"result,omitempty"`
	Violation    string `json:"violation,omitempty"`
	StateLookup  bool   `json:"state_lookup,omitempty"`
}

// auditResourcePolicyContextFrom builds a standalone value copy of rp for the
// audit event. Returns nil when the guard did not evaluate policy for this
// request (the common case), so resource_policy is omitted entirely rather
// than emitted as an empty object.
func auditResourcePolicyContextFrom(rp *ResourcePolicyMeta) *auditResourcePolicyContext {
	if rp == nil || !rp.Evaluated {
		return nil
	}
	return &auditResourcePolicyContext{
		Kind:         rp.Kind,
		Operation:    rp.Operation,
		StateSource:  rp.StateSource,
		Requirements: rp.Requirements,
		Result:       rp.Result,
		Violation:    rp.Violation,
		StateLookup:  rp.StateLookup,
	}
}

// auditMutationRuleOutcome is the audit-log JSON shape of one
// MutationRuleOutcome.
type auditMutationRuleOutcome struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Mode    string `json:"mode"`
	Outcome string `json:"outcome"`
}

// auditMutationRecord is the audit-log JSON shape of a request's
// MutationRecord.
type auditMutationRecord struct {
	Rules         []auditMutationRuleOutcome `json:"rules,omitempty"`
	ActualChanged bool                       `json:"actual_changed"`
}

// newAuditMutationRecord deep-copies rec's rule trace into an independent
// value safe to hold past the pooled RequestMeta/MutationRecord's lifetime.
// Returns nil when rec is nil or empty, so the "mutation" field is omitted
// entirely for the overwhelming majority of requests that never matched a
// mutation rule.
func newAuditMutationRecord(rec *MutationRecord) *auditMutationRecord {
	if rec == nil || len(rec.Rules) == 0 {
		return nil
	}
	rules := make([]auditMutationRuleOutcome, len(rec.Rules))
	for i, outcome := range rec.Rules {

		rules[i] = auditMutationRuleOutcome(outcome)
	}
	return &auditMutationRecord{Rules: rules, ActualChanged: rec.ActualChanged}
}

// AuditLogMiddleware emits a dedicated audit event after each request.
func AuditLogMiddleware(logger *AuditLogger, opts AuditOptions) func(http.Handler) http.Handler {
	if logger == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	ownershipContext := auditOwnershipContext{
		Enabled:  opts.OwnershipOwner != "",
		Owner:    opts.OwnershipOwner,
		LabelKey: opts.OwnershipLabelKey,
	}
	listener := auditListener(opts.Listener)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc, ownRC := wrapResponseCapture(w)
			meta, ownMeta := ensureRequestMeta(rc)
			if ownMeta {
				defer putRequestMeta(meta)
			}
			if ownRC {
				defer putResponseCapture(rc)
			}

			next.ServeHTTP(rc, r)

			actorRemoteAddr, actorSourceIP := auditActorIdentity(r)
			transportListener, transportScheme, transportProtocol := auditTransportIdentity(r, listener)
			listenerName := ""
			if identity, ok := inbound.FromContext(r.Context()); ok {
				listenerName = identity.Name
			}

			mutationRecord := newAuditMutationRecord(meta.Mutation)
			event := auditEvent{
				EventType:         "http_request",
				Timestamp:         logger.now(),
				RequestID:         requestIDFromRequest(r),
				ClientRequestID:   clientRequestIDForRequest(r, meta),
				TraceID:           meta.TraceID,
				TraceParentID:     meta.TraceParentID,
				TraceSpanID:       meta.TraceSpanID,
				TraceSampled:      traceSampled(meta.TraceFlags),
				Method:            requestMethod(r),
				RawPath:           requestPath(r),
				NormalizedPath:    meta.NormPath,
				Decision:          meta.Decision,
				ReasonCode:        meta.ReasonCode,
				Reason:            meta.Reason,
				MatchedRule:       meta.Rule,
				SelectedProfile:   meta.Profile,
				RolloutMode:       meta.RolloutMode,
				Status:            rc.status,
				ActorRemoteAddr:   actorRemoteAddr,
				ActorSourceIP:     actorSourceIP,
				TransportListener: transportListener,
				TransportScheme:   transportScheme,
				TransportProtocol: transportProtocol,
				ListenerName:      listenerName,
				OwnershipContext:  ownershipContext,
				ResourcePolicy:    auditResourcePolicyContextFrom(meta.ResourcePolicy),
				Mutation:          mutationRecord,
			}

			logger.log(event)
		})
	}
}

func (l *AuditLogger) log(event auditEvent) {
	if l == nil {
		return
	}
	select {
	case <-l.done:
		l.recordDrop()
		return
	default:
	}

	select {
	case l.events <- event:
	default:
		l.recordDrop()
	}
}

func (l *AuditLogger) recordDrop() {
	total := l.dropped.Add(1)
	now := time.Now().UnixNano()
	last := l.lastWarn.Load()
	if now-last < auditDropWarningInterval.Nanoseconds() || !l.lastWarn.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("audit events dropped", "dropped_total", total)
}

// DroppedEvents reports events discarded because the buffer was full or the
// logger had already closed.
func (l *AuditLogger) DroppedEvents() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

// Close drains queued audit events before returning. It does not close the
// underlying writer; callers that own the sink should close that separately.
func (l *AuditLogger) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		close(l.done)
		l.wg.Wait()
	})
	return nil
}

func (l *AuditLogger) run() {
	defer l.wg.Done()
	for {
		select {
		case event := <-l.events:
			_ = l.enc.Encode(event)
		case <-l.done:
			l.drain()
			return
		}
	}
}

func (l *AuditLogger) drain() {
	for {
		select {
		case event := <-l.events:
			_ = l.enc.Encode(event)
		default:
			return
		}
	}
}

func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get(requestIDHeader)
}

func requestMethod(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Method
}

func requestPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Path
}

func auditActorIdentity(r *http.Request) (remoteAddr string, sourceIP string) {
	if r == nil {
		return "", ""
	}
	remoteAddr = r.RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		sourceIP = host
	}
	return remoteAddr, sourceIP
}

func auditListener(listener string) string {
	if listener == "unix" {
		return "unix"
	}
	return "tcp"
}

func auditTransportIdentity(r *http.Request, listener string) (transportListener string, scheme string, protocol string) {
	transportListener = auditListener(listener)
	scheme = "http"
	if r == nil {
		return transportListener, scheme, ""
	}
	if r.Proto != "" {
		protocol = r.Proto
	}
	if r.TLS != nil {
		scheme = "https"
	}
	return transportListener, scheme, protocol
}

// logBufferSize is the size of the bufio.Writer used when logging to a file.
// stderr and stdout are left unbuffered so dev/debug output appears immediately.
// 64 KiB keeps busy hosts from flushing (and holding the writer mutex) every
// dozen access-log lines; logFlushInterval still bounds record staleness.
const logBufferSize = 64 * 1024

// logFlushInterval bounds the worst-case delay between a log record being
// written and reaching disk on a low-throughput host. Busy hosts flush
// implicitly when the buffer fills; the periodic flush is the safety
// net for hosts where records trickle in.
const logFlushInterval = time.Second

// SafeString escapes record-delimiting characters before untrusted text reaches
// a logging API. Both slog handlers already quote these values, but doing this at
// the trust boundary also protects custom handlers and makes the invariant
// explicit to static analysis.
func SafeString(value string) string {
	value = strings.ReplaceAll(value, "\r", `\r`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

// New creates a structured logger with the given level and format.
// Output may be "stderr", "stdout", or a file path.
func New(level, format, output string) (*slog.Logger, io.Closer, error) {
	writer, closer, err := outputWriter(output)
	if err != nil {
		return nil, nil, err
	}

	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}

	switch format {
	case "text":
		handler = slog.NewTextHandler(writer, opts)
	default:
		handler = slog.NewJSONHandler(writer, opts)
	}

	return slog.New(handler), closer, nil
}

// ValidateOutput checks whether the configured log output target is supported.
// Allowed values are stderr, stdout, or a local file path.
func ValidateOutput(output string) error {
	_, err := normalizeOutput(output)
	return err
}

func outputWriter(output string) (io.Writer, io.Closer, error) {
	normalized, err := normalizeOutput(output)
	if err != nil {
		return nil, nil, err
	}

	switch normalized {
	case "stderr":
		return os.Stderr, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	default:

		f, err := os.OpenFile(normalized, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log output %q: %w", normalized, err)
		}
		w := newBufferedFileWriter(f, logBufferSize, logFlushInterval)
		return w, w, nil
	}
}

// bufferedFileWriter wraps a *bufio.Writer over an *os.File with a periodic
// flush goroutine so log records do not sit in the in-memory buffer
// indefinitely on low-throughput hosts. The mutex serializes Write and the
// periodic flush, since bufio.Writer is not concurrency-safe.
type bufferedFileWriter struct {
	mu       sync.Mutex
	buf      *bufio.Writer
	file     *os.File
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newBufferedFileWriter(f *os.File, size int, flushInterval time.Duration) *bufferedFileWriter {
	w := &bufferedFileWriter{
		buf:  bufio.NewWriterSize(f, size),
		file: f,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go w.flushLoop(flushInterval)
	return w
}

func (w *bufferedFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *bufferedFileWriter) flushLoop(interval time.Duration) {
	defer close(w.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			_ = w.buf.Flush()
			w.mu.Unlock()
		case <-w.stop:
			return
		}
	}
}

func (w *bufferedFileWriter) Close() error {
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	flushErr := w.buf.Flush()
	closeErr := w.file.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

func normalizeOutput(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", fmt.Errorf("invalid log output (must be stderr, stdout, or a local file path)")
	}

	switch trimmed {
	case "stderr", "stdout":
		return trimmed, nil
	default:
		cleaned := filepath.Clean(trimmed)
		if !filepath.IsLocal(cleaned) {
			return "", fmt.Errorf("invalid log output %q (must be stderr, stdout, or a local file path)", output)
		}
		return cleaned, nil
	}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// MutationRuleOutcome is one compiled admission-mutation rule's outcome for
// a single request.
type MutationRuleOutcome struct {
	// ID is the rule's configured id.
	ID string
	// Type is "inject_labels" or "remap_image".
	Type string
	// Mode is "enforce", "warn", or "audit".
	Mode string
	// Outcome is one of "applied", "noop", "would_apply", "would_noop", or
	// "failed".
	Outcome string
}

// MutationRecord is the pooled per-request admission-mutation trace attached
// to RequestMeta.Mutation. It is populated only when at least one mutation
// rule matched the request's surface; a request with no configured mutation
// rules for its surface never gets one attached.
type MutationRecord struct {
	Rules []MutationRuleOutcome
	// ActualChanged reports whether an enforce-mode rule actually rewrote
	// the committed request body.
	ActualChanged bool
	// HasWarnEvaluation reports whether at least one warn-mode rule was
	// evaluated against the shadow document, regardless of its outcome —
	// used to elevate the access log line to WARN even when the request
	// itself was allowed.
	HasWarnEvaluation bool
}

var mutationRecordPool = sync.Pool{
	New: func() any {
		return &MutationRecord{}
	},
}

// GetMutationRecord returns a pooled, zeroed MutationRecord.
func GetMutationRecord() *MutationRecord {
	rec, _ := mutationRecordPool.Get().(*MutationRecord)
	if rec == nil {
		return &MutationRecord{}
	}
	return rec
}

// PutMutationRecord returns rec to the pool after zeroing its fields,
// matching putRequestMeta's pattern for the RequestMeta it hangs off of.
func PutMutationRecord(rec *MutationRecord) {
	if rec == nil {
		return
	}
	rec.Rules = rec.Rules[:0]
	rec.ActualChanged = false
	rec.HasWarnEvaluation = false
	mutationRecordPool.Put(rec)
}

// ResourcePolicyMeta records the outcome of #152's post-ownership
// resource-limit guard (internal/filter/resource_limit_guard.go) for a single
// request. It is deliberately bounded to classification fields — never raw
// current/effective resource values, full inspect JSON, PreviousSpec content,
// labels, or identifiers beyond the normalized path RequestMeta already
// carries — so access and audit logs stay safe to ship off-box.
type ResourcePolicyMeta struct {
	// Evaluated is true once the guard actually consulted require_* policy
	// for this request (i.e. at least one applicable flag was active). When
	// false, RequestMeta.ResourcePolicy is nil instead of an evaluated-false
	// value — Evaluated exists mainly for callers that already hold a
	// non-nil pointer.
	Evaluated bool
	// Kind is "container" or "service".
	Kind string
	// Operation is "create", "update", "manual_rollback", or
	// "automatic_rollback".
	Operation string
	// StateSource is "request", "effective_state", "previous_spec", or
	// "current_spec" — which document supplied the values that were
	// validated.
	StateSource string
	// Requirements is a stable, comma-joined list of the requirement classes
	// that were active for this request (e.g. "memory,cpu,pids").
	Requirements string
	// Result is "allow", "deny", "would_deny", "invalid", "lookup_failed", or
	// "state_changed".
	Result string
	// Violation is the requirement class that failed ("memory"|"cpu"|
	// "hard_cpu"|"pids"), empty when Result is not a policy denial.
	Violation string
	// StateLookup is true when the guard issued a daemon GET to resolve
	// omitted/rollback state for this request.
	StateLookup bool
}

var resourcePolicyMetaPool = sync.Pool{
	New: func() any {
		return &ResourcePolicyMeta{}
	},
}

// GetResourcePolicyMeta returns a pooled, zeroed ResourcePolicyMeta for the
// caller to populate and attach to RequestMeta.ResourcePolicy. Only called by
// filter.ResourceLimitGuard when at least one applicable require_* flag is
// active, so unrelated requests never pay for this allocation.
func GetResourcePolicyMeta() *ResourcePolicyMeta {
	m, _ := resourcePolicyMetaPool.Get().(*ResourcePolicyMeta)
	if m == nil {
		return &ResourcePolicyMeta{}
	}
	return m
}

func putResourcePolicyMeta(m *ResourcePolicyMeta) {
	if m == nil {
		return
	}
	*m = ResourcePolicyMeta{}
	resourcePolicyMetaPool.Put(m)
}

// appendResourcePolicyAttrs appends resource_policy_* access-log fields when
// the guard evaluated policy for this request. Nil (the common case: no
// applicable require_* flag) appends nothing.
func appendResourcePolicyAttrs(attrs []slog.Attr, rp *ResourcePolicyMeta) []slog.Attr {
	if rp == nil || !rp.Evaluated {
		return attrs
	}
	attrs = append(attrs,
		slog.Bool("resource_policy_evaluated", rp.Evaluated),
		slog.String("resource_policy_kind", SafeString(rp.Kind)),
		slog.String("resource_policy_operation", SafeString(rp.Operation)),
		slog.String("resource_policy_source", SafeString(rp.StateSource)),
		slog.String("resource_policy_requirements", SafeString(rp.Requirements)),
		slog.String("resource_policy_result", SafeString(rp.Result)),
		slog.Bool("resource_policy_state_lookup", rp.StateLookup),
	)
	if rp.Violation != "" {
		attrs = append(attrs, slog.String("resource_policy_violation", SafeString(rp.Violation)))
	}
	return attrs
}

const (
	traceparentHeader = "Traceparent"
	tracestateHeader  = "Tracestate"

	traceVersion   = "00"
	traceFlagsNone = "00"
)

var traceRandRead = rand.Read

// TraceContextMiddleware participates in W3C trace context propagation without
// exporting spans. It preserves a valid incoming trace ID, replaces the parent
// ID with a proxy-local span ID, and records the IDs in RequestMeta for logs.
func TraceContextMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, ok := traceContextFromRequest(r)
			if !ok {
				ctx = newRootTraceContext()
				if r != nil {
					r.Header.Del(tracestateHeader)
				}
			}

			if r != nil {
				traceparent := formatTraceparent(ctx)
				r.Header.Set(traceparentHeader, traceparent)
				w.Header().Set(traceparentHeader, traceparent)

				meta := MetaForRequest(w, r)
				if meta == nil {
					meta = &RequestMeta{}
					r = r.WithContext(WithMeta(r.Context(), meta))
				}
				meta.TraceID = ctx.traceID
				meta.TraceParentID = ctx.parentID
				meta.TraceSpanID = ctx.spanID
				meta.TraceFlags = ctx.flags
			}

			next.ServeHTTP(w, r)
		})
	}
}

type traceContext struct {
	traceID  string
	parentID string
	spanID   string
	flags    string
}

func traceContextFromRequest(r *http.Request) (traceContext, bool) {
	if r == nil {
		return traceContext{}, false
	}
	traceID, parentID, flags, ok := parseTraceparent(r.Header.Get(traceparentHeader))
	if !ok {
		return traceContext{}, false
	}
	return traceContext{
		traceID:  traceID,
		parentID: parentID,
		spanID:   newTraceSpanID(),
		flags:    flags,
	}, true
}

func newRootTraceContext() traceContext {
	return traceContext{
		traceID: newTraceID(),
		spanID:  newTraceSpanID(),
		flags:   traceFlagsNone,
	}
}

func formatTraceparent(ctx traceContext) string {
	return traceVersion + "-" + ctx.traceID + "-" + ctx.spanID + "-" + ctx.flags
}

func parseTraceparent(value string) (traceID string, parentID string, flags string, ok bool) {
	if len(value) != 55 ||
		value[2] != '-' ||
		value[35] != '-' ||
		value[52] != '-' ||
		value[:2] != traceVersion {
		return "", "", "", false
	}

	traceID = value[3:35]
	parentID = value[36:52]
	flags = value[53:55]
	if !isLowerHex(traceID) ||
		!isLowerHex(parentID) ||
		!isLowerHex(flags) ||
		isZeroHex(traceID) ||
		isZeroHex(parentID) {
		return "", "", "", false
	}
	return traceID, parentID, flags, true
}

func traceSampled(flags string) bool {
	if len(flags) != 2 {
		return false
	}
	high, ok := lowerHexValue(flags[0])
	if !ok {
		return false
	}
	low, ok := lowerHexValue(flags[1])
	if !ok {
		return false
	}
	return ((high<<4)|low)&1 == 1
}

func newTraceID() string {
	var raw [16]byte
	if fillRandomNonZero(raw[:]) {
		return hex.EncodeToString(raw[:])
	}
	fallback := fallbackRequestIDRaw()
	return hex.EncodeToString(fallback[:])
}

func newTraceSpanID() string {
	var raw [8]byte
	if fillRandomNonZero(raw[:]) {
		return hex.EncodeToString(raw[:])
	}
	fallback := fallbackRequestIDRaw()
	return hex.EncodeToString(fallback[8:])
}

func fillRandomNonZero(dst []byte) bool {
	for range 3 {
		n, err := traceRandRead(dst)
		if err == nil && n == len(dst) && !allZero(dst) {
			return true
		}
	}
	return false
}

func allZero(dst []byte) bool {
	for _, value := range dst {
		if value != 0 {
			return false
		}
	}
	return true
}

func isLowerHex(value string) bool {
	for i := 0; i < len(value); i++ {
		if _, ok := lowerHexValue(value[i]); !ok {
			return false
		}
	}
	return true
}

func isZeroHex(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '0' {
			return false
		}
	}
	return true
}

func lowerHexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}
