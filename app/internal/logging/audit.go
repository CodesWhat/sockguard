package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

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
}

const auditLogBufferSize = 1024

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
	Status            int                   `json:"status"`
	ActorRemoteAddr   string                `json:"actor_remote_addr"`
	ActorSourceIP     string                `json:"actor_source_ip"`
	TransportListener string                `json:"transport_listener"`
	TransportScheme   string                `json:"transport_scheme"`
	TransportProtocol string                `json:"transport_protocol"`
	OwnershipContext  auditOwnershipContext `json:"ownership"`
}

type auditOwnershipContext struct {
	Enabled  bool   `json:"enabled"`
	Owner    string `json:"owner"`
	LabelKey string `json:"label_key"`
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
				Status:            rc.status,
				ActorRemoteAddr:   actorRemoteAddr,
				ActorSourceIP:     actorSourceIP,
				TransportListener: transportListener,
				TransportScheme:   transportScheme,
				TransportProtocol: transportProtocol,
				OwnershipContext:  ownershipContext,
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
		return
	default:
	}
	// Preserve request latency under audit-sink backpressure; a saturated queue
	// drops the event rather than blocking the caller.
	select {
	case l.events <- event:
	default:
	}
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
