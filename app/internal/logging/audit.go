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
	OwnershipOwner    string
	OwnershipLabelKey string
}

// AuditLogger writes stable JSON audit events to a dedicated sink.
type AuditLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
	now func() string
}

// NewAuditLogger constructs a dedicated JSON audit logger.
func NewAuditLogger(w io.Writer) *AuditLogger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &AuditLogger{
		enc: enc,
		now: func() string {
			return time.Now().UTC().Format(time.RFC3339Nano)
		},
	}
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
	return NewAuditLogger(writer), closer, nil
}

type auditEvent struct {
	EventType        string                 `json:"event_type"`
	Timestamp        string                 `json:"timestamp"`
	RequestID        string                 `json:"request_id"`
	ClientRequestID  string                 `json:"client_request_id"`
	Method           string                 `json:"method"`
	RawPath          string                 `json:"raw_path"`
	NormalizedPath   string                 `json:"normalized_path"`
	Decision         string                 `json:"decision"`
	ReasonCode       string                 `json:"reason_code"`
	Reason           string                 `json:"reason"`
	MatchedRule      int                    `json:"matched_rule"`
	SelectedProfile  string                 `json:"selected_profile"`
	Status           int                    `json:"status"`
	ActorIdentity    map[string]any         `json:"actor_identity"`
	TransportID      map[string]any         `json:"transport_identity"`
	OwnershipContext map[string]any         `json:"ownership"`
}

// AuditLogMiddleware emits a dedicated audit event after each request.
func AuditLogMiddleware(logger *AuditLogger, opts AuditOptions) func(http.Handler) http.Handler {
	if logger == nil {
		return func(next http.Handler) http.Handler { return next }
	}

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

			event := auditEvent{
				EventType:       "http_request",
				Timestamp:       logger.now(),
				RequestID:       requestIDFromRequest(r),
				ClientRequestID: clientRequestIDForRequest(r, meta),
				Method:          requestMethod(r),
				RawPath:         requestPath(r),
				NormalizedPath:  meta.NormPath,
				Decision:        meta.Decision,
				ReasonCode:      meta.ReasonCode,
				Reason:          meta.Reason,
				MatchedRule:     meta.Rule,
				SelectedProfile: meta.Profile,
				Status:          rc.status,
				ActorIdentity:   auditActorIdentity(r),
				TransportID:     auditTransportIdentity(r),
				OwnershipContext: map[string]any{
					"enabled":   opts.OwnershipOwner != "",
					"owner":     opts.OwnershipOwner,
					"label_key": opts.OwnershipLabelKey,
				},
			}

			logger.log(event)
		})
	}
}

func (l *AuditLogger) log(event auditEvent) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(event)
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

func auditActorIdentity(r *http.Request) map[string]any {
	identity := map[string]any{
		"remote_addr": "",
		"source_ip":   "",
	}
	if r == nil {
		return identity
	}
	identity["remote_addr"] = r.RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		identity["source_ip"] = host
	}
	return identity
}

func auditTransportIdentity(r *http.Request) map[string]any {
	identity := map[string]any{
		"listener": "tcp",
		"scheme":   "http",
		"protocol": "",
	}
	if r == nil {
		return identity
	}
	if r.Proto != "" {
		identity["protocol"] = r.Proto
	}
	if r.TLS != nil {
		identity["scheme"] = "https"
	}
	if r.RemoteAddr == "" {
		identity["listener"] = "unix"
	}
	return identity
}
