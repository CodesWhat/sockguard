package logging

import (
	"net"
	"net/http"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/inbound"
)

// RequestSummary is a value copy of the facts a completed request leaves in
// RequestMeta, safe to hold after the pooled metadata is recycled. It carries
// no headers, query string, bodies, free-text reason or client-supplied IDs.
type RequestSummary struct {
	Method         string
	NormalizedPath string
	Decision       string
	ReasonCode     string
	Rule           int
	Profile        string
	RolloutMode    string
	// Listener is the operator-configured listener name, empty when the
	// request carries no inbound identity.
	Listener string
	// PeerHost is the host part of RemoteAddr, empty for unix sockets.
	PeerHost  string
	RequestID string
	TraceID   string
	// ParentSpanID is the incoming parent span, empty for a new root.
	ParentSpanID string
	// SpanID is the proxy-local span ID.
	SpanID  string
	Sampled bool
	Status  int
	Start   time.Time
	End     time.Time
}

// ObserveRequestsMiddleware calls observe once per completed request with a
// RequestSummary. It must be installed inside TraceContextMiddleware and
// RequestIDMiddleware so those IDs are already stamped. observe runs on the
// request goroutine and must not block.
func ObserveRequestsMiddleware(observe func(RequestSummary)) func(http.Handler) http.Handler {
	if observe == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rc, ownRC := wrapResponseCapture(w)
			if rc.meta == nil {
				// No outer wrapper carries metadata: adopt the one the trace
				// middleware parked in the request context so inner layers
				// keep resolving the same trace IDs.
				if m := Meta(r.Context()); m != nil {
					rc.meta = m
				}
			}
			meta, ownMeta := ensureRequestMeta(rc)
			if ownMeta {
				defer putRequestMeta(meta)
			}
			if ownRC {
				defer putResponseCapture(rc)
			}

			next.ServeHTTP(rc, r)

			status := rc.status
			if status == 0 {
				status = http.StatusOK
			}
			summary := RequestSummary{
				Method:         requestMethod(r),
				NormalizedPath: meta.NormPath,
				Decision:       meta.Decision,
				ReasonCode:     meta.ReasonCode,
				Rule:           meta.Rule,
				Profile:        meta.Profile,
				RolloutMode:    meta.RolloutMode,
				RequestID:      requestIDFromRequest(r),
				TraceID:        meta.TraceID,
				ParentSpanID:   meta.TraceParentID,
				SpanID:         meta.TraceSpanID,
				Sampled:        traceSampled(meta.TraceFlags),
				Status:         status,
				Start:          start,
				End:            time.Now(),
			}
			if identity, ok := inbound.FromContext(r.Context()); ok {
				summary.Listener = identity.Name
			}
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				summary.PeerHost = host
			}
			observe(summary)
		})
	}
}
