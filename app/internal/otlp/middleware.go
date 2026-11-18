package otlp

import (
	"math/rand/v2"
	"net/http"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/metrics"
)

// RootSampler returns the head-sampling decision for new root traces at the
// given ratio. 0 never samples and 1 always samples.
func RootSampler(ratio float64) func() bool {
	switch {
	case ratio <= 0:
		return func() bool { return false }
	case ratio >= 1:
		return func() bool { return true }
	default:
		return func() bool { return rand.Float64() < ratio } // #nosec G404 -- trace sampling, not a security decision
	}
}

// Middleware exports one span per completed request that carries the W3C
// sampled flag. Install it inside the trace-context and request-ID middlewares
// (so their IDs are stamped) and outside the metrics middleware. The sampled
// flag is the whole export decision: an incoming traceparent's flag is
// honored as-is, and for new roots TraceContextMiddlewareWithRootSampler has
// already applied the configured ratio.
func Middleware(e *Exporter) func(http.Handler) http.Handler {
	if e == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return logging.ObserveRequestsMiddleware(func(s logging.RequestSummary) {
		if !s.Sampled || s.TraceID == "" || s.SpanID == "" {
			return
		}
		e.Enqueue(buildSpan(s))
	})
}

// knownMethods bounds the method label: anything else is "_OTHER", per the
// OpenTelemetry HTTP semantic conventions.
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodConnect: true,
	http.MethodOptions: true, http.MethodTrace: true,
}

// buildSpan copies an allowlisted set of fields into a Span. Nothing outside
// this function reaches the wire: no query string, headers, bodies, free-text
// reason or client-supplied request ID.
func buildSpan(s logging.RequestSummary) Span {
	method := s.Method
	if !knownMethods[method] {
		method = "_OTHER"
	}
	route := metrics.RouteCategory(s.NormalizedPath)

	attrs := make([]Attr, 0, 12)
	attrs = append(attrs,
		StringAttr("http.request.method", method),
		IntAttr("http.response.status_code", int64(s.Status)),
		StringAttr("http.route", route),
	)
	add := func(key, value string) {
		if value != "" {
			attrs = append(attrs, StringAttr(key, value))
		}
	}
	add("sockguard.normalized_path", s.NormalizedPath)
	// An empty decision means no layer denied the request, which is how the
	// access log reads it too.
	decision := s.Decision
	if decision == "" {
		decision = "allow"
	}
	add("sockguard.decision", decision)
	add("sockguard.reason_code", s.ReasonCode)
	attrs = append(attrs, IntAttr("sockguard.rule", int64(s.Rule)))
	add("sockguard.profile", s.Profile)
	add("sockguard.rollout_mode", s.RolloutMode)
	add("sockguard.listener", s.Listener)
	add("network.peer.address", s.PeerHost)
	add("sockguard.request_id", s.RequestID)

	return Span{
		TraceID:      s.TraceID,
		SpanID:       s.SpanID,
		ParentSpanID: s.ParentSpanID,
		Name:         method + " " + route,
		Start:        s.Start,
		End:          s.End,
		Error:        s.Status >= 500,
		Attrs:        attrs,
	}
}
