package logging

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTraceContextRootSamplerSetsSampledFlag(t *testing.T) {
	tests := []struct {
		name        string
		sampler     func() bool
		traceparent string
		wantSuffix  string
	}{
		{"nil sampler leaves roots unsampled", nil, "", "-00"},
		{"sampler true marks roots sampled", func() bool { return true }, "", "-01"},
		{"sampler false leaves roots unsampled", func() bool { return false }, "", "-00"},
		{"incoming flags win over sampler", func() bool { return true }, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", "-00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := TraceContextMiddlewareWithRootSampler(tt.sampler)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tt.traceparent != "" {
				req.Header.Set("Traceparent", tt.traceparent)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			tp := rec.Header().Get("Traceparent")
			if len(tp) != 55 || tp[52:] != tt.wantSuffix {
				t.Errorf("traceparent = %q, want suffix %q", tp, tt.wantSuffix)
			}
		})
	}
}

func TestObserveRequestsMiddlewareReportsSummary(t *testing.T) {
	var got []RequestSummary
	h := TraceContextMiddlewareWithRootSampler(func() bool { return true })(
		RequestIDMiddleware()(
			ObserveRequestsMiddleware(func(s RequestSummary) { got = append(got, s) })(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Inner layers must still resolve the trace IDs the outer
					// middleware stamped, even with no access/audit wrapper.
					if meta := MetaForRequest(w, r); meta == nil || meta.TraceID == "" {
						t.Errorf("inner layer lost trace metadata: %+v", meta)
					}
					SetDeniedWithCode(w, r, "rule_deny", "why", func(p string) string { return p })
					w.WriteHeader(http.StatusForbidden)
				}))))
	req := httptest.NewRequest(http.MethodDelete, "/containers/abc?x=1", nil)
	req.RemoteAddr = "192.0.2.7:1234"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(got) != 1 {
		t.Fatalf("observed %d requests, want 1", len(got))
	}
	s := got[0]
	if s.Method != http.MethodDelete || s.NormalizedPath != "/containers/abc" || s.Decision != DecisionDeny ||
		s.ReasonCode != "rule_deny" || s.Status != http.StatusForbidden || !s.Sampled ||
		s.PeerHost != "192.0.2.7" || len(s.TraceID) != 32 || len(s.SpanID) != 16 || s.RequestID == "" {
		t.Errorf("summary = %+v", s)
	}
	if !s.End.After(s.Start) && !s.End.Equal(s.Start) {
		t.Errorf("end %v before start %v", s.End, s.Start)
	}
}

func TestObserveRequestsMiddlewareDefaultsStatusAndNilObserver(t *testing.T) {
	var got RequestSummary
	h := ObserveRequestsMiddleware(func(s RequestSummary) { got = s })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if got.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", got.Status)
	}
	passthrough := ObserveRequestsMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	rec := httptest.NewRecorder()
	passthrough.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != 204 {
		t.Errorf("nil observer changed behavior: %d", rec.Code)
	}
}
