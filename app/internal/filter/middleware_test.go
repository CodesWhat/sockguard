package filter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/internal/logging"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// verboseMiddleware returns the filter middleware with verbose deny responses
// so tests that assert on method/path/reason fields still work after the
// production default for `response.deny_verbosity` flipped to `minimal`.
// Use this in any test that needs to see rendered deny metadata; tests that
// verify minimal behavior explicitly should call MiddlewareWithOptions
// directly.
func verboseMiddleware(rules []*CompiledRule, logger *slog.Logger) func(http.Handler) http.Handler {
	return MiddlewareWithOptions(rules, logger, Options{
		PolicyConfig: PolicyConfig{
			DenyResponseVerbosity: DenyResponseVerbosityVerbose,
		},
	})
}

type devNull struct{}

func (devNull) Write(b []byte) (int, error) { return len(b), nil }

var errWriteFailed = errors.New("write failed")

type loggedRequest struct {
	message string
	level   slog.Level
	attrs   map[string]any
}

type collectingHandler struct {
	mu      sync.Mutex
	records []loggedRequest
}

func (h *collectingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *collectingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]any, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	h.mu.Lock()
	h.records = append(h.records, loggedRequest{message: r.Message, level: r.Level, attrs: attrs})
	h.mu.Unlock()
	return nil
}

func (h *collectingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *collectingHandler) WithGroup(string) slog.Handler { return h }

func (h *collectingHandler) snapshot() []loggedRequest {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]loggedRequest, len(h.records))
	copy(out, h.records)
	return out
}

type failingResponseWriter struct {
	header http.Header
	status int
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
}

type failOnceResponseWriter struct {
	header        http.Header
	committed     http.Header
	status        int
	writeCalls    int
	headerWritten bool
	body          bytes.Buffer
}

func (w *failOnceResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failOnceResponseWriter) WriteHeader(status int) {
	if !w.headerWritten {
		w.committed = w.Header().Clone()
		w.headerWritten = true
	}
	w.status = status
}

func (w *failOnceResponseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	w.writeCalls++
	if w.writeCalls == 1 {
		return 0, errWriteFailed
	}
	return w.body.Write(p)
}

func TestMiddlewareAllowed(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := verboseMiddleware(rules, testLogger())(inner)
	req := httptest.NewRequest("GET", "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("expected request to reach inner handler")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareDenied(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})

	handler := verboseMiddleware(rules, testLogger())(inner)
	req := httptest.NewRequest("POST", "/containers/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("expected request to NOT reach inner handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Message != "request denied by sockguard policy" {
		t.Errorf("message = %q, want 'request denied by sockguard policy'", body.Message)
	}
	if body.Method != "POST" {
		t.Errorf("method = %q, want POST", body.Method)
	}
	if body.Path != "/containers/create" {
		t.Errorf("path = %q, want /containers/create", body.Path)
	}
	if body.Reason != "deny all" {
		t.Errorf("reason = %q, want 'deny all'", body.Reason)
	}
}

func TestMiddlewareRolloutMode(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	cases := []struct {
		mode             string
		wantReachInner   bool
		wantStatus       int
		wantDecision     string
		wantReasonCode   string
		wantPassThroughResponseEmpty bool
	}{
		{mode: "", wantReachInner: false, wantStatus: http.StatusForbidden, wantDecision: "deny", wantReasonCode: reasonCodeMatchedDenyRule},
		{mode: "enforce", wantReachInner: false, wantStatus: http.StatusForbidden, wantDecision: "deny", wantReasonCode: reasonCodeMatchedDenyRule},
		{mode: "warn", wantReachInner: true, wantStatus: http.StatusTeapot, wantDecision: logging.DecisionWouldDeny, wantReasonCode: reasonCodeMatchedDenyRule, wantPassThroughResponseEmpty: true},
		{mode: "audit", wantReachInner: true, wantStatus: http.StatusTeapot, wantDecision: logging.DecisionWouldDeny, wantReasonCode: reasonCodeMatchedDenyRule, wantPassThroughResponseEmpty: true},
	}

	for _, tc := range cases {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			reached := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusTeapot)
			})

			handler := verboseMiddleware(rules, testLogger())(inner)
			req := httptest.NewRequest("POST", "/containers/create", nil)

			meta := &logging.RequestMeta{RolloutMode: tc.mode}
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if reached != tc.wantReachInner {
				t.Fatalf("inner reached=%v, want %v", reached, tc.wantReachInner)
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if meta.Decision != tc.wantDecision {
				t.Errorf("meta.Decision = %q, want %q", meta.Decision, tc.wantDecision)
			}
			if meta.ReasonCode != tc.wantReasonCode {
				t.Errorf("meta.ReasonCode = %q, want %q", meta.ReasonCode, tc.wantReasonCode)
			}
			if tc.wantPassThroughResponseEmpty && rec.Body.Len() != 0 {
				t.Errorf("expected empty body for pass-through, got %q", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareDeniedMinimalVerbosity(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected request to NOT reach inner handler")
	})

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			DenyResponseVerbosity: DenyResponseVerbosityMinimal,
		},
	})(inner)
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Message != "request denied by sockguard policy" {
		t.Errorf("message = %q, want 'request denied by sockguard policy'", body.Message)
	}
	if body.Method != "" {
		t.Errorf("method = %q, want empty", body.Method)
	}
	if body.Path != "" {
		t.Errorf("path = %q, want empty", body.Path)
	}
	if body.Reason != "" {
		t.Errorf("reason = %q, want empty", body.Reason)
	}
}

func TestMiddlewareRejectsOversizedBoundedRequestBodiesWith413(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		limit      int
		wantPrefix string
	}{
		{name: "container create", path: "/containers/create", limit: maxContainerCreateBodyBytes, wantPrefix: "container create denied: request body exceeds"},
		{name: "service create", path: "/services/create", limit: maxServiceBodyBytes, wantPrefix: "service denied: request body exceeds"},
		{name: "volume create", path: "/volumes/create", limit: maxVolumeBodyBytes, wantPrefix: "volume create denied: request body exceeds"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowRule, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: tt.path, Action: ActionAllow, Index: 0})
			denyRule, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
			rules := []*CompiledRule{allowRule, denyRule}

			reached := false
			handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				reached = true
			}))

			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(bytes.Repeat([]byte{'x'}, tt.limit+1)))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if reached {
				t.Fatal("expected oversized request to NOT reach inner handler")
			}
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
			}

			var body DenialResponse
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Message != "request denied by sockguard policy" {
				t.Fatalf("message = %q, want %q", body.Message, "request denied by sockguard policy")
			}
			if !strings.HasPrefix(body.Reason, tt.wantPrefix) {
				t.Fatalf("reason = %q, want prefix %q", body.Reason, tt.wantPrefix)
			}
		})
	}
}

func TestInspectAllowedRequestPrefersHighestSeverityMatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	var called []string

	policy := runtimePolicy{
		inspectPolicies: []requestInspectPolicy{
			{
				matches:  func(*http.Request, string) bool { return true },
				severity: inspectSeverityMedium,
				inspect: func(*slog.Logger, *http.Request, string) (string, error) {
					called = append(called, "medium")
					return "medium deny", nil
				},
				errorLogMessage:   "medium failed",
				denyReasonOnError: "medium error",
			},
			{
				matches:  func(*http.Request, string) bool { return true },
				severity: inspectSeverityCritical,
				inspect: func(*slog.Logger, *http.Request, string) (string, error) {
					called = append(called, "critical")
					return "critical deny", nil
				},
				errorLogMessage:   "critical failed",
				denyReasonOnError: "critical error",
			},
		},
	}

	reason, reasonCode, status := policy.inspectAllowedRequest(testLogger(), req, NormalizePath(req.URL.Path))
	if reason != "critical deny" {
		t.Fatalf("reason = %q, want %q", reason, "critical deny")
	}
	if reasonCode != reasonCodeRequestBodyPolicyDenied {
		t.Fatalf("reasonCode = %q, want %q", reasonCode, reasonCodeRequestBodyPolicyDenied)
	}
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", status, http.StatusForbidden)
	}
	if got, want := strings.Join(called, ","), "critical"; got != want {
		t.Fatalf("called = %q, want %q", got, want)
	}
}

func TestInspectAllowedRequestNoMatchAllocatesNothing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	neverMatches := func(*http.Request, string) bool { return false }
	policy := runtimePolicy{
		inspectPolicies: []requestInspectPolicy{
			{matches: neverMatches, severity: inspectSeverityMedium},
			{matches: neverMatches, severity: inspectSeverityHigh},
			{matches: neverMatches, severity: inspectSeverityCritical},
		},
	}

	allocs := testing.AllocsPerRun(1000, func() {
		reason, reasonCode, status := policy.inspectAllowedRequest(nil, req, "/containers/json")
		if reason != "" || reasonCode != "" || status != 0 {
			t.Fatalf("inspectAllowedRequest() = (%q, %q, %d), want empty result", reason, reasonCode, status)
		}
	})
	if allocs != 0 {
		t.Fatalf("inspectAllowedRequest() allocations = %.0f, want 0", allocs)
	}
}

func TestInspectAllowedRequestManyMatchesAllocatesNothing(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/plugins/create", nil)
	inspectPolicies := make([]requestInspectPolicy, 12)
	for i := range inspectPolicies {
		inspectPolicies[i] = requestInspectPolicy{
			matches:  func(*http.Request, string) bool { return true },
			severity: inspectSeverityCritical,
			inspect:  func(*slog.Logger, *http.Request, string) (string, error) { return "", nil },
		}
	}
	policy := runtimePolicy{inspectPolicies: inspectPolicies}

	allocs := testing.AllocsPerRun(1000, func() {
		reason, reasonCode, status := policy.inspectAllowedRequest(nil, req, "/plugins/create")
		if reason != "" || reasonCode != "" || status != 0 {
			t.Fatalf("inspectAllowedRequest() = (%q, %q, %d), want empty result", reason, reasonCode, status)
		}
	})
	if allocs != 0 {
		t.Fatalf("inspectAllowedRequest() allocations = %.0f, want 0", allocs)
	}
}

func TestRuleDecisionReasonCode(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		reason string
		want   string
	}{
		{name: "allow", action: ActionAllow, want: reasonCodeMatchedAllowRule},
		{name: "deny no matching allow rule", action: ActionDeny, reason: "no matching allow rule", want: reasonCodeNoMatchingAllowRule},
		{name: "deny matched deny rule", action: ActionDeny, reason: "deny all", want: reasonCodeMatchedDenyRule},
		{name: "unknown action", action: Action("audit"), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleDecisionReasonCode(tt.action, tt.reason); got != tt.want {
				t.Fatalf("ruleDecisionReasonCode(%q, %q) = %q, want %q", tt.action, tt.reason, got, tt.want)
			}
		})
	}
}

func TestRequestRejectionReasonCode(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   string
	}{
		{name: "request body too large", status: http.StatusRequestEntityTooLarge, want: reasonCodeRequestBodyTooLarge},
		{name: "request body policy denied", status: http.StatusForbidden, want: reasonCodeRequestBodyPolicyDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestRejectionReasonCode(tt.status); got != tt.want {
				t.Fatalf("requestRejectionReasonCode(%d) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestParseDenyResponseVerbosity(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  DenyResponseVerbosity
	}{
		{name: "minimal", input: "minimal", want: DenyResponseVerbosityMinimal},
		{name: "verbose", input: "verbose", want: DenyResponseVerbosityVerbose},
		{name: "empty defaults minimal", input: "", want: DenyResponseVerbosityMinimal},
		{name: "invalid defaults minimal", input: "chatty", want: DenyResponseVerbosityMinimal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseDenyResponseVerbosity(tt.input); got != tt.want {
				t.Fatalf("ParseDenyResponseVerbosity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPolicyConfigNormalized(t *testing.T) {
	cfg := PolicyConfig{
		DenyResponseVerbosity: "chatty",
	}

	got := cfg.normalized()
	if got.DenyResponseVerbosity != DenyResponseVerbosityMinimal {
		t.Fatalf("normalized deny verbosity = %q, want %q", got.DenyResponseVerbosity, DenyResponseVerbosityMinimal)
	}
}

func TestMiddlewareWritesMeta(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := logging.MetaForRequest(w, r)
		if m == nil {
			t.Fatal("expected request meta")
			return
		}
		if m.Decision != "allow" {
			t.Errorf("Decision = %q, want allow", m.Decision)
		}
		if m.Rule != 0 {
			t.Errorf("Rule = %d, want 0", m.Rule)
		}
		if m.NormPath != "/_ping" {
			t.Errorf("NormPath = %q, want /_ping", m.NormPath)
		}
	})

	handler := verboseMiddleware(rules, testLogger())(inner)

	// Simulate access log middleware by injecting meta
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest("GET", "/_ping", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Also verify meta was written (accessible from outer middleware)
	if meta.Decision != "allow" {
		t.Errorf("meta.Decision = %q, want allow", meta.Decision)
	}
}

func TestDenyWithReasonCodePopulatesEmptyNormPath(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/%2e%2e/images/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()

	denyWithReasonCode(rec, req, logger, reasonCodeClientPolicyProfileUnresolved, "profile not found", DenyResponseVerbosityMinimal)

	if meta.Decision != string(ActionDeny) {
		t.Fatalf("meta.Decision = %q, want deny", meta.Decision)
	}
	if meta.ReasonCode != reasonCodeClientPolicyProfileUnresolved {
		t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeClientPolicyProfileUnresolved)
	}
	if meta.Reason != "profile not found" {
		t.Fatalf("meta.Reason = %q, want profile not found", meta.Reason)
	}
	if meta.NormPath != "/images/json" {
		t.Fatalf("meta.NormPath = %q, want /images/json", meta.NormPath)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestDenyWithReasonCodeLogsEncodeError(t *testing.T) {
	collector := &collectingHandler{}
	logger := slog.New(collector)
	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec := &failingResponseWriter{}

	denyWithReasonCode(rec, req, logger, reasonCodeClientPolicyProfileUnresolved, "profile not found", DenyResponseVerbosityMinimal)

	if rec.status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.status, http.StatusForbidden)
	}
	records := collector.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
	if records[0].message != "failed to encode denial response" {
		t.Fatalf("log message = %q, want encode failure", records[0].message)
	}
}

func TestMiddlewareConcurrentRequestMetaIsolation(t *testing.T) {
	allowRule, _ := CompileRule(Rule{Methods: []string{http.MethodGet}, Pattern: "/allowed/**", Action: ActionAllow, Index: 0})
	denyRule, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{allowRule, denyRule}

	const totalRequests = 64
	const allowedRequests = totalRequests / 2

	collector := &collectingHandler{}
	logger := slog.New(collector)

	releaseAllowed := make(chan struct{})
	enteredAllowed := make(chan string, allowedRequests)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enteredAllowed <- r.URL.Path
		<-releaseAllowed
		w.WriteHeader(http.StatusAccepted)
	})

	handler := logging.AccessLogMiddleware(logger)(verboseMiddleware(rules, logger)(inner))

	type expectation struct {
		message        string
		decision       string
		rule           int
		normalizedPath string
		reason         string
		status         int
	}

	expectations := make(map[string]expectation, totalRequests)
	requests := make([]struct {
		method string
		path   string
	}, 0, totalRequests)

	for i := 0; i < totalRequests; i++ {
		if i%2 == 0 {
			path := fmt.Sprintf("/allowed/%02d", i)
			requests = append(requests, struct {
				method string
				path   string
			}{method: http.MethodGet, path: path})
			expectations[path] = expectation{
				message:        "request",
				decision:       "allow",
				rule:           0,
				normalizedPath: NormalizePath(path),
				status:         http.StatusAccepted,
			}
			continue
		}

		path := fmt.Sprintf("/blocked/%02d", i)
		requests = append(requests, struct {
			method string
			path   string
		}{method: http.MethodPost, path: path})
		expectations[path] = expectation{
			message:        "request_denied",
			decision:       "deny",
			rule:           1,
			normalizedPath: NormalizePath(path),
			reason:         "deny all",
			status:         http.StatusForbidden,
		}
	}

	var wg sync.WaitGroup
	wg.Add(len(requests))
	errCh := make(chan error, len(requests))

	for _, reqSpec := range requests {
		reqSpec := reqSpec
		go func() {
			defer wg.Done()

			req := httptest.NewRequest(reqSpec.method, reqSpec.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got, want := rec.Code, expectations[reqSpec.path].status; got != want {
				errCh <- fmt.Errorf("status for %s = %d, want %d", reqSpec.path, got, want)
			}
		}()
	}

	for i := 0; i < allowedRequests; i++ {
		<-enteredAllowed
	}
	close(releaseAllowed)

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	records := collector.snapshot()
	if len(records) != totalRequests {
		t.Fatalf("log records = %d, want %d", len(records), totalRequests)
	}

	seen := make(map[string]loggedRequest, totalRequests)
	for _, record := range records {
		path, _ := record.attrs["path"].(string)
		if path == "" {
			t.Fatalf("log record %q missing path attr: %#v", record.message, record.attrs)
		}
		seen[path] = record
	}

	for _, reqSpec := range requests {
		want := expectations[reqSpec.path]
		record, ok := seen[reqSpec.path]
		if !ok {
			t.Fatalf("missing log record for %s", reqSpec.path)
		}

		if record.message != want.message {
			t.Errorf("message for %s = %q, want %q", reqSpec.path, record.message, want.message)
		}
		if got, _ := record.attrs["method"].(string); got != reqSpec.method {
			t.Errorf("method for %s = %q, want %q", reqSpec.path, got, reqSpec.method)
		}
		if got, _ := record.attrs["path"].(string); got != reqSpec.path {
			t.Errorf("path for %s = %q, want %q", reqSpec.path, got, reqSpec.path)
		}
		if got, _ := record.attrs["normalized_path"].(string); got != want.normalizedPath {
			t.Errorf("normalized_path for %s = %q, want %q", reqSpec.path, got, want.normalizedPath)
		}
		if got, _ := record.attrs["decision"].(string); got != want.decision {
			t.Errorf("decision for %s = %q, want %q", reqSpec.path, got, want.decision)
		}
		if got, ok := record.attrs["rule"].(int64); !ok || int(got) != want.rule {
			t.Errorf("rule for %s = %v, want %d", reqSpec.path, record.attrs["rule"], want.rule)
		}
		if got, _ := record.attrs["reason"].(string); got != want.reason {
			t.Errorf("reason for %s = %q, want %q", reqSpec.path, got, want.reason)
		}
	}
}

func TestMiddlewareAllowsLargePayloadPassThrough(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	payload := []byte(`{"Image":"busybox:1.37","Labels":{"payload":"` + strings.Repeat("sockguard-payload-", 1<<15) + `"}}`)
	wantDigest := sha256.Sum256(payload)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if len(body) != len(payload) {
			t.Fatalf("body len = %d, want %d", len(body), len(payload))
		}
		gotDigest := sha256.Sum256(body)
		if gotDigest != wantDigest {
			t.Fatalf("body sha256 = %s, want %s", hex.EncodeToString(gotDigest[:]), hex.EncodeToString(wantDigest[:]))
		}
		w.WriteHeader(http.StatusAccepted)
	})

	handler := verboseMiddleware(rules, testLogger())(inner)
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

func TestMiddlewareDeniesPrivilegedContainerCreate(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	reached := false
	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox:1.37","HostConfig":{"Privileged":true}}`))
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Fatal("expected privileged container create to be denied before reaching inner handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "privileged") {
		t.Fatalf("reason = %q, want privileged denial", body.Reason)
	}
	if meta.Decision != "deny" {
		t.Fatalf("meta.Decision = %q, want deny", meta.Decision)
	}
	if meta.Reason != body.Reason {
		t.Fatalf("meta.Reason = %q, want %q", meta.Reason, body.Reason)
	}
}

func TestMiddlewareDeniesHostNetworkContainerCreate(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected host-network container create to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox:1.37","HostConfig":{"NetworkMode":"host"}}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "host network") {
		t.Fatalf("reason = %q, want host network denial", body.Reason)
	}
}

func TestMiddlewareDeniesUnallowlistedContainerCreateBindMounts(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected bind-mounted container create to be denied")
	}))

	req := httptest.NewRequest(
		http.MethodPost,
		"/containers/create",
		strings.NewReader(`{"Image":"busybox:1.37","HostConfig":{"Binds":["/srv/unsafe:/data:rw"],"Mounts":[{"Type":"bind","Source":"/srv/also-unsafe","Target":"/config"}]}}`),
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "bind mount") {
		t.Fatalf("reason = %q, want bind mount denial", body.Reason)
	}
}

func TestMiddlewareAllowsAllowlistedContainerCreateBindMounts(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	payload := []byte(`{"Image":"busybox:1.37","HostConfig":{"Binds":["/srv/sockguard/data:/data:rw","named-cache:/cache"],"Mounts":[{"Type":"bind","Source":"/srv/sockguard/config","Target":"/config"},{"Type":"volume","Source":"build-cache","Target":"/var/cache"}]}}`)
	wantDigest := sha256.Sum256(payload)

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			ContainerCreate: ContainerCreateOptions{
				AllowedBindMounts: []string{"/srv/sockguard"},
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if gotDigest := sha256.Sum256(body); gotDigest != wantDigest {
			t.Fatalf("body sha256 = %s, want %s", hex.EncodeToString(gotDigest[:]), hex.EncodeToString(wantDigest[:]))
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

func TestMiddlewareVersionPrefixInDenial(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach inner handler")
	})

	handler := verboseMiddleware(rules, testLogger())(inner)
	req := httptest.NewRequest("POST", "/v1.45/containers/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Original path should be preserved in denial response
	if body.Path != "/v1.45/containers/create" {
		t.Errorf("path = %q, want /v1.45/containers/create", body.Path)
	}
}

func TestMiddlewareDeniedRedactsSensitiveVerbosePaths(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	rules := []*CompiledRule{r1}

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "secret resource",
			path: "/v1.45/secrets/prod-db-password",
			want: "/v1.45/secrets/<redacted>",
		},
		{
			name: "swarm unlock key",
			path: "/v1.45/swarm/unlockkey",
			want: "/v1.45/swarm/<redacted>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("should not reach inner handler")
			}))
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}

			var body DenialResponse
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Path != tt.want {
				t.Fatalf("path = %q, want %q", body.Path, tt.want)
			}
			if body.Method != http.MethodPost {
				t.Fatalf("method = %q, want %q", body.Method, http.MethodPost)
			}
			if body.Reason != "deny all" {
				t.Fatalf("reason = %q, want %q", body.Reason, "deny all")
			}
		})
	}
}

func TestMiddlewareEmptyRulesDeny(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})

	handler := verboseMiddleware(nil, testLogger())(inner)
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("expected request to NOT reach inner handler with empty rules")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Reason != "no matching allow rule" {
		t.Errorf("reason = %q, want %q", body.Reason, "no matching allow rule")
	}
}

func TestMiddlewareNilMetaInContext(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := verboseMiddleware(rules, testLogger())(inner)
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("expected request to reach inner handler with nil meta in context")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareLogsEncodeError(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach inner handler")
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	handler := verboseMiddleware(rules, logger)(inner)
	req := httptest.NewRequest("POST", "/containers/create", nil)
	rec := &failingResponseWriter{}
	handler.ServeHTTP(rec, req)

	if rec.status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.status, http.StatusForbidden)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "failed to encode denial response") {
		t.Errorf("expected encode error log, got %q", logOutput)
	}
	if !strings.Contains(logOutput, errWriteFailed.Error()) {
		t.Errorf("expected write error in log, got %q", logOutput)
	}
}

func TestMiddlewareDoesNotAttemptFallbackAfterHeadersCommitted(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach inner handler")
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	handler := verboseMiddleware(rules, logger)(inner)
	req := httptest.NewRequest("POST", "/v1.45/../containers/create", nil)
	rec := &failOnceResponseWriter{}
	handler.ServeHTTP(rec, req)

	if rec.status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.status, http.StatusForbidden)
	}
	if got := rec.committed.Get("Content-Type"); got != "application/json" {
		t.Fatalf("committed Content-Type = %q, want application/json", got)
	}
	if rec.writeCalls != 1 {
		t.Fatalf("write calls = %d, want 1", rec.writeCalls)
	}
	if rec.body.Len() != 0 {
		t.Fatalf("body length = %d, want 0", rec.body.Len())
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "failed to encode denial response") {
		t.Errorf("expected encode error log, got %q", logOutput)
	}
	if !strings.Contains(logOutput, errWriteFailed.Error()) {
		t.Errorf("expected write error in log, got %q", logOutput)
	}
}

func TestMiddlewareDeniesWhenContainerCreateInspectionFails(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	logs := &collectingHandler{}
	handler := verboseMiddleware([]*CompiledRule{rule}, slog.New(logs))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected request to be denied before reaching inner handler")
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req.Body = &readErrorReadCloser{
		readErr: errors.New("read failed"),
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Reason != "unable to inspect container create request body" {
		t.Fatalf("reason = %q, want inspection failure", body.Reason)
	}

	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
	if records[0].message != "failed to inspect container create request body" {
		t.Fatalf("message = %q, want inspection failure log", records[0].message)
	}
}

func TestMiddlewareDeniesWhenExecInspectionFails(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	logs := &collectingHandler{}
	handler := verboseMiddleware([]*CompiledRule{rule}, slog.New(logs))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected request to be denied before reaching inner handler")
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", nil)
	req.Body = &readErrorReadCloser{readErr: errors.New("read failed")}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Reason != "unable to inspect exec request body" {
		t.Fatalf("reason = %q, want inspection failure", body.Reason)
	}

	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
	if records[0].message != "failed to inspect exec request body" {
		t.Fatalf("message = %q, want inspection failure log", records[0].message)
	}
}

func TestMiddlewareLogsDebugForMalformedContainerCreateBody(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	logs := &collectingHandler{}
	reached := false
	handler := verboseMiddleware([]*CompiledRule{rule}, slog.New(logs))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"HostConfig":`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("expected malformed container create body to pass through to Docker")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
	if records[0].level != slog.LevelDebug {
		t.Fatalf("level = %v, want %v", records[0].level, slog.LevelDebug)
	}
	if records[0].message != "container create request body is not valid JSON; deferring to Docker validation" {
		t.Fatalf("message = %q, want malformed JSON debug log", records[0].message)
	}
}

func TestMiddlewareLogsDebugForMalformedExecBody(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	logs := &collectingHandler{}
	reached := false
	handler := verboseMiddleware([]*CompiledRule{rule}, slog.New(logs))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", strings.NewReader(`{"Cmd":`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("expected malformed exec body to pass through to Docker")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	records := logs.snapshot()
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1", len(records))
	}
	if records[0].level != slog.LevelDebug {
		t.Fatalf("level = %v, want %v", records[0].level, slog.LevelDebug)
	}
	if records[0].message != "exec request body is not valid JSON; deferring to Docker validation" {
		t.Fatalf("message = %q, want malformed JSON debug log", records[0].message)
	}
}

func TestRedactDeniedPathEmpty(t *testing.T) {
	if got := redactDeniedPath(""); got != "" {
		t.Fatalf("redactDeniedPath(\"\") = %q, want empty", got)
	}
}

// TestMiddlewareWrapperDelegates verifies the Middleware convenience wrapper
// produces identical behavior to MiddlewareWithOptions with empty Options{}.
func TestMiddlewareWrapperDelegates(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	// Middleware is the thin public wrapper around MiddlewareWithOptions.
	handler := Middleware(rules, testLogger())(inner)
	req := httptest.NewRequest("GET", "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("expected request to reach inner handler via Middleware wrapper")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestMiddlewareWrapperDenies confirms Middleware still denies unmatched requests.
func TestMiddlewareWrapperDenies(t *testing.T) {
	rules := []*CompiledRule{} // empty rules → default-deny everything

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("should not reach inner handler")
	})

	handler := Middleware(rules, testLogger())(inner)
	req := httptest.NewRequest("POST", "/containers/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestMatchesSwarmInspectionNonPostMethod covers the r.Method != POST branch.
func TestMatchesSwarmInspectionNonPostMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/swarm/init", nil)
	if matchesSwarmInspection(req, "/swarm/init") {
		t.Error("matchesSwarmInspection() = true for GET, want false")
	}
}

// TestMatchesSwarmInspectionNilRequest covers the r == nil branch.
func TestMatchesSwarmInspectionNilRequest(t *testing.T) {
	if matchesSwarmInspection(nil, "/swarm/init") {
		t.Error("matchesSwarmInspection() = true for nil request, want false")
	}
}

// TestMatchesSwarmInspectionAllPaths exercises all switch arms.
func TestMatchesSwarmInspectionAllPaths(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/swarm/init", true},
		{"/swarm/join", true},
		{"/swarm/update", true},
		{"/swarm/leave", false},
		{"/containers/create", false},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodPost, tt.path, nil)
		got := matchesSwarmInspection(req, tt.path)
		if got != tt.want {
			t.Errorf("matchesSwarmInspection(POST, %q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// TestMiddlewareProfileResolutionUnknownProfile covers the "profile not found"
// branch inside the ResolveProfile path.
func TestMiddlewareProfileResolutionUnknownProfile(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/**", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("should not reach inner handler when profile is unknown")
	})

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{DenyResponseVerbosity: DenyResponseVerbosityVerbose},
		Profiles:     map[string]Policy{}, // no profiles registered
		ResolveProfile: func(*http.Request) (string, bool) {
			return "nonexistent-profile", true
		},
	})(inner)

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "profile") {
		t.Errorf("reason = %q, want profile-resolution denial", body.Reason)
	}
}

// TestMiddlewareProfileResolutionFound verifies a successfully resolved
// profile overrides the default policy.
func TestMiddlewareProfileResolutionFound(t *testing.T) {
	defaultRules := []*CompiledRule{} // deny all by default

	profileRule, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := MiddlewareWithOptions(defaultRules, testLogger(), Options{
		PolicyConfig: PolicyConfig{DenyResponseVerbosity: DenyResponseVerbosityVerbose},
		Profiles: map[string]Policy{
			"trusted": {Rules: []*CompiledRule{profileRule}},
		},
		ResolveProfile: func(*http.Request) (string, bool) {
			return "trusted", true
		},
	})(inner)

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("expected request to reach inner handler via profile policy")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestMiddlewareResolveProfileReturnsFalse verifies that when ResolveProfile
// returns ok=false the default policy is used without any profile lookup.
func TestMiddlewareResolveProfileReturnsFalse(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		ResolveProfile: func(*http.Request) (string, bool) {
			return "", false // no profile selected
		},
	})(inner)

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("expected request to reach inner handler when ResolveProfile returns false")
	}
}

// TestMiddlewareProfileResolutionSetsMetaProfile verifies that when ResolveProfile
// returns a non-empty profile name and logging.MetaForRequest returns a non-nil meta,
// meta.Profile is populated (middleware.go lines 148-150).
func TestMiddlewareProfileResolutionSetsMetaProfile(t *testing.T) {
	profileRule, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})

	handler := MiddlewareWithOptions([]*CompiledRule{}, testLogger(), Options{
		PolicyConfig: PolicyConfig{DenyResponseVerbosity: DenyResponseVerbosityVerbose},
		Profiles: map[string]Policy{
			"trusted": {Rules: []*CompiledRule{profileRule}},
		},
		ResolveProfile: func(*http.Request) (string, bool) {
			return "trusted", true
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Inject RequestMeta into context so MetaForRequest returns it (covers lines 148-150).
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if meta.Profile != "trusted" {
		t.Fatalf("meta.Profile = %q, want %q", meta.Profile, "trusted")
	}
}

// TestInspectAllowedRequestReturnsRejectionStatusFromError covers the
// requestRejectionError path inside inspectAllowedRequest.
func TestInspectAllowedRequestReturnsRejectionStatusFromError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", nil)

	policy := runtimePolicy{
		inspectPolicies: []requestInspectPolicy{
			{
				matches:  func(*http.Request, string) bool { return true },
				severity: inspectSeverityMedium,
				inspect: func(*slog.Logger, *http.Request, string) (string, error) {
					return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, "entity too large")
				},
				errorLogMessage:   "inspect failed",
				denyReasonOnError: "unable to inspect",
			},
		},
	}

	reason, reasonCode, status := policy.inspectAllowedRequest(testLogger(), req, "/volumes/create")
	if reason != "entity too large" {
		t.Fatalf("reason = %q, want %q", reason, "entity too large")
	}
	if reasonCode != reasonCodeRequestBodyTooLarge {
		t.Fatalf("reasonCode = %q, want %q", reasonCode, reasonCodeRequestBodyTooLarge)
	}
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", status, http.StatusRequestEntityTooLarge)
	}
}
