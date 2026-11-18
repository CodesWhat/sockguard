package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

type otlpCollected struct {
	mu     sync.Mutex
	bodies []string
}

func (c *otlpCollected) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.bodies, "\n")
}

func newOTLPTestCollector(t *testing.T) (*httptest.Server, *otlpCollected) {
	t.Helper()
	c := &otlpCollected{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, string(body))
		c.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func startUnixDockerStub(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "[]")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// otlpWiringSpan is the slice of an exported span this test asserts on.
type otlpWiringSpan struct {
	Status struct {
		Code int `json:"code"`
	} `json:"status"`
	Attributes []struct {
		Key   string `json:"key"`
		Value struct {
			StringValue *string `json:"stringValue"`
			IntValue    *string `json:"intValue"`
		} `json:"value"`
	} `json:"attributes"`
}

func decodeOTLPWiringSpans(t *testing.T, bodies string) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, body := range strings.Split(bodies, "\n") {
		if body == "" {
			continue
		}
		var p struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []otlpWiringSpan `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatalf("decode export: %v", err)
		}
		for _, rs := range p.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					m := map[string]string{}
					for _, a := range s.Attributes {
						if a.Value.StringValue != nil {
							m[a.Key] = *a.Value.StringValue
						} else if a.Value.IntValue != nil {
							m[a.Key] = *a.Value.IntValue
						}
					}
					out = append(out, m)
				}
			}
		}
	}
	return out
}

func TestServeChainExportsOTLPSpansForAllowAndDeny(t *testing.T) {
	collector, got := newOTLPTestCollector(t)

	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "otlp-upstream")
	startUnixDockerStub(t, cfg.Upstream.Socket)
	cfg.Log.AccessLog = false
	cfg.Metrics.Enabled = true
	cfg.OTLP.Enabled = true
	cfg.OTLP.Endpoint = collector.URL + "/v1/traces"
	cfg.OTLP.FlushInterval = "10ms"
	cfg.OTLP.Headers = map[string]string{"x-key": "otlp-header-secret"}

	rules, err := compileRuleConfigsForTest([]config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/containers/json"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "free text reason"},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	deps := newServeTestDeps()
	runtime, err := newServeRuntime(&cfg, newDiscardLogger(), deps)
	if err != nil {
		t.Fatalf("newServeRuntime: %v", err)
	}
	if runtime.otlp == nil {
		t.Fatal("otlp.enabled did not create an exporter")
	}
	handler, teardown, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{
		Cfg: &cfg, Logger: newDiscardLogger(), Rules: rules, Deps: deps, Runtime: runtime,
	})
	t.Cleanup(teardown)

	for _, tc := range []struct {
		method, path string
		wantStatus   int
	}{
		{http.MethodGet, "/containers/json?secret=hunter2", http.StatusOK},
		{http.MethodDelete, "/containers/abc123?secret=hunter2", http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.wantStatus {
			t.Fatalf("%s %s = %d, want %d; body %s", tc.method, tc.path, rec.Code, tc.wantStatus, rec.Body.String())
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.otlp.Close(ctx); err != nil {
		t.Fatalf("close exporter: %v", err)
	}

	raw := got.all()
	for _, leak := range []string{"hunter2", "otlp-header-secret", "free text reason"} {
		if strings.Contains(raw, leak) {
			t.Errorf("export leaks %q", leak)
		}
	}
	spans := decodeOTLPWiringSpans(t, raw)
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2; payload %s", len(spans), raw)
	}
	byMethod := map[string]map[string]string{}
	for _, s := range spans {
		byMethod[s["http.request.method"]] = s
	}
	if s := byMethod["GET"]; s["sockguard.decision"] != "allow" || s["http.response.status_code"] != "200" || s["sockguard.normalized_path"] != "/containers/json" {
		t.Errorf("allow span attrs = %v", s)
	}
	if s := byMethod["DELETE"]; s["sockguard.decision"] != "deny" || s["http.response.status_code"] != "403" || s["sockguard.reason_code"] == "" {
		t.Errorf("deny span attrs = %v", s)
	}

	// The exporter's counters surface on the metrics endpoint.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{
		"sockguard_otlp_spans_exported_total 2",
		`sockguard_otlp_spans_dropped_total{reason="queue_full"} 0`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	// The two spans may land in one batch or two, so require at least one
	// successful export request rather than exactly one.
	const successPrefix = `sockguard_otlp_export_requests_total{result="success"} `
	_, after, found := strings.Cut(rec.Body.String(), successPrefix)
	if !found {
		t.Errorf("metrics missing %q", successPrefix)
	} else if v, err := strconv.Atoi(strings.Fields(after)[0]); err != nil || v < 1 {
		t.Errorf("success export requests = %q, want >= 1", strings.Fields(after)[0])
	}
}

func TestServeChainOTLPDisabledAddsNothing(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "otlp-off")
	cfg.Log.AccessLog = false
	cfg.Metrics.Enabled = true
	deps := newServeTestDeps()
	runtime, err := newServeRuntime(&cfg, newDiscardLogger(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.otlp != nil {
		t.Fatal("exporter created while otlp.enabled=false")
	}
	handler, teardown, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{Cfg: &cfg, Logger: newDiscardLogger(), Deps: deps, Runtime: runtime})
	t.Cleanup(teardown)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rec.Body.String(), "sockguard_otlp_") {
		t.Error("otlp metrics exposed while disabled")
	}
	// Roots stay unsampled when the exporter is off, as before.
	if tp := rec.Header().Get("Traceparent"); !strings.HasSuffix(tp, "-00") {
		t.Errorf("traceparent = %q, want unsampled root", tp)
	}
	runtime.closeOTLP(0) // nil exporter: no-op
}

func TestPolicyConfigHashDoesNotExposeOTLPHeaderValues(t *testing.T) {
	cfg := config.Defaults()
	cfg.OTLP.Headers = map[string]string{"x-key": "otlp-header-secret"}
	h := policyConfigHash(&cfg)
	if len(h) != 64 || strings.Contains(h, "otlp-header-secret") {
		t.Fatalf("hash = %q", h)
	}
	if h == policyConfigHash(&config.Config{}) {
		t.Fatal("hash ignores config")
	}
}
