package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/admin"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/otlp"
)

const adminOTLPSecretHeader = "admin-otlp-header-secret"

// adminOTLPFixture is the dedicated admin chain wired to a real exporter that
// posts to the given collector URL.
type adminOTLPFixture struct {
	cfg      config.Config
	exporter *otlp.Exporter
	handler  http.Handler
}

func newAdminOTLPFixture(t *testing.T, endpoint string, mutate func(*config.Config)) *adminOTLPFixture {
	t.Helper()
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-otlp")
	cfg.Log.AccessLog = false
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"
	cfg.OTLP.Enabled = true
	cfg.OTLP.Endpoint = endpoint
	cfg.OTLP.FlushInterval = "10ms"
	cfg.OTLP.SampleRatio = 1
	cfg.OTLP.Headers = map[string]string{"x-key": adminOTLPSecretHeader}
	if mutate != nil {
		mutate(&cfg)
	}
	exporter, err := newOTLPExporter(cfg.OTLP)
	if err != nil {
		t.Fatalf("newOTLPExporter: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exporter.Close(ctx)
	})
	versioner := admin.NewPolicyVersioner()
	versioner.Update(admin.PolicySnapshot{Rules: 1, Source: "startup"})
	return &adminOTLPFixture{
		cfg:      cfg,
		exporter: exporter,
		handler:  buildAdminHandlerChain(&cfg, newDiscardLogger(), nil, versioner, exporter),
	}
}

func (f *adminOTLPFixture) do(method, target, remote, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *adminOTLPFixture) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.exporter.Close(ctx); err != nil {
		t.Fatalf("close exporter: %v", err)
	}
}

type adminOTLPSpan struct {
	Name  string
	Attrs map[string]string
}

func decodeAdminOTLPSpans(t *testing.T, bodies string) []adminOTLPSpan {
	t.Helper()
	var out []adminOTLPSpan
	for _, body := range strings.Split(bodies, "\n") {
		if body == "" {
			continue
		}
		var p struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []struct {
						Name       string `json:"name"`
						Attributes []struct {
							Key   string `json:"key"`
							Value struct {
								StringValue *string `json:"stringValue"`
								IntValue    *string `json:"intValue"`
							} `json:"value"`
						} `json:"attributes"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatalf("decode export: %v", err)
		}
		for _, rs := range p.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					sp := adminOTLPSpan{Name: s.Name, Attrs: map[string]string{}}
					for _, a := range s.Attributes {
						switch {
						case a.Value.StringValue != nil:
							sp.Attrs[a.Key] = *a.Value.StringValue
						case a.Value.IntValue != nil:
							sp.Attrs[a.Key] = *a.Value.IntValue
						}
					}
					out = append(out, sp)
				}
			}
		}
	}
	return out
}

func TestAdminChainExportsSpansAcrossAccessBoundary(t *testing.T) {
	collector, got := newOTLPTestCollector(t)
	f := newAdminOTLPFixture(t, collector.URL+"/v1/traces", func(cfg *config.Config) {
		cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
	})

	if rec := f.do(http.MethodGet, f.cfg.Admin.PolicyVersionPath, "192.0.2.10:1234", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed IP status = %d, want 403", rec.Code)
	}
	if rec := f.do(http.MethodGet, f.cfg.Admin.PolicyVersionPath, "10.1.2.3:1234", ""); rec.Code != http.StatusOK {
		t.Fatalf("allowed IP status = %d, want 200", rec.Code)
	}
	f.close(t)

	spans := decodeAdminOTLPSpans(t, got.all())
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2; payload %s", len(spans), got.all())
	}
	byStatus := map[string]adminOTLPSpan{}
	for _, s := range spans {
		byStatus[s.Attrs["http.response.status_code"]] = s
	}
	denied, ok := byStatus["403"]
	if !ok {
		t.Fatalf("no span for the denied request: %v", spans)
	}
	if denied.Attrs["sockguard.decision"] != "deny" || denied.Attrs["sockguard.reason_code"] == "" {
		t.Errorf("denied span attrs = %v, want deny with a reason code", denied.Attrs)
	}
	if denied.Name != "GET "+f.cfg.Admin.PolicyVersionPath || denied.Attrs["http.route"] != f.cfg.Admin.PolicyVersionPath {
		t.Errorf("denied span name/route = %q / %q", denied.Name, denied.Attrs["http.route"])
	}
	allowed := byStatus["200"]
	if allowed.Attrs["sockguard.decision"] != "allow" {
		t.Errorf("allowed span attrs = %v", allowed.Attrs)
	}
	if allowed.Attrs["network.peer.address"] != "10.1.2.3" {
		t.Errorf("allowed span peer = %q", allowed.Attrs["network.peer.address"])
	}
}

func TestAdminSpansCarryNoSensitiveContent(t *testing.T) {
	collector, got := newOTLPTestCollector(t)
	f := newAdminOTLPFixture(t, collector.URL+"/v1/traces", nil)

	const yamlSecret = "super-secret-yaml-marker"
	f.do(http.MethodPost, f.cfg.Admin.Path+"?apikey=query-secret", "127.0.0.1:1", "upstream:\n  socket: /tmp/"+yamlSecret+"\n")
	f.do(http.MethodGet, "/not-an-admin-path/"+"attacker-chosen-segment?q=query-secret", "127.0.0.1:1", "")
	f.close(t)

	raw := got.all()
	for _, leak := range []string{yamlSecret, "query-secret", adminOTLPSecretHeader, "attacker-chosen-segment"} {
		if strings.Contains(raw, leak) {
			t.Errorf("export leaks %q", leak)
		}
	}
	spans := decodeAdminOTLPSpans(t, raw)
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2; payload %s", len(spans), raw)
	}
	routes := map[string]bool{}
	for _, s := range spans {
		routes[s.Attrs["http.route"]] = true
	}
	if !routes[f.cfg.Admin.Path] || !routes["unknown"] {
		t.Errorf("routes = %v, want %q and unknown", routes, f.cfg.Admin.Path)
	}
}

func TestAdminSpansBackpressureNeverBlocksRequests(t *testing.T) {
	release := make(chan struct{})
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(collector.Close)
	f := newAdminOTLPFixture(t, collector.URL+"/v1/traces", func(cfg *config.Config) {
		cfg.OTLP.QueueSize = 8
		cfg.OTLP.BatchSize = 4
	})
	t.Cleanup(func() { close(release) })

	var worst time.Duration
	for range 24 {
		t0 := time.Now()
		if rec := f.do(http.MethodGet, f.cfg.Admin.PolicyVersionPath, "127.0.0.1:1", ""); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 with a stalled collector", rec.Code)
		}
		if d := time.Since(t0); d > worst {
			worst = d
		}
	}
	if worst > 50*time.Millisecond {
		t.Errorf("slowest admin request took %v, want < 50ms", worst)
	}
	if f.exporter.Stats().DroppedQueueFull == 0 {
		t.Error("DroppedQueueFull = 0, want > 0 with a stalled collector")
	}
}

func TestAdminSpansCollectorFailureDoesNotAffectRequests(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(collector.Close)
	f := newAdminOTLPFixture(t, collector.URL+"/v1/traces", nil)

	for range 3 {
		if rec := f.do(http.MethodGet, f.cfg.Admin.PolicyVersionPath, "127.0.0.1:1", ""); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 with a rejecting collector", rec.Code)
		}
	}
	f.close(t)
	if got := f.exporter.Stats().DroppedExportFailed; got == 0 {
		t.Error("DroppedExportFailed = 0, want > 0 after the collector rejected the batch")
	}
	if rec := f.do(http.MethodGet, f.cfg.Admin.PolicyVersionPath, "127.0.0.1:1", ""); rec.Code != http.StatusOK {
		t.Fatalf("status after exporter close = %d, want 200", rec.Code)
	}
}

func TestAdminSpansFlushOnShutdownAndSurviveAfterClose(t *testing.T) {
	collector, got := newOTLPTestCollector(t)
	f := newAdminOTLPFixture(t, collector.URL+"/v1/traces", func(cfg *config.Config) {
		// Long enough that only the shutdown flush can deliver the spans.
		cfg.OTLP.FlushInterval = "1h"
	})

	for range 3 {
		f.do(http.MethodGet, f.cfg.Admin.PolicyVersionPath, "127.0.0.1:1", "")
	}
	f.close(t)
	if n := len(decodeAdminOTLPSpans(t, got.all())); n != 3 {
		t.Fatalf("flushed spans = %d, want 3", n)
	}
	// A request that outlives the exporter is dropped, never a panic or hang.
	if rec := f.do(http.MethodGet, f.cfg.Admin.PolicyVersionPath, "127.0.0.1:1", ""); rec.Code != http.StatusOK {
		t.Fatalf("status after close = %d, want 200", rec.Code)
	}
	if f.exporter.Stats().DroppedShutdown == 0 {
		t.Error("DroppedShutdown = 0, want the post-close span counted")
	}
}

func TestAdminChainWithoutExporterAddsNoSpanLayer(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:0"
	versioner := admin.NewPolicyVersioner()
	versioner.Update(admin.PolicySnapshot{Rules: 1, Source: "startup"})
	h := buildAdminHandlerChain(&cfg, newDiscardLogger(), nil, versioner, nil)
	req := httptest.NewRequest(http.MethodGet, cfg.Admin.PolicyVersionPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
