package filter

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

var benchRules []*CompiledRule

func init() {
	specs := []Rule{
		{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0},
		{Methods: []string{"GET"}, Pattern: "/version", Action: ActionAllow, Index: 1},
		{Methods: []string{"GET"}, Pattern: "/containers/json", Action: ActionAllow, Index: 2},
		{Methods: []string{"GET"}, Pattern: "/containers/*/json", Action: ActionAllow, Index: 3},
		{Methods: []string{"GET"}, Pattern: "/images/json", Action: ActionAllow, Index: 4},
		{Methods: []string{"GET"}, Pattern: "/networks/**", Action: ActionAllow, Index: 5},
		{Methods: []string{"POST"}, Pattern: "/containers/*/start", Action: ActionAllow, Index: 6},
		{Methods: []string{"POST"}, Pattern: "/containers/*/stop", Action: ActionAllow, Index: 7},
		{Methods: []string{"POST"}, Pattern: "/containers/*/restart", Action: ActionAllow, Index: 8},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 9},
	}
	benchRules = make([]*CompiledRule, len(specs))
	for i, s := range specs {
		r, err := CompileRule(s)
		if err != nil {
			panic(err)
		}
		benchRules[i] = r
	}
}

func BenchmarkNormalizePath(b *testing.B) {
	paths := []struct {
		name string
		path string
	}{
		{"bare", "/containers/json"},
		{"versioned", "/v1.45/containers/json"},
		{"deep", "/v1.45/containers/abc123def/json"},
		{"traversal", "/v1.45/../containers/json"},
		{"clean", "/_ping"},
	}
	for _, p := range paths {
		b.Run(p.name, func(b *testing.B) {
			for b.Loop() {
				NormalizePath(p.path)
			}
		})
	}
}

func BenchmarkEvaluateNormalized(b *testing.B) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"first_rule_hit", "GET", "/_ping"},
		{"mid_rule_hit", "GET", "/networks/bridge"},
		{"post_allow", "POST", "/containers/abc123/start"},
		{"deny_fallthrough", "DELETE", "/containers/abc123"},
		{"versioned_path", "GET", "/v1.45/containers/json"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			norm := NormalizePath(c.path)
			for b.Loop() {
				evaluateNormalized(benchRules, c.method, norm)
			}
		})
	}
}

func BenchmarkEvaluate(b *testing.B) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"first_rule_hit", "GET", "/_ping"},
		{"deny_fallthrough", "DELETE", "/containers/abc123"},
		{"versioned_post", "POST", "/v1.45/containers/abc123/stop"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			req := httptest.NewRequest(c.method, c.path, nil)
			for b.Loop() {
				Evaluate(benchRules, req)
			}
		})
	}
}

var benchLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type benchmarkResponseWriter struct {
	header http.Header
	status int
}

func newBenchmarkResponseWriter() *benchmarkResponseWriter {
	return &benchmarkResponseWriter{
		header: make(http.Header),
	}
}

func (w *benchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (w *benchmarkResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *benchmarkResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(p), nil
}

func (w *benchmarkResponseWriter) Reset() {
	clear(w.header)
	w.status = 0
}

func TestBenchmarkResponseWriterReset(t *testing.T) {
	w := newBenchmarkResponseWriter()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write([]byte(`{"message":"denied"}`)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if w.status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.status, http.StatusForbidden)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	w.Reset()

	if w.status != 0 {
		t.Fatalf("status after reset = %d, want 0", w.status)
	}
	if len(w.Header()) != 0 {
		t.Fatalf("header count after reset = %d, want 0", len(w.Header()))
	}
}

func BenchmarkMiddlewareAllow(b *testing.B) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := Middleware(benchRules, benchLogger)(next)

	req := httptest.NewRequest("GET", "/v1.45/containers/json", nil)
	w := newBenchmarkResponseWriter()

	for b.Loop() {
		w.Reset()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkMiddlewareDeny(b *testing.B) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := Middleware(benchRules, benchLogger)(next)

	req := httptest.NewRequest("DELETE", "/containers/abc123", nil)
	w := newBenchmarkResponseWriter()

	for b.Loop() {
		w.Reset()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkMiddlewareAllowLargePayload(b *testing.B) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			b.Fatalf("copy request body: %v", err)
		}
	})
	handler := Middleware(benchRules, benchLogger)(next)
	payload := bytes.Repeat([]byte("sockguard-payload-"), 1<<15)
	w := newBenchmarkResponseWriter()

	for b.Loop() {
		w.Reset()
		req := httptest.NewRequest("POST", "/containers/abc123/start", bytes.NewReader(payload))
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkMiddlewareDenyLargePayload(b *testing.B) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		b.Fatal("deny path should not reach next handler")
	})
	handler := Middleware(benchRules, benchLogger)(next)
	payload := bytes.Repeat([]byte("sockguard-payload-"), 1<<15)
	w := newBenchmarkResponseWriter()

	for b.Loop() {
		w.Reset()
		req := httptest.NewRequest("DELETE", "/containers/abc123", bytes.NewReader(payload))
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkGlobToRegex(b *testing.B) {
	patterns := []struct {
		name    string
		pattern string
	}{
		{"simple", "/_ping"},
		{"single_wild", "/containers/*/json"},
		{"double_wild", "/networks/**"},
		{"complex", "/v1.*/containers/*/logs"},
	}
	for _, p := range patterns {
		b.Run(p.name, func(b *testing.B) {
			for b.Loop() {
				globToRegex(p.pattern)
			}
		})
	}
}
