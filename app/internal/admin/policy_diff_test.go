package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

func TestPolicyDiffHTTPBoundary(t *testing.T) {
	for _, tt := range []struct {
		name, method, path, body string
		want                     int
		calls                    int
	}{
		{"comparison", "POST", "/admin/policy/diff", "ok", 200, 1},
		{"normalized path", "POST", "/admin//policy/./diff/", "ok", 200, 1},
		{"other route", "POST", "/containers/create", "ok", 204, 0},
		{"wrong method", "GET", "/admin/policy/diff", "ok", 405, 0},
		{"too large", "POST", "/admin/policy/diff", "longer than eight", 413, 0},
		{"invalid candidate", "POST", "/admin/policy/diff", "invalid", 422, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			calls, reads := 0, 0
			handler := NewPolicyDiffInterceptor(PolicyDiffOptions{
				Path: "/admin/policy/diff", MaxRequestBytes: 8,
				Source: func() *PolicySnapshot { reads++; return &PolicySnapshot{Version: 7, Config: &cfg} },
				Compare: func(data []byte, snap *PolicySnapshot) PolicyDiffResponse {
					calls++
					return PolicyDiffResponse{OK: string(data) != "invalid", BaseVersion: snap.Version}
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want || calls != tt.calls || reads > 1 {
				t.Fatalf("status=%d calls=%d reads=%d, want status=%d calls=%d", rec.Code, calls, reads, tt.want, tt.calls)
			}
			if tt.want == 405 && rec.Header().Get("Allow") != "POST" {
				t.Fatal("missing POST method allowance")
			}
		})
	}
}

func TestPolicyDiffFailsClosedWithoutPublishedConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		snap *PolicySnapshot
	}{
		{"no generation", nil},
		{"metadata only", &PolicySnapshot{Version: 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewPolicyDiffInterceptor(PolicyDiffOptions{
				Path: "/diff", Source: func() *PolicySnapshot { return tt.snap },
				Compare: func([]byte, *PolicySnapshot) PolicyDiffResponse {
					t.Fatal("compared unavailable policy")
					return PolicyDiffResponse{}
				},
			})(http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("POST", "/diff", nil))
			if rec.Code != 503 {
				t.Fatalf("status=%d, want 503", rec.Code)
			}
		})
	}
}

func TestPolicyDiffReadErrorDoesNotExposeDetails(t *testing.T) {
	cfg := config.Defaults()
	h := NewPolicyDiffInterceptor(PolicyDiffOptions{
		Path: "/diff", Source: func() *PolicySnapshot { return &PolicySnapshot{Config: &cfg} },
		Compare: func([]byte, *PolicySnapshot) PolicyDiffResponse {
			t.Fatal("compared failed body")
			return PolicyDiffResponse{}
		},
	})(http.NotFoundHandler())
	req := httptest.NewRequest("POST", "/diff", nil)
	req.Body = io.NopCloser(iotest.ErrReader(errors.New("private-reader-detail")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "private-reader-detail") {
		t.Fatalf("unexpected response: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyDiffConfigNeverEntersVersionJSON(t *testing.T) {
	cfg := config.Defaults()
	cfg.Listen.TLS.KeyFile = "/private/key-material"
	body, err := json.Marshal(PolicySnapshot{Version: 1, Config: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "key-material") || strings.Contains(string(body), "Config") {
		t.Fatalf("configuration leaked through version JSON: %s", body)
	}
}

func TestPolicyDiffReadsOneConcurrentGeneration(t *testing.T) {
	v := NewPolicyVersioner()
	initial := config.Defaults()
	v.Update(PolicySnapshot{Config: &initial})
	var inconsistent atomic.Bool
	h := NewPolicyDiffInterceptor(PolicyDiffOptions{
		Path: "/diff", Source: v.Snapshot,
		Compare: func(_ []byte, snap *PolicySnapshot) PolicyDiffResponse {
			if snap.Config.Health.Path != "/health" && snap.Config.Health.Path != strings.Repeat("x", snap.Rules) {
				inconsistent.Store(true)
			}
			return PolicyDiffResponse{OK: true, BaseVersion: snap.Version}
		},
	})(http.NotFoundHandler())
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 1; i <= 40; i++ {
			cfg := config.Defaults()
			cfg.Health.Path = strings.Repeat("x", i)
			v.Update(PolicySnapshot{Config: &cfg, Rules: i})
		}
	})
	for range 4 {
		wg.Go(func() {
			for range 40 {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest("POST", "/diff", nil))
				if rec.Code != 200 {
					inconsistent.Store(true)
				}
			}
		})
	}
	wg.Wait()
	if inconsistent.Load() {
		t.Fatal("a comparison mixed configuration and metadata generations")
	}
}
