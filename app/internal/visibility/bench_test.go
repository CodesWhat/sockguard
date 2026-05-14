package visibility

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/internal/dockerresource"
)

// BenchmarkPatternFilterContainerList measures the allocation budget for
// response-body pattern filtering on a realistic container list payload.
// The budget is intentionally loose — pattern filtering requires JSON
// round-trip decoding; the goal is to catch regressions, not micro-optimize.
func BenchmarkPatternFilterContainerList(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Build a realistic 20-container payload — 10 matching, 10 not.
	items := make([]map[string]any, 20)
	for i := range items {
		if i%2 == 0 {
			items[i] = map[string]any{
				"Id":    "abc123",
				"Names": []string{"/traefik"},
				"Image": "traefik:latest",
			}
		} else {
			items[i] = map[string]any{
				"Id":    "def456",
				"Names": []string{"/portainer"},
				"Image": "portainer/portainer:latest",
			}
		}
	}
	body, _ := json.Marshal(items)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	handler := middlewareWithDeps(logger, Options{
		NamePatterns:  []string{"traefik"},
		ImagePatterns: []string{"traefik:*"},
	}, visibilityDeps{})(upstream)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}

// BenchmarkPatternFilterImageList mirrors BenchmarkPatternFilterContainerList
// for the image list endpoint.
func BenchmarkPatternFilterImageList(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	items := make([]map[string]any, 20)
	for i := range items {
		if i%2 == 0 {
			items[i] = map[string]any{
				"RepoTags": []string{"traefik:latest"},
			}
		} else {
			items[i] = map[string]any{
				"RepoTags": []string{"redis:7"},
			}
		}
	}
	body, _ := json.Marshal(items)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik:*"},
	}, visibilityDeps{})(upstream)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1.53/images/json", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}

// BenchmarkResourceMetaMatchesPatterns measures the hot path for per-request
// pattern matching on a compiledPolicy with realistic patterns.
func BenchmarkResourceMetaMatchesPatterns(b *testing.B) {
	policy, err := compilePolicy(nil, []string{"traefik", "portainer"}, []string{"traefik:*"})
	if err != nil {
		b.Fatalf("compilePolicy: %v", err)
	}

	meta := &resourceMeta{
		names: []string{"/traefik"},
		image: "traefik:latest",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = resourceMetaMatchesPatterns(meta, dockerresource.KindContainer, &policy)
	}
}

// BenchmarkContainerInspectWithPatterns measures a full container-inspect
// middleware round-trip when both label selectors and pattern axes are active.
func BenchmarkContainerInspectWithPatterns(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deps := visibilityDeps{
		inspectResource: func(_ context.Context, _ dockerresource.Kind, _ string) (map[string]string, bool, error) {
			return map[string]string{"com.example.team": "platform"}, true, nil
		},
		inspectResourceMeta: func(_ context.Context, _ dockerresource.Kind, _ string) (*resourceMeta, bool, error) {
			return &resourceMeta{names: []string{"/traefik"}, image: "traefik:latest"}, true, nil
		},
	}

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.example.team=platform"},
		NamePatterns:          []string{"traefik"},
	}, deps)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc/json", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}
