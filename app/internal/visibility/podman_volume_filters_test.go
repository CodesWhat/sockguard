package visibility

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

var podmanVolumeListPaths = []string{"/volumes", "/v1.45/volumes", "/libpod/volumes/json", "/v5.8.1/libpod/volumes/json"}

func podmanVolumeVisibilityHandler(flavor upstreamflavor.Flavor, reached *bool) http.Handler {
	return middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        flavor,
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
}

func TestPodmanVolumeListRefusesNonLabelFilters(t *testing.T) {
	t.Parallel()
	for _, path := range podmanVolumeListPaths {
		for _, filters := range []string{
			`{"driver":["local"]}`,
			`{"name":["v"]}`,
			`{"label!":["x"]}`,
			`{"until":["1h"]}`,
			`{"label":["a=b"],"dangling":["true"]}`,
			`{"driver":{"local":true}}`,
		} {
			t.Run(path+" "+filters, func(t *testing.T) {
				t.Parallel()
				reached := false
				meta := &logging.RequestMeta{RolloutMode: "warn"}
				req := httptest.NewRequest(http.MethodGet, path+"?filters="+url.QueryEscape(filters), nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				podmanVolumeVisibilityHandler(upstreamflavor.Podman, &reached).ServeHTTP(rec, req)

				if reached || rec.Code != http.StatusForbidden {
					t.Fatalf("reached = %v status = %d, want refused with 403; body: %s", reached, rec.Code, rec.Body.String())
				}
				if meta.ReasonCode != reasonCodeVisibilityPodmanVolumeFilter {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPodmanVolumeFilter)
				}
				if !strings.Contains(rec.Body.String(), "disjunctively") {
					t.Fatalf("body = %s, want the disjunctive combinator explanation", rec.Body.String())
				}
			})
		}
	}
}

func TestPodmanVolumeListAllowsLabelOnlyOrNoFilters(t *testing.T) {
	t.Parallel()
	for _, path := range podmanVolumeListPaths {
		for name, query := range map[string]string{
			"no filters":   "",
			"label only":   "?filters=" + url.QueryEscape(`{"label":["a=b"]}`),
			"legacy label": "?filters=" + url.QueryEscape(`{"label":{"a=b":true}}`),
		} {
			t.Run(path+" "+name, func(t *testing.T) {
				t.Parallel()
				reached := false
				rec := httptest.NewRecorder()
				podmanVolumeVisibilityHandler(upstreamflavor.Podman, &reached).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+query, nil))
				if !reached || rec.Code != http.StatusOK {
					t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestDockerVolumeListFiltersAreNotRefusedByVisibility(t *testing.T) {
	t.Parallel()
	for _, path := range podmanVolumeListPaths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			reached := false
			rec := httptest.NewRecorder()
			podmanVolumeVisibilityHandler(upstreamflavor.Docker, &reached).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+"?filters="+url.QueryEscape(`{"driver":["local"]}`), nil))
			if !reached || rec.Code != http.StatusOK {
				t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
			}
		})
	}
}
