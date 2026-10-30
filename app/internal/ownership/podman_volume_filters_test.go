package ownership

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

var podmanVolumeFilterRoutes = []struct {
	method string
	path   string
}{
	{http.MethodGet, "/volumes"},
	{http.MethodPost, "/volumes/prune"},
	{http.MethodGet, "/libpod/volumes/json"},
	{http.MethodPost, "/libpod/volumes/prune"},
	{http.MethodGet, "/v5.8.1/libpod/volumes/json"},
	{http.MethodPost, "/v1.45/volumes/prune"},
}

func podmanVolumeFilterHandler(t *testing.T, flavor upstreamflavor.Flavor, reached *bool) http.Handler {
	t.Helper()
	return middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner", UpstreamFlavor: flavor}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			*reached = true
			w.WriteHeader(http.StatusOK)
		}))
}

func TestPodmanVolumeListAndPruneRefuseNonLabelFilters(t *testing.T) {
	t.Parallel()
	for _, route := range podmanVolumeFilterRoutes {
		for _, filters := range []string{
			`{"driver":["local"]}`,
			`{"label!":["x"]}`,
			`{"until":["1h"]}`,
			`{"label":["a=b"],"dangling":["true"]}`,
			`{"name":{"v":true}}`,
		} {
			t.Run(route.method+" "+route.path+" "+filters, func(t *testing.T) {
				t.Parallel()
				reached := false
				handler := podmanVolumeFilterHandler(t, upstreamflavor.Podman, &reached)
				meta := &logging.RequestMeta{RolloutMode: "warn"}
				req := httptest.NewRequest(route.method, route.path+"?filters="+url.QueryEscape(filters), nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if reached || rec.Code != http.StatusForbidden {
					t.Fatalf("reached = %v status = %d, want refused with 403; body: %s", reached, rec.Code, rec.Body.String())
				}
				if meta.ReasonCode != reasonCodeOwnerPodmanVolumeFilterUnscopeable {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerPodmanVolumeFilterUnscopeable)
				}
				if !strings.Contains(rec.Body.String(), "disjunctively") {
					t.Fatalf("body = %s, want the disjunctive combinator explanation", rec.Body.String())
				}
			})
		}
	}
}

func TestPodmanVolumeListAndPruneAllowLabelOnlyOrNoFilters(t *testing.T) {
	t.Parallel()
	for _, route := range podmanVolumeFilterRoutes {
		for name, query := range map[string]string{
			"no filters":   "",
			"label only":   "?filters=" + url.QueryEscape(`{"label":["a=b"]}`),
			"legacy label": "?filters=" + url.QueryEscape(`{"label":{"a=b":true}}`),
		} {
			t.Run(route.method+" "+route.path+" "+name, func(t *testing.T) {
				t.Parallel()
				reached := false
				handler := podmanVolumeFilterHandler(t, upstreamflavor.Podman, &reached)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(route.method, route.path+query, nil))
				if !reached || rec.Code != http.StatusOK {
					t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestDockerVolumeFiltersAreNotRefused(t *testing.T) {
	t.Parallel()
	for _, route := range podmanVolumeFilterRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := podmanVolumeFilterHandler(t, upstreamflavor.Docker, &reached)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(route.method, route.path+"?filters="+url.QueryEscape(`{"driver":["local"]}`), nil))
			if !reached || rec.Code != http.StatusOK {
				t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPodmanNonVolumeRoutesKeepOtherFilterKeys(t *testing.T) {
	t.Parallel()
	reached := false
	handler := podmanVolumeFilterHandler(t, upstreamflavor.Podman, &reached)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/containers/json?filters="+url.QueryEscape(`{"status":["running"]}`), nil))
	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached = %v status = %d, want true and 200", reached, rec.Code)
	}
}
