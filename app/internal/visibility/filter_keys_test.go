package visibility

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
	"github.com/codeswhat/sockguard/v2/app/internal/upstreamflavor"
)

func TestVisibilityRefusesFilterKeysContainingEquals(t *testing.T) {
	t.Parallel()
	paths := []string{"/v1.53/events", "/v5.8.1/libpod/events", "/containers/json"}
	encodings := map[string]string{
		"modern": `{"label=com.sockguard.visible":["false"]}`,
		"legacy": `{"label=com.sockguard.visible":{"false":true}}`,
	}
	for _, path := range paths {
		for name, filters := range encodings {
			t.Run(path+"/"+name, func(t *testing.T) {
				t.Parallel()
				handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
					VisibleResourceLabels: []string{"com.sockguard.visible=true"},
					UpstreamFlavor:        upstreamflavor.Podman,
				}, visibilityDeps{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("request with an invalid filter key reached the upstream")
				}))
				meta := &logging.RequestMeta{RolloutMode: "enforce"}
				req := httptest.NewRequest(http.MethodGet, path+"?filters="+url.QueryEscape(filters), nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
				}
				if meta.ReasonCode != reasonCodeVisibilityFilterKeyInvalid {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeVisibilityFilterKeyInvalid)
				}
				if !strings.Contains(rec.Body.String(), "must not contain") {
					t.Fatalf("body = %s, want the filter key message", rec.Body.String())
				}
			})
		}
	}
}

func TestVisibilityFilterKeyCheckLeavesNormalFiltersAlone(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1.53/events", "/v5.8.1/libpod/events", "/containers/json"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
				UpstreamFlavor:        upstreamflavor.Podman,
			}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))
			filters := `{"label":["a=b"],"type":["container"]}`
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+"?filters="+url.QueryEscape(filters), nil))
			if !reached || rec.Code != http.StatusOK {
				t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
			}
		})
	}
}
