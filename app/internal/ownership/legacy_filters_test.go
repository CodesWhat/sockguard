package ownership

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Docker's legacy filter encoding (map[string]map[string]bool) must survive
// the owner-label rewrite end-to-end: the owner label leads the label filter and
// a non-colliding legacy client label is kept while every other legacy key is flattened to the
// modern array form with deterministic (sorted) ordering.
func TestMiddlewareOwnerLabelFilterAcceptsLegacyFilterEncoding(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filtersJSON := r.URL.Query().Get("filters")
		var filters map[string][]string
		if err := json.NewDecoder(strings.NewReader(filtersJSON)).Decode(&filters); err != nil {
			t.Fatalf("upstream filters are not modern array form: %v (raw %q)", err, filtersJSON)
		}
		if got := filters["label"]; len(got) != 2 || got[0] != "com.sockguard.owner=job-123" || got[1] != "existing=1" {
			t.Fatalf("label filters = %#v, want [com.sockguard.owner=job-123 existing=1]", got)
		}
		if got := filters["status"]; len(got) != 2 || got[0] != "paused" || got[1] != "running" {
			t.Fatalf("status filters = %#v, want sorted [paused running] flattened from legacy map", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	legacy := `{"label":{"existing=1":true},"status":{"running":true,"paused":true}}`
	req := httptest.NewRequest(http.MethodGet, "/containers/json?filters="+url.QueryEscape(legacy), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
