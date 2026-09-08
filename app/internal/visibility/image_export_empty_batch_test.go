package visibility

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestVisibilityDockerBatchImageExportWithNoSelectedReferencesPassesThrough
// pins the `len(references) > 0` gate in handleVisibilityImageExportRequest's
// imageExportRouteDockerBatch case: GET /images/get with no "names" query
// parameter at all selects zero references, and an empty selection must fall
// through to the next handler rather than being refused as unscopeable. The
// refusal exists because a named selection has platform effects sockguard
// cannot enumerate; an unfiltered "export everything" request carries no such
// per-name effect to fail to enumerate.
func TestVisibilityDockerBatchImageExportWithNoSelectedReferencesPassesThrough(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/images/get", nil))

	if !reached {
		t.Fatalf("Docker batch export with no selected references was denied (status %d), want it to reach the upstream handler", rec.Code)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
