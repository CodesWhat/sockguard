package ownership

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

func TestRemainingLibpodRoutesRefusedUnderOwnerIsolation(t *testing.T) {
	t.Parallel()
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/libpod/generate/other-tenant/systemd"},
		{http.MethodHead, "/libpod/generate/other-tenant/systemd"},
		{http.MethodPost, "/libpod/quadlets?replace=true"},
		{http.MethodDelete, "/libpod/quadlets?all=true"},
		{http.MethodDelete, "/libpod/quadlets?quadlets=other.container"},
		{http.MethodDelete, "/libpod/artifacts/remove?all=true"},
		{http.MethodDelete, "/libpod/artifacts/remove?artifacts=other"},
		{http.MethodDelete, "/libpod/quadlets/other.container"},
		{http.MethodDelete, "/libpod/artifacts/registry.example/team/other:latest"},
		{http.MethodGet, "/libpod/quadlets/other.container/file"},
		{http.MethodHead, "/libpod/quadlets/other.container/file"},
		{http.MethodGet, "/libpod/quadlets/other.container/exists"},
		{http.MethodGet, "/libpod/quadlets/json"},
		{http.MethodGet, "/libpod/artifacts/registry.example/team/other:latest/extract"},
		{http.MethodHead, "/libpod/artifacts/registry.example/team/other:latest/extract"},
		{http.MethodGet, "/libpod/artifacts/registry.example/team/other:latest/json"},
		{http.MethodGet, "/libpod/artifacts/json"},
		{http.MethodPost, "/libpod/artifacts/add"},
		{http.MethodPost, "/libpod/artifacts/local/add"},
		{http.MethodPost, "/libpod/artifacts/pull"},
		{http.MethodPost, "/libpod/artifacts/registry.example/team/other:latest/push"},
	} {
		for _, prefix := range []string{"", "/v6.0.0"} {
			for _, mode := range []string{"enforce", "warn", "audit"} {
				t.Run(route.method+prefix+route.path+mode, func(t *testing.T) {
					t.Parallel()
					reached := false
					handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusNoContent) }))
					req := httptest.NewRequest(route.method, prefix+route.path, nil)
					req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: mode}))
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if reached || rec.Code != http.StatusForbidden {
						t.Fatalf("reached=%v status=%d body=%s", reached, rec.Code, rec.Body.String())
					}
				})
			}
		}
	}
}
