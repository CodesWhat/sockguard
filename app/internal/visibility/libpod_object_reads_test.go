package visibility

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

func TestLibpodObjectReadsRefusedUnderVisibility(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/libpod/quadlets/other.container/file", "/libpod/quadlets/other.container/exists", "/libpod/quadlets/json",
		"/libpod/artifacts/registry.example/team/other:latest/extract", "/libpod/artifacts/registry.example/team/other:latest/json", "/libpod/artifacts/json",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, prefix := range []string{"", "/v6.1.4"} {
				for _, opts := range []Options{{VisibleResourceLabels: []string{"visible=true"}}, {NamePatterns: []string{"web-*"}}} {
					for _, mode := range []string{"enforce", "warn", "audit"} {
						t.Run(method+prefix+path+mode, func(t *testing.T) {
							reached := false
							handler := middlewareWithDeps(testVisibilityLogger(), opts, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusNoContent) }))
							req := httptest.NewRequest(method, prefix+path, nil)
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
	}
}
