package visibility

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/dockerresource"
)

func TestExecInspectUsesEveryContainerVisibilityAxis(t *testing.T) {
	t.Parallel()
	for _, opts := range []Options{
		{NamePatterns: []string{"web-*"}},
		{ImagePatterns: []string{"nginx:*"}},
		{VisibleResourceLabels: []string{"visible=true"}, NamePatterns: []string{"web-*"}},
		{VisibleResourceLabels: []string{"visible=true"}, ImagePatterns: []string{"nginx:*"}},
	} {
		for _, path := range []string{"/exec/session/json", "/libpod/exec/session/json", "/v1.44/exec/session/json", "/v6.1.4/libpod/exec/session/json"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, visible := range []bool{false, true} {
					meta := &resourceMeta{names: []string{"/db-1"}, image: "postgres:latest"}
					if visible {
						meta = &resourceMeta{names: []string{"/web-1"}, image: "nginx:latest"}
					}
					deps := visibilityDeps{
						inspectExec: func(context.Context, string) (string, bool, error) { return "parent", true, nil },
						inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
							return map[string]string{"visible": "true"}, true, nil
						},
						inspectResourceMeta: func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error) {
							return meta, true, nil
						},
						inspectResourceDetails: func(context.Context, dockerresource.Kind, string) (*resourceDetails, bool, error) {
							return &resourceDetails{labels: map[string]string{"visible": "true"}, meta: meta}, true, nil
						},
					}
					reached := false
					handler := middlewareWithDeps(testVisibilityLogger(), opts, deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusNoContent) }))
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
					want := http.StatusNotFound
					if visible {
						want = http.StatusNoContent
					}
					if rec.Code != want || reached != visible {
						t.Errorf("%s %s opts=%+v visible=%v: reached=%v status=%d want=%d", method, path, opts, visible, reached, rec.Code, want)
					}
				}
			}
		}
	}
}
