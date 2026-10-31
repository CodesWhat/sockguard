package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBuildFrontendOverrideCannotBypassRunInspection(t *testing.T) {
	for _, path := range []string{"/build", "/v1.47/build", "/libpod/build", "/v5.0.0/libpod/build"} {
		for _, tc := range []struct {
			name, query      string
			allowRun, denied bool
		}{
			{"override", "buildargs=" + url.QueryEscape(`{"BUILDKIT_SYNTAX":"evil.example/frontend"}`), false, true},
			{"null override", "buildargs=" + url.QueryEscape(`{"BUILDKIT_SYNTAX":null}`), false, true},
			{"ambiguous key", "Buildargs=" + url.QueryEscape(`{"BUILDKIT_SYNTAX":"evil"}`), false, true},
			{"repeated", "buildargs={}&buildargs=" + url.QueryEscape(`{"BUILDKIT_SYNTAX":"evil"}`), false, true},
			{"malformed", "buildargs=not-json", false, true},
			{"ordinary argument", "buildargs=" + url.QueryEscape(`{"VERSION":"1"}`), false, false},
			{"override with RUN allowed", "buildargs=" + url.QueryEscape(`{"BUILDKIT_SYNTAX":"evil"}`), true, false},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				rule, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: NormalizePath(path), Action: ActionAllow})
				if err != nil {
					t.Fatal(err)
				}
				handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{PolicyConfig: PolicyConfig{Build: BuildOptions{AllowRunInstructions: tc.allowRun, AllowHostNetwork: true}}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
				body := mustBuildContextTar(t, "Dockerfile", "FROM scratch\n")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest("POST", path+"?"+tc.query, bytes.NewReader(body)))
				want := http.StatusNoContent
				if tc.denied {
					want = http.StatusForbidden
				}
				if rec.Code != want {
					t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body)
				}
			})
		}
	}
}

func TestBuildFrontendOverrideWithEmptyBody(t *testing.T) {
	p := newBuildPolicy(BuildOptions{})
	req := httptest.NewRequest("POST", "/build?buildargs="+url.QueryEscape(`{"BUILDKIT_SYNTAX":"evil"}`), nil)
	reason, err := p.inspect(testLogger(), req, "/build")
	if err != nil || !strings.Contains(reason, "frontend") {
		t.Fatalf("reason %q, error %v", reason, err)
	}
}
