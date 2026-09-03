package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContainerRemoveDefaultPolicyMatchesDockerQuerySemantics(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		rawQuery string
		wantCode int
	}{
		{name: "bare remove", path: "/containers/abc", wantCode: http.StatusNoContent},
		{name: "version prefixed bare remove", path: "/v1.45/containers/abc", wantCode: http.StatusNoContent},
		{name: "unrelated query", path: "/containers/abc", rawQuery: "timeout=10", wantCode: http.StatusNoContent},
		{name: "case distinct key", path: "/containers/abc", rawQuery: "Force=true", wantCode: http.StatusNoContent},
		{name: "empty force", path: "/containers/abc", rawQuery: "force=", wantCode: http.StatusNoContent},
		{name: "bare force key", path: "/containers/abc", rawQuery: "force", wantCode: http.StatusNoContent},
		{name: "zero force", path: "/containers/abc", rawQuery: "force=0", wantCode: http.StatusNoContent},
		{name: "no force", path: "/containers/abc", rawQuery: "force=no", wantCode: http.StatusNoContent},
		{name: "false force", path: "/containers/abc", rawQuery: "force=false", wantCode: http.StatusNoContent},
		{name: "none force", path: "/containers/abc", rawQuery: "force=none", wantCode: http.StatusNoContent},
		{name: "trimmed mixed case false", path: "/containers/abc", rawQuery: "force=%20FaLsE%20", wantCode: http.StatusNoContent},
		{name: "false anonymous volume removal", path: "/containers/abc", rawQuery: "v=false", wantCode: http.StatusNoContent},
		{name: "false link removal", path: "/containers/abc", rawQuery: "link=none", wantCode: http.StatusNoContent},
		{name: "first repeated value controls false", path: "/containers/abc", rawQuery: "force=false&force=true", wantCode: http.StatusNoContent},
		{name: "force true", path: "/containers/abc", rawQuery: "force=true", wantCode: http.StatusForbidden},
		{name: "version prefixed force true", path: "/v1.45/containers/abc", rawQuery: "force=true", wantCode: http.StatusForbidden},
		{name: "anonymous volume removal true", path: "/containers/abc", rawQuery: "v=1", wantCode: http.StatusForbidden},
		{name: "link removal true", path: "/containers/abc", rawQuery: "link=yes", wantCode: http.StatusForbidden},
		{name: "docker treats off as true", path: "/containers/abc", rawQuery: "force=off", wantCode: http.StatusForbidden},
		{name: "docker treats malformed boolean as true", path: "/containers/abc", rawQuery: "force=definitely-not", wantCode: http.StatusForbidden},
		{name: "encoded key and value", path: "/containers/abc", rawQuery: "%66orce=%74rue", wantCode: http.StatusForbidden},
		{name: "first repeated value controls true", path: "/containers/abc", rawQuery: "force=true&force=false", wantCode: http.StatusForbidden},
		{name: "later destructive parameter", path: "/containers/abc", rawQuery: "force=false&v=true", wantCode: http.StatusForbidden},
		{name: "invalid percent escape", path: "/containers/abc", rawQuery: "force=%zz", wantCode: http.StatusBadRequest},
		{name: "invalid semicolon separator", path: "/containers/abc", rawQuery: "force=false;v=true", wantCode: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := containerRemoveTestHandler(t, PolicyConfig{})
			req := httptest.NewRequest(http.MethodDelete, tt.path, nil)
			req.URL.RawQuery = tt.rawQuery
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestContainerRemoveControlsAreIndependent(t *testing.T) {
	tests := []struct {
		name               string
		allowForce         bool
		allowRemoveVolumes bool
		allowRemoveLinks   bool
		query              string
		wantCode           int
	}{
		{name: "force opt in allows force", allowForce: true, query: "force=garbage", wantCode: http.StatusNoContent},
		{name: "force opt in does not allow volumes", allowForce: true, query: "v=true", wantCode: http.StatusForbidden},
		{name: "force opt in does not allow links", allowForce: true, query: "link=true", wantCode: http.StatusForbidden},
		{name: "volume opt in allows volumes", allowRemoveVolumes: true, query: "v=true", wantCode: http.StatusNoContent},
		{name: "volume opt in does not allow force", allowRemoveVolumes: true, query: "force=true", wantCode: http.StatusForbidden},
		{name: "link opt in allows links", allowRemoveLinks: true, query: "link=true", wantCode: http.StatusNoContent},
		{name: "link opt in does not allow volumes", allowRemoveLinks: true, query: "v=true", wantCode: http.StatusForbidden},
		{name: "all opt ins allow all destructive controls", allowForce: true, allowRemoveVolumes: true, allowRemoveLinks: true, query: "force=true&v=true&link=true", wantCode: http.StatusNoContent},
		{name: "malformed query still fails before all opt ins", allowForce: true, allowRemoveVolumes: true, allowRemoveLinks: true, query: "force=%zz", wantCode: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := PolicyConfig{ContainerRemove: ContainerRemoveOptions{
				AllowForce:         tt.allowForce,
				AllowRemoveVolumes: tt.allowRemoveVolumes,
				AllowRemoveLinks:   tt.allowRemoveLinks,
			}}
			handler := containerRemoveTestHandler(t, cfg)
			req := httptest.NewRequest(http.MethodDelete, "/containers/abc", nil)
			req.URL.RawQuery = tt.query
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestContainerRemoveInspectorIgnoresOtherDeletePaths(t *testing.T) {
	handler := containerRemoveTestHandler(t, PolicyConfig{})
	req := httptest.NewRequest(http.MethodDelete, "/images/abc?force=true", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func containerRemoveTestHandler(t *testing.T, cfg PolicyConfig) http.Handler {
	t.Helper()
	allow, err := CompileRule(Rule{Methods: []string{http.MethodDelete}, Pattern: "/**", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("compile allow rule: %v", err)
	}
	return MiddlewareWithOptions([]*CompiledRule{allow}, testLogger(), Options{PolicyConfig: cfg})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}
