package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestContainerRemoveDefaultPolicyQuerySemantics pins how the default policy
// reads `force`, `v` and `link`: each value with dockerd's boolean parsing,
// and each parameter only when it is sent once under its exact spelling. A
// repeated flag or one in another case is refused, because dockerd reads the
// first value of the exact key and Podman folds the key's case and reads the
// last, so the two can disagree about whether the removal is forced.
func TestContainerRemoveDefaultPolicyQuerySemantics(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		rawQuery string
		wantCode int
	}{
		{name: "bare remove", path: "/containers/abc", wantCode: http.StatusNoContent},
		{name: "version prefixed bare remove", path: "/v1.45/containers/abc", wantCode: http.StatusNoContent},
		{name: "unrelated query", path: "/containers/abc", rawQuery: "timeout=10", wantCode: http.StatusNoContent},
		{name: "case distinct key is ambiguous", path: "/containers/abc", rawQuery: "Force=true", wantCode: http.StatusForbidden},
		{name: "empty force", path: "/containers/abc", rawQuery: "force=", wantCode: http.StatusNoContent},
		{name: "bare force key", path: "/containers/abc", rawQuery: "force", wantCode: http.StatusNoContent},
		{name: "zero force", path: "/containers/abc", rawQuery: "force=0", wantCode: http.StatusNoContent},
		{name: "no force", path: "/containers/abc", rawQuery: "force=no", wantCode: http.StatusNoContent},
		{name: "false force", path: "/containers/abc", rawQuery: "force=false", wantCode: http.StatusNoContent},
		{name: "none force", path: "/containers/abc", rawQuery: "force=none", wantCode: http.StatusNoContent},
		{name: "trimmed mixed case false", path: "/containers/abc", rawQuery: "force=%20FaLsE%20", wantCode: http.StatusNoContent},
		{name: "false anonymous volume removal", path: "/containers/abc", rawQuery: "v=false", wantCode: http.StatusNoContent},
		{name: "false link removal", path: "/containers/abc", rawQuery: "link=none", wantCode: http.StatusNoContent},
		{name: "repeated value is ambiguous when the first is false", path: "/containers/abc", rawQuery: "force=false&force=true", wantCode: http.StatusForbidden},
		{name: "force true", path: "/containers/abc", rawQuery: "force=true", wantCode: http.StatusForbidden},
		{name: "version prefixed force true", path: "/v1.45/containers/abc", rawQuery: "force=true", wantCode: http.StatusForbidden},
		{name: "anonymous volume removal true", path: "/containers/abc", rawQuery: "v=1", wantCode: http.StatusForbidden},
		{name: "link removal true", path: "/containers/abc", rawQuery: "link=yes", wantCode: http.StatusForbidden},
		{name: "docker treats off as true", path: "/containers/abc", rawQuery: "force=off", wantCode: http.StatusForbidden},
		{name: "docker treats malformed boolean as true", path: "/containers/abc", rawQuery: "force=definitely-not", wantCode: http.StatusForbidden},
		{name: "encoded key and value", path: "/containers/abc", rawQuery: "%66orce=%74rue", wantCode: http.StatusForbidden},
		{name: "repeated value is ambiguous when the first is true", path: "/containers/abc", rawQuery: "force=true&force=false", wantCode: http.StatusForbidden},
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

// TestLibpodContainerRemoveAppliesTheSameGates pins the remove gates on
// Podman's DELETE /libpod/containers/{id}. Before, only /containers/{id} was
// inspected, so the libpod spelling of a forced or volume-deleting removal
// passed any rule that allowed the path. The libpod route reads the volumes
// flag from `volumes` and adds `depend`, which can remove a whole pod and its
// anonymous volumes, so both sit behind allow_remove_volumes, as does the
// documented-but-ignored `v`. `link` isn't read on this route.
func TestLibpodContainerRemoveAppliesTheSameGates(t *testing.T) {
	tests := []struct {
		name               string
		allowForce         bool
		allowRemoveVolumes bool
		path               string
		rawQuery           string
		wantCode           int
		wantReason         string
	}{
		{name: "bare remove", path: "/libpod/containers/abc", wantCode: http.StatusNoContent},
		{name: "version prefixed bare remove", path: "/v5.0.0/libpod/containers/abc", wantCode: http.StatusNoContent},
		{name: "podman-remote rm shape", path: "/v5.8.6/libpod/containers/abc", rawQuery: "depend=false&force=false&ignore=false&volumes=false", wantCode: http.StatusNoContent},
		{name: "timeout and ignore are not gated", path: "/v5.0.0/libpod/containers/abc", rawQuery: "timeout=5&ignore=true", wantCode: http.StatusNoContent},
		{name: "link is not read on the libpod route", path: "/v5.0.0/libpod/containers/abc", rawQuery: "link=true", wantCode: http.StatusNoContent},
		{name: "force", path: "/v5.0.0/libpod/containers/abc", rawQuery: "force=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{name: "unversioned force", path: "/libpod/containers/abc", rawQuery: "force=1", wantCode: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{name: "force on", path: "/v5.0.0/libpod/containers/abc", rawQuery: "force=on", wantCode: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{name: "volumes", path: "/v5.0.0/libpod/containers/abc", rawQuery: "volumes=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: anonymous volume removal is not allowed"},
		{name: "documented v", path: "/v5.0.0/libpod/containers/abc", rawQuery: "v=1", wantCode: http.StatusForbidden, wantReason: "container remove denied: anonymous volume removal is not allowed"},
		{name: "depend", path: "/v5.0.0/libpod/containers/abc", rawQuery: "depend=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: removing dependent containers can delete anonymous volumes and is not allowed"},
		{name: "force in another spelling", path: "/v5.0.0/libpod/containers/abc", rawQuery: "Force=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: ambiguous force query parameter"},
		{name: "volumes behind a false first value", path: "/v5.0.0/libpod/containers/abc", rawQuery: "volumes=false&volumes=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: ambiguous volumes query parameter"},
		{name: "depend in another spelling", path: "/v5.0.0/libpod/containers/abc", rawQuery: "Depend=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: ambiguous depend query parameter"},
		{name: "name decoded into two segments", path: "/v5.0.0/libpod/containers/a/b", rawQuery: "force=1", wantCode: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{name: "invalid percent escape", path: "/v5.0.0/libpod/containers/abc", rawQuery: "force=%zz", wantCode: http.StatusBadRequest},
		{name: "force opt in allows force", allowForce: true, path: "/v5.0.0/libpod/containers/abc", rawQuery: "force=true", wantCode: http.StatusNoContent},
		{name: "force opt in does not allow volumes", allowForce: true, path: "/v5.0.0/libpod/containers/abc", rawQuery: "force=true&volumes=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: anonymous volume removal is not allowed"},
		{name: "force opt in does not allow depend", allowForce: true, path: "/v5.0.0/libpod/containers/abc", rawQuery: "force=true&depend=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: removing dependent containers"},
		{name: "volume opt in allows volumes and depend", allowRemoveVolumes: true, path: "/v5.0.0/libpod/containers/abc", rawQuery: "volumes=true&v=true&depend=true", wantCode: http.StatusNoContent},
		{name: "volume opt in does not allow force", allowRemoveVolumes: true, path: "/v5.0.0/libpod/containers/abc", rawQuery: "volumes=true&force=true", wantCode: http.StatusForbidden, wantReason: "container remove denied: force removal is not allowed"},
		{name: "both opt ins allow podman-remote rm -f -v --depend", allowForce: true, allowRemoveVolumes: true, path: "/v5.8.6/libpod/containers/abc", rawQuery: "depend=true&force=true&ignore=false&volumes=true", wantCode: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := PolicyConfig{
				DenyResponseVerbosity: DenyResponseVerbosityVerbose,
				ContainerRemove: ContainerRemoveOptions{
					AllowForce:         tt.allowForce,
					AllowRemoveVolumes: tt.allowRemoveVolumes,
				},
			}
			handler := containerRemoveTestHandler(t, cfg)
			req := httptest.NewRequest(http.MethodDelete, tt.path, nil)
			req.URL.RawQuery = tt.rawQuery
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantReason != "" && !strings.Contains(rec.Body.String(), tt.wantReason) {
				t.Fatalf("body = %s, want a reason containing %q", rec.Body.String(), tt.wantReason)
			}
		})
	}
}

// TestContainerRemoveFlagsDoNotCrossRoutes pins which flags each route reads:
// `volumes` and `depend` mean nothing to dockerd, and Podman's compat route
// decodes them and never uses them, so they stay unread there, while `link`
// stays unread on the libpod route, which ignores it.
func TestContainerRemoveFlagsDoNotCrossRoutes(t *testing.T) {
	policy := newContainerRemovePolicy(ContainerRemoveOptions{})
	for _, target := range []string{
		"/containers/abc?volumes=true&depend=true",
		"/libpod/containers/abc?link=true",
		"/libpod/containers/create?link=true",
	} {
		req := httptest.NewRequest(http.MethodDelete, target, nil)
		reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
		if err != nil || reason != "" {
			t.Errorf("inspect(%s) = (%q, %v), want (\"\", nil)", target, reason, err)
		}
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
