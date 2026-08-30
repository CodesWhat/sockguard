package ownership

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

func TestImageOwnershipEffectDenialRouteClassification(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		wantDeny bool
	}{
		{name: "Docker per-image export", method: http.MethodGet, path: "/images/app/get", wantDeny: true},
		{name: "Docker namespaced per-image export", method: http.MethodGet, path: "/images/registry.example/team/app/get", wantDeny: true},
		{name: "Docker batch export collection", method: http.MethodGet, path: "/images/get"},
		{name: "Docker image list collection", method: http.MethodGet, path: "/images/json"},
		{name: "Docker per-image export HEAD", method: http.MethodHead, path: "/images/app/get"},
		{name: "Docker per-image export POST", method: http.MethodPost, path: "/images/app/get"},
		{name: "Docker per-image delete", method: http.MethodDelete, path: "/images/app", wantDeny: true},
		{name: "Docker image named get delete", method: http.MethodDelete, path: "/images/get", wantDeny: true},
		{name: "libpod per-image delete", method: http.MethodDelete, path: "/libpod/images/app", wantDeny: true},
		{name: "libpod image named json delete", method: http.MethodDelete, path: "/libpod/images/json", wantDeny: true},
		{name: "libpod batch remove collection", method: http.MethodDelete, path: "/libpod/images/remove"},
		{name: "libpod batch export collection", method: http.MethodGet, path: "/libpod/images/export"},
		{name: "safe native libpod per-image export", method: http.MethodGet, path: "/libpod/images/app/get"},
		{name: "unrelated resource", method: http.MethodDelete, path: "/containers/app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotDeny := imageEffectDenial(tt.method, tt.path)
			if gotDeny != tt.wantDeny {
				t.Fatalf("imageEffectDenial(%q, %q) deny = %v, want %v", tt.method, tt.path, gotDeny, tt.wantDeny)
			}
		})
	}
}

func TestImageOwnershipRefusesDockerPerImageExportsWithUnenumerablePlatformEffects(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "omitted platform exports every variant", target: "/v1.53/images/mine%3A1/get"},
		{name: "explicit platform may differ from inspected variant", target: "/v1.53/images/mine%3A1/get?platform=linux%2Farm64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"mine:1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
				},
			}}
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				inspector.inspectResource,
				inspector.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("Docker image export with unenumerable platform effects reached the upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.target, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none before refusing an effect set that cannot be enumerated", inspector.calls)
			}
		})
	}
}

func TestImageOwnershipRefusesDockerPerImageDeletesWithUnenumerableEffects(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "default delete prunes parents and removes every platform", target: "/v1.53/images/mine%3A1"},
		{name: "no-prune still removes every platform", target: "/v1.53/images/mine%3A1?noprune=true"},
		{name: "explicit platform selection may differ from inspected variant", target: "/v1.53/images/mine%3A1?noprune=true&platforms=%5B%7B%22os%22%3A%22linux%22%2C%22architecture%22%3A%22arm64%22%7D%5D"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"mine:1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
				},
			}}
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				inspector.inspectResource,
				inspector.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("Docker image delete with unenumerable effects reached the upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, tt.target, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none before refusing an effect set that cannot be enumerated", inspector.calls)
			}
		})
	}
}

func TestImageOwnershipRefusesLibpodPerImageDeletesWithRecursiveEffects(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "implicit recursive parent removal has no no-prune control", target: "/v5.8.1/libpod/images/mine%3A1"},
		{name: "force may remove containers using the image", target: "/v5.8.1/libpod/images/mine%3A1?force=true"},
		{name: "manifest lookup retargets the removal", target: "/v5.8.1/libpod/images/mine%3A1?lookupManifest=true"},
		{name: "Unicode case-folded manifest lookup key is honored by the daemon decoder", target: "/v5.8.1/libpod/images/mine%3A1?lookupManifest=false&lookupManife%C5%BFt=true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"mine:1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
				},
			}}
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				inspector.inspectResource,
				inspector.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("libpod per-image delete with recursive effects reached the upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, tt.target, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none before refusing an effect set that cannot be bounded", inspector.calls)
			}
		})
	}
}

func TestImageOwnershipPreservesSafeNativeLibpodExport(t *testing.T) {
	inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindImage): {
			"mine:1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
		},
	}}
	reached := false
	handler := middlewareWithDeps(
		testLogger(),
		Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
		inspector.inspectResource,
		inspector.inspectExec,
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v5.8.1/libpod/images/mine%3A1/get", nil))

	if rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
	}
	if len(inspector.calls) != 1 || inspector.calls[0].kind != dockerresource.KindImage || inspector.calls[0].id != "mine:1" {
		t.Fatalf("inspect calls = %#v, want one image lookup for mine:1", inspector.calls)
	}
}
