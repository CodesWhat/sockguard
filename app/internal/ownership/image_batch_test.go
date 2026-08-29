package ownership

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

func TestImageBatchOwnershipPreflightsEveryNamedImage(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		wantIDs []string
	}{
		{
			name:    "compat one tagged reference",
			method:  http.MethodGet,
			target:  "/images/get?names=registry.example%2Fteam%2Fapp%3A1",
			wantIDs: []string{"registry.example/team/app:1"},
		},
		{
			name:   "versioned compat repeated tag and image ID",
			method: http.MethodGet,
			target: "/v1.52/images/get?names=registry.example%2Fteam%2Fapp%3A1&names=sha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantIDs: []string{
				"registry.example/team/app:1",
				"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name:   "versioned libpod export repeated tag and digest",
			method: http.MethodGet,
			target: "/v5.8.1/libpod/images/export?format=docker-archive&references=registry.example%2Fteam%2Fapp%3A1&references=registry.example%2Fteam%2Fapp%40sha256%3Abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			wantIDs: []string{
				"registry.example/team/app:1",
				"registry.example/team/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name:    "libpod export bare reference resolves one image",
			method:  http.MethodGet,
			target:  "/libpod/images/export?references=alpine",
			wantIDs: []string{"alpine"},
		},
		{
			name:   "versioned libpod remove repeated references",
			method: http.MethodDelete,
			target: "/v5.8.1/libpod/images/remove?force=true&images=registry.example%2Fteam%2Fapp%3A1&images=sha256%3Acccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			wantIDs: []string{
				"registry.example/team/app:1",
				"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			},
		},
		{
			name:    "libpod remove does not split commas",
			method:  http.MethodDelete,
			target:  "/libpod/images/remove?all=false&images=mine%3A1%2Ctheirs%3A1",
			wantIDs: []string{"mine:1,theirs:1"},
		},
		{
			name:    "libpod named remove uses the last repeated all value",
			method:  http.MethodDelete,
			target:  "/libpod/images/remove?all=false&all=true&images=mine%3A1",
			wantIDs: []string{"mine:1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {},
			}
			for _, id := range tt.wantIDs {
				resources[string(dockerresource.KindImage)][id] = inspectResult{
					labels: map[string]string{"com.sockguard.owner": "job-123"},
					found:  true,
				}
			}
			inspector := &recordingInspector{resources: resources}
			reached := false
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true},
				inspector.inspectResource,
				inspector.inspectExec,
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if r.URL.RawQuery != httptest.NewRequest(tt.method, tt.target, nil).URL.RawQuery {
					t.Fatalf("forwarded RawQuery = %q, want original %q", r.URL.RawQuery, httptest.NewRequest(tt.method, tt.target, nil).URL.RawQuery)
				}
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if rec.Code != http.StatusNoContent || !reached {
				t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
			}
			gotIDs := make([]string, 0, len(inspector.calls))
			for _, call := range inspector.calls {
				if call.kind != dockerresource.KindImage {
					t.Fatalf("inspect kind = %q, want %q", call.kind, dockerresource.KindImage)
				}
				gotIDs = append(gotIDs, call.id)
			}
			if !slices.Equal(gotIDs, tt.wantIDs) {
				t.Fatalf("inspected images = %#v, want %#v", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestImageBatchOwnershipDeniesTheWholeRequestWhenAnyImageIsUnauthorized(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		badID  string
		result inspectResult
	}{
		{
			name:   "compat mixed owner batch",
			method: http.MethodGet,
			target: "/images/get?names=mine%3A1&names=theirs%3A1",
			badID:  "theirs:1",
			result: inspectResult{labels: map[string]string{"com.sockguard.owner": "other-job"}, found: true},
		},
		{
			name:   "libpod export unresolved image",
			method: http.MethodGet,
			target: "/libpod/images/export?references=mine%3A1&references=missing%3A1",
			badID:  "missing:1",
			result: inspectResult{found: false},
		},
		{
			name:   "libpod remove requires owner label despite allow unowned",
			method: http.MethodDelete,
			target: "/libpod/images/remove?images=mine%3A1&images=unlabeled%3A1",
			badID:  "unlabeled:1",
			result: inspectResult{labels: map[string]string{}, found: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"mine:1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
					tt.badID: tt.result,
				},
			}}
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true},
				fi.inspectResource,
				fi.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("failed image batch preflight reached the upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
		})
	}
}

func TestImageBatchOwnershipLookupFailureStopsBeforeTheUpstream(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "compat", method: http.MethodGet, target: "/images/get?names=broken%3A1"},
		{name: "libpod export", method: http.MethodGet, target: "/libpod/images/export?references=broken%3A1"},
		{name: "libpod remove", method: http.MethodDelete, target: "/libpod/images/remove?images=broken%3A1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"broken:1": {err: errors.New("inspect failed")},
				},
			}}
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				fi.inspectResource,
				fi.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("image batch with a failed lookup reached the upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
			}
		})
	}
}

func TestImageBatchOwnershipRejectsUnsafeOrMalformedSelectors(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		rawQuery   string
		wantStatus int
	}{
		{name: "compat bare repository expands all tags", method: http.MethodGet, target: "/images/get?names=team%2Fapp", wantStatus: http.StatusForbidden},
		{name: "versioned compat namespaced bare repository", method: http.MethodGet, target: "/v1.45/images/get?names=registry.example%3A5000%2Fteam%2Fapp", wantStatus: http.StatusForbidden},
		{name: "libpod remove with omitted images removes a collection", method: http.MethodDelete, target: "/libpod/images/remove", wantStatus: http.StatusForbidden},
		{name: "libpod remove all false without images still removes a collection", method: http.MethodDelete, target: "/libpod/images/remove?all=false", wantStatus: http.StatusForbidden},
		{name: "libpod remove all true", method: http.MethodDelete, target: "/libpod/images/remove?all=true", wantStatus: http.StatusForbidden},
		{name: "compat empty name", method: http.MethodGet, target: "/images/get?names=", wantStatus: http.StatusBadRequest},
		{name: "libpod empty export reference", method: http.MethodGet, target: "/libpod/images/export?references=", wantStatus: http.StatusBadRequest},
		{name: "libpod empty remove image", method: http.MethodDelete, target: "/libpod/images/remove?images=", wantStatus: http.StatusBadRequest},
		{name: "libpod malformed last all value", method: http.MethodDelete, target: "/libpod/images/remove?all=false&all=invalid&images=mine%3A1", wantStatus: http.StatusBadRequest},
		{name: "malformed percent escape", method: http.MethodGet, target: "/images/get", rawQuery: "names=%zz", wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"team/app":                       {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
					"registry.example:5000/team/app": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
					"mine:1":                         {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
				},
			}}
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				fi.inspectResource,
				fi.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("unsafe image batch reached the upstream")
			}))

			req := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.rawQuery != "" {
				req.URL.RawQuery = tt.rawQuery
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestImageBatchOwnershipForwardsOmittedNoEffectExportLists(t *testing.T) {
	for _, target := range []string{"/images/get", "/libpod/images/export"} {
		t.Run(target, func(t *testing.T) {
			reached := false
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				fakeInspector{}.inspectResource,
				fakeInspector{}.inspectExec,
			)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

			if rec.Code != http.StatusNoContent || !reached {
				t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
			}
		})
	}
}

func TestImageBatchOwnershipDisabledLeavesRequestsUntouched(t *testing.T) {
	tests := []struct {
		method string
		target string
	}{
		{method: http.MethodGet, target: "/images/get?names=team%2Fapp"},
		{method: http.MethodGet, target: "/libpod/images/export?references="},
		{method: http.MethodDelete, target: "/libpod/images/remove?all=true"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			wantQuery := httptest.NewRequest(tt.method, tt.target, nil).URL.RawQuery
			handler := middlewareWithDeps(
				testLogger(),
				Options{},
				func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					t.Fatal("disabled ownership performed an image lookup")
					return nil, false, nil
				},
				fakeInspector{}.inspectExec,
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RawQuery != wantQuery {
					t.Fatalf("forwarded RawQuery = %q, want %q", r.URL.RawQuery, wantQuery)
				}
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
		})
	}
}
