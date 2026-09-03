package ownership

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

func TestImageBatchOwnershipPreflightsEveryNamedImage(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		wantIDs []string
	}{
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
			name:   "libpod export folds every reference key variant in arrival order",
			method: http.MethodGet,
			target: "/libpod/images/export?References=mine%3A1&REFERENCES=theirs%3A1&references=ours%3A1",
			wantIDs: []string{
				"mine:1",
				"theirs:1",
				"ours:1",
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
			target: "/v5.8.1/libpod/images/remove?noprune=true&images=registry.example%2Fteam%2Fapp%3A1&images=sha256%3Acccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			wantIDs: []string{
				"registry.example/team/app:1",
				"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			},
		},
		{
			name:   "libpod remove folds every image key variant in arrival order",
			method: http.MethodDelete,
			target: "/libpod/images/remove?noprune=true&Images=mine%3A1&IMAGES=theirs%3A1&images=ours%3A1",
			wantIDs: []string{
				"mine:1",
				"theirs:1",
				"ours:1",
			},
		},
		{
			name:    "libpod remove does not split commas",
			method:  http.MethodDelete,
			target:  "/libpod/images/remove?all=false&noprune=true&images=mine%3A1%2Ctheirs%3A1",
			wantIDs: []string{"mine:1,theirs:1"},
		},
		{
			name:    "libpod named remove uses the last repeated all value",
			method:  http.MethodDelete,
			target:  "/libpod/images/remove?all=false&all=true&noprune=true&images=mine%3A1",
			wantIDs: []string{"mine:1"},
		},
		{
			name:    "libpod named remove uses the last repeated safe scalar values",
			method:  http.MethodDelete,
			target:  "/libpod/images/remove?force=true&force=false&noprune=false&noprune=true&lookupManifest=true&lookupManifest=false&images=mine%3A1",
			wantIDs: []string{"mine:1"},
		},
		{
			name:    "libpod named remove accepts Gorilla on for safe scalar values",
			method:  http.MethodDelete,
			target:  "/libpod/images/remove?all=on&force=false&noprune=on&lookupManifest=false&images=mine%3A1",
			wantIDs: []string{"mine:1"},
		},
		{
			name:    "libpod empty scalar case variant does not clear a true setter",
			method:  http.MethodDelete,
			target:  "/libpod/images/remove?NoPrune=true&noprune=&images=mine%3A1",
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

func TestImageBatchOwnershipDeduplicatesUpstreamLookups(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
	}{
		{
			name:   "libpod export repeated case variants",
			method: http.MethodGet,
			target: "/libpod/images/export?references=mine%3A1&References=mine%3A1&REFERENCES=mine%3A1",
		},
		{
			name:   "libpod remove repeated case variants",
			method: http.MethodDelete,
			target: "/libpod/images/remove?noprune=true&images=mine%3A1&Images=mine%3A1&IMAGES=mine%3A1",
		},
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
			)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			if len(inspector.calls) != 1 || inspector.calls[0].id != "mine:1" {
				t.Fatalf("inspect calls = %#v, want one lookup for mine:1", inspector.calls)
			}
		})
	}
}

func TestImageBatchOwnershipRejectsTooManySelectedReferencesBeforeLookup(t *testing.T) {
	const maxSelectedReferences = 256

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
		t.Fatal("oversized image batch reached the upstream")
	}))

	target := "/libpod/images/export?" + strings.Repeat("References=mine%3A1&", maxSelectedReferences+1)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "exceeds 256 image reference limit") {
		t.Fatalf("body = %q, want image reference limit", rec.Body.String())
	}
	if len(inspector.calls) != 0 {
		t.Fatalf("inspect calls = %#v, want none", inspector.calls)
	}
}

func TestImageBatchOwnershipRefusesCompatExportWhosePlatformEffectsCannotBeFullyAuthorized(t *testing.T) {
	tests := []struct {
		name   string
		target string
		id     string
	}{
		{
			name:   "dockerd exact names remain conservatively denied",
			target: "/images/get?names=registry.example%2Fteam%2Fapp%3A1",
			id:     "registry.example/team/app:1",
		},
		{
			name:   "Podman compat ASCII case-folded names",
			target: "/images/get?Names=registry.example%2Fteam%2Fapp%3A1",
			id:     "registry.example/team/app:1",
		},
		{
			name:   "Podman compat Unicode case-folded names",
			target: "/images/get?name%C5%BF=registry.example%2Fteam%2Fapp%3A1",
			id:     "registry.example/team/app:1",
		},
		{
			name:   "tag with one platform not carried into inspect",
			target: "/v1.52/images/get?names=registry.example%2Fteam%2Fapp%3A1&platform=linux%2Farm64",
			id:     "registry.example/team/app:1",
		},
		{
			name:   "full ID may name an index",
			target: "/v1.52/images/get?names=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&platform=linux%2Famd64",
			id:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:   "digest with several selected platforms",
			target: "/v1.52/images/get?names=registry.example%2Fteam%2Fapp%40sha256%3Abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&platform=linux%2Famd64&platform=linux%2Farm64",
			id:     "registry.example/team/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					tt.id: {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
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
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.target, nil))

			if rec.Code != http.StatusForbidden || reached {
				t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "multi-platform image export") {
				t.Fatalf("body = %q, want multi-platform image export denial", rec.Body.String())
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none for an export whose full effect cannot be enumerated", inspector.calls)
			}
		})
	}
}

func TestImageBatchOwnershipRejectsEffectExpandingLibpodRemoveOptions(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantStatus int
		wantReason string
	}{
		{
			name:       "force removes containers",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=true&force=true",
			wantStatus: http.StatusForbidden,
			wantReason: "force image batch removal",
		},
		{
			name:       "Gorilla on force removes containers",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=on&force=on",
			wantStatus: http.StatusForbidden,
			wantReason: "force image batch removal",
		},
		{
			name:       "force case variants have competing final values",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=true&Force=false&FORCE=true",
			wantStatus: http.StatusForbidden,
			wantReason: "force image batch removal",
		},
		{
			name:       "pruning enabled by default",
			target:     "/libpod/images/remove?images=mine%3A1",
			wantStatus: http.StatusForbidden,
			wantReason: "requires noprune=true",
		},
		{
			name:       "pruning explicitly enabled",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=false",
			wantStatus: http.StatusForbidden,
			wantReason: "requires noprune=true",
		},
		{
			name:       "pruning case variants have competing final values",
			target:     "/libpod/images/remove?images=mine%3A1&NoPrune=true&NOPRUNE=false",
			wantStatus: http.StatusForbidden,
			wantReason: "requires noprune=true",
		},
		{
			name:       "manifest lookup retargets removal",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=true&lookupManifest=true",
			wantStatus: http.StatusForbidden,
			wantReason: "manifest-list image batch removal",
		},
		{
			name:       "Gorilla on manifest lookup retargets removal",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=on&lookupManifest=on",
			wantStatus: http.StatusForbidden,
			wantReason: "manifest-list image batch removal",
		},
		{
			name:       "manifest lookup case variants have competing final values",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=true&LookupManifest=false&LOOKUPMANIFEST=true",
			wantStatus: http.StatusForbidden,
			wantReason: "manifest-list image batch removal",
		},
		{
			name:       "manifest lookup Unicode case variant",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=true&lookupManifest=false&lookupManife%C5%BFt=true",
			wantStatus: http.StatusForbidden,
			wantReason: "manifest-list image batch removal",
		},
		{
			name:       "malformed case variant scalar",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=true&Force=invalid",
			wantStatus: http.StatusBadRequest,
			wantReason: "force",
		},
		{
			name:       "malformed case variant all scalar",
			target:     "/libpod/images/remove?images=mine%3A1&noprune=true&All=invalid",
			wantStatus: http.StatusBadRequest,
			wantReason: "all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, tt.target, nil))

			if rec.Code != tt.wantStatus || reached {
				t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, tt.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantReason) {
				t.Fatalf("body = %q, want reason containing %q", rec.Body.String(), tt.wantReason)
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none before rejecting unsafe removal controls", inspector.calls)
			}
		})
	}
}

func TestImageBatchOwnershipDeniesTheWholeRequestWhenAnyImageIsUnauthorized(t *testing.T) {
	// wantStatus differs per case because the two denial verdicts answer with
	// different statuses: a member that resolves to another owner is a 403,
	// and one the daemon cannot resolve at all is a 404. Both refuse the whole
	// batch before the upstream is contacted, which is what the handler below
	// asserts.
	tests := []struct {
		name       string
		method     string
		target     string
		badID      string
		result     inspectResult
		wantStatus int
	}{
		{
			name:       "libpod export mixed owner batch",
			method:     http.MethodGet,
			target:     "/libpod/images/export?references=mine%3A1&references=theirs%3A1",
			badID:      "theirs:1",
			result:     inspectResult{labels: map[string]string{"com.sockguard.owner": "other-job"}, found: true},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "libpod export unresolved image",
			method:     http.MethodGet,
			target:     "/libpod/images/export?references=mine%3A1&references=missing%3A1",
			badID:      "missing:1",
			result:     inspectResult{found: false},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "libpod remove requires owner label despite allow unowned",
			method:     http.MethodDelete,
			target:     "/libpod/images/remove?noprune=true&images=mine%3A1&images=unlabeled%3A1",
			badID:      "unlabeled:1",
			result:     inspectResult{labels: map[string]string{}, found: true},
			wantStatus: http.StatusForbidden,
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

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
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
		{name: "libpod export", method: http.MethodGet, target: "/libpod/images/export?references=broken%3A1"},
		{name: "libpod remove", method: http.MethodDelete, target: "/libpod/images/remove?noprune=true&images=broken%3A1"},
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

// TestImageBatchOwnershipCoversHeadOnExportRoutes pins HEAD to the same gate
// GET gets on the two export routes. imageIdentifier and libpodImageIdentifier
// both reserve the collection words "get" and "export" for GET and HEAD
// alike, so a HEAD that skipped the batch gate would reach the daemon with no
// owner check at all rather than falling back to a per-image one.
func TestImageBatchOwnershipCoversHeadOnExportRoutes(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantReason string
	}{
		{
			name:       "Docker-compat batch export",
			target:     "/v1.53/images/get?names=theirs%3A1",
			wantReason: "multi-platform image export",
		},
		{
			name:       "native libpod batch export",
			target:     "/v5.8.1/libpod/images/export?references=theirs%3A1",
			wantReason: "owner policy denied access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"theirs:1": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
				},
			}}
			reached := false
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true},
				inspector.inspectResource,
				inspector.inspectExec,
			)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, tt.target, nil))

			if rec.Code != http.StatusForbidden || reached {
				t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantReason) {
				t.Fatalf("body = %q, want it to name %q", rec.Body.String(), tt.wantReason)
			}
		})
	}
}

// TestImageBatchOwnershipCompatExportRefusalHonorsRollout records the contract
// the visibility layer's refusal of the same two routes is held to. Both
// layers see GET /images/get?names= and GET /images/{name}/get, the chain runs
// visibility before ownership, and a warn-mode request has to reach the daemon
// through both of them or through neither.
func TestImageBatchOwnershipCompatExportRefusalHonorsRollout(t *testing.T) {
	targets := []string{"/v1.53/images/get?names=mine%3A1", "/v1.53/images/mine%3A1/get"}

	for _, target := range targets {
		for _, mode := range []string{"warn", "audit"} {
			t.Run(target+" in "+mode, func(t *testing.T) {
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

				meta := &logging.RequestMeta{RolloutMode: mode}
				req := httptest.NewRequest(http.MethodGet, target, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusNoContent || !reached {
					t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
				}
				if meta.Decision != logging.DecisionWouldDeny {
					t.Fatalf("decision = %q, want %q", meta.Decision, logging.DecisionWouldDeny)
				}
				if meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerPolicyDeniedAccess)
				}
				if len(inspector.calls) != 0 {
					t.Fatalf("inspect calls = %#v, want none even when the verdict passes through", inspector.calls)
				}
			})
		}
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
