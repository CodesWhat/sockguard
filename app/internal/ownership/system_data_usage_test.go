package ownership

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
	"github.com/codeswhat/sockguard/app/internal/visibility"
)

const ownerLabelForTest = DefaultLabelKey

// modernSystemDFUpstream is an Engine API >= 1.52 /system/df body holding one
// container, image and volume for each of two owners, plus a build-cache
// record that carries no labels at all.
var modernSystemDFUpstream = `{
  "ContainerUsage":{"ActiveCount":2,"TotalCount":2,"Reclaimable":1000,"TotalSize":2000,"Items":[
    {"Id":"c-a","Names":["/team-a-web"],"Image":"alpine","Labels":{"` + ownerLabelForTest + `":"team-a"}},
    {"Id":"c-b","Names":["/team-b-web"],"Image":"nginx","Labels":{"` + ownerLabelForTest + `":"team-b"}}
  ]},
  "ImageUsage":{"ActiveCount":2,"TotalCount":2,"Reclaimable":3000,"TotalSize":4000,"Items":[
    {"Id":"sha256:a","RepoTags":["team-a/app:1"],"Labels":{"` + ownerLabelForTest + `":"team-a"}},
    {"Id":"sha256:b","RepoTags":["team-b/app:1"],"Labels":{"` + ownerLabelForTest + `":"team-b"}},
    {"Id":"sha256:none","RepoTags":["scratch:latest"],"Labels":null}
  ]},
  "VolumeUsage":{"ActiveCount":2,"TotalCount":2,"Reclaimable":5000,"TotalSize":6000,"Items":[
    {"Name":"vol-a","Labels":{"` + ownerLabelForTest + `":"team-a"}},
    {"Name":"vol-b","Labels":{"` + ownerLabelForTest + `":"team-b"}}
  ]},
  "BuildCacheUsage":{"ActiveCount":1,"TotalCount":1,"Reclaimable":7000,"TotalSize":8000,"Items":[
    {"ID":"bc1","Description":"RUN echo team-b-build-secret"}
  ]}
}`

// legacySystemDFUpstream is the same host in the Engine API <= 1.51 shape.
var legacySystemDFUpstream = `{
  "LayersSize":1092588,
  "Containers":[
    {"Id":"c-a","Names":["/team-a-web"],"Image":"alpine","Labels":{"` + ownerLabelForTest + `":"team-a"}},
    {"Id":"c-b","Names":["/team-b-web"],"Image":"nginx","Labels":{"` + ownerLabelForTest + `":"team-b"}}
  ],
  "Images":[
    {"Id":"sha256:a","RepoTags":["team-a/app:1"],"Labels":{"` + ownerLabelForTest + `":"team-a"}},
    {"Id":"sha256:b","RepoTags":["team-b/app:1"],"Labels":{"` + ownerLabelForTest + `":"team-b"}}
  ],
  "Volumes":[
    {"Name":"vol-a","Labels":{"` + ownerLabelForTest + `":"team-a"}},
    {"Name":"vol-b","Labels":{"` + ownerLabelForTest + `":"team-b"}}
  ],
  "BuildCache":[{"ID":"bc1","Description":"RUN echo team-b-build-secret"}]
}`

func systemDFUpstreamHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
}

func getSystemDFForTest(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestSystemDataUsageOwnerIsolationHidesOtherOwners is the regression test for
// the enumeration bypass: before the response filter existed, GET /system/df
// proxied unchanged, so a caller scoped to team-a saw every team-b container,
// volume and image on the host.
func TestSystemDataUsageOwnerIsolationHidesOtherOwners(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "engine api 1.52 usage objects", body: modernSystemDFUpstream},
		{name: "engine api 1.51 bare arrays", body: legacySystemDFUpstream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(tt.body))

			rec := getSystemDFForTest(t, handler)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()

			for _, mine := range []string{"c-a", "team-a-web", "vol-a", "sha256:a"} {
				if !strings.Contains(body, mine) {
					t.Errorf("owned resource %q missing from /system/df: %s", mine, body)
				}
			}
			for _, theirs := range []string{"c-b", "team-b-web", "vol-b", "sha256:b", "team-b/app:1"} {
				if strings.Contains(body, theirs) {
					t.Errorf("other owner's resource %q leaked through /system/df: %s", theirs, body)
				}
			}
		})
	}
}

// TestSystemDataUsageOwnerIsolationDropsUnlabeledImages pins the consistency
// rule: GET /images/json under ownership lists only images carrying the owner
// label (addOwnerLabelFilter always sends it upstream), so an unlabeled image
// must not appear in /system/df either.
func TestSystemDataUsageOwnerIsolationDropsUnlabeledImages(t *testing.T) {
	t.Parallel()
	for _, allowUnowned := range []bool{false, true} {
		t.Run("allow_unowned_images="+strconv.FormatBool(allowUnowned), func(t *testing.T) {
			t.Parallel()
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a", AllowUnownedImages: allowUnowned},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(modernSystemDFUpstream))

			if body := getSystemDFForTest(t, handler).Body.String(); strings.Contains(body, "sha256:none") {
				t.Fatalf("unlabeled image leaked through /system/df: %s", body)
			}
		})
	}
}

// TestSystemDataUsageOwnerIsolationDropsBuildCache pins the fail-closed
// build-cache decision at the middleware boundary.
func TestSystemDataUsageOwnerIsolationDropsBuildCache(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(modernSystemDFUpstream))

	body := getSystemDFForTest(t, handler).Body.String()
	if strings.Contains(body, "team-b-build-secret") || strings.Contains(body, "bc1") {
		t.Fatalf("build cache record leaked through /system/df: %s", body)
	}
}

// TestSystemDataUsageOwnerIsolationDropsUnknownSections pins the fix for the
// leak this filter existed to close and did not: a top-level section this build
// does not recognize used to be re-marshaled verbatim, so a future Engine API
// section, or one only a Docker-compat upstream sends, reached the client with
// every item in it. BuilderSize is here because it is reachable today rather
// than hypothetical: the Engine API only removed it in v1.42.
func TestSystemDataUsageOwnerIsolationDropsUnknownSections(t *testing.T) {
	t.Parallel()
	upstream := `{"ImageUsage":{"TotalCount":1,"Items":[{"Id":"sha256:mine","Labels":{"` + ownerLabelForTest + `":"team-a"}}]},` +
		`"PluginUsage":{"TotalCount":2,"Items":[{"Id":"p1","Labels":{"` + ownerLabelForTest + `":"team-b"}}]},` +
		`"CheckpointUsage":[{"Id":"cp1"}],"BuilderSize":777}`
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(upstream))

	body := getSystemDFForTest(t, handler).Body.String()
	for _, leaked := range []string{"PluginUsage", "CheckpointUsage", "BuilderSize", "p1", "cp1", "777"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("%q reached the client through /system/df: %s", leaked, body)
		}
	}
	if !strings.Contains(body, "sha256:mine") {
		t.Fatalf("the caller's own image was dropped too, so this proves nothing: %s", body)
	}
}

// TestSystemDataUsageOwnerIsolationRewritesAggregates pins the aggregate
// decision at the middleware boundary: TotalCount matches what the caller can
// see, every other host-wide total is zeroed.
func TestSystemDataUsageOwnerIsolationRewritesAggregates(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(modernSystemDFUpstream))

	var payload map[string]map[string]any
	if err := json.Unmarshal(getSystemDFForTest(t, handler).Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode filtered /system/df: %v", err)
	}
	for _, section := range []string{"ContainerUsage", "ImageUsage", "VolumeUsage"} {
		if got := payload[section]["TotalCount"]; got != float64(1) {
			t.Errorf("%s.TotalCount = %v, want 1", section, got)
		}
		for _, aggregate := range []string{"ActiveCount", "Reclaimable", "TotalSize"} {
			if got := payload[section][aggregate]; got != float64(0) {
				t.Errorf("%s.%s = %v, want 0 (host-wide total)", section, aggregate, got)
			}
		}
	}
}

func TestSystemDataUsageLegacyLayersSizeZeroed(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(legacySystemDFUpstream))

	var payload map[string]any
	if err := json.Unmarshal(getSystemDFForTest(t, handler).Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode filtered /system/df: %v", err)
	}
	if got := payload["LayersSize"]; got != float64(0) {
		t.Fatalf("LayersSize = %v, want 0", got)
	}
}

// TestSystemDataUsageInertWithoutOwnership proves the change costs nothing to
// an operator who never opted into owner isolation: the response is forwarded
// byte for byte, aggregates and build cache included.
func TestSystemDataUsageInertWithoutOwnership(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testLogger(), Options{},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(modernSystemDFUpstream))

	if got := getSystemDFForTest(t, handler).Body.String(); got != modernSystemDFUpstream {
		t.Fatalf("body was rewritten with no owner configured:\n got: %s\nwant: %s", got, modernSystemDFUpstream)
	}
}

// TestSystemDataUsageSetsContentLength asserts the rewritten body's length
// replaces the upstream's, so the client does not hang waiting for bytes the
// filter removed.
func TestSystemDataUsageSetsContentLength(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(modernSystemDFUpstream))

	rec := getSystemDFForTest(t, handler)
	want := strconv.Itoa(rec.Body.Len())
	if got := rec.Header().Get("Content-Length"); got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
	}
}

// TestSystemDataUsageOversizedResponseReturns502 mirrors the /containers/json
// overflow branch: an upstream body past the 8 MiB cap is refused rather than
// silently truncated into a partially filtered response.
func TestSystemDataUsageOversizedResponseReturns502(t *testing.T) {
	t.Parallel()
	chunk := `{"Id":"c-b","Labels":{"` + ownerLabelForTest + `":"team-b"}},`
	huge := `{"ContainerUsage":{"Items":[` +
		strings.Repeat(chunk, (filter.MaxResponseBodyBytes/len(chunk))+5000) +
		`{"Id":"c-b"}]}}`

	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(huge))

	rec := getSystemDFForTest(t, handler)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for oversized response", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("body = %q, want too-large message", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "team-b") {
		t.Fatalf("oversized response leaked upstream bytes: %s", rec.Body.String())
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag = %q, want cleared on a generated error", got)
	}
}

func TestSystemDataUsageUndecodableBodyReturns502(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(`{"ContainerUsage":`))

	rec := getSystemDFForTest(t, handler)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for an undecodable body; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSystemDataUsageNonFilterableStatusesPassThrough covers the status codes
// that carry no data-usage payload.
func TestSystemDataUsageNonFilterableStatusesPassThrough(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		status   int
		body     string
		wantBody string
	}{
		{name: "daemon error", status: http.StatusInternalServerError, body: `{"message":"boom"}`, wantBody: `{"message":"boom"}`},
		{name: "not modified", status: http.StatusNotModified, body: `stale`, wantBody: ""},
		{name: "no content", status: http.StatusNoContent, body: `stale`, wantBody: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			})
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

			rec := getSystemDFForTest(t, handler)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if got := rec.Body.String(); got != tt.wantBody {
				t.Fatalf("body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}

// TestSystemDataUsageHeadRequestNotIntercepted: a HEAD carries no body, so
// there is nothing to filter and nothing to leak. Buffering it would only risk
// replacing the daemon's Content-Length with 0.
func TestSystemDataUsageHeadRequestNotIntercepted(t *testing.T) {
	t.Parallel()
	reached := false
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
	})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	req := httptest.NewRequest(http.MethodHead, "/v1.53/system/df", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("HEAD did not reach the upstream")
	}
	if got := rec.Header().Get("Content-Length"); got != "4096" {
		t.Fatalf("Content-Length = %q, want the upstream's 4096 untouched", got)
	}
}

func TestSystemDataUsageItemOwned(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "team-a", LabelKey: ownerLabelForTest}
	tests := []struct {
		name    string
		section responsefilter.SystemDataUsageSection
		item    string
		want    bool
		wantErr bool
	}{
		{name: "owned container", section: responsefilter.SystemDataUsageContainers, item: `{"Labels":{"` + ownerLabelForTest + `":"team-a"}}`, want: true},
		{name: "other owner container", section: responsefilter.SystemDataUsageContainers, item: `{"Labels":{"` + ownerLabelForTest + `":"team-b"}}`},
		{name: "unlabeled container", section: responsefilter.SystemDataUsageContainers, item: `{"Labels":{}}`},
		{name: "null labels", section: responsefilter.SystemDataUsageVolumes, item: `{"Labels":null}`},
		{name: "missing labels", section: responsefilter.SystemDataUsageVolumes, item: `{"Name":"vol"}`},
		{name: "owned image", section: responsefilter.SystemDataUsageImages, item: `{"Labels":{"` + ownerLabelForTest + `":"team-a"}}`, want: true},
		// Unreachable through FilterSystemDataUsage, which removes unknown
		// top-level keys before any item is classified. Kept so the predicate
		// stays fail-closed if a section is added to the shape table before it
		// is added here. TestSystemDataUsageOwnerIsolationDropsUnknownSections
		// is the one that pins the reachable behavior.
		{name: "unknown section fails closed", section: responsefilter.SystemDataUsageSection("future"), item: `{"Labels":{"` + ownerLabelForTest + `":"team-a"}}`},
		{name: "undecodable item", section: responsefilter.SystemDataUsageContainers, item: `{"Labels":`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := systemDataUsageItemOwned(tt.section, json.RawMessage(tt.item), opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want an error so the caller fails closed, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("systemDataUsageItemOwned() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("systemDataUsageItemOwned() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSystemDataUsageOwnershipAndVisibilityCompose exercises the two response
// filters in their production nesting — the serve chain builds
// visibility -> ownership -> proxy, so the owner filter runs on the raw body
// and the visibility filter runs on the owner-filtered one. Both must apply.
//
// This is the only place the ownership package reaches for the visibility
// package; the dependency is test-only and one-way (visibility never imports
// ownership), so it introduces no cycle.
func TestSystemDataUsageOwnershipAndVisibilityCompose(t *testing.T) {
	t.Parallel()
	upstream := `{"ContainerUsage":{"TotalCount":3,"Items":[
      {"Id":"c-mine-prod","Names":["/prod-web"],"Labels":{"` + ownerLabelForTest + `":"team-a","tier":"prod"}},
      {"Id":"c-mine-dev","Names":["/dev-web"],"Labels":{"` + ownerLabelForTest + `":"team-a","tier":"dev"}},
      {"Id":"c-theirs-prod","Names":["/other-web"],"Labels":{"` + ownerLabelForTest + `":"team-b","tier":"prod"}}
    ]}}`

	inner := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(upstream))
	handler := visibility.Middleware("", testLogger(), visibility.Options{
		VisibleResourceLabels: []string{"tier=prod"},
	})(inner)

	// Over a real connection, so the two nested Content-Length rewrites are
	// validated by an HTTP client rather than a recorder: a stale length from
	// the inner filter would hang or truncate the read here.
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/v1.53/system/df")
	if err != nil {
		t.Fatalf("GET /system/df: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /system/df: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(raw)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(raw))
	}

	body := string(raw)
	if !strings.Contains(body, "c-mine-prod") {
		t.Fatalf("owned + visible container missing: %s", body)
	}
	if strings.Contains(body, "c-mine-dev") {
		t.Fatalf("visibility selector did not apply: %s", body)
	}
	if strings.Contains(body, "c-theirs-prod") {
		t.Fatalf("owner isolation did not apply: %s", body)
	}
}
