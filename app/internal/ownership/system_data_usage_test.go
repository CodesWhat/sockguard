package ownership

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
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
// that carry no data-usage payload. A 304 is deliberately absent: it is a
// revalidation of a copy no filter ever saw, so it is refused rather than
// passed through — see conditional_request_test.go.
func TestSystemDataUsageNonFilterableStatusesPassThrough(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		status   int
		body     string
		wantBody string
	}{
		{name: "daemon error", status: http.StatusInternalServerError, body: `{"message":"boom"}`, wantBody: `{"message":"boom"}`},
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

// TestSystemDataUsageHeadStripsUpstreamRepresentation: a HEAD carries no body
// to classify by owner, but the daemon's Content-Length and ETag describe the
// whole host inventory, so the length counts every other owner's containers,
// images and volumes. The request still reaches the daemon; the metadata does
// not reach the client.
func TestSystemDataUsageHeadStripsUpstreamRepresentation(t *testing.T) {
	t.Parallel()
	reached := false
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Length", "4096")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"upstream"`)
		w.Header().Set("Last-Modified", "Wed, 03 Sep 2026 10:00:00 GMT")
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
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"Content-Length", "ETag", "Last-Modified"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("%s = %q, want it cleared on a HEAD owner isolation scopes", name, got)
		}
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want the media type kept", got)
	}
}

// TestSystemDataUsageHeadOverRealServerRefusesNotModified is the wire-level
// counterpart of TestSystemDataUsageHeadFailsClosedOnNotModified: it proves
// that when the upstream answers a HEAD with a recorded 304, the 502
// refusal's JSON error body never actually reaches the client — Go's HEAD
// handling eats a handler's body writes on the wire — rather than merely
// going unchecked by a ResponseRecorder.
func TestSystemDataUsageHeadOverRealServerRefusesNotModified(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusNotModified)
	})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodHead, server.URL+"/v1.53/system/df", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if got := resp.Header.Get("ETag"); got != "" {
		t.Errorf("ETag = %q, want the upstream validator cleared off the refusal", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want nothing forwarded for a HEAD refusal", body)
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

// libpodSystemDFUpstream is a GET /libpod/system/df body in Podman's own
// report shape (entities.SystemDfReport at v5.8.1), holding one image,
// container and volume for each of two owners.
//
// It carries no labels anywhere, because that shape has no Labels field on any
// of its three item types — see
// responsefilter.LibpodSystemDataUsageDenyReason. The team-a/team-b split
// below lives entirely in free-text Repository/Image/Names/VolumeName values,
// which is exactly why owner isolation cannot be applied to it.
const libpodSystemDFUpstream = `{
  "ImagesSize": 1092588,
  "Images": [
    {"Repository":"docker.io/team-a/app","Tag":"1","ImageID":"aaaa111122223333","Size":5000,"SharedSize":1000,"UniqueSize":4000,"Containers":1},
    {"Repository":"docker.io/team-b/app","Tag":"1","ImageID":"bbbb444455556666","Size":6000,"SharedSize":1000,"UniqueSize":5000,"Containers":1}
  ],
  "Containers": [
    {"ContainerID":"c-a","Image":"docker.io/team-a/app:1","Command":["sleep","infinity"],"LocalVolumes":1,"Size":100,"RWSize":50,"Status":"running","Names":"team-a-web"},
    {"ContainerID":"c-b","Image":"docker.io/team-b/app:1","Command":["sleep","infinity"],"LocalVolumes":1,"Size":200,"RWSize":60,"Status":"running","Names":"team-b-web"}
  ],
  "Volumes": [
    {"VolumeName":"vol-a","Links":1,"Size":300,"ReclaimableSize":300},
    {"VolumeName":"vol-b","Links":1,"Size":400,"ReclaimableSize":400}
  ]
}`

// countingUpstream serves body and records whether it was ever reached, so a
// test can assert that a refusal happened in front of the daemon rather than
// after buffering its answer.
func countingUpstream(body string, reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
}

func getPathForTest(t *testing.T, handler http.Handler, method, path string) (*httptest.ResponseRecorder, *logging.RequestMeta) {
	t.Helper()
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, meta
}

// TestLibpodSystemDataUsageRefusedUnderOwnership is the regression test for
// the sibling of the /system/df enumeration bypass: NormalizePath strips the
// API version prefix but not "/libpod", so GET /libpod/system/df matched
// neither the compat filter's predicate nor any owner-label injection, and a
// caller scoped to team-a that had been allowed the path received Podman's
// full host inventory.
//
// It cannot be filtered into shape, so it is refused. The upstream must not be
// reached at all: a body this proxy cannot scope must not be buffered, and
// there is no upstream answer — well-formed, malformed or oversized — that
// changes the outcome.
func TestLibpodSystemDataUsageRefusedUnderOwnership(t *testing.T) {
	t.Parallel()
	// The undecodable row is the fail-closed case: whatever the daemon would
	// have said, the client gets this proxy's refusal and none of its bytes.
	// There is no oversized row because there is nothing to be oversized —
	// asserting the upstream is never reached generalizes over every body it
	// could have sent.
	tests := []struct {
		name     string
		method   string
		path     string
		upstream string
	}{
		{name: "bare libpod path", method: http.MethodGet, path: "/libpod/system/df", upstream: libpodSystemDFUpstream},
		{name: "podman v5.8.1 client spelling", method: http.MethodGet, path: "/v5.8.1/libpod/system/df", upstream: libpodSystemDFUpstream},
		{name: "libpod minimum api version", method: http.MethodGet, path: "/v4.0.0/libpod/system/df", upstream: libpodSystemDFUpstream},
		{name: "two-part version prefix", method: http.MethodGet, path: "/v5.0/libpod/system/df", upstream: libpodSystemDFUpstream},
		{name: "undecodable upstream body", method: http.MethodGet, path: "/v5.8.1/libpod/system/df", upstream: `{"Containers":[{"ContainerID":"c-b","Names":"team-b-web"`},
		// HEAD must be refused the same as GET: the switch this refusal lives
		// in used to gate on GET alone, so a HEAD request fell all the way
		// through to next.ServeHTTP and reached the daemon unscoped.
		{name: "HEAD request", method: http.MethodHead, path: "/v5.8.1/libpod/system/df", upstream: libpodSystemDFUpstream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(countingUpstream(tt.upstream, &reached))

			rec, meta := getPathForTest(t, handler, tt.method, tt.path)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
			}
			if reached {
				t.Error("the daemon was queried for a report that cannot be scoped")
			}
			if meta.ReasonCode != reasonCodeOwnerLibpodDataUsageUnscoped {
				t.Errorf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerLibpodDataUsageUnscoped)
			}
			body := rec.Body.String()
			for _, leaked := range []string{"team-b", "c-b", "vol-b", "bbbb444455556666", "1092588"} {
				if strings.Contains(body, leaked) {
					t.Errorf("host inventory %q reached the client: %s", leaked, body)
				}
			}
			if !strings.Contains(body, "carry no labels") {
				t.Errorf("refusal does not say why it happened: %s", body)
			}
		})
	}
}

func TestLibpodShowMountedRefusedUnderOwnership(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/libpod/containers/showmounted"},
		{method: http.MethodGet, path: "/v5.8.1/libpod/containers/showmounted"},
		// HEAD must be refused the same as GET; see the equivalent case in
		// TestLibpodSystemDataUsageRefusedUnderOwnership for why.
		{method: http.MethodHead, path: "/v5.8.1/libpod/containers/showmounted"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(countingUpstream(`{"other-id":"/var/lib/containers/storage/overlay/other/merged"}`, &reached))

			rec, meta := getPathForTest(t, handler, tt.method, tt.path)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
			}
			if reached {
				t.Fatal("the daemon was queried for mount paths that cannot be owner-scoped")
			}
			if meta.ReasonCode != "owner_libpod_show_mounted_unscopeable" {
				t.Fatalf("meta.ReasonCode = %q, want owner_libpod_show_mounted_unscopeable", meta.ReasonCode)
			}
			for _, leaked := range []string{"other-id", "/var/lib/containers"} {
				if strings.Contains(rec.Body.String(), leaked) {
					t.Fatalf("mount inventory %q reached the client: %s", leaked, rec.Body.String())
				}
			}
		})
	}
}

// TestLibpodSystemDataUsageInertWithoutOwnership proves the refusal costs
// nothing to a single-tenant Podman deployment: with no owner configured there
// is no tenant boundary to enforce, so the rule engine stays the only control
// and the report is forwarded byte for byte.
func TestLibpodSystemDataUsageInertWithoutOwnership(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(countingUpstream(libpodSystemDFUpstream, &reached))

	rec, _ := getPathForTest(t, handler, http.MethodGet, "/v5.8.1/libpod/system/df")
	if !reached {
		t.Fatal("upstream was not reached with no owner configured")
	}
	if got := rec.Body.String(); got != libpodSystemDFUpstream {
		t.Fatalf("body was rewritten with no owner configured:\n got: %s\nwant: %s", got, libpodSystemDFUpstream)
	}
}

// TestLibpodSystemDataUsageRefusalIsExact keeps the refusal from widening into
// the rest of the libpod surface. Everything here is either a different
// endpoint or a different method, and every one of them still reaches the
// daemon.
func TestLibpodSystemDataUsageRefusalIsExact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "compat disk usage is filtered, not refused", method: http.MethodGet, path: "/v1.53/system/df"},
		{name: "libpod container list", method: http.MethodGet, path: "/v5.8.1/libpod/containers/json"},
		{name: "longer libpod system path", method: http.MethodGet, path: "/v5.8.1/libpod/system/dfstats"},
		{name: "parent libpod system path", method: http.MethodGet, path: "/v5.8.1/libpod/system"},
		{name: "non-GET method", method: http.MethodPost, path: "/v5.8.1/libpod/system/df"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(countingUpstream(`{}`, &reached))

			rec, _ := getPathForTest(t, handler, tt.method, tt.path)
			if !reached {
				t.Fatalf("the refusal swallowed %s %s; status = %d, body: %s", tt.method, tt.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// system_data_usage.go: ownerFilterWriter.Write — buffer size boundary. A
// single write that lands exactly on filter.MaxResponseBodyBytes must still
// be buffered in full; only strictly exceeding the limit trips overflow.
// ---------------------------------------------------------------------------

func TestOwnerFilterWriterWriteAcceptsExactlyMaxSizedWrite(t *testing.T) {
	t.Parallel()
	w := newOwnerFilterWriter(httptest.NewRecorder())
	buf := bytes.Repeat([]byte("x"), filter.MaxResponseBodyBytes)

	n, err := w.Write(buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(buf) {
		t.Fatalf("Write() n = %d, want %d", n, len(buf))
	}
	if w.overflow {
		t.Fatal("overflow = true for a write exactly at the size limit, want false")
	}
	if w.body.Len() != len(buf) {
		t.Fatalf("buffered body length = %d, want %d (an at-limit write must not be discarded)", w.body.Len(), len(buf))
	}
}

// ---------------------------------------------------------------------------
// system_data_usage.go: ownerFilterWriter.flushOwned — non-2xx status
// boundary. Status 300 (http.StatusMultipleChoices) is the first status the
// "forward verbatim, do not attempt to parse as a system/df report" branch
// must catch; 299 already falls through the same way, but is not the
// mutated comparison's boundary and is not asserted here.
// ---------------------------------------------------------------------------

func TestOwnerFilterWriterFlushOwnedForwardsMultipleChoicesVerbatim(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	w := newOwnerFilterWriter(rec)
	w.statusCode = http.StatusMultipleChoices
	body := "not a system/df JSON body at all"
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if _, err := w.flushOwned(Options{Owner: "team-a"}); err != nil {
		t.Fatalf("flushOwned() error = %v, want nil (a >=300 status must forward verbatim, never attempt to decode the body as a system/df report)", err)
	}
	if rec.Code != http.StatusMultipleChoices {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMultipleChoices)
	}
	if rec.Body.String() != body {
		t.Fatalf("body = %q, want %q forwarded verbatim", rec.Body.String(), body)
	}
}

// ---------------------------------------------------------------------------
// system_data_usage.go: filterSystemDataUsageResponse — the
// FirstSightSystemDataUsageSections(dropped); len(fresh) > 0 guard around the
// "dropped unclassifiable response sections" warning log.
// ---------------------------------------------------------------------------

// TestFilterSystemDataUsageResponseLogsOnFirstUnclassifiableSection uses a
// top-level /system/df key unique to this *run* of the test to prove the
// warning fires on first sight.
//
// FirstSightSystemDataUsageSections (responsefilter package) dedupes through
// an unexported, package-level sync.Map with no reset hook this package can
// reach, so a fixed key would only fire once per test binary process: a
// second pass (go test -count=2, or any other test in this process that
// probes the same key) would find it already marked seen and the warning
// would never log, failing this test nondeterministically depending on run
// order. Mixing in the test name and a nanosecond timestamp keeps the key
// fresh on every invocation without needing to touch that map at all.
func TestFilterSystemDataUsageResponseLogsOnFirstUnclassifiableSection(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	probeSection := fmt.Sprintf("ZZZOwnershipMutationBoundaryProbe_%s_%d", t.Name(), time.Now().UnixNano())
	upstream := `{"ImageUsage":{"TotalCount":1,"Items":[{"Id":"sha256:mine","Labels":{"` + ownerLabelForTest + `":"team-a"}}]},` +
		`"` + probeSection + `":{"TotalCount":1,"Items":[{"Id":"x1"}]}}`
	handler := middlewareWithDeps(logger, Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(upstream))

	getSystemDFForTest(t, handler)

	if !strings.Contains(buf.String(), "dropped unclassifiable response sections") {
		t.Fatalf("log = %q, want a warning naming the unclassifiable section", buf.String())
	}
	if !strings.Contains(buf.String(), probeSection) {
		t.Fatalf("log = %q, want it to name %s", buf.String(), probeSection)
	}
}

// TestFilterSystemDataUsageResponseNoLogWhenEveryKnownSectionSeen asserts the
// negative: a response built only from known sections (no unclassifiable
// keys) must not emit the warning at all.
func TestFilterSystemDataUsageResponseNoLogWhenEveryKnownSectionSeen(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	handler := middlewareWithDeps(logger, Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(systemDFUpstreamHandler(modernSystemDFUpstream))

	getSystemDFForTest(t, handler)

	if strings.Contains(buf.String(), "dropped unclassifiable response sections") {
		t.Fatalf("log = %q, want no unclassifiable-sections warning when every top-level key is a known section", buf.String())
	}
}

// TestSystemDataUsageRewriteClearsUpstreamRepresentationHeaders pins the
// success path against the same rule the two 502 paths in this file already
// follow: a body sockguard rewrote is not the daemon's, so the daemon's
// validator and encoding for it must not go out with it. Content-Length was
// corrected on its own, which left an ETag describing the unfiltered host
// inventory on a response that no longer contains it.
func TestSystemDataUsageRewriteClearsUpstreamRepresentationHeaders(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Digest", "sha-256=:upstream:")
		w.Header().Set("Content-Encoding", "identity")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Content-Location", "/v1.53/system/df")
		w.Header().Set("Content-MD5", "upstream-md5")
		w.Header().Set("Content-Range", "bytes 0-99/100")
		w.Header().Set("Digest", "sha-256=upstream")
		w.Header().Set("ETag", `"upstream-etag"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		w.Header().Set("Repr-Digest", "sha-256=:upstream:")
		w.Header().Set("Trailer", "X-Upstream-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, modernSystemDFUpstream)
	})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	rec := getSystemDFForTest(t, handler)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "team-b") {
		t.Fatalf("other owner survived the filter: %s", rec.Body.String())
	}
	for _, name := range []string{
		"Accept-Ranges", "Content-Digest", "Content-Encoding", "Content-Language",
		"Content-Location", "Content-MD5", "Content-Range", "Digest", "ETag",
		"Last-Modified", "Repr-Digest", "Trailer", "Transfer-Encoding",
	} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("%s = %q after a body rewrite, want cleared", name, got)
		}
	}
	if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(rec.Body.Len()); got != want {
		t.Fatalf("Content-Length = %q, want %q (the rewritten body's own length)", got, want)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want the upstream's application/json kept", got)
	}
}
