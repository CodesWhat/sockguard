package visibility

import (
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
)

// modernSystemDFForTest is an Engine API >= 1.52 /system/df body: two
// containers, two images and two volumes split across a "prod" and a "dev"
// tier, plus an unlabeled build-cache record.
const modernSystemDFForTest = `{
  "ContainerUsage":{"ActiveCount":2,"TotalCount":2,"Reclaimable":1000,"TotalSize":2000,"Items":[
    {"Id":"c-prod","Names":["/prod-web"],"Image":"team/prod:1","Labels":{"tier":"prod"}},
    {"Id":"c-dev","Names":["/dev-web"],"Image":"team/dev:1","Labels":{"tier":"dev"}}
  ]},
  "ImageUsage":{"ActiveCount":2,"TotalCount":2,"Reclaimable":3000,"TotalSize":4000,"Items":[
    {"Id":"sha256:prod","RepoTags":["team/prod:1"],"Labels":{"tier":"prod"}},
    {"Id":"sha256:dev","RepoTags":["team/dev:1"],"Labels":{"tier":"dev"}}
  ]},
  "VolumeUsage":{"ActiveCount":2,"TotalCount":2,"Reclaimable":5000,"TotalSize":6000,"Items":[
    {"Name":"vol-prod","Labels":{"tier":"prod"}},
    {"Name":"vol-dev","Labels":{"tier":"dev"}}
  ]},
  "BuildCacheUsage":{"ActiveCount":1,"TotalCount":1,"Reclaimable":7000,"TotalSize":8000,"Items":[
    {"ID":"bc1","Description":"RUN echo dev-tier-build-secret"}
  ]}
}`

// legacySystemDFForTest is the same host in the Engine API <= 1.51 shape.
const legacySystemDFForTest = `{
  "LayersSize":1092588,
  "Containers":[
    {"Id":"c-prod","Names":["/prod-web"],"Image":"team/prod:1","Labels":{"tier":"prod"}},
    {"Id":"c-dev","Names":["/dev-web"],"Image":"team/dev:1","Labels":{"tier":"dev"}}
  ],
  "Images":[
    {"Id":"sha256:prod","RepoTags":["team/prod:1"],"Labels":{"tier":"prod"}},
    {"Id":"sha256:dev","RepoTags":["team/dev:1"],"Labels":{"tier":"dev"}}
  ],
  "Volumes":[
    {"Name":"vol-prod","Labels":{"tier":"prod"}},
    {"Name":"vol-dev","Labels":{"tier":"dev"}}
  ],
  "BuildCache":[{"ID":"bc1","Description":"RUN echo dev-tier-build-secret"}]
}`

func systemDFHandlerForTest(t *testing.T, opts Options, body string) http.Handler {
	t.Helper()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
	return middlewareWithDeps(slog.New(slog.NewTextHandler(io.Discard, nil)), opts, visibilityDeps{})(upstream)
}

func getSystemDFForTest(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestSystemDataUsageSelectorPolicyHidesNonMatchingItems is the regression
// test: /system/df accepts no `filters` parameter, so before the response
// filter existed the label selectors that constrain /containers/json, /volumes
// and /images/json had nothing to attach to and every resource on the host was
// enumerable through it.
func TestSystemDataUsageSelectorPolicyHidesNonMatchingItems(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "engine api 1.52 usage objects", body: modernSystemDFForTest},
		{name: "engine api 1.51 bare arrays", body: legacySystemDFForTest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, tt.body)

			rec := getSystemDFForTest(t, handler)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, visible := range []string{"c-prod", "sha256:prod", "vol-prod"} {
				if !strings.Contains(body, visible) {
					t.Errorf("visible resource %q missing from /system/df: %s", visible, body)
				}
			}
			for _, hidden := range []string{"c-dev", "dev-web", "sha256:dev", "vol-dev"} {
				if strings.Contains(body, hidden) {
					t.Errorf("hidden resource %q leaked through /system/df: %s", hidden, body)
				}
			}
		})
	}
}

// TestSystemDataUsagePatternPolicyFiltersContainersAndImages asserts the
// name/image pattern axes reach /system/df exactly as far as they reach
// /containers/json and /images/json — and no further: volumes carry no pattern
// axis anywhere in this package, so a patterns-only policy leaves them alone.
func TestSystemDataUsagePatternPolicyFiltersContainersAndImages(t *testing.T) {
	t.Parallel()
	// "prod-*" matches the container name; "prod:*" matches the image's short
	// name, which is what imageItemVisibleByPatterns compares against (
	// imageShortName("team/prod:1") is "prod:1").
	handler := systemDFHandlerForTest(t, Options{NamePatterns: []string{"prod-*", "prod:*"}}, modernSystemDFForTest)

	body := getSystemDFForTest(t, handler).Body.String()
	if !strings.Contains(body, "c-prod") || !strings.Contains(body, "sha256:prod") {
		t.Errorf("pattern-matching container/image missing: %s", body)
	}
	if strings.Contains(body, "c-dev") || strings.Contains(body, "sha256:dev") {
		t.Errorf("non-matching container/image leaked: %s", body)
	}
	for _, volume := range []string{"vol-prod", "vol-dev"} {
		if !strings.Contains(body, volume) {
			t.Errorf("volume %q hidden by a patterns-only policy; volumes carry no pattern axis: %s", volume, body)
		}
	}
}

// TestSystemDataUsageSelectorsAndPatternsBothApply covers the AND of the two
// axes on a single item.
func TestSystemDataUsageSelectorsAndPatternsBothApply(t *testing.T) {
	t.Parallel()
	body := `{"ContainerUsage":{"TotalCount":3,"Items":[
      {"Id":"c-both","Names":["/prod-web"],"Labels":{"tier":"prod"}},
      {"Id":"c-label-only","Names":["/dev-web"],"Labels":{"tier":"prod"}},
      {"Id":"c-name-only","Names":["/prod-api"],"Labels":{"tier":"dev"}}
    ]}}`
	handler := systemDFHandlerForTest(t, Options{
		VisibleResourceLabels: []string{"tier=prod"},
		NamePatterns:          []string{"prod-web"},
	}, body)

	got := getSystemDFForTest(t, handler).Body.String()
	if !strings.Contains(got, "c-both") {
		t.Errorf("item passing both axes was hidden: %s", got)
	}
	for _, hidden := range []string{"c-label-only", "c-name-only"} {
		if strings.Contains(got, hidden) {
			t.Errorf("item failing one axis leaked: %q in %s", hidden, got)
		}
	}
}

// TestSystemDataUsageUnlabeledItemsHiddenBySelectors pins the fail-closed
// treatment of an item with no labels, matching matchesSelectors and the
// daemon-side `label` filter the other list endpoints push upstream.
func TestSystemDataUsageUnlabeledItemsHiddenBySelectors(t *testing.T) {
	t.Parallel()
	body := `{"VolumeUsage":{"TotalCount":2,"Items":[{"Name":"vol-labeled","Labels":{"tier":"prod"}},{"Name":"vol-bare"}]}}`
	handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, body)

	got := getSystemDFForTest(t, handler).Body.String()
	if strings.Contains(got, "vol-bare") {
		t.Fatalf("unlabeled volume leaked past a label selector: %s", got)
	}
}

func TestSystemDataUsageDropsBuildCache(t *testing.T) {
	t.Parallel()
	handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, modernSystemDFForTest)

	got := getSystemDFForTest(t, handler).Body.String()
	if strings.Contains(got, "dev-tier-build-secret") || strings.Contains(got, "bc1") {
		t.Fatalf("build cache record leaked through /system/df: %s", got)
	}
}

// TestSystemDataUsageVisibilityDropsUnknownSections pins the fix for the leak
// this filter existed to close and did not: a top-level section this build does
// not recognize used to be re-marshaled verbatim, so a future Engine API
// section, or one only a Docker-compat upstream sends, reached the client with
// every item in it and no policy axis applied. BuilderSize is here because it
// is reachable today rather than hypothetical: the Engine API only removed it
// in v1.42.
func TestSystemDataUsageVisibilityDropsUnknownSections(t *testing.T) {
	t.Parallel()
	upstream := `{"ImageUsage":{"TotalCount":1,"Items":[{"Id":"sha256:prod","Labels":{"tier":"prod"}}]},` +
		`"PluginUsage":{"TotalCount":2,"Items":[{"Id":"p1","Labels":{"tier":"dev"}}]},` +
		`"CheckpointUsage":[{"Id":"cp1"}],"BuilderSize":777}`
	handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, upstream)

	got := getSystemDFForTest(t, handler).Body.String()
	for _, leaked := range []string{"PluginUsage", "CheckpointUsage", "BuilderSize", "p1", "cp1", "777"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("%q reached the client through /system/df: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "sha256:prod") {
		t.Fatalf("the visible image was dropped too, so this proves nothing: %s", got)
	}
}

func TestSystemDataUsageRewritesAggregates(t *testing.T) {
	t.Parallel()
	handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, modernSystemDFForTest)

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

// TestSystemDataUsageInertWithoutPolicy proves the change costs nothing to an
// operator who configured no visibility policy: the middleware is a
// pass-through and the response is forwarded byte for byte.
func TestSystemDataUsageInertWithoutPolicy(t *testing.T) {
	t.Parallel()
	handler := systemDFHandlerForTest(t, Options{}, modernSystemDFForTest)

	rec := getSystemDFForTest(t, handler)
	if got := rec.Body.String(); got != modernSystemDFForTest {
		t.Fatalf("body was rewritten with no policy configured:\n got: %s\nwant: %s", got, modernSystemDFForTest)
	}
	if got := rec.Header().Get("ETag"); got != `"upstream"` {
		t.Fatalf("ETag = %q, want the upstream's untouched", got)
	}
}

func TestSystemDataUsageSetsContentLength(t *testing.T) {
	t.Parallel()
	handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, modernSystemDFForTest)

	rec := getSystemDFForTest(t, handler)
	want := strconv.Itoa(rec.Body.Len())
	if got := rec.Header().Get("Content-Length"); got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
	}
}

// TestSystemDataUsageOversizedResponseReturns502 mirrors the /containers/json
// overflow branch: past the 8 MiB cap the response is refused, never truncated
// into a partially filtered body.
func TestSystemDataUsageOversizedResponseReturns502(t *testing.T) {
	t.Parallel()
	chunk := `{"Id":"c-dev","Labels":{"tier":"dev"}},`
	huge := `{"ContainerUsage":{"Items":[` +
		strings.Repeat(chunk, (filter.MaxResponseBodyBytes/len(chunk))+5000) +
		`{"Id":"c-dev"}]}}`
	handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, huge)

	rec := getSystemDFForTest(t, handler)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for oversized response", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("body = %q, want too-large message", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"tier":"dev"`) {
		t.Fatalf("oversized response leaked upstream bytes: %s", rec.Body.String())
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag = %q, want cleared on a generated error", got)
	}
}

// TestSystemDataUsageUndecodableBodyReturns502 pins the deliberate difference
// from flushFiltered: a /system/df body that will not decode is refused rather
// than forwarded, because we cannot prove it hides nothing.
func TestSystemDataUsageUndecodableBodyReturns502(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "truncated object", body: `{"ContainerUsage":`},
		{name: "array instead of object", body: `[{"Id":"c-dev"}]`},
		{name: "empty body", body: ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := systemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, tt.body)
			rec := getSystemDFForTest(t, handler)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502; body: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

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
			handler := middlewareWithDeps(slog.New(slog.NewTextHandler(io.Discard, nil)),
				Options{VisibleResourceLabels: []string{"tier=prod"}}, visibilityDeps{})(upstream)

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
// there is nothing to filter and nothing to leak.
func TestSystemDataUsageHeadRequestNotIntercepted(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
	})
	handler := middlewareWithDeps(slog.New(slog.NewTextHandler(io.Discard, nil)),
		Options{VisibleResourceLabels: []string{"tier=prod"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodHead, "/v1.53/system/df", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Length"); got != "4096" {
		t.Fatalf("Content-Length = %q, want the upstream's 4096 untouched", got)
	}
}

// TestSystemDataUsageProfilePolicyApplies asserts the per-client profile
// policy, not just the default one, reaches /system/df.
func TestSystemDataUsageProfilePolicyApplies(t *testing.T) {
	t.Parallel()
	handler := systemDFHandlerForTest(t, Options{
		Profiles:       map[string]Policy{"team-a": {VisibleResourceLabels: []string{"tier=prod"}}},
		ResolveProfile: func(*http.Request) (string, bool) { return "team-a", true },
	}, modernSystemDFForTest)

	got := getSystemDFForTest(t, handler).Body.String()
	if !strings.Contains(got, "c-prod") {
		t.Errorf("visible container missing under a profile policy: %s", got)
	}
	if strings.Contains(got, "c-dev") {
		t.Errorf("hidden container leaked under a profile policy: %s", got)
	}
}

// TestSystemDataUsageItemVisibleUnknownSectionFailsClosed covers a branch that
// FilterSystemDataUsage no longer reaches, since it removes unknown top-level
// keys before any item is classified. It stays so the predicate remains
// fail-closed if a section is added to the shape table before it is added here.
// The reachable behavior is pinned by
// TestSystemDataUsageVisibilityDropsUnknownSections.
func TestSystemDataUsageItemVisibleUnknownSectionFailsClosed(t *testing.T) {
	t.Parallel()
	policy := &compiledPolicy{}
	visible, err := systemDataUsageItemVisible(responsefilter.SystemDataUsageSection("future"), json.RawMessage(`{}`), policy)
	if err != nil {
		t.Fatalf("systemDataUsageItemVisible() error = %v", err)
	}
	if visible {
		t.Fatal("an unrecognized /system/df section must be hidden, not forwarded")
	}
}

func TestSystemDataUsageItemVisibleReportsDecodeErrors(t *testing.T) {
	t.Parallel()
	policy := &compiledPolicy{selectors: []compiledSelector{{key: "tier", value: "prod", hasValue: true}}}
	for _, section := range []responsefilter.SystemDataUsageSection{
		responsefilter.SystemDataUsageContainers,
		responsefilter.SystemDataUsageImages,
		responsefilter.SystemDataUsageVolumes,
	} {
		if _, err := systemDataUsageItemVisible(section, json.RawMessage(`{"Labels":`), policy); err == nil {
			t.Fatalf("section %s: want an error so the caller fails closed, got nil", section)
		}
	}
}

// libpodSystemDFForTest is a GET /libpod/system/df body in Podman's own report
// shape (entities.SystemDfReport at v5.8.1), holding one image, container and
// volume per tier.
//
// The prod/dev split lives entirely in free-text Repository/Image/Names/
// VolumeName values. None of the three item types has a Labels field, so the
// selector axes have nothing to read; the name and image pattern axes do not
// help either, because needsPatternResponseFilter scopes them to two
// Docker-compat list endpoints and neither ContainerSummary nor ImageSummary
// is what this shape contains. See
// responsefilter.LibpodSystemDataUsageDenyReason.
const libpodSystemDFForTest = `{
  "ImagesSize": 1092588,
  "Images": [
    {"Repository":"docker.io/team/prod","Tag":"1","ImageID":"aaaa111122223333","Size":5000,"SharedSize":1000,"UniqueSize":4000,"Containers":1},
    {"Repository":"docker.io/team/dev","Tag":"1","ImageID":"bbbb444455556666","Size":6000,"SharedSize":1000,"UniqueSize":5000,"Containers":1}
  ],
  "Containers": [
    {"ContainerID":"c-prod","Image":"docker.io/team/prod:1","Command":["sleep","infinity"],"LocalVolumes":1,"Size":100,"RWSize":50,"Status":"running","Names":"prod-web"},
    {"ContainerID":"c-dev","Image":"docker.io/team/dev:1","Command":["sleep","infinity"],"LocalVolumes":1,"Size":200,"RWSize":60,"Status":"running","Names":"dev-web"}
  ],
  "Volumes": [
    {"VolumeName":"vol-prod","Links":1,"Size":300,"ReclaimableSize":300},
    {"VolumeName":"vol-dev","Links":1,"Size":400,"ReclaimableSize":400}
  ]
}`

func libpodSystemDFHandlerForTest(t *testing.T, opts Options, body string, reached *bool) http.Handler {
	t.Helper()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
	return middlewareWithDeps(slog.New(slog.NewTextHandler(io.Discard, nil)), opts, visibilityDeps{})(upstream)
}

func getLibpodPathForTest(t *testing.T, handler http.Handler, method, path string) (*httptest.ResponseRecorder, *logging.RequestMeta) {
	t.Helper()
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, meta
}

// TestLibpodSystemDataUsageRefusedUnderVisibilityPolicy is the regression test
// for the sibling of the /system/df enumeration bypass: NormalizePath strips
// the API version prefix but not "/libpod", so GET /libpod/system/df matched
// neither the compat response filter nor needsVisibilityLabelFilter, and a
// caller restricted to the prod tier that had been allowed the path received
// Podman's full host inventory.
//
// The report cannot be filtered into shape under any policy axis, so it is
// refused before the daemon is queried at all.
func TestLibpodSystemDataUsageRefusedUnderVisibilityPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		opts     Options
		path     string
		upstream string
	}{
		{
			name:     "selector policy, bare libpod path",
			opts:     Options{VisibleResourceLabels: []string{"tier=prod"}},
			path:     "/libpod/system/df",
			upstream: libpodSystemDFForTest,
		},
		{
			name:     "selector policy, podman v5.8.1 client spelling",
			opts:     Options{VisibleResourceLabels: []string{"tier=prod"}},
			path:     "/v5.8.1/libpod/system/df",
			upstream: libpodSystemDFForTest,
		},
		{
			name:     "selector policy, libpod minimum api version",
			opts:     Options{VisibleResourceLabels: []string{"tier=prod"}},
			path:     "/v4.0.0/libpod/system/df",
			upstream: libpodSystemDFForTest,
		},
		{
			name:     "name pattern policy",
			opts:     Options{NamePatterns: []string{"prod-*"}},
			path:     "/v5.8.1/libpod/system/df",
			upstream: libpodSystemDFForTest,
		},
		{
			// Fail-closed: whatever the daemon would have said, the client
			// gets this proxy's refusal and none of its bytes.
			name:     "undecodable upstream body",
			opts:     Options{VisibleResourceLabels: []string{"tier=prod"}},
			path:     "/v5.8.1/libpod/system/df",
			upstream: `{"Containers":[{"ContainerID":"c-dev","Names":"dev-web"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := libpodSystemDFHandlerForTest(t, tt.opts, tt.upstream, &reached)

			rec, meta := getLibpodPathForTest(t, handler, http.MethodGet, tt.path)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
			}
			if reached {
				t.Error("the daemon was queried for a report the policy cannot be applied to")
			}
			if meta.ReasonCode != reasonCodeVisibilityLibpodDataUsage {
				t.Errorf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityLibpodDataUsage)
			}
			body := rec.Body.String()
			for _, leaked := range []string{"dev-web", "c-dev", "vol-dev", "bbbb444455556666", "1092588"} {
				if strings.Contains(body, leaked) {
					t.Errorf("host inventory %q reached the client: %s", leaked, body)
				}
			}
		})
	}
}

func TestLibpodShowMountedRefusedUnderVisibilityPolicy(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/libpod/containers/showmounted",
		"/v5.8.1/libpod/containers/showmounted",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := libpodSystemDFHandlerForTest(t,
				Options{VisibleResourceLabels: []string{"tier=prod"}},
				`{"dev-id":"/var/lib/containers/storage/overlay/dev/merged"}`,
				&reached,
			)

			rec, meta := getLibpodPathForTest(t, handler, http.MethodGet, path)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
			}
			if reached {
				t.Fatal("the daemon was queried for mount paths that cannot be visibility-scoped")
			}
			if meta.ReasonCode != "visibility_libpod_showmounted_unscopeable" {
				t.Fatalf("meta.ReasonCode = %q, want visibility_libpod_showmounted_unscopeable", meta.ReasonCode)
			}
			for _, leaked := range []string{"dev-id", "/var/lib/containers"} {
				if strings.Contains(rec.Body.String(), leaked) {
					t.Fatalf("mount inventory %q reached the client: %s", leaked, rec.Body.String())
				}
			}
		})
	}
}

// TestLibpodSystemDataUsageInertWithoutVisibilityPolicy proves the refusal
// costs nothing to a deployment with no visibility policy: there is no
// boundary to enforce, so the rule engine stays the only control.
func TestLibpodSystemDataUsageInertWithoutVisibilityPolicy(t *testing.T) {
	t.Parallel()
	reached := false
	handler := libpodSystemDFHandlerForTest(t, Options{}, libpodSystemDFForTest, &reached)

	rec, _ := getLibpodPathForTest(t, handler, http.MethodGet, "/v5.8.1/libpod/system/df")
	if !reached {
		t.Fatal("upstream was not reached with no visibility policy configured")
	}
	if got := rec.Body.String(); got != libpodSystemDFForTest {
		t.Fatalf("body was rewritten with no visibility policy:\n got: %s\nwant: %s", got, libpodSystemDFForTest)
	}
}

// TestLibpodSystemDataUsageVisibilityRefusalIsExact keeps the refusal from
// widening into the rest of the libpod surface.
func TestLibpodSystemDataUsageVisibilityRefusalIsExact(t *testing.T) {
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
			handler := libpodSystemDFHandlerForTest(t, Options{VisibleResourceLabels: []string{"tier=prod"}}, `{}`, &reached)

			rec, _ := getLibpodPathForTest(t, handler, tt.method, tt.path)
			if !reached {
				t.Fatalf("the refusal swallowed %s %s; status = %d, body: %s", tt.method, tt.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSystemDataUsageNoUnknownSectionsNeverWarns is the boundary regression
// for `len(fresh) > 0` in handleVisibilitySystemDataUsageRequest: a
// /system/df response with no unrecognized top-level sections must produce
// zero dropped-section warnings. A `>=` in place of `>` makes this clause
// true even when fresh is empty (len(nil) >= 0), logging a warning about
// sections that were never actually dropped.
func TestSystemDataUsageNoUnknownSectionsNeverWarns(t *testing.T) {
	t.Parallel()
	logger, buf := warnCapturingLogger()

	handler := middlewareWithDeps(logger, Options{VisibleResourceLabels: []string{"tier=prod"}}, visibilityDeps{})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, modernSystemDFForTest)
		}),
	)

	rec := getSystemDFForTest(t, handler)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(buf.String(), "dropped unclassifiable response sections") {
		t.Fatalf("log output = %q, want no dropped-sections warning for an all-known response", buf.String())
	}
}

// TestSystemDataUsageFreshUnknownSectionWarnsOnce is the negation regression
// for the same clause: a /system/df response carrying a section this build
// does not recognize must warn, naming the section — exactly once, even when
// the same section keeps showing up on later requests. A `<=` in place of `>`
// flips the clause so it is only true when fresh is empty, silencing the
// warning exactly when there is something to report; that mutant would also
// pass a test that only checked "warns at least once", so this sends the same
// unknown section on two requests and asserts the warning fires on the first
// and is suppressed on the second, which is the actual "WarnsOnce" contract
// this test is named for.
//
// Dropped-section state lives in responsefilter's package-level
// unreportedSystemDataUsageKeys sync.Map (see FirstSightSystemDataUsageSections),
// which persists for the life of the process — including across a `go test
// -count>1` rerun of this same binary. visibility has no way to reach into
// that map to reset it between runs, so a fixed section key would be marked
// seen by the first run and silently stop warning on the second, making this
// test's assertion fail with no code change. Deriving the key from the test
// name and the current time keeps every run's key unique.
func TestSystemDataUsageFreshUnknownSectionWarnsOnce(t *testing.T) {
	t.Parallel()
	logger, buf := warnCapturingLogger()

	unknownSectionKey := fmt.Sprintf("ZZZVisibilityUnknownSection_%s_%d", t.Name(), time.Now().UnixNano())
	body := `{"ContainerUsage":{"Items":[]},"ImageUsage":{"Items":[]},"VolumeUsage":{"Items":[]},"` +
		unknownSectionKey + `":{"anything":true}}`

	handler := middlewareWithDeps(logger, Options{VisibleResourceLabels: []string{"tier=prod"}}, visibilityDeps{})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, body)
		}),
	)

	rec := getSystemDFForTest(t, handler)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	rec2 := getSystemDFForTest(t, handler)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second request status = %d, want 200; body: %s", rec2.Code, rec2.Body.String())
	}

	got := buf.String()
	if !strings.Contains(got, "dropped unclassifiable response sections") {
		t.Fatalf("log output = %q, want a dropped-sections warning", got)
	}
	if warnings := strings.Count(got, unknownSectionKey); warnings != 1 {
		t.Fatalf("log output = %q, want exactly one dropped-sections warning naming %q, got %d", got, unknownSectionKey, warnings)
	}
}
