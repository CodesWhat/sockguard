package visibility

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// libpod_coverage_test.go closes the three libpod visibility gaps found by
// auditing internal/visibility/libpod_paths.go against its Docker-compat
// counterparts in middleware.go: the images route family was absent from both
// the list-filter set and the inspect dispatch, GET /libpod/events was in
// neither, and libpodContainerReadIdentifier's suffix list was shorter than
// containerReadIdentifier's.
//
// Every test here carries a Docker-compat leg over the same fixture, so a
// change that silently stopped the middleware from touching ANY request would
// fail the compat leg too rather than leaving these passing vacuously.

// --- upstream fakes -------------------------------------------------------
//
// The list and event endpoints are not filtered by sockguard; sockguard
// rewrites the `filters` query and the daemon does the work. So proving a
// resource's data is actually absent from the client's response needs an
// upstream that applies the filter the way the real daemon does — including
// the difference in how the two evaluate several values under one key, which
// is the whole reason /libpod/events cannot reuse addVisibilityLabelFilters.

// labelFilterValuesForTest returns the `label` values in a forwarded request's
// `filters` parameter, decoded the way dockerd's filters.FromJSON and Podman's
// util.FiltersFromRequest both decode it.
func labelFilterValuesForTest(t *testing.T, r *http.Request) []string {
	t.Helper()
	decoded, err := dockerfilters.Decode(r.URL.Query().Get("filters"))
	if err != nil {
		t.Fatalf("forwarded filters %q did not decode: %v", r.URL.Query().Get("filters"), err)
	}
	return decoded["label"]
}

// labelSelectorMatchesForTest reports whether one "key" or "key=value" filter
// value matches a resource's labels.
func labelSelectorMatchesForTest(labels map[string]string, value string) bool {
	key, want, hasValue := strings.Cut(value, "=")
	got, ok := labels[key]
	if !ok {
		return false
	}
	return !hasValue || got == want
}

// conjunctiveLabelMatchForTest is how every LIST endpoint on both daemons
// evaluates several `label` values: all of them must match. dockerd uses
// filters.Args.MatchKVList; Podman uses filters.MatchLabelFilters for
// containers, volumes and networks and libimage's applyFilters ("All filters
// of each key must apply") for images.
func conjunctiveLabelMatchForTest(labels map[string]string, values []string) bool {
	for _, value := range values {
		if !labelSelectorMatchesForTest(labels, value) {
			return false
		}
	}
	return true
}

// disjunctiveLabelMatchForTest is how Podman's EVENT endpoint evaluates them
// instead: libpod/events/filters.go's applyFilters returns a match as soon as
// one filter under a key succeeds, over the comment "Filters under the same
// key are disjunctive while each key must match". /events and /libpod/events
// are one handler (compat.GetEvents), so this is also what a Podman upstream
// does with the Docker-compat spelling.
func disjunctiveLabelMatchForTest(labels map[string]string, values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if labelSelectorMatchesForTest(labels, value) {
			return true
		}
	}
	return false
}

type labeledItemForTest struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

// listUpstreamForTest is a daemon that returns items only when they satisfy
// every forwarded `label` filter value.
func listUpstreamForTest(t *testing.T, items []labeledItemForTest) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := labelFilterValuesForTest(t, r)
		kept := []labeledItemForTest{}
		for _, item := range items {
			if conjunctiveLabelMatchForTest(item.Labels, values) {
				kept = append(kept, item)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(kept); err != nil {
			t.Fatalf("encode list response: %v", err)
		}
	})
}

// eventsUpstreamForTest is Podman's event endpoint: one NDJSON record per
// event whose attributes satisfy AT LEAST ONE forwarded `label` value.
func eventsUpstreamForTest(t *testing.T, items []labeledItemForTest) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := labelFilterValuesForTest(t, r)
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		for _, item := range items {
			if disjunctiveLabelMatchForTest(item.Labels, values) {
				if err := enc.Encode(item); err != nil {
					t.Fatalf("encode event: %v", err)
				}
			}
		}
	})
}

type libpodContainerListItemForTest struct {
	raw    string
	labels map[string]string
}

func libpodContainerListUpstreamForTest(t *testing.T, items []libpodContainerListItemForTest) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := labelFilterValuesForTest(t, r)
		kept := make([]string, 0, len(items))
		for _, item := range items {
			if conjunctiveLabelMatchForTest(item.labels, values) {
				kept = append(kept, item.raw)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[" + strings.Join(kept, ",") + "]"))
	})
}

func TestLibpodContainerListAppliesPatternAxes(t *testing.T) {
	t.Parallel()
	items := []libpodContainerListItemForTest{
		{
			raw:    `{"Id":"keep-first","Names":["allowed-api"],"Image":"quay.io/team/api:v1","Labels":{"tenant":"visible"},"Command":["serve","api"],"Pod":"pod-a","State":"running"}`,
			labels: map[string]string{"tenant": "visible"},
		},
		{
			raw:    `{"Id":"drop-name","Names":["hidden-db"],"Image":"quay.io/team/db:v1","Labels":{"tenant":"visible"},"Command":["serve","db"],"Pod":"pod-b","State":"running"}`,
			labels: map[string]string{"tenant": "visible"},
		},
		{
			raw:    `{"Id":"selector-hidden","Names":["allowed-worker"],"Image":"quay.io/team/worker:v1","Labels":{"tenant":"hidden"},"Command":["serve","worker"],"Pod":"pod-c","State":"paused"}`,
			labels: map[string]string{"tenant": "hidden"},
		},
		{
			raw:    `{"Id":"keep-second","Names":["allowed-web"],"Image":"quay.io/team/web:v1","Labels":{"tenant":"visible"},"Command":["serve","web"],"Pod":"pod-d","State":"running","Extra":{"keep":true}}`,
			labels: map[string]string{"tenant": "visible"},
		},
	}

	tests := []struct {
		name string
		opts Options
		want []int
	}{
		{
			name: "patterns only",
			opts: Options{NamePatterns: []string{"allowed-*"}},
			want: []int{0, 2, 3},
		},
		{
			name: "selector and name pattern",
			opts: Options{
				VisibleResourceLabels: []string{"tenant=visible"},
				NamePatterns:          []string{"allowed-*"},
			},
			want: []int{0, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := middlewareWithDeps(testVisibilityLogger(), tt.opts, visibilityDeps{})(libpodContainerListUpstreamForTest(t, items))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v5.8.1/libpod/containers/json", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			wantItems := make([]string, 0, len(tt.want))
			for _, index := range tt.want {
				wantItems = append(wantItems, items[index].raw)
			}
			wantBody := "[" + strings.Join(wantItems, ",") + "]"
			if got := rec.Body.String(); got != wantBody {
				t.Fatalf("body = %s, want retained native items in original order: %s", got, wantBody)
			}
			if got := rec.Header().Get("Content-Length"); got != fmt.Sprintf("%d", len(wantBody)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(wantBody))
			}
		})
	}
}

func TestLibpodContainerListPatternFilterCapsOversizedResponse(t *testing.T) {
	t.Parallel()
	chunk := `{"Id":"c","Names":["allowed-c"],"Image":"alpine"},`
	huge := "[" + strings.Repeat(chunk, (filter.MaxResponseBodyBytes/len(chunk))+5000) +
		`{"Id":"c","Names":["allowed-c"],"Image":"alpine"}]`

	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		NamePatterns: []string{"allowed-*"},
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(huge))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v5.8.1/libpod/containers/json", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d for oversized native list; body bytes: %d", rec.Code, http.StatusBadGateway, rec.Body.Len())
	}
	if !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("body = %q, want too-large message", rec.Body.String())
	}
}

// --- gap 1: the images route family ---------------------------------------

// TestLibpodImageListAppliesVisibilityLabelFilter covers the list half of the
// images gap: GET /libpod/images/json was in neither
// needsLibpodVisibilityLabelFilter nor, therefore,
// needsVisibilityLabelFilter, so a policy that hid an image on
// GET /images/json handed the same image over on the libpod spelling. The
// shipped podman-readonly.yaml preset allows that path unmodified.
func TestLibpodImageListAppliesVisibilityLabelFilter(t *testing.T) {
	t.Parallel()
	images := []labeledItemForTest{
		{ID: "sha256:visible", Labels: map[string]string{"com.sockguard.visible": "true"}},
		{ID: "sha256:hidden", Labels: map[string]string{"com.sockguard.visible": "false"}},
	}
	for _, path := range []string{"/images/json", "/libpod/images/json"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{})(listUpstreamForTest(t, images))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "sha256:visible") {
				t.Fatalf("body = %s, want the visible image present", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "sha256:hidden") {
				t.Fatalf("body = %s, want the hidden image absent", rec.Body.String())
			}
		})
	}
}

// TestLibpodImageReadHidesHiddenImage covers the inspect half: no libpod image
// identifier existed in requestVisibleWithPolicy at all, so every per-image
// libpod read fell through to its default-visible tail with no upstream
// inspect performed.
func TestLibpodImageReadHidesHiddenImage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want string // identifier the visibility inspect must resolve
	}{
		{name: "compat inspect", path: "/images/app/json", want: "app"},
		{name: "compat history", path: "/images/app/history", want: "app"},
		{name: "compat export", path: "/images/app/get", want: "app"},
		{name: "libpod inspect", path: "/libpod/images/app/json", want: "app"},
		{name: "libpod history", path: "/libpod/images/app/history", want: "app"},
		{name: "libpod export", path: "/libpod/images/app/get", want: "app"},
		{name: "libpod layer tree", path: "/libpod/images/app/tree", want: "app"},
		{name: "libpod changes", path: "/libpod/images/app/changes", want: "app"},
		{name: "libpod exists oracle", path: "/libpod/images/app/exists", want: "app"},
		{name: "libpod namespaced reference", path: "/libpod/images/registry.io/team/app/json", want: "registry.io/team/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotKind dockerresource.Kind
			var gotIdentifier string
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
					gotKind, gotIdentifier = kind, id
					return map[string]string{"com.sockguard.visible": "false"}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"Id":"sha256:hidden","Config":{"Env":["API_KEY=s3cr3t"]}}`))
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "s3cr3t") || strings.Contains(rec.Body.String(), "sha256:hidden") {
				t.Fatalf("body = %s, want the hidden image's data absent", rec.Body.String())
			}
			if gotKind != dockerresource.KindImage || gotIdentifier != tt.want {
				t.Fatalf("inspect = %s/%q, want %s/%q", gotKind, gotIdentifier, dockerresource.KindImage, tt.want)
			}
		})
	}
}

// TestLibpodImageCollectionRoutesAreNotImageIdentifiers pins the other half of
// the images fix: the collection routes must not be mistaken for an image
// named after the keyword, which would cost an upstream inspect per list
// request and, on the list route, hide the response behind a 404.
func TestLibpodImageCollectionRoutesAreNotImageIdentifiers(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/libpod/images/json",
		"/libpod/images/search",
		"/libpod/images/export",
		"/images/json",
	} {
		if identifier, ok := libpodImageReadIdentifier(path); ok {
			t.Fatalf("libpodImageReadIdentifier(%q) = %q, want no match", path, identifier)
		}
	}
}

// --- gap 2: GET /libpod/events --------------------------------------------

// TestLibpodEventsReplacesClientSuppliedLabelFilter is the load-bearing test
// for the events gap. The Docker-compat leg documents the behavior that is
// correct there and wrong here: addVisibilityLabelFilters APPENDS the policy
// selector to whatever the client sent, which is safe only because dockerd
// ANDs label values. Podman's event filter ORs them, so the same append lets a
// caller name any label a hidden container carries and be handed its events.
func TestLibpodEventsReplacesClientSuppliedLabelFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		path             string
		wantLabelFilters []string
	}{
		{
			name:             "compat events still append",
			path:             `/events?filters={"label":["role=db"]}`,
			wantLabelFilters: []string{"role=db", "com.sockguard.visible=true"},
		},
		{
			name:             "libpod events replace",
			path:             `/libpod/events?filters={"label":["role=db"]}`,
			wantLabelFilters: []string{"com.sockguard.visible=true"},
		},
		{
			name:             "libpod events normalize a legacy-shape client filter",
			path:             `/libpod/events?filters={"label":{"role=db":true,"com.sockguard.visible=true":true}}`,
			wantLabelFilters: []string{"com.sockguard.visible=true"},
		},
		{
			name:             "libpod events inject when the client sent none",
			path:             "/libpod/events",
			wantLabelFilters: []string{"com.sockguard.visible=true"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got []string
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = labelFilterValuesForTest(t, r)
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			if strings.Join(got, ",") != strings.Join(tt.wantLabelFilters, ",") {
				t.Fatalf("forwarded label filters = %v, want %v", got, tt.wantLabelFilters)
			}
		})
	}
}

// TestLibpodEventsExcludesAnotherTenantUnderPodmanFilterSemantics runs the
// forwarded query through an upstream that evaluates it the way Podman does,
// so the assertion is about the events the client actually receives rather
// than about the query string alone.
func TestLibpodEventsExcludesAnotherTenantUnderPodmanFilterSemantics(t *testing.T) {
	t.Parallel()
	events := []labeledItemForTest{
		{ID: "own-container", Labels: map[string]string{"com.sockguard.visible": "true", "role": "web"}},
		{ID: "other-tenant-container", Labels: map[string]string{"com.sockguard.visible": "false", "role": "db"}},
	}
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{})(eventsUpstreamForTest(t, events))

	rec := httptest.NewRecorder()
	// The client names a label only the other tenant's container carries. On
	// an appending injection Podman's disjunctive `label` key would return its
	// events.
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/libpod/events?filters={"label":["role=db"]}`, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "other-tenant-container") {
		t.Fatalf("stream = %s, want the other tenant's events absent", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "own-container") {
		t.Fatalf("stream = %s, want the caller's own events present", rec.Body.String())
	}
}

// TestLibpodEventsRefusesMultiSelectorPolicy pins the branch that cannot be
// expressed: two ANDed selectors have no second filter key to occupy, so they
// would be ORed. The Docker-compat leg proves the same policy still works
// there, i.e. that the refusal is specific to the shape and not a blanket
// regression of multi-selector policies.
func TestLibpodEventsRefusesMultiSelectorPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		path             string
		wantStatus       int
		wantUpstream     bool
		wantLabelFilters []string
	}{
		{
			name:             "compat events accept two selectors",
			path:             "/events",
			wantStatus:       http.StatusNoContent,
			wantUpstream:     true,
			wantLabelFilters: []string{"com.sockguard.visible=true", "com.sockguard.tier=web"},
		},
		{
			name:         "libpod events refuse two selectors",
			path:         "/libpod/events",
			wantStatus:   http.StatusForbidden,
			wantUpstream: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			upstreamReached := false
			var got []string
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true", "com.sockguard.tier=web"},
			}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamReached = true
				got = labelFilterValuesForTest(t, r)
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if upstreamReached != tt.wantUpstream {
				t.Fatalf("upstreamReached = %v, want %v", upstreamReached, tt.wantUpstream)
			}
			if !tt.wantUpstream {
				if !strings.Contains(rec.Body.String(), "libpod events denied") {
					t.Fatalf("body = %s, want the libpod events deny reason", rec.Body.String())
				}
				return
			}
			if strings.Join(got, ",") != strings.Join(tt.wantLabelFilters, ",") {
				t.Fatalf("forwarded label filters = %v, want %v", got, tt.wantLabelFilters)
			}
		})
	}
}

// TestLibpodEventsRefusalIgnoresRolloutMode pins the refusal as unconditional,
// matching denyLibpodSystemDataUsage: a warn-mode deployment forwarding the
// whole host's event stream is the disclosure this closes.
func TestLibpodEventsRefusalIgnoresRolloutMode(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true", "com.sockguard.tier=web"},
	}, visibilityDeps{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("warn mode reached the upstream event stream")
	}))

	req := httptest.NewRequest(http.MethodGet, "/libpod/events", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "warn"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestLibpodEventsWithPatternsOnlyPolicyIsForwarded holds the third branch at
// the Docker-compat path's behavior: pattern axes reach neither event
// endpoint, and compileVisibilityPolicies already warns about that at startup,
// so a patterns-only policy must not start refusing one of the two.
func TestLibpodEventsWithPatternsOnlyPolicyIsForwarded(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/events", "/libpod/events"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			forwarded := false
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				NamePatterns: []string{"web-*"},
			}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				if raw := r.URL.Query().Get("filters"); raw != "" {
					t.Fatalf("forwarded filters = %q, want the request untouched", raw)
				}
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if !forwarded || rec.Code != http.StatusNoContent {
				t.Fatalf("forwarded = %v status = %d, want true and %d", forwarded, rec.Code, http.StatusNoContent)
			}
		})
	}
}

// --- gap 3: the per-resource read suffix lists ----------------------------

// TestLibpodReadSubresourcesHideHiddenResource covers the third gap and the
// siblings the audit turned up next to it: libpodContainerReadIdentifier's
// suffix list was shorter than containerReadIdentifier's (no "archive"), and
// the pod, network, volume and secret identifiers matched only ".../json"
// while Podman also serves /exists, /top, /export and — for networks — the
// bare /libpod/networks/{id} spelling from the same handlers.
//
// Ownership already denied every one of these paths, because
// libpodContainerIdentifier and friends match any action on a named resource.
// The gap was confined to deployments running visibility standalone, which the
// docs support: the named-profile example in the configuration reference gives
// its watchtower profile a visible_resource_labels policy and no owner at all.
func TestLibpodReadSubresourcesHideHiddenResource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		kind dockerresource.Kind
		id   string
	}{
		{name: "compat container archive", path: "/containers/c1/archive?path=/etc", kind: dockerresource.KindContainer, id: "c1"},
		{name: "libpod container archive", path: "/libpod/containers/c1/archive?path=/etc", kind: dockerresource.KindContainer, id: "c1"},
		{name: "libpod container exists oracle", path: "/libpod/containers/c1/exists", kind: dockerresource.KindContainer, id: "c1"},
		{name: "libpod container healthcheck", path: "/libpod/containers/c1/healthcheck", kind: dockerresource.KindContainer, id: "c1"},
		{name: "compat volume inspect", path: "/volumes/v1", kind: dockerresource.KindVolume, id: "v1"},
		{name: "libpod volume export", path: "/libpod/volumes/v1/export", kind: dockerresource.KindVolume, id: "v1"},
		{name: "libpod volume exists oracle", path: "/libpod/volumes/v1/exists", kind: dockerresource.KindVolume, id: "v1"},
		{name: "libpod pod top", path: "/libpod/pods/p1/top", kind: dockerresource.KindLibpodPod, id: "p1"},
		{name: "libpod pod exists oracle", path: "/libpod/pods/p1/exists", kind: dockerresource.KindLibpodPod, id: "p1"},
		{name: "compat network inspect", path: "/networks/n1", kind: dockerresource.KindNetwork, id: "n1"},
		{name: "libpod network bare inspect", path: "/libpod/networks/n1", kind: dockerresource.KindLibpodNetwork, id: "n1"},
		{name: "libpod network exists oracle", path: "/libpod/networks/n1/exists", kind: dockerresource.KindLibpodNetwork, id: "n1"},
		{name: "compat secret inspect", path: "/secrets/s1", kind: dockerresource.KindSecret, id: "s1"},
		{name: "libpod secret exists oracle", path: "/libpod/secrets/s1/exists", kind: dockerresource.KindSecret, id: "s1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotKind dockerresource.Kind
			var gotIdentifier string
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
					gotKind, gotIdentifier = kind, id
					return map[string]string{"com.sockguard.visible": "false"}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("hidden-resource-payload"))
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "hidden-resource-payload") {
				t.Fatalf("body = %s, want the hidden resource's data absent", rec.Body.String())
			}
			if gotKind != tt.kind || gotIdentifier != tt.id {
				t.Fatalf("inspect = %s/%q, want %s/%q", gotKind, gotIdentifier, tt.kind, tt.id)
			}
		})
	}
}

func TestVisibilityLibpodContainerReadsApplyNamePatternPolicy(t *testing.T) {
	t.Parallel()
	paths := []string{
		"/libpod/containers/c1/json",
		"/libpod/containers/c1/logs",
		"/libpod/containers/c1/stats",
		"/libpod/containers/c1/top",
		"/libpod/containers/c1/changes",
		"/libpod/containers/c1/export",
		"/libpod/containers/c1/archive?path=/etc",
		"/libpod/containers/c1/exists",
		"/libpod/containers/c1/healthcheck",
	}
	tests := []struct {
		name       string
		opts       Options
		labels     map[string]string
		nameMeta   string
		wantStatus int
		wantReach  bool
	}{
		{
			name:       "patterns only denies nonmatching name",
			opts:       Options{NamePatterns: []string{"allowed-*"}},
			nameMeta:   "/hidden",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "patterns only allows matching name",
			opts:       Options{NamePatterns: []string{"allowed-*"}},
			nameMeta:   "/allowed-app",
			wantStatus: http.StatusNoContent,
			wantReach:  true,
		},
		{
			name: "matching selector does not override nonmatching name",
			opts: Options{
				VisibleResourceLabels: []string{"tenant=allowed"},
				NamePatterns:          []string{"allowed-*"},
			},
			labels:     map[string]string{"tenant": "allowed"},
			nameMeta:   "/hidden",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "matching name does not override nonmatching selector",
			opts: Options{
				VisibleResourceLabels: []string{"tenant=allowed"},
				NamePatterns:          []string{"allowed-*"},
			},
			labels:     map[string]string{"tenant": "hidden"},
			nameMeta:   "/allowed-app",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "matching selector and name are forwarded",
			opts: Options{
				VisibleResourceLabels: []string{"tenant=allowed"},
				NamePatterns:          []string{"allowed-*"},
			},
			labels:     map[string]string{"tenant": "allowed"},
			nameMeta:   "/allowed-app",
			wantStatus: http.StatusNoContent,
			wantReach:  true,
		},
	}

	for _, path := range paths {
		for _, tt := range tests {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				assertInspectTarget := func(kind dockerresource.Kind, id string) {
					t.Helper()
					if kind != dockerresource.KindContainer || id != "c1" {
						t.Fatalf("inspect = %s/%q, want %s/c1", kind, id, dockerresource.KindContainer)
					}
				}
				reached := false
				handler := middlewareWithDeps(testVisibilityLogger(), tt.opts, visibilityDeps{
					inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
						assertInspectTarget(kind, id)
						return tt.labels, true, nil
					},
					inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
						assertInspectTarget(kind, id)
						return &resourceMeta{names: []string{tt.nameMeta}}, true, nil
					},
					inspectResourceDetails: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceDetails, bool, error) {
						assertInspectTarget(kind, id)
						return &resourceDetails{
							labels: tt.labels,
							meta:   &resourceMeta{names: []string{tt.nameMeta}},
						}, true, nil
					},
				})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusNoContent)
				}))

				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

				if rec.Code != tt.wantStatus || reached != tt.wantReach {
					t.Fatalf("status = %d reached = %v, want %d and %v; body: %s", rec.Code, reached, tt.wantStatus, tt.wantReach, rec.Body.String())
				}
			})
		}
	}
}

// TestLibpodListRoutesAreNotSingleResourceIdentifiers guards the one hazard
// the broadened network matcher introduces: singleSegmentIdentifier was
// written for the Docker-compat API, where "json" is only ever a write-side
// collection keyword, so the bare /libpod/networks/{id} spelling has to
// exclude the list route by hand.
func TestLibpodListRoutesAreNotSingleResourceIdentifiers(t *testing.T) {
	t.Parallel()
	matchers := map[string]func(string) (string, bool){
		"libpodContainerReadIdentifier":  libpodContainerReadIdentifier,
		"libpodImageReadIdentifier":      libpodImageReadIdentifier,
		"libpodPodReadIdentifier":        libpodPodReadIdentifier,
		"libpodNetworkInspectIdentifier": libpodNetworkInspectIdentifier,
		"libpodVolumeInspectIdentifier":  libpodVolumeInspectIdentifier,
		"libpodSecretInspectIdentifier":  libpodSecretInspectIdentifier,
	}
	listRoutes := []string{
		"/libpod/containers/json",
		"/libpod/images/json",
		"/libpod/pods/json",
		"/libpod/pods/stats",
		"/libpod/networks/json",
		"/libpod/volumes/json",
		"/libpod/secrets/json",
	}
	for name, matcher := range matchers {
		for _, path := range listRoutes {
			if identifier, ok := matcher(path); ok {
				t.Fatalf("%s(%q) = %q, want no match on a collection route", name, path, identifier)
			}
		}
	}
}

// --- the ownership/visibility asymmetry itself -----------------------------

// TestLibpodEventsIsDeliberatelyAbsentFromTheLabelFilterSet is the test a
// future "fix the inconsistency" edit has to fail.
//
// GET /libpod/events is in ownership's libpodNeedsOwnerFilter and is NOT in
// this package's needsLibpodVisibilityLabelFilter, and that difference is
// load-bearing rather than drift. addOwnerLabelFilter REPLACES the `label`
// key with one value, and Podman evaluates several values under one event
// filter key disjunctively, so with exactly one value disjunctive and
// conjunctive evaluation coincide and the injection is sound.
// addVisibilityLabelFilters APPENDS, and a visibility policy may carry more
// than one selector, so the same injection here would return every event
// matching ANY selector plus anything the client named. Adding the path to
// the set below would silently restore that.
//
// ownership's own half of the pin is
// TestLibpodEventsIsOwnerFilteredByReplacement in internal/ownership.
func TestLibpodEventsIsDeliberatelyAbsentFromTheLabelFilterSet(t *testing.T) {
	t.Parallel()
	if needsLibpodVisibilityLabelFilter(LibpodEventsPath) {
		t.Fatalf("needsLibpodVisibilityLabelFilter(%q) = true; the append-style injection cannot express a multi-selector policy on Podman's disjunctive event filter — it is refused in libpod_events.go instead", LibpodEventsPath)
	}
	if needsVisibilityLabelFilter(LibpodEventsPath) {
		t.Fatalf("needsVisibilityLabelFilter(%q) = true, want false", LibpodEventsPath)
	}
	// The Docker-compat spelling stays in the set: dockerd ANDs label filter
	// values, so appending there narrows.
	if !needsVisibilityLabelFilter("/events") {
		t.Fatal(`needsVisibilityLabelFilter("/events") = false, want true`)
	}
}

// TestLibpodEventsRefusalCarriesItsReasonCode pins the audit trail, matching
// what TestLibpodSystemDataUsage* asserts for the other unscopeable libpod
// read: an operator greps the reason code to find requests this refusal cost
// them, so a refusal logged under a generic code is a refusal they cannot
// find.
func TestLibpodEventsRefusalCarriesItsReasonCode(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true", "com.sockguard.tier=web"},
	}, visibilityDeps{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("refused request reached the upstream event stream")
	}))

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v5.8.1/libpod/events", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if meta.ReasonCode != reasonCodeVisibilityLibpodEvents {
		t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityLibpodEvents)
	}
}

// TestLibpodEventsInertWithoutVisibilityPolicy proves the refusal costs
// nothing to a deployment that configured no visibility policy: there is no
// boundary to enforce, so the rule engine stays the only control. It also
// covers the version-prefixed spelling a Podman binding actually sends, which
// is the reason LibpodEventsPath is compared against the normalized path
// rather than r.URL.Path.
func TestLibpodEventsInertWithoutVisibilityPolicy(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if raw := r.URL.Query().Get("filters"); raw != `{"label":["role=db"]}` {
			t.Fatalf("forwarded filters = %q, want the client's own untouched", raw)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/v5.8.1/libpod/events?filters={"label":["role=db"]}`, nil))

	if !reached || rec.Code != http.StatusNoContent {
		t.Fatalf("reached = %v status = %d, want true and %d", reached, rec.Code, http.StatusNoContent)
	}
}

// --- unscopeable libpod reads ----------------------------------------------

// wantVisibilityUnscopeableReasonCodes pins the exact reason code this
// middleware logs for each entry in filter.LibpodUnscopeableReads(), written
// out rather than assembled from ReasonCodeStem for the reason
// wantOwnerUnscopeableReasonCodes is. The two maps differ only in the prefix,
// which is how an operator tells which layer refused the request.
var wantVisibilityUnscopeableReasonCodes = map[string]string{
	filter.LibpodShowMountedPath:    "visibility_libpod_show_mounted_unscopeable",
	filter.LibpodContainerStatsPath: "visibility_libpod_container_stats_unscopeable",
	filter.LibpodPodStatsPath:       "visibility_libpod_pod_stats_unscopeable",
}

// TestLibpodUnscopeableReadsAreRefusedUnderVisibilityPolicy covers every
// libpod read of the /libpod/system/df shape from this side. Neither policy
// axis has a field to read in any of them: no labels for the selectors, no
// name or image for the patterns, and no `filters` query parameter to attach
// anything to.
//
// Both policy shapes are covered for each, because a patterns-only policy is
// the one that would slip through a refusal written to key off selectors
// alone.
func TestLibpodUnscopeableReadsAreRefusedUnderVisibilityPolicy(t *testing.T) {
	t.Parallel()
	shapes := []struct {
		name          string
		opts          Options
		versionPrefix string
	}{
		{name: "selectors", opts: Options{VisibleResourceLabels: []string{"com.sockguard.visible=true"}}},
		{name: "patterns only", opts: Options{NamePatterns: []string{"web-*"}}},
		{name: "version prefixed", opts: Options{VisibleResourceLabels: []string{"com.sockguard.visible=true"}}, versionPrefix: "/v5.8.1"},
	}
	reads := filter.LibpodUnscopeableReads()
	// Checked both ways round, for the reason
	// TestLibpodUnscopeableReadsAreRefusedUnderOwnerIsolation is.
	if len(reads) != len(wantVisibilityUnscopeableReasonCodes) {
		t.Fatalf("filter.LibpodUnscopeableReads() has %d entries for %d expected reason codes; an endpoint was added or dropped without a decision here", len(reads), len(wantVisibilityUnscopeableReasonCodes))
	}
	for _, read := range reads {
		wantCode, ok := wantVisibilityUnscopeableReasonCodes[read.Path]
		if !ok {
			t.Fatalf("filter.LibpodUnscopeableReads() gained %q with no expected reason code; decide what this middleware logs for it", read.Path)
		}
		for _, shape := range shapes {
			t.Run(read.Path+"/"+shape.name, func(t *testing.T) {
				t.Parallel()
				handler := middlewareWithDeps(testVisibilityLogger(), shape.opts, visibilityDeps{})(
					http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
						t.Fatal("refused request reached the upstream")
					}))

				// Warn mode must not forward it, matching denyLibpodSystemDataUsage.
				meta := &logging.RequestMeta{RolloutMode: "warn"}
				req := httptest.NewRequest(http.MethodGet, shape.versionPrefix+read.Path, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
				}
				if meta.ReasonCode != wantCode {
					t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, wantCode)
				}
				if !strings.Contains(rec.Body.String(), read.Reason) {
					t.Fatalf("body = %s, want the deny reason %q", rec.Body.String(), read.Reason)
				}
			})
		}
	}
}

// TestLibpodUnscopeableReadsAreInertWithoutVisibilityPolicy proves the
// refusals cost nothing to a deployment with no visibility policy.
func TestLibpodUnscopeableReadsAreInertWithoutVisibilityPolicy(t *testing.T) {
	t.Parallel()
	for _, read := range filter.LibpodUnscopeableReads() {
		t.Run(read.Path, func(t *testing.T) {
			t.Parallel()
			const body = `{"c-1":"/var/lib/containers/storage/overlay/deadbeef/merged"}`
			reached := false
			handler := middlewareWithDeps(testVisibilityLogger(), Options{}, visibilityDeps{})(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					_, _ = w.Write([]byte(body))
				}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, read.Path, nil))

			if !reached || rec.Body.String() != body {
				t.Fatalf("reached = %v body = %s, want true and the upstream body untouched", reached, rec.Body.String())
			}
		})
	}
}

// TestLibpodUnscopeableReadsAreNotCoveredByAnyVisibilityIdentifier pins why
// each refusal has to be its own branch. Every libpod read identifier in this
// package needs an "/id/suffix" shape, and all three paths are a bare word
// after the prefix, so none of them matched: before the refusals the requests
// fell through to the default-visible tail of requestVisibleWithPolicy and
// were forwarded with the host inventory intact.
//
// This is the one real difference from the ownership side, where
// libpodContainerIdentifier does classify two of the three as containers.
func TestLibpodUnscopeableReadsAreNotCoveredByAnyVisibilityIdentifier(t *testing.T) {
	t.Parallel()
	identifiers := map[string]func(string) (string, bool){
		"libpodContainerReadIdentifier":  libpodContainerReadIdentifier,
		"libpodImageReadIdentifier":      libpodImageReadIdentifier,
		"libpodPodReadIdentifier":        libpodPodReadIdentifier,
		"libpodNetworkInspectIdentifier": libpodNetworkInspectIdentifier,
		"libpodVolumeInspectIdentifier":  libpodVolumeInspectIdentifier,
		"libpodSecretInspectIdentifier":  libpodSecretInspectIdentifier,
	}
	for _, read := range filter.LibpodUnscopeableReads() {
		t.Run(read.Path, func(t *testing.T) {
			t.Parallel()
			for name, classify := range identifiers {
				if identifier, ok := classify(read.Path); ok {
					t.Fatalf("%s(%q) = %q, want no match", name, read.Path, identifier)
				}
			}
			if needsVisibilityLabelFilter(read.Path) {
				t.Fatalf("needsVisibilityLabelFilter(%q) = true; the endpoint accepts no filters query parameter", read.Path)
			}
			if needsLibpodVisibilityLabelFilter(read.Path) {
				t.Fatalf("needsLibpodVisibilityLabelFilter(%q) = true; the endpoint accepts no filters query parameter", read.Path)
			}
		})
	}
}
