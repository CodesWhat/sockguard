package ownership

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// libpod_coverage_test.go covers the libpod paths this package's own
// hand-maintained lists had drifted away from: GET /libpod/events and
// GET /libpod/images/json were in neither libpodNeedsOwnerFilter nor any
// identifier, so an owner-isolated client got the whole host's event stream
// and image list back by switching from the Docker-compat spelling to the
// libpod one, and every per-image libpod action ran with no ownership check
// at all.
//
// Every test here carries a Docker-compat leg over the same fixture, so a
// change that stopped the middleware from touching ANY request would fail the
// compat leg too rather than leaving these passing vacuously.

// forwardedLabelFiltersForTest returns the `label` values in a forwarded
// request's `filters` parameter, decoded the way dockerd's filters.FromJSON
// and Podman's util.FiltersFromRequest both decode it.
func forwardedLabelFiltersForTest(t *testing.T, r *http.Request) []string {
	t.Helper()
	raw := r.URL.Query().Get("filters")
	decoded, err := dockerfilters.Decode(raw)
	if err != nil {
		t.Fatalf("forwarded filters %q did not decode: %v", raw, err)
	}
	return decoded["label"]
}

// TestLibpodEventsIsOwnerFilteredByReplacement is this package's half of the
// ownership/visibility asymmetry pin. GET /libpod/events belongs in
// libpodNeedsOwnerFilter and GET /libpod/events is deliberately NOT in
// visibility's needsLibpodVisibilityLabelFilter, and the difference is
// load-bearing rather than drift: addOwnerLabelFilter REPLACES the `label`
// key with exactly one value, and Podman evaluates several values under one
// event filter key disjunctively (libpod/events/filters.go's applyFilters:
// "Filters under the same key are disjunctive while each key must match"), so
// with one value disjunctive and conjunctive evaluation coincide. Visibility
// appends and may hold several selectors, so it refuses the endpoint instead.
//
// visibility's half of the pin is
// TestLibpodEventsIsDeliberatelyAbsentFromTheLabelFilterSet.
func TestLibpodEventsIsOwnerFilteredByReplacement(t *testing.T) {
	t.Parallel()
	if !libpodNeedsOwnerFilter(libpodPrefix + "events") {
		t.Fatalf("libpodNeedsOwnerFilter(%q) = false; without it an owner-isolated client reads every tenant's event stream through the libpod spelling", libpodPrefix+"events")
	}
	tests := []struct {
		name string
		path string
	}{
		{name: "compat events", path: `/events?filters={"label":["com.sockguard.owner=other-job"]}`},
		{name: "libpod events", path: `/libpod/events?filters={"label":["com.sockguard.owner=other-job"]}`},
		{name: "libpod events version prefixed", path: `/v5.8.1/libpod/events?filters={"label":["com.sockguard.owner=other-job"]}`},
		{name: "libpod events legacy-shape client filter", path: `/libpod/events?filters={"label":{"com.sockguard.owner=other-job":true}}`},
		{name: "libpod events no client filter", path: "/libpod/events"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got []string
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					got = forwardedLabelFiltersForTest(t, r)
					w.WriteHeader(http.StatusNoContent)
				}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			want := []string{"com.sockguard.owner=job-123"}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("forwarded label filters = %v, want %v (the client's own owner value must not survive beside the injected one — Podman ORs them)", got, want)
			}
		})
	}
}

// TestLibpodImageListIsOwnerFiltered covers the list half of the images gap.
// The shipped podman-readonly.yaml preset allows GET /libpod/images/json
// unmodified, so before this the preset plus owner isolation handed a client
// every image on the host.
func TestLibpodImageListIsOwnerFiltered(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/images/json", "/libpod/images/json"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			var got []string
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					got = forwardedLabelFiltersForTest(t, r)
					w.WriteHeader(http.StatusNoContent)
				}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			if strings.Join(got, ",") != "com.sockguard.owner=job-123" {
				t.Fatalf("forwarded label filters = %v, want the owner label injected", got)
			}
		})
	}
}

// TestLibpodImageActionsAreOwnerChecked covers the per-image half: no libpod
// image identifier existed in allowPathOwnershipRequest at all, so every
// libpod image read, export, push, tag and delete passed through with no
// ownership check while its Docker-compat spelling was denied.
func TestLibpodImageActionsAreOwnerChecked(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "compat inspect", method: http.MethodGet, path: "/images/app/json"},
		{name: "libpod inspect", method: http.MethodGet, path: "/libpod/images/app/json"},
		{name: "libpod history", method: http.MethodGet, path: "/libpod/images/app/history"},
		{name: "libpod export", method: http.MethodGet, path: "/libpod/images/app/get"},
		{name: "libpod layer tree", method: http.MethodGet, path: "/libpod/images/app/tree"},
		{name: "libpod exists oracle", method: http.MethodGet, path: "/libpod/images/app/exists"},
		{name: "libpod push", method: http.MethodPost, path: "/libpod/images/app/push"},
		{name: "libpod scp to another host", method: http.MethodPost, path: "/libpod/images/scp/app"},
		{name: "libpod tag", method: http.MethodPost, path: "/libpod/images/app/tag"},
		{name: "libpod untag", method: http.MethodPost, path: "/libpod/images/app/untag"},
		{name: "libpod delete", method: http.MethodDelete, path: "/libpod/images/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"app": {labels: map[string]string{"com.sockguard.owner": "other-job"}, found: true},
				},
			}}
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatalf("%s %s reached the upstream for another owner's image", tt.method, tt.path)
				}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			wantPrefix := strings.HasPrefix(tt.path, libpodPrefix)
			if got := strings.Contains(rec.Body.String(), "libpod owner policy denied"); got != wantPrefix {
				t.Fatalf("body = %s, want libpod deny-reason prefix = %v", rec.Body.String(), wantPrefix)
			}
		})
	}
}

// TestLibpodImageIdentifier pins the classification itself, which the
// end-to-end tests above cannot: a collection route misread as an image named
// after its keyword costs an upstream inspect per request and, once an image
// really is called "json", denies the list route outright.
func TestLibpodImageIdentifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		path   string
		want   string
		wantOK bool
	}{
		// Collection routes, reserved for the method Podman routes them on.
		{name: "list", method: http.MethodGet, path: "/libpod/images/json"},
		{name: "search", method: http.MethodGet, path: "/libpod/images/search"},
		{name: "batch export", method: http.MethodGet, path: "/libpod/images/export"},
		{name: "load", method: http.MethodPost, path: "/libpod/images/load"},
		{name: "import", method: http.MethodPost, path: "/libpod/images/import"},
		{name: "pull", method: http.MethodPost, path: "/libpod/images/pull"},
		{name: "prune", method: http.MethodPost, path: "/libpod/images/prune"},
		{name: "batch remove", method: http.MethodDelete, path: "/libpod/images/remove"},
		// The reservation is per-method: an image really named "json" is
		// still a resource on any method that does not route the collection.
		{name: "image named json on delete", method: http.MethodDelete, path: "/libpod/images/json", want: "json", wantOK: true},
		{name: "image named prune on delete", method: http.MethodDelete, path: "/libpod/images/prune", want: "prune", wantOK: true},
		{name: "image named remove on get", method: http.MethodGet, path: "/libpod/images/remove/json", want: "remove", wantOK: true},
		// Per-image actions.
		{name: "inspect", method: http.MethodGet, path: "/libpod/images/app/json", want: "app", wantOK: true},
		{name: "resolve", method: http.MethodGet, path: "/libpod/images/app/resolve", want: "app", wantOK: true},
		{name: "changes", method: http.MethodGet, path: "/libpod/images/app/changes", want: "app", wantOK: true},
		{name: "bare delete", method: http.MethodDelete, path: "/libpod/images/app", want: "app", wantOK: true},
		// Podman routes these with {name:.*}, so a namespaced reference has
		// to survive the trim intact.
		{name: "namespaced inspect", method: http.MethodGet, path: "/libpod/images/registry.io/team/app/json", want: "registry.io/team/app", wantOK: true},
		{name: "namespaced delete", method: http.MethodDelete, path: "/libpod/images/registry.io/team/app", want: "registry.io/team/app", wantOK: true},
		// scp names its image after a route segment rather than in the query
		// string, so the segment is stripped and the reference checked.
		{name: "scp", method: http.MethodPost, path: "/libpod/images/scp/app", want: "app", wantOK: true},
		{name: "scp namespaced", method: http.MethodPost, path: "/libpod/images/scp/registry.io/team/app", want: "registry.io/team/app", wantOK: true},
		// gorilla/mux resolves the per-image action routes first because
		// Podman registers them earlier, so this is an image named "scp/app"
		// being pushed, not an scp of "app".
		{name: "image named scp/app pushed", method: http.MethodPost, path: "/libpod/images/scp/app/push", want: "scp/app", wantOK: true},
		{name: "scp on a method that does not route it", method: http.MethodDelete, path: "/libpod/images/scp/app", want: "scp/app", wantOK: true},
		// Docker-compat paths must never satisfy a libpod matcher.
		{name: "compat inspect", method: http.MethodGet, path: "/images/app/json"},
		{name: "compat list", method: http.MethodGet, path: "/images/json"},
		{name: "empty remainder", method: http.MethodGet, path: "/libpod/images/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := libpodImageIdentifier(tt.method, tt.path)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("libpodImageIdentifier(%q, %q) = %q, %v; want %q, %v", tt.method, tt.path, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestLibpodImageChecksHonorAllowUnownedImages holds the libpod image path at
// the Docker-compat one's behavior for the one option that changes it. Images
// are the single resource kind whose ownership check has an opt-out, because
// a base image pulled outside sockguard carries no owner label; a libpod
// spelling that ignored the option would deny what its compat twin allows,
// and one that ignored the check entirely would allow what it denies.
func TestLibpodImageChecksHonorAllowUnownedImages(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/images/app/json", "/libpod/images/app/json"} {
		for _, allowUnowned := range []bool{true, false} {
			name := path + "/deny-unowned"
			wantStatus := http.StatusForbidden
			if allowUnowned {
				name = path + "/allow-unowned"
				wantStatus = http.StatusNoContent
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				fi := fakeInspector{resources: map[string]map[string]inspectResult{
					string(dockerresource.KindImage): {
						"app": {labels: map[string]string{}, found: true},
					},
				}}
				opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: allowUnowned}
				reached := false
				handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						reached = true
						w.WriteHeader(http.StatusNoContent)
					}))

				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

				if rec.Code != wantStatus || reached != allowUnowned {
					t.Fatalf("reached = %v status = %d, want %v and %d; body: %s", reached, rec.Code, allowUnowned, wantStatus, rec.Body.String())
				}
			})
		}
	}
}

// --- unscopeable libpod reads ----------------------------------------------

// wantOwnerUnscopeableReasonCodes pins the exact reason code this middleware
// logs for each entry in filter.LibpodUnscopeableReads(). It is written out
// rather than assembled from ReasonCodeStem so the assembled wire string is
// asserted literally: an operator greps the access log for these, and a stem
// rename that quietly changes them fails here. A new entry with no line in
// this map fails too, which is the point — the code is a decision, not a
// derivation.
var wantOwnerUnscopeableReasonCodes = map[string]string{
	filter.LibpodShowMountedPath:    "owner_libpod_show_mounted_unscopeable",
	filter.LibpodContainerStatsPath: "owner_libpod_container_stats_unscopeable",
	filter.LibpodPodStatsPath:       "owner_libpod_pod_stats_unscopeable",
}

// TestLibpodUnscopeableReadsAreRefusedUnderOwnerIsolation covers every libpod
// read of the /libpod/system/df shape: a body that enumerates the host, no
// label or owner field on any entry to filter it by, and no `filters` query
// parameter for addOwnerLabelFilter to attach to. Each entry's doc comment in
// internal/filter carries the Podman v5.8.1 evidence for its own shape.
//
// The version-prefixed leg matters more here than elsewhere: Podman registers
// only the VersionedPath spelling of all three routes, so /v5.8.1/... is the
// only spelling a real Podman binding ever sends.
func TestLibpodUnscopeableReadsAreRefusedUnderOwnerIsolation(t *testing.T) {
	t.Parallel()
	reads := filter.LibpodUnscopeableReads()
	// Checked both ways round. The table drives the cases, so an entry
	// deleted from filter.LibpodUnscopeableReads() would otherwise silently
	// stop being tested here rather than fail.
	if len(reads) != len(wantOwnerUnscopeableReasonCodes) {
		t.Fatalf("filter.LibpodUnscopeableReads() has %d entries for %d expected reason codes; an endpoint was added or dropped without a decision here", len(reads), len(wantOwnerUnscopeableReasonCodes))
	}
	for _, read := range reads {
		wantCode, ok := wantOwnerUnscopeableReasonCodes[read.Path]
		if !ok {
			t.Fatalf("filter.LibpodUnscopeableReads() gained %q with no expected reason code; decide what this middleware logs for it", read.Path)
		}
		for _, path := range []string{read.Path, "/v5.8.1" + read.Path} {
			t.Run(path, func(t *testing.T) {
				t.Parallel()
				opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
				handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(
					http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
						t.Fatal("refused request reached the upstream")
					}))

				// Warn mode must not forward it: response-side isolation is
				// not a verdict an operator stages, and a forwarded host
				// inventory is not something they can measure the impact of
				// afterwards.
				meta := &logging.RequestMeta{RolloutMode: "warn"}
				req := httptest.NewRequest(http.MethodGet, path, nil)
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

// TestLibpodUnscopeableReadsAreInertWithoutOwner proves the refusals cost
// nothing to a deployment that configured no owner: there is no boundary to
// enforce, so the rule engine stays the only control.
func TestLibpodUnscopeableReadsAreInertWithoutOwner(t *testing.T) {
	t.Parallel()
	for _, read := range filter.LibpodUnscopeableReads() {
		t.Run(read.Path, func(t *testing.T) {
			t.Parallel()
			const body = `{"c-1":"/var/lib/containers/storage/overlay/deadbeef/merged"}`
			reached := false
			handler := middlewareWithDeps(testLogger(), Options{}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(
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

// TestLibpodUnscopeableReadsWereNotCoveredByTheExistingIdentifiers pins why
// each refusal has to be its own branch rather than falling out of the path
// classifiers, and the two failure modes differ.
//
// The identifier helpers deliberately reserve all three collection paths, so
// they reach the upstream without any resource ownership check running. The
// refusal branch remains necessary to keep their host-wide data unavailable.
func TestLibpodUnscopeableReadsWereNotCoveredByTheExistingIdentifiers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path           string
		classify       func(method, normPath string) (string, bool)
		wantIdentifier string
		wantOK         bool
	}{
		{path: filter.LibpodShowMountedPath, classify: libpodContainerIdentifier, wantIdentifier: "", wantOK: false},
		{path: filter.LibpodContainerStatsPath, classify: libpodContainerIdentifier, wantIdentifier: "", wantOK: false},
		{path: filter.LibpodPodStatsPath, classify: libpodPodIdentifier, wantIdentifier: "", wantOK: false},
	}
	if len(tests) != len(filter.LibpodUnscopeableReads()) {
		t.Fatalf("%d cases for %d unscopeable reads; a new one needs its own answer here", len(tests), len(filter.LibpodUnscopeableReads()))
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			identifier, ok := tt.classify(http.MethodGet, tt.path)
			if ok != tt.wantOK || identifier != tt.wantIdentifier {
				t.Fatalf("classify(GET, %q) = %q, %v; want %q, %v — if this changes, the refusal branch is the only thing covering the endpoint", tt.path, identifier, ok, tt.wantIdentifier, tt.wantOK)
			}
			if libpodNeedsOwnerFilter(tt.path) {
				t.Fatalf("libpodNeedsOwnerFilter(%q) = true; the endpoint accepts no filters query parameter", tt.path)
			}
		})
	}
}

// TestLibpodContainerStatsIsRefusedEvenWhenTheCallerOwnsAContainerNamedStats
// is the sharp edge of the previous test. Relying on the not-found inspect to
// deny GET /libpod/containers/stats would hand the caller the key: create a
// container named "stats", which they own and are entitled to, and the
// identifier check starts PASSING — the request is forwarded and Podman serves
// live usage for every running container on the host, because gorilla/mux
// routes /libpod/containers/stats to the collection handler regardless of what
// containers exist.
//
// The second leg is the control: the same fixture on /libpod/containers/stats/json
// is a genuine inspect of that container and stays allowed, so the refusal is
// scoped to the collection path rather than banning the name.
func TestLibpodContainerStatsIsRefusedEvenWhenTheCallerOwnsAContainerNamedStats(t *testing.T) {
	t.Parallel()
	inspector := fakeInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindContainer): {
			"stats": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
		},
	}}
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}

	t.Run("collection path is refused", func(t *testing.T) {
		t.Parallel()
		handler := middlewareWithDeps(testLogger(), opts, inspector.inspectResource, inspector.inspectExec)(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("refused request reached the upstream")
			}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, filter.LibpodContainerStatsPath, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "libpod container stats denied") {
			t.Fatalf("body = %s, want the container-stats deny reason", rec.Body.String())
		}
	})

	t.Run("owned container named stats is still inspectable", func(t *testing.T) {
		t.Parallel()
		reached := false
		handler := middlewareWithDeps(testLogger(), opts, inspector.inspectResource, inspector.inspectExec)(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/containers/stats/json", nil))
		if !reached || rec.Code != http.StatusOK {
			t.Fatalf("reached = %v status = %d, want true and %d; body: %s", reached, rec.Code, http.StatusOK, rec.Body.String())
		}
	})
}
