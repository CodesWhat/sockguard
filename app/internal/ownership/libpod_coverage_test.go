package ownership

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestLibpodImageScpOwnershipMatrix(t *testing.T) {
	t.Parallel()
	states := []struct {
		name           string
		source         string
		wantIdentifier string
		labels         map[string]string
		found          bool
		remote         bool
	}{
		{name: "owned", source: "registry.io/team/json", wantIdentifier: "registry.io/team/json", labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
		{name: "localhost user owned", source: "alice@localhost::registry.io/team/json", wantIdentifier: "registry.io/team/json", labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
		{name: "foreign", source: "registry.io/team/json", wantIdentifier: "registry.io/team/json", labels: map[string]string{"com.sockguard.owner": "other-job"}, found: true},
		{name: "localhost user foreign", source: "alice@localhost::registry.io/team/json", wantIdentifier: "registry.io/team/json", labels: map[string]string{"com.sockguard.owner": "other-job"}, found: true},
		{name: "unowned", source: "registry.io/team/json", wantIdentifier: "registry.io/team/json", labels: map[string]string{}, found: true},
		{name: "localhost user unowned", source: "alice@localhost::registry.io/team/json", wantIdentifier: "registry.io/team/json", labels: map[string]string{}, found: true},
		{name: "not found", source: "registry.io/team/json", wantIdentifier: "registry.io/team/json"},
		{name: "localhost user not found", source: "alice@localhost::registry.io/team/json", wantIdentifier: "registry.io/team/json"},
		{name: "remote", source: "builder::registry.io/team/json", remote: true},
	}
	versions := []struct {
		name   string
		prefix string
	}{
		{name: "unversioned"},
		{name: "versioned", prefix: "/v5.8.1"},
	}

	for _, state := range states {
		for _, allowUnowned := range []bool{false, true} {
			for _, version := range versions {
				for _, rolloutMode := range []string{"enforce", "warn", "audit"} {
					name := state.name + "/allow_unowned=" + strconv.FormatBool(allowUnowned) + "/" + version.name + "/" + rolloutMode
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						inspectCalls := 0
						upstreamCalls := 0
						handler := middlewareWithDeps(
							testLogger(),
							Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: allowUnowned},
							func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
								inspectCalls++
								if kind != dockerresource.KindImage || identifier != state.wantIdentifier {
									t.Fatalf("inspect = %s/%q, want %s/%q", kind, identifier, dockerresource.KindImage, state.wantIdentifier)
								}
								return state.labels, state.found, nil
							},
							fakeInspector{}.inspectExec,
						)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							upstreamCalls++
							w.WriteHeader(http.StatusNoContent)
						}))

						meta := &logging.RequestMeta{RolloutMode: rolloutMode}
						req := httptest.NewRequest(http.MethodPost, version.prefix+"/libpod/images/scp/"+state.source, nil)
						req = req.WithContext(logging.WithMeta(req.Context(), meta))
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, req)

						wantDenied := state.remote || state.found && state.labels["com.sockguard.owner"] != "job-123" && (!allowUnowned || len(state.labels) > 0)
						wantForwarded := !wantDenied || rolloutMode != "enforce"
						wantStatus := http.StatusForbidden
						if wantForwarded {
							wantStatus = http.StatusNoContent
						}
						wantUpstreamCalls := 0
						if wantForwarded {
							wantUpstreamCalls = 1
						}
						if rec.Code != wantStatus || upstreamCalls != wantUpstreamCalls {
							t.Fatalf("status = %d upstream calls = %d, want %d and %d; body: %s", rec.Code, upstreamCalls, wantStatus, wantUpstreamCalls, rec.Body.String())
						}
						wantInspectCalls := 1
						if state.remote {
							wantInspectCalls = 0
						}
						if inspectCalls != wantInspectCalls {
							t.Fatalf("local image inspect calls = %d, want %d", inspectCalls, wantInspectCalls)
						}
						if !wantDenied {
							if meta.Decision != "" || meta.ReasonCode != "" || meta.Reason != "" {
								t.Fatalf("allowed meta = decision %q code %q reason %q, want no ownership denial", meta.Decision, meta.ReasonCode, meta.Reason)
							}
							return
						}
						wantDecision := logging.DecisionDeny
						if rolloutMode != "enforce" {
							wantDecision = logging.DecisionWouldDeny
						}
						if meta.Decision != wantDecision || meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
							t.Fatalf("meta = decision %q code %q, want %q and %q", meta.Decision, meta.ReasonCode, wantDecision, reasonCodeOwnerPolicyDeniedAccess)
						}
						wantReason := "libpod owner policy denied access to image"
						if state.remote {
							wantReason = "libpod owner policy denied access to remote image source"
						}
						if meta.Reason != wantReason {
							t.Fatalf("meta reason = %q, want %q", meta.Reason, wantReason)
						}
					})
				}
			}
		}
	}
}

func TestLibpodImageScpOwnershipIsInertWithoutOwner(t *testing.T) {
	t.Parallel()
	for _, source := range []string{"registry.io/team/json", "builder::registry.io/team/json", "alice@localhost::registry.io/team/json"} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			upstreamCalls := 0
			handler := middlewareWithDeps(testLogger(), Options{}, func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				t.Fatal("ownership-disabled request performed an image inspect")
				return nil, false, nil
			}, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls++
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/images/scp/"+source, nil))

			if rec.Code != http.StatusNoContent || upstreamCalls != 1 {
				t.Fatalf("status = %d upstream calls = %d, want %d and 1", rec.Code, upstreamCalls, http.StatusNoContent)
			}
		})
	}
}

func TestLibpodImageScpPreservesPostActionRouteCollisions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		path           string
		wantIdentifier string
	}{
		{name: "push with no extra segment", path: "/libpod/images/scp/push", wantIdentifier: "scp"},
		{name: "tag with no extra segment", path: "/libpod/images/scp/tag", wantIdentifier: "scp"},
		{name: "untag with no extra segment", path: "/libpod/images/scp/untag", wantIdentifier: "scp"},
		{name: "nested push", path: "/libpod/images/scp/builder::app/push", wantIdentifier: "scp/builder::app"},
		{name: "nested tag", path: "/libpod/images/scp/builder::app/tag", wantIdentifier: "scp/builder::app"},
		{name: "nested untag", path: "/libpod/images/scp/builder::app/untag", wantIdentifier: "scp/builder::app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotIdentifier string
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
				if kind != dockerresource.KindImage {
					t.Fatalf("inspect kind = %s, want %s", kind, dockerresource.KindImage)
				}
				gotIdentifier = identifier
				return map[string]string{"com.sockguard.owner": "job-123"}, true, nil
			}, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tt.path, nil))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			if gotIdentifier != tt.wantIdentifier {
				t.Fatalf("inspect identifier = %q, want %q", gotIdentifier, tt.wantIdentifier)
			}
		})
	}
}

func TestLibpodImageScpUsesPodmansEncodedRouteShape(t *testing.T) {
	t.Parallel()
	t.Run("encoded slash remains part of the local SCP source", func(t *testing.T) {
		t.Parallel()
		var gotIdentifier string
		handler := middlewareWithDeps(
			testLogger(),
			Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
			func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
				if kind != dockerresource.KindImage {
					t.Fatalf("inspect kind = %s, want %s", kind, dockerresource.KindImage)
				}
				gotIdentifier = identifier
				return map[string]string{"com.sockguard.owner": "other-job"}, true, nil
			},
			fakeInspector{}.inspectExec,
		)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("foreign encoded-slash SCP source reached upstream")
		}))

		req := httptest.NewRequest(http.MethodPost, "/libpod/images/scp/foreign%2Fpush", nil)
		if req.URL.Path != "/libpod/images/scp/foreign/push" || req.URL.RawPath != "/libpod/images/scp/foreign%2Fpush" {
			t.Fatalf("request path = %q raw path = %q, want decoded and encoded route views", req.URL.Path, req.URL.RawPath)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if gotIdentifier != "foreign/push" {
			t.Fatalf("inspect identifier = %q, want %q", gotIdentifier, "foreign/push")
		}
	})

	t.Run("encoded slash cannot disguise a true remote source", func(t *testing.T) {
		t.Parallel()
		handler := middlewareWithDeps(
			testLogger(),
			Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
			func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				t.Fatal("true remote encoded-slash SCP source performed a local inspect")
				return nil, false, nil
			},
			fakeInspector{}.inspectExec,
		)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("true remote encoded-slash SCP source reached upstream")
		}))

		req := httptest.NewRequest(http.MethodPost, "/libpod/images/scp/builder::foreign%2Fpush", nil)
		if req.URL.Path != "/libpod/images/scp/builder::foreign/push" || req.URL.RawPath != "/libpod/images/scp/builder::foreign%2Fpush" {
			t.Fatalf("request path = %q raw path = %q, want decoded and encoded route views", req.URL.Path, req.URL.RawPath)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "remote image source") {
			t.Fatalf("body = %q, want remote-source denial", rec.Body.String())
		}
	})
}

func TestPodmanVersionGrammarCannotBypassOwnerIsolationBehindCatchall(t *testing.T) {
	t.Parallel()
	allowAll, err := filter.CompileRule(filter.Rule{Methods: []string{"*"}, Pattern: "/**", Action: filter.ActionAllow})
	if err != nil {
		t.Fatalf("compile catch-all allow rule: %v", err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		inspect    bool
		identifier string
	}{
		{name: "prerelease manifest inspect", method: http.MethodGet, path: "/v5.8.1-dev/libpod/manifests/app/json"},
		{name: "four-component manifest exists", method: http.MethodGet, path: "/v5.8.1.2/libpod/manifests/app/exists"},
		{name: "prerelease SCP", method: http.MethodPost, path: "/v5.8.1-dev/libpod/images/scp/app", inspect: true, identifier: "app"},
		{name: "four-component SCP", method: http.MethodPost, path: "/v5.8.1.2/libpod/images/scp/app", inspect: true, identifier: "app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inspectCalls := 0
			ownerHandler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
					inspectCalls++
					if !tt.inspect || kind != dockerresource.KindImage || identifier != tt.identifier {
						t.Fatalf("inspect = %s/%q, want image/%q", kind, identifier, tt.identifier)
					}
					return map[string]string{"com.sockguard.owner": "other-job"}, true, nil
				},
				fakeInspector{}.inspectExec,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("Podman-versioned isolation target reached upstream")
			}))
			handler := filter.MiddlewareWithOptions([]*filter.CompiledRule{allowAll}, testLogger(), filter.Options{})(ownerHandler)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			wantInspectCalls := 0
			if tt.inspect {
				wantInspectCalls = 1
			}
			if inspectCalls != wantInspectCalls {
				t.Fatalf("inspect calls = %d, want %d", inspectCalls, wantInspectCalls)
			}
		})
	}
}

func TestLibpodImageScpMalformedLocalSourceIsDenied(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(
		testLogger(),
		Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
		func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
			t.Fatal("malformed local image source performed an image inspect")
			return nil, false, nil
		},
		fakeInspector{}.inspectExec,
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("malformed local image source reached upstream")
	}))

	meta := &logging.RequestMeta{RolloutMode: "enforce"}
	req := httptest.NewRequest(http.MethodPost, "/libpod/images/scp/alice@localhost::", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "could not resolve local image source") {
		t.Fatalf("body = %q, want local-source resolution denial", rec.Body.String())
	}
	if meta.Decision != logging.DecisionDeny || meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
		t.Fatalf("meta = decision %q code %q, want %q and %q", meta.Decision, meta.ReasonCode, logging.DecisionDeny, reasonCodeOwnerPolicyDeniedAccess)
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
		{name: "scp source ending in json", method: http.MethodPost, path: "/libpod/images/scp/registry.io/team/json", want: "registry.io/team/json", wantOK: true},
		{name: "scp source ending in history", method: http.MethodPost, path: "/libpod/images/scp/registry.io/team/history", want: "registry.io/team/history", wantOK: true},
		{name: "scp source ending in exists", method: http.MethodPost, path: "/libpod/images/scp/registry.io/team/exists", want: "registry.io/team/exists", wantOK: true},
		{name: "scp remote source is not a local identifier", method: http.MethodPost, path: "/libpod/images/scp/builder::registry.io/team/json"},
		{name: "scp localhost user source extracts image", method: http.MethodPost, path: "/libpod/images/scp/alice@localhost::registry.io/team/json", want: "registry.io/team/json", wantOK: true},
		{name: "scp malformed localhost user source is not a local identifier", method: http.MethodPost, path: "/libpod/images/scp/alice@localhost::"},
		{name: "post does not trim a get-only suffix", method: http.MethodPost, path: "/libpod/images/app/json", want: "app/json", wantOK: true},
		{name: "get does not trim a post-only suffix", method: http.MethodGet, path: "/libpod/images/app/push", want: "app/push", wantOK: true},
		// gorilla/mux resolves the per-image action routes first because
		// Podman registers them earlier, so this is an image named "scp/app"
		// being pushed, not an scp of "app".
		{name: "image named scp/app pushed", method: http.MethodPost, path: "/libpod/images/scp/app/push", want: "scp/app", wantOK: true},
		{name: "image named scp/app tagged", method: http.MethodPost, path: "/libpod/images/scp/app/tag", want: "scp/app", wantOK: true},
		{name: "image named scp/app untagged", method: http.MethodPost, path: "/libpod/images/scp/app/untag", want: "scp/app", wantOK: true},
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
	filter.LibpodManifestExistsPath: "owner_libpod_manifest_exists_unscopeable",
	filter.LibpodManifestJSONPath:   "owner_libpod_manifest_json_unscopeable",
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

// TestLibpodUnscopeableContainerReadsDenyBeforeInspect pins the ordering of
// the refusal relative to ordinary per-container ownership checks. The two
// collection paths happen to look like containers named "stats" and
// "showmounted" to libpodContainerIdentifier. No daemon state for either
// name may affect the refusal, and warn/audit rollout must not turn a foreign
// container verdict into pass-through before the collection denial runs.
func TestLibpodUnscopeableContainerReadsDenyBeforeInspect(t *testing.T) {
	t.Parallel()

	states := []struct {
		name   string
		labels map[string]string
		found  bool
		err    error
	}{
		{name: "not found"},
		{name: "owned", labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
		{name: "foreign", labels: map[string]string{"com.sockguard.owner": "other-job"}, found: true},
		{name: "unowned", labels: map[string]string{}, found: true},
		{name: "inspect error", err: errors.New("inspect failed")},
	}
	paths := []string{filter.LibpodShowMountedPath, filter.LibpodContainerStatsPath}
	rolloutModes := []string{"enforce", "warn", "audit"}

	for _, path := range paths {
		for _, state := range states {
			for _, rolloutMode := range rolloutModes {
				t.Run(path+"/"+state.name+"/"+rolloutMode, func(t *testing.T) {
					t.Parallel()
					inspectCalls := 0
					upstreamCalls := 0
					inspectResource := func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
						inspectCalls++
						return state.labels, state.found, state.err
					}
					handler := middlewareWithDeps(
						testLogger(),
						Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
						inspectResource,
						fakeInspector{}.inspectExec,
					)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
						upstreamCalls++
					}))

					meta := &logging.RequestMeta{RolloutMode: rolloutMode}
					req := httptest.NewRequest(http.MethodGet, path, nil)
					req = req.WithContext(logging.WithMeta(req.Context(), meta))
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)

					if rec.Code != http.StatusForbidden {
						t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
					}
					if inspectCalls != 0 {
						t.Fatalf("inspect calls = %d, want 0", inspectCalls)
					}
					if upstreamCalls != 0 {
						t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
					}
					if meta.ReasonCode != wantOwnerUnscopeableReasonCodes[path] {
						t.Fatalf("reason code = %q, want %q", meta.ReasonCode, wantOwnerUnscopeableReasonCodes[path])
					}
				})
			}
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
// The manifest reads likewise have no ownership identifier: manifest-list
// responses carry no owner labels, and the image identifier only covers the
// distinct /libpod/images route family.
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
		{path: filter.LibpodManifestExistsPath, classify: libpodImageIdentifier, wantIdentifier: "", wantOK: false},
		{path: filter.LibpodManifestJSONPath, classify: libpodImageIdentifier, wantIdentifier: "", wantOK: false},
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
