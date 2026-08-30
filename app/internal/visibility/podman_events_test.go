package visibility

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// podman_events_test.go covers the Docker-compat GET /events on a Podman
// upstream.
//
// The endpoint is not filtered by sockguard: sockguard rewrites the `filters`
// query and the daemon does the work. So proving an event is actually absent
// from the client's response needs an upstream that applies the filter the way
// the real daemon does — including the difference in how the two engines
// evaluate several values under one key, which is the entire reason this file
// exists.

func podmanEventsTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// eventLabelFilterValues returns the `label` values in a forwarded request's
// `filters` parameter, decoded the way dockerd's filters.FromJSON and Podman's
// util.FiltersFromRequest both decode it.
func eventLabelFilterValues(t *testing.T, r *http.Request) []string {
	t.Helper()
	raw := r.URL.Query().Get("filters")
	decoded, err := dockerfilters.Decode(raw)
	if err != nil {
		t.Fatalf("forwarded filters %q did not decode: %v", raw, err)
	}
	return decoded["label"]
}

type eventForTest struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

// eventSelectorMatches reports whether one "key" or "key=value" filter value
// matches an event's attributes.
func eventSelectorMatches(labels map[string]string, value string) bool {
	key, want, hasValue := strings.Cut(value, "=")
	got, ok := labels[key]
	if !ok {
		return false
	}
	return !hasValue || got == want
}

// podmanEventsUpstream is Podman's event endpoint: one NDJSON record per event
// whose attributes satisfy AT LEAST ONE forwarded `label` value.
// libpod/events/filters.go's applyFilters returns a match as soon as one
// filter under a key succeeds, over the comment "Filters under the same key
// are disjunctive while each key must match (conjuctive)". /events and
// /libpod/events are one handler (compat.GetEvents, registered on both paths
// in pkg/api/server/register_events.go at v5.8.1), so this is also what a
// Podman upstream does with the Docker-compat spelling.
func podmanEventsUpstream(t *testing.T, events []eventForTest, forwarded *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forwarded != nil {
			*forwarded = true
		}
		values := eventLabelFilterValues(t, r)
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		for _, event := range events {
			matched := len(values) == 0
			for _, value := range values {
				if eventSelectorMatches(event.Labels, value) {
					matched = true
					break
				}
			}
			if matched {
				if err := enc.Encode(event); err != nil {
					t.Fatalf("encode event: %v", err)
				}
			}
		}
	})
}

// dockerEventsUpstream is dockerd's event endpoint: an event must satisfy
// EVERY forwarded `label` value (daemon/events/filter.go runs them through
// filters.Args.MatchKVList).
func dockerEventsUpstream(t *testing.T, events []eventForTest) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := eventLabelFilterValues(t, r)
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		for _, event := range events {
			matched := true
			for _, value := range values {
				if !eventSelectorMatches(event.Labels, value) {
					matched = false
					break
				}
			}
			if matched {
				if err := enc.Encode(event); err != nil {
					t.Fatalf("encode event: %v", err)
				}
			}
		}
	})
}

// twoSelectorEvents is the fixture the multi-selector cases share: only
// "mine" satisfies both selectors, "theirs" satisfies one of them, and
// "unrelated" satisfies neither.
var twoSelectorEvents = []eventForTest{
	{ID: "mine", Labels: map[string]string{"com.sockguard.visible": "true", "com.sockguard.client": "watchtower"}},
	{ID: "theirs", Labels: map[string]string{"com.sockguard.visible": "true", "com.sockguard.client": "other"}},
	{ID: "unrelated", Labels: map[string]string{"com.sockguard.visible": "false", "com.sockguard.client": "other"}},
}

// TestPodmanCompatEventsRefusesMultipleSelectors is the load-bearing test.
//
// Against a Podman upstream, the append-style injection every other list
// endpoint uses turns a two-selector policy into an OR: the daemon streams
// every event matching EITHER selector, so "theirs" — which the policy hides —
// reaches the client. The endpoint is refused instead, and the refusal must
// happen before the upstream is contacted at all.
func TestPodmanCompatEventsRefusesMultipleSelectors(t *testing.T) {
	t.Parallel()
	forwarded := false
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true", "com.sockguard.client=watchtower"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, visibilityDeps{})(podmanEventsUpstream(t, twoSelectorEvents, &forwarded))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/events", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if forwarded {
		t.Fatal("the request reached the upstream; a refusal must not read another tenant's events")
	}
	for _, id := range []string{"mine", "theirs", "unrelated"} {
		if strings.Contains(rec.Body.String(), `"Id":"`+id+`"`) {
			t.Fatalf("body = %s, want no event data at all", rec.Body.String())
		}
	}
}

// TestPodmanCompatEventsWouldLeakUnderAppendInjection is the counterfactual
// that gives the test above its meaning: it drives the SAME fixture through
// the Docker code path (append) against the Podman upstream, which is exactly
// what shipping without this fix does, and shows the hidden event arriving.
// If a later change makes appending safe on Podman, this test fails and the
// refusal can be reconsidered on evidence.
func TestPodmanCompatEventsWouldLeakUnderAppendInjection(t *testing.T) {
	t.Parallel()
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true", "com.sockguard.client=watchtower"},
		UpstreamFlavor:        upstreamflavor.Docker, // the pre-fix behavior
	}, visibilityDeps{})(podmanEventsUpstream(t, twoSelectorEvents, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/events", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"Id":"theirs"`) {
		t.Fatalf("body = %s, want the disjunctive leak this fix exists to close", rec.Body.String())
	}
}

// TestPodmanCompatEventsInjectsSingleSelector covers the case Podman's filter
// shape CAN express: one selector, written as the sole `label` value, so
// disjunctive and conjunctive evaluation coincide.
func TestPodmanCompatEventsInjectsSingleSelector(t *testing.T) {
	t.Parallel()
	events := []eventForTest{
		{ID: "visible", Labels: map[string]string{"com.sockguard.visible": "true"}},
		{ID: "hidden", Labels: map[string]string{"com.sockguard.visible": "false"}},
	}
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, visibilityDeps{})(podmanEventsUpstream(t, events, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/events", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"Id":"visible"`) {
		t.Fatalf("body = %s, want the visible event present", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"Id":"hidden"`) {
		t.Fatalf("body = %s, want the hidden event absent", rec.Body.String())
	}
}

// TestPodmanCompatEventsTreatsRepeatedEffectiveSelectorAsOne covers a profile
// that repeats a selector it inherits from the default policy. The merged
// policy is still one distinct constraint, so Podman's single label-filter
// value can enforce it and the event stream must not be refused as though two
// independent selectors were present.
func TestPodmanCompatEventsTreatsRepeatedEffectiveSelectorAsOne(t *testing.T) {
	t.Parallel()
	events := []eventForTest{
		{ID: "visible", Labels: map[string]string{"com.sockguard.visible": "true"}},
		{ID: "hidden", Labels: map[string]string{"com.sockguard.visible": "false"}},
	}
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		Profiles: map[string]Policy{
			"watchtower": {VisibleResourceLabels: []string{" com.sockguard.visible = true "}},
		},
		ResolveProfile: func(*http.Request) (string, bool) { return "watchtower", true },
		UpstreamFlavor: upstreamflavor.Podman,
	}, visibilityDeps{})(podmanEventsUpstream(t, events, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/events", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"Id":"visible"`) {
		t.Fatalf("body = %s, want the visible event present", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"Id":"hidden"`) {
		t.Fatalf("body = %s, want the hidden event absent", rec.Body.String())
	}
}

// TestPodmanCompatEventsReplacesClientSuppliedLabelFilter covers the bypass
// that makes replacement necessary rather than merely tidy. A client-supplied
// `label` value sits under the same disjunctive key as the injected selector,
// so appending would let a caller name any label a hidden container carries
// and be handed its events.
func TestPodmanCompatEventsReplacesClientSuppliedLabelFilter(t *testing.T) {
	t.Parallel()
	events := []eventForTest{
		{ID: "visible", Labels: map[string]string{"com.sockguard.visible": "true", "app": "mine"}},
		{ID: "hidden", Labels: map[string]string{"com.sockguard.visible": "false", "app": "theirs"}},
	}
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, visibilityDeps{})(podmanEventsUpstream(t, events, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/v1.53/events?filters={"label":["app=theirs"]}`, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"Id":"hidden"`) {
		t.Fatalf("body = %s, want the client-supplied label filter to have been replaced, not ORed", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"Id":"visible"`) {
		t.Fatalf("body = %s, want the visible event present", rec.Body.String())
	}
}

// TestPodmanCompatEventsReplacesLegacyFilterEncoding pins the same
// replacement against Docker's legacy map[string]map[string]bool filter
// spelling, which dockerfilters.Decode also accepts and Podman's
// util.FiltersFromRequest reads too. Rewriting only the modern encoding would
// forward the legacy one untouched.
func TestPodmanCompatEventsReplacesLegacyFilterEncoding(t *testing.T) {
	t.Parallel()
	events := []eventForTest{
		{ID: "visible", Labels: map[string]string{"com.sockguard.visible": "true"}},
		{ID: "hidden", Labels: map[string]string{"com.sockguard.visible": "false", "app": "theirs"}},
	}
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, visibilityDeps{})(podmanEventsUpstream(t, events, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/v1.53/events?filters={"label":{"app=theirs":true}}`, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"Id":"hidden"`) {
		t.Fatalf("body = %s, want the legacy-encoded label filter replaced too", rec.Body.String())
	}
}

// TestPodmanCompatEventsPreservesNonLabelFilters checks the narrowing a
// client asked for on a DIFFERENT key survives. Podman's applyFilters is
// conjunctive ACROSS keys, so `type` and `label` compose correctly; dropping
// the client's `type` would break a legitimate query for no safety gain.
func TestPodmanCompatEventsPreservesNonLabelFilters(t *testing.T) {
	t.Parallel()
	var gotFilters map[string][]string
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, err := dockerfilters.Decode(r.URL.Query().Get("filters"))
		if err != nil {
			t.Fatalf("forwarded filters did not decode: %v", err)
		}
		gotFilters = decoded
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/v1.53/events?filters={"type":["container"],"label":["app=theirs"]}`, nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if len(gotFilters["type"]) != 1 || gotFilters["type"][0] != "container" {
		t.Fatalf("forwarded type filter = %v, want the client's own value preserved", gotFilters["type"])
	}
	if len(gotFilters["label"]) != 1 || gotFilters["label"][0] != "com.sockguard.visible=true" {
		t.Fatalf("forwarded label filter = %v, want exactly the injected selector", gotFilters["label"])
	}
}

// TestPodmanCompatEventsForwardsPatternsOnlyPolicy covers a policy with
// pattern axes and no selectors. There is nothing to inject and nothing the
// endpoint can express, so it forwards untouched — the same thing it does on
// a Docker upstream. compileVisibilityPolicies already warns at startup that
// such a policy leaves the event stream unrestricted.
func TestPodmanCompatEventsForwardsPatternsOnlyPolicy(t *testing.T) {
	t.Parallel()
	forwarded := false
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		NamePatterns:   []string{"traefik*"},
		UpstreamFlavor: upstreamflavor.Podman,
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		if raw := r.URL.Query().Get("filters"); raw != `{"type":["container"]}` {
			t.Fatalf("forwarded filters = %q, want the client's own untouched", raw)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/v1.53/events?filters={"type":["container"]}`, nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if !forwarded {
		t.Fatal("a patterns-only policy must forward /events, not refuse it")
	}
}

// TestDockerCompatEventsIsUnchangedByFlavorDetection is the "Docker behaves
// exactly as it does today" proof. Against a Docker upstream the two
// selectors are appended and ANDed, so the client sees only the event
// satisfying both — no refusal, no replacement, and the client's own label
// filter is preserved rather than dropped.
func TestDockerCompatEventsIsUnchangedByFlavorDetection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		flavor upstreamflavor.Flavor
	}{
		{name: "explicit docker", flavor: upstreamflavor.Docker},
		{name: "unset field keeps the pre-detection behavior", flavor: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			events := append([]eventForTest(nil), twoSelectorEvents...)
			events = append(events, eventForTest{
				ID:     "kept",
				Labels: map[string]string{"com.sockguard.visible": "true", "com.sockguard.client": "watchtower", "app": "mine"},
			})
			handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true", "com.sockguard.client=watchtower"},
				UpstreamFlavor:        tt.flavor,
			}, visibilityDeps{})(dockerEventsUpstream(t, events))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/v1.53/events?filters={"label":["app=mine"]}`, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"Id":"kept"`) {
				t.Fatalf("body = %s, want the client's own label filter still applied alongside the injected selectors", rec.Body.String())
			}
			for _, id := range []string{"mine", "theirs", "unrelated"} {
				if strings.Contains(rec.Body.String(), `"Id":"`+id+`"`) {
					t.Fatalf("body = %s, want %q filtered out by the conjunction", rec.Body.String(), id)
				}
			}
		})
	}
}

// TestPodmanFlavorLeavesOtherListEndpointsAlone bounds the blast radius: the
// flavor only changes /events. Podman's LIST endpoints run label filters
// through filters.MatchLabelFilters (containers, volumes, networks) or
// libimage's applyFilters (images), all of which require every value to
// match, so appending stays correct there and a multi-selector policy must
// NOT be refused.
func TestPodmanFlavorLeavesOtherListEndpointsAlone(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1.53/containers/json", "/v1.53/images/json", "/v1.53/volumes", "/v1.53/networks", "/v1.53/secrets"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			var got []string
			handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true", "com.sockguard.client=watchtower"},
				UpstreamFlavor:        upstreamflavor.Podman,
			}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = eventLabelFilterValues(t, r)
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			if len(got) != 2 {
				t.Fatalf("forwarded label filters = %v, want both selectors appended", got)
			}
		})
	}
}

// TestPodmanCompatEventsIgnoresWriteMethods pins that the refusal is scoped
// to read methods. A POST to /events is not an event stream; the middleware's
// method gate already forwards it, and narrowing that here would be an
// unrelated behavior change.
func TestPodmanCompatEventsIgnoresWriteMethods(t *testing.T) {
	t.Parallel()
	forwarded := false
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"a=1", "b=2"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1.53/events", nil))

	if !forwarded || rec.Code != http.StatusNoContent {
		t.Fatalf("POST /events: forwarded=%v status=%d, want it untouched", forwarded, rec.Code)
	}
}

// TestPodmanCompatEventsRejectsUndecodableFilters covers the fail-closed path
// for a `filters` parameter the shared decoder refuses: the request must be
// answered with a 400 rather than forwarded with the client's original query.
func TestPodmanCompatEventsRejectsUndecodableFilters(t *testing.T) {
	t.Parallel()
	forwarded := false
	handler := middlewareWithDeps(podmanEventsTestLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		UpstreamFlavor:        upstreamflavor.Podman,
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, `/v1.53/events?filters={"label":[1]}`, nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if forwarded {
		t.Fatal("an undecodable filter must not be forwarded")
	}
}
