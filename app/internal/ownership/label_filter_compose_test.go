package ownership

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/visibility"
)

// forwardedFilters runs one GET through the production middleware nesting —
// visibility wraps ownership wraps upstream, exactly as
// buildServeHandlerLayersWithRuntime assembles it — and returns the decoded
// `filters` query parameter the upstream daemon actually received.
//
// This is the only place the ownership package reaches for the visibility
// package besides the /system/df compose test; the dependency is test-only and
// one-way (visibility never imports ownership), so it introduces no cycle.
func forwardedFilters(t *testing.T, target string, ownerOpts Options, visOpts visibility.Options) map[string][]string {
	t.Helper()

	var forwarded string
	var reached bool
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		forwarded = r.URL.Query().Get("filters")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	})

	inner := middlewareWithDeps(testLogger(), ownerOpts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)
	handler := visibility.Middleware("", testLogger(), visOpts)(inner)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200; body: %s", target, rec.Code, rec.Body.String())
	}
	if !reached {
		t.Fatalf("GET %s never reached the upstream handler", target)
	}

	decoded := map[string][]string{}
	if forwarded != "" {
		if err := json.Unmarshal([]byte(forwarded), &decoded); err != nil {
			t.Fatalf("decode forwarded filters %q: %v", forwarded, err)
		}
	}
	return decoded
}

func assertFilterValues(t *testing.T, got map[string][]string, key string, want []string) {
	t.Helper()
	values := slices.Clone(got[key])
	slices.Sort(values)
	expected := slices.Clone(want)
	slices.Sort(expected)
	if !slices.Equal(values, expected) {
		t.Fatalf("forwarded %q filter = %v, want %v (full filters: %v)", key, got[key], want, got)
	}
}

// TestListLabelFilterComposesOwnerAndVisibilitySelectors is the regression pin
// for the scoping bypass where ownership's owner-label injection discarded the
// visibility selectors that ran before it. Both layers write the same `label`
// filter key, and Docker (api/types/filters.Args.MatchKVList) and Podman
// (containers/common/pkg/filters.MatchLabelFilters) both require EVERY value
// under `label` to match, so the two selector sets must arrive together for
// the daemon to AND them.
func TestListLabelFilterComposesOwnerAndVisibilitySelectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		target    string
		filterKey string
	}{
		{name: "docker containers", target: "/v1.53/containers/json", filterKey: "label"},
		{name: "docker images", target: "/v1.53/images/json", filterKey: "label"},
		{name: "docker volumes", target: "/v1.53/volumes", filterKey: "label"},
		{name: "docker events", target: "/v1.53/events", filterKey: "label"},
		{name: "docker services", target: "/v1.53/services", filterKey: "label"},
		// /nodes is the one path where the two layers pick a different filter
		// key than everywhere else. They have to pick the same one as each
		// other or the record is filed under a key ownership never reads.
		{name: "docker nodes", target: "/v1.53/nodes", filterKey: "node.label"},
		{name: "libpod containers", target: "/libpod/containers/json", filterKey: "label"},
		{name: "libpod pods", target: "/libpod/pods/json", filterKey: "label"},
		{name: "libpod volumes", target: "/libpod/volumes/json", filterKey: "label"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := forwardedFilters(t, tc.target,
				Options{Owner: "team-a"},
				visibility.Options{VisibleResourceLabels: []string{"tier=prod", "zone=eu"}},
			)
			assertFilterValues(t, got, tc.filterKey, []string{
				ownerLabelForTest + "=team-a",
				"tier=prod",
				"zone=eu",
			})
		})
	}
}

// TestListLabelFilterKeepsVisibilityScopeWhileDroppingClientValues is the
// other half of the composition rule. Ownership must still discard every
// client-supplied value under the label key — Docker's Swarm control-plane
// lists fold `label` into a map keyed by label name, so a client value
// repeating a proxy-enforced key can displace it — while keeping the
// selectors visibility injected on the same request.
func TestListLabelFilterKeepsVisibilityScopeWhileDroppingClientValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		clientFilter string
		want         []string
	}{
		{
			name:         "client forges another owner and a looser tier",
			clientFilter: `{"label":["` + ownerLabelForTest + `=victim","tier=dev"]}`,
			want:         []string{ownerLabelForTest + "=team-a", "tier=prod"},
		},
		{
			// The client sent the visibility selector itself, so visibility
			// had no query rewrite to do. The selector is still policy-
			// enforced and must survive ownership's client-value drop.
			name:         "client already sent the visibility selector",
			clientFilter: `{"label":["tier=prod"]}`,
			want:         []string{ownerLabelForTest + "=team-a", "tier=prod"},
		},
		{
			// Filter keys ownership does not enforce are none of its business
			// and must reach the daemon untouched.
			name:         "unrelated filter keys survive",
			clientFilter: `{"label":["tier=dev"],"status":["running"]}`,
			want:         []string{ownerLabelForTest + "=team-a", "tier=prod"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := forwardedFilters(t, "/v1.53/containers/json?filters="+url.QueryEscape(tc.clientFilter),
				Options{Owner: "team-a"},
				visibility.Options{VisibleResourceLabels: []string{"tier=prod"}},
			)
			assertFilterValues(t, got, "label", tc.want)
			for _, value := range got["label"] {
				if strings.Contains(value, "victim") || value == "tier=dev" {
					t.Fatalf("client-supplied label value survived: %v", got["label"])
				}
			}
		})
	}
}

// TestListLabelFilterUnchangedWithoutVisibilitySelectors pins that the
// composition change did not alter the ownership-only path: with nothing
// injected upstream of it, ownership still forwards exactly the owner label.
func TestListLabelFilterUnchangedWithoutVisibilitySelectors(t *testing.T) {
	t.Parallel()
	got := forwardedFilters(t, "/v1.53/containers/json?filters="+url.QueryEscape(`{"label":["tier=dev"]}`),
		Options{Owner: "team-a"},
		visibility.Options{},
	)
	assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=team-a"})
}

// TestListLabelFilterKeepsUnrelatedFilterKeys pins that neither layer disturbs
// filter keys it does not enforce.
func TestListLabelFilterKeepsUnrelatedFilterKeys(t *testing.T) {
	t.Parallel()
	got := forwardedFilters(t, "/v1.53/containers/json?filters="+url.QueryEscape(`{"status":["running"]}`),
		Options{Owner: "team-a"},
		visibility.Options{VisibleResourceLabels: []string{"tier=prod"}},
	)
	assertFilterValues(t, got, "status", []string{"running"})
	assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=team-a", "tier=prod"})
}

// TestListLabelFilterDeduplicatesOwnerLabelAgainstInjectedSelector covers the
// belt-and-braces case config validation makes unreachable in a running proxy:
// a visibility selector naming the ownership label key with the same value.
// The two must collapse to one filter value rather than being sent twice.
func TestListLabelFilterDeduplicatesOwnerLabelAgainstInjectedSelector(t *testing.T) {
	t.Parallel()
	got := forwardedFilters(t, "/v1.53/containers/json",
		Options{Owner: "team-a", LabelKey: "owner"},
		visibility.Options{VisibleResourceLabels: []string{"owner=team-a"}},
	)
	if values := got["label"]; len(values) != 1 || values[0] != "owner=team-a" {
		t.Fatalf("label filter = %v, want exactly [owner=team-a]", values)
	}
}
