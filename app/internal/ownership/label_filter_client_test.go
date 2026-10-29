package ownership

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/upstreamflavor"
	"github.com/codeswhat/sockguard/v2/app/internal/visibility"
)

const composeProjectKey = "com.docker.compose.project"

// forwardedFiltersFor is forwardedFilters with a caller-chosen method, so
// prune endpoints can be driven through the same visibility+ownership nesting.
func forwardedFiltersFor(t *testing.T, method, target string, ownerOpts Options, visOpts visibility.Options) map[string][]string {
	t.Helper()
	if method == http.MethodGet {
		return forwardedFilters(t, target, ownerOpts, visOpts)
	}
	var forwarded string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.URL.Query().Get("filters")
		w.WriteHeader(http.StatusOK)
	})
	inner := middlewareWithDeps(testLogger(), ownerOpts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)
	handler := visibility.Middleware("", testLogger(), visOpts)(inner)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: status = %d; body: %s", method, target, rec.Code, rec.Body.String())
	}
	return decodeFiltersForTest(t, forwarded)
}

func decodeFiltersForTest(t *testing.T, raw string) map[string][]string {
	t.Helper()
	decoded := map[string][]string{}
	if raw == "" {
		return decoded
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("decode filters %q: %v", raw, err)
	}
	return decoded
}

func TestListLabelFilterKeepsComposeSelectors(t *testing.T) {
	t.Parallel()
	client := `{"label":["com.docker.compose.project=demo","com.docker.compose.service=b","com.docker.compose.oneoff=False"]}`
	got := forwardedFilters(t, "/v1.53/containers/json?filters="+url.QueryEscape(client),
		Options{Owner: "demo", LabelKey: composeProjectKey},
		visibility.Options{},
	)
	assertFilterValues(t, got, "label", []string{
		composeProjectKey + "=demo",
		"com.docker.compose.service=b",
		"com.docker.compose.oneoff=False",
	})
	if got["label"][0] != composeProjectKey+"=demo" {
		t.Fatalf("owner selector must lead, got %v", got["label"])
	}
}

func TestListLabelFilterKeepDropRule(t *testing.T) {
	t.Parallel()

	const owner = ownerLabelForTest
	tests := []struct {
		name   string
		client string
		want   []string // after the leading owner selector
	}{
		{name: "same owner selector is not duplicated", client: `{"label":["` + owner + `=team-a"]}`, want: nil},
		{name: "owner key with other value dropped", client: `{"label":["` + owner + `=other"]}`, want: nil},
		{name: "owner key negation dropped", client: `{"label":["` + owner + `!=x"]}`, want: nil},
		{name: "owner key bare dropped", client: `{"label":["` + owner + `"]}`, want: nil},
		{name: "owner key with whitespace dropped", client: `{"label":["  ` + owner + ` =other"]}`, want: nil},
		{name: "empty value dropped", client: `{"label":["","a=b"]}`, want: []string{"a=b"}},
		{name: "non-colliding kept in client order", client: `{"label":["z=1","a=b","z=1"]}`, want: []string{"z=1", "a=b"}},
		{name: "negation of other key dropped", client: `{"label":["a!=b","c=d"]}`, want: []string{"c=d"}},
		{name: "legacy map spelling kept", client: `{"label":{"a=b":true}}`, want: []string{"a=b"}},
		{name: "legacy map spelling colliding dropped", client: `{"label":{"` + owner + `=x":true}}`, want: nil},
	}

	targets := []struct {
		name, method, path, key string
	}{
		{"containers", http.MethodGet, "/v1.53/containers/json", "label"},
		{"networks", http.MethodGet, "/v1.53/networks", "label"},
		{"volumes", http.MethodGet, "/v1.53/volumes", "label"},
		{"images", http.MethodGet, "/v1.53/images/json", "label"},
		{"containers prune", http.MethodPost, "/v1.53/containers/prune", "label"},
		{"services", http.MethodGet, "/v1.53/services", "label"},
		{"nodes", http.MethodGet, "/v1.53/nodes", "node.label"},
		{"libpod containers", http.MethodGet, "/libpod/containers/json", "label"},
	}

	for _, target := range targets {
		for _, tc := range tests {
			t.Run(target.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				client := strings.Replace(tc.client, `"label"`, `"`+target.key+`"`, 1)
				got := forwardedFiltersFor(t, target.method, target.path+"?filters="+url.QueryEscape(client),
					Options{Owner: "team-a"}, visibility.Options{})
				want := append([]string{owner + "=team-a"}, tc.want...)
				if len(got[target.key]) != len(want) {
					t.Fatalf("%s = %v, want %v", target.key, got[target.key], want)
				}
				for i := range want {
					if got[target.key][i] != want[i] {
						t.Fatalf("%s = %v, want %v", target.key, got[target.key], want)
					}
				}
			})
		}
	}
}

func TestLibpodImagePruneSendsOnlyEnforcedSelectors(t *testing.T) {
	t.Parallel()
	client := `{"label":["a=b","c=d"],"until":["1h"]}`
	got := forwardedFiltersFor(t, http.MethodPost, "/libpod/images/prune?filters="+url.QueryEscape(client),
		Options{Owner: "team-a"}, visibility.Options{})
	assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=team-a"})
	assertFilterValues(t, got, "until", []string{"1h"})
}

func TestListLabelFilterVisibilityKeyCollision(t *testing.T) {
	t.Parallel()
	client := `{"label":["tier=dev","tier!=x","region=eu"]}`
	got := forwardedFilters(t, "/v1.53/containers/json?filters="+url.QueryEscape(client),
		Options{Owner: "team-a"},
		visibility.Options{VisibleResourceLabels: []string{"tier=prod"}},
	)
	assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=team-a", "tier=prod", "region=eu"})
}

func TestEventsDropEveryClientLabelSelector(t *testing.T) {
	t.Parallel()
	client := `{"label":["a=b","com.docker.compose.service=b"],"type":["container"]}`
	for _, path := range []string{"/v1.53/events", "/libpod/events"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			got := forwardedFilters(t, path+"?filters="+url.QueryEscape(client),
				Options{Owner: "team-a"}, visibility.Options{})
			assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=team-a"})
			assertFilterValues(t, got, "type", []string{"container"})
		})
	}
	t.Run("with visibility", func(t *testing.T) {
		t.Parallel()
		got := forwardedFilters(t, "/v1.53/events?filters="+url.QueryEscape(client),
			Options{Owner: "team-a"}, visibility.Options{VisibleResourceLabels: []string{"tier=prod"}})
		assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=team-a", "tier=prod"})
	})
}

func TestSelectorLabelKey(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"a=b":    "a",
		"a!=b":   "a",
		" a =b":  "a",
		"a":      "a",
		"a!":     "a",
		"a=b=c":  "a",
		"a!!=b":  "a!",
		"":       "",
		"=x":     "",
		" a! =b": "a",
	}
	for in, want := range tests {
		if got := selectorLabelKey(in); got != want {
			t.Errorf("selectorLabelKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListLabelFilterValueContainingNegationToken(t *testing.T) {
	t.Parallel()
	const owner = ownerLabelForTest + "=team-a"
	tests := []struct {
		name   string
		method string
		path   string
		flavor upstreamflavor.Flavor
		client string
		want   []string
	}{
		{"equality value kept on containers", http.MethodGet, "/v1.53/containers/json", upstreamflavor.Docker, "note=hello!=world", []string{owner, "note=hello!=world"}},
		{"equality value kept on container prune", http.MethodPost, "/v1.53/containers/prune", upstreamflavor.Docker, "note=hello!=world", []string{owner, "note=hello!=world"}},
		{"equality value kept on images under docker", http.MethodGet, "/v1.53/images/json", upstreamflavor.Docker, "note=hello!=world", []string{owner, "note=hello!=world"}},
		{"equality value dropped on images under podman", http.MethodGet, "/v1.53/images/json", upstreamflavor.Podman, "note=hello!=world", []string{owner}},
		{"equality value dropped on libpod images under podman", http.MethodGet, "/libpod/images/json", upstreamflavor.Podman, "note=hello!=world", []string{owner}},
		{"equality value kept on containers under podman", http.MethodGet, "/v1.53/containers/json", upstreamflavor.Podman, "note=hello!=world", []string{owner, "note=hello!=world"}},
		{"negation dropped on containers", http.MethodGet, "/v1.53/containers/json", upstreamflavor.Docker, "a!=b", []string{owner}},
		{"negation dropped on prune", http.MethodPost, "/v1.53/containers/prune", upstreamflavor.Docker, "a!=b", []string{owner}},
		{"negation dropped on images under docker", http.MethodGet, "/v1.53/images/json", upstreamflavor.Docker, "a!=b", []string{owner}},
		{"spaced negation dropped", http.MethodGet, "/v1.53/containers/json", upstreamflavor.Docker, "a! =b", []string{owner}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := `{"label":["` + tc.client + `"]}`
			got := forwardedFiltersFor(t, tc.method, tc.path+"?filters="+url.QueryEscape(client),
				Options{Owner: "team-a", UpstreamFlavor: tc.flavor}, visibility.Options{})
			assertFilterValues(t, got, "label", tc.want)
		})
	}
}

func TestListLabelFilterManyClientSelectors(t *testing.T) {
	t.Parallel()
	const n = 5000
	client := make([]string, 0, n+2)
	for i := 0; i < n; i++ {
		client = append(client, fmt.Sprintf("k%d=v", i))
	}
	client = append(client, "k0=v", ownerLabelForTest+"=other")
	encoded, err := json.Marshal(map[string][]string{"label": client})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/containers/json?filters="+url.QueryEscape(string(encoded)), nil)
	if err := addOwnerLabelFilter(req, ownerLabelForTest, "team-a", false); err != nil {
		t.Fatal(err)
	}
	got := decodeFiltersForTest(t, req.URL.Query().Get("filters"))["label"]
	if len(got) != n+1 || got[0] != ownerLabelForTest+"=team-a" {
		t.Fatalf("len=%d first=%q, want %d values led by the owner selector", len(got), got[0], n+1)
	}
	for i := 0; i < n; i++ {
		if got[i+1] != fmt.Sprintf("k%d=v", i) {
			t.Fatalf("got[%d] = %q, order not preserved", i+1, got[i+1])
		}
	}
}
