package ownership

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
		{name: "negation of other key kept", client: `{"label":["a!=b"]}`, want: []string{"a!=b"}},
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
