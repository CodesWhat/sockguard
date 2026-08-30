package visibility

import (
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
)

// FuzzPodmanEventLabelFilter drives client-controlled `filters` query values
// through the single-selector rewrite.
//
// The invariant is the whole security property of the Podman /events path: a
// request that is forwarded must carry EXACTLY the injected selector under the
// `label` key and nothing else. Podman ORs the values under that key, so one
// surviving client value is a disclosure, not a cosmetic leftover. The
// alternative outcome — an error, and therefore a 400 with no upstream call —
// is equally acceptable; what must never happen is a forwarded request with a
// second label value, or a panic.
func FuzzPodmanEventLabelFilter(f *testing.F) {
	f.Add("")
	f.Add(`{"label":["app=theirs"]}`)
	f.Add(`{"label":["a","b","c"]}`)
	f.Add(`{"label":{"app=theirs":true}}`)                 // legacy encoding
	f.Add(`{"label":{"app=theirs":true,"x=y":false}}`)     // legacy, mixed booleans
	f.Add(`{"type":["container"],"label":["app=theirs"]}`) // second key preserved
	f.Add(`{"LABEL":["app=theirs"]}`)                      // case variance on the key
	f.Add(`{"label":[]}`)                                  // empty list
	f.Add(`{"label":null}`)                                // null
	f.Add(`{"label":[1]}`)                                 // wrong element type
	f.Add(`{"label":["com.sockguard.visible=true"]}`)      // already the selector
	f.Add(`{"label":["=","","a=","=b","a=b=c"]}`)          // degenerate selectors
	f.Add(`not json`)                                      // undecodable
	f.Add(`[]`)                                            // wrong top-level shape

	selector := compiledSelector{key: "com.sockguard.visible", value: "true", hasValue: true}
	want := selector.key + "=" + selector.value

	f.Fuzz(func(t *testing.T, filters string) {
		req := httptest.NewRequest("GET", "/events", nil)
		query := req.URL.Query()
		query.Set("filters", filters)
		req.URL.RawQuery = query.Encode()

		if err := setPodmanEventLabelFilter(req, selector); err != nil {
			// A rejected filter is answered with a 400 and never forwarded,
			// so there is nothing left to assert about it.
			return
		}

		decoded, err := dockerfilters.Decode(req.URL.Query().Get("filters"))
		if err != nil {
			t.Fatalf("rewritten filters did not decode: %v (input %q)", err, filters)
		}
		if got := decoded["label"]; !slices.Equal(got, []string{want}) {
			t.Fatalf("label values = %v, want exactly [%q] (input %q)", got, want, filters)
		}
	})
}

// TestPodmanEventLabelFilterIgnoresCapitalFiltersParameter pins a Podman
// parsing detail the rewrite depends on. util.FiltersFromRequest checks
// `filters` FIRST and only falls back to `Filters` when the lowercase one is
// absent, so writing the lowercase parameter is enough: a capitalized one the
// client also sent is never read. If that preference ever reversed, the
// rewrite would need to clear both.
func TestPodmanEventLabelFilterIgnoresCapitalFiltersParameter(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("GET", `/events?Filters={"label":["app=theirs"]}`, nil)
	selector := compiledSelector{key: "com.sockguard.visible", value: "true", hasValue: true}

	if err := setPodmanEventLabelFilter(req, selector); err != nil {
		t.Fatalf("setPodmanEventLabelFilter() error = %v", err)
	}

	query := req.URL.Query()
	if _, ok := query["filters"]; !ok {
		t.Fatalf("rewritten query = %q, want a lowercase filters parameter that takes precedence", req.URL.RawQuery)
	}
	decoded, err := dockerfilters.Decode(query.Get("filters"))
	if err != nil {
		t.Fatalf("rewritten filters did not decode: %v", err)
	}
	if len(decoded["label"]) != 1 || decoded["label"][0] != "com.sockguard.visible=true" {
		t.Fatalf("label values = %v, want exactly the injected selector", decoded["label"])
	}
}
