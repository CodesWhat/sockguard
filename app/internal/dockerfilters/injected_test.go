package dockerfilters

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestRecordInjectedSelectorsAccumulatesPerKey(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	if got := InjectedSelectors(req, "label"); got != nil {
		t.Fatalf("InjectedSelectors on a fresh request = %v, want nil", got)
	}

	first := RecordInjectedSelectors(req, "label", []string{"tier=prod"})
	second := RecordInjectedSelectors(first, "label", []string{"zone=eu"})
	other := RecordInjectedSelectors(second, "node.label", []string{"role=worker"})

	if got := InjectedSelectors(other, "label"); !slices.Equal(got, []string{"tier=prod", "zone=eu"}) {
		t.Fatalf("label selectors = %v, want [tier=prod zone=eu] in injection order", got)
	}
	if got := InjectedSelectors(other, "node.label"); !slices.Equal(got, []string{"role=worker"}) {
		t.Fatalf("node.label selectors = %v, want [role=worker]", got)
	}
	if got := InjectedSelectors(other, "status"); got != nil {
		t.Fatalf("unrecorded key = %v, want nil", got)
	}

	// The record must not leak backwards onto the request the caller already
	// forwarded: a middleware that derives a request twice would otherwise see
	// its own later writes on an earlier copy.
	if got := InjectedSelectors(req, "label"); got != nil {
		t.Fatalf("original request = %v, want nil (record must live on the derived request)", got)
	}
	if got := InjectedSelectors(first, "label"); !slices.Equal(got, []string{"tier=prod"}) {
		t.Fatalf("first derived request = %v, want only [tier=prod]", got)
	}
}

// A second record under the same key must copy rather than write into the
// previous record's backing array. Two requests derived from one parent would
// otherwise write the same slot, and the second write would silently rewrite
// the first request's recorded selectors.
//
// The corruption is only observable when the parent record's slice has spare
// capacity, which depends on Go's allocator size classes rather than on
// anything this package controls, so the fixture size is derived at run time
// instead of hard-coded.
func TestRecordInjectedSelectorsDoesNotAliasEarlierRecords(t *testing.T) {
	t.Parallel()

	base := make([]string, 0)
	for len(base) == cap(base) {
		if len(base) > 4096 {
			t.Skip("no record size in range leaves spare capacity on this allocator")
		}
		base = append([]string(nil), make([]string, len(base)+1)...)
	}
	for i := range base {
		base[i] = fmt.Sprintf("k%d=v", i)
	}

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	parent := RecordInjectedSelectors(req, "label", base)
	left := RecordInjectedSelectors(parent, "label", []string{"zone=eu"})
	right := RecordInjectedSelectors(parent, "label", []string{"zone=us"})

	if got := InjectedSelectors(left, "label"); !slices.Equal(got, append(slices.Clone(base), "zone=eu")) {
		t.Fatalf("left branch tail = %v, want zone=eu", got[len(got)-1:])
	}
	if got := InjectedSelectors(right, "label"); !slices.Equal(got, append(slices.Clone(base), "zone=us")) {
		t.Fatalf("right branch tail = %v, want zone=us", got[len(got)-1:])
	}
	if got := InjectedSelectors(parent, "label"); !slices.Equal(got, base) {
		t.Fatalf("parent = %v, want the base selectors unchanged", got)
	}
}

func TestRecordInjectedSelectorsNoOpInputs(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	if got := RecordInjectedSelectors(req, "label", nil); got != req {
		t.Fatal("recording no values must return the request unchanged")
	}
	if got := RecordInjectedSelectors(req, "label", []string{}); got != req {
		t.Fatal("recording an empty slice must return the request unchanged")
	}
	if got := RecordInjectedSelectors(nil, "label", []string{"tier=prod"}); got != nil {
		t.Fatal("recording on a nil request must return nil")
	}
	if got := InjectedSelectors(nil, "label"); got != nil {
		t.Fatalf("InjectedSelectors(nil) = %v, want nil", got)
	}
}
