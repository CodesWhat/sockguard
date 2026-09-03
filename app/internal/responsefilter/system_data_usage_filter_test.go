package responsefilter

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// keepAll is the identity predicate: it exercises the aggregate and
// build-cache rules without any item-level filtering interfering.
func keepAll(SystemDataUsageSection, json.RawMessage) (bool, error) { return true, nil }

// keepNamed keeps container/volume items whose Name field is in names and image
// items whose Id is in names.
func keepNamed(names ...string) SystemDataUsageKeepFunc {
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	return func(_ SystemDataUsageSection, raw json.RawMessage) (bool, error) {
		var item struct {
			Name string `json:"Name"`
			Id   string `json:"Id"` //nolint:revive,staticcheck // Docker's wire field is "Id", not "ID"
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return false, err
		}
		return wanted[item.Name] || wanted[item.Id], nil
	}
}

func decodeMapForTest(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode filtered body: %v; body = %s", err, body)
	}
	return payload
}

func usageItemNamesForTest(t *testing.T, payload map[string]any, keys ...string) []string {
	t.Helper()
	current := any(payload)
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %T is not an object", keys, current)
		}
		current = object[key]
	}
	items, ok := current.([]any)
	if !ok {
		t.Fatalf("path %v: %T is not an array", keys, current)
	}
	names := make([]string, 0, len(items))
	for _, value := range items {
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("path %v: item %T is not an object", keys, value)
		}
		name, _ := object["Name"].(string)
		if name == "" {
			name, _ = object["Id"].(string)
		}
		names = append(names, name)
	}
	return names
}

func numberForTest(t *testing.T, payload map[string]any, keys ...string) float64 {
	t.Helper()
	current := any(payload)
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %T is not an object", keys, current)
		}
		current = object[key]
	}
	number, ok := current.(float64)
	if !ok {
		t.Fatalf("path %v: %T is not a number", keys, current)
	}
	return number
}

// modernSystemDFBody is the Engine API >= 1.52 shape: per-section usage
// objects carrying ActiveCount / TotalCount / Reclaimable / TotalSize / Items.
const modernSystemDFBody = `{
  "ContainerUsage":{"ActiveCount":1,"TotalCount":2,"Reclaimable":111,"TotalSize":222,
    "Items":[{"Id":"c-mine","Name":"mine"},{"Id":"c-theirs","Name":"theirs"}]},
  "ImageUsage":{"ActiveCount":1,"TotalCount":2,"Reclaimable":333,"TotalSize":444,
    "Items":[{"Id":"img-mine"},{"Id":"img-theirs"}]},
  "VolumeUsage":{"ActiveCount":1,"TotalCount":2,"Reclaimable":555,"TotalSize":666,
    "Items":[{"Name":"vol-mine"},{"Name":"vol-theirs"}]},
  "BuildCacheUsage":{"ActiveCount":1,"TotalCount":2,"Reclaimable":777,"TotalSize":888,
    "Items":[{"ID":"bc1","Description":"secret build step"},{"ID":"bc2","Description":"another"}]}
}`

// legacySystemDFBody is the Engine API <= 1.51 shape: bare top-level arrays
// plus the host-wide LayersSize total.
const legacySystemDFBody = `{
  "LayersSize":1092588,
  "Containers":[{"Id":"c-mine","Name":"mine"},{"Id":"c-theirs","Name":"theirs"}],
  "Images":[{"Id":"img-mine"},{"Id":"img-theirs"}],
  "Volumes":[{"Name":"vol-mine"},{"Name":"vol-theirs"}],
  "BuildCache":[{"ID":"bc1","Description":"secret build step"}]
}`

func TestFilterSystemDataUsageModernShapeKeepsOnlySelectedItems(t *testing.T) {
	t.Parallel()
	out, _, err := FilterSystemDataUsage([]byte(modernSystemDFBody), keepNamed("mine", "img-mine", "vol-mine"))
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	payload := decodeMapForTest(t, out)

	for _, tc := range []struct {
		path []string
		want string
	}{
		{path: []string{"ContainerUsage", "Items"}, want: "mine"},
		{path: []string{"ImageUsage", "Items"}, want: "img-mine"},
		{path: []string{"VolumeUsage", "Items"}, want: "vol-mine"},
	} {
		got := usageItemNamesForTest(t, payload, tc.path...)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("%v = %v, want exactly [%s]", tc.path, got, tc.want)
		}
	}
}

func TestFilterSystemDataUsageLegacyShapeKeepsOnlySelectedItems(t *testing.T) {
	t.Parallel()
	out, _, err := FilterSystemDataUsage([]byte(legacySystemDFBody), keepNamed("mine", "img-mine", "vol-mine"))
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	payload := decodeMapForTest(t, out)

	for _, tc := range []struct {
		key  string
		want string
	}{
		{key: "Containers", want: "mine"},
		{key: "Images", want: "img-mine"},
		{key: "Volumes", want: "vol-mine"},
	} {
		got := usageItemNamesForTest(t, payload, tc.key)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("%s = %v, want exactly [%s]", tc.key, got, tc.want)
		}
	}
}

// TestFilterSystemDataUsageDropsBuildCache pins the fail-closed decision:
// build-cache records carry no labels, so no policy can classify them and they
// never survive filtering — in either response shape, even when the caller's
// predicate would keep everything.
func TestFilterSystemDataUsageDropsBuildCache(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		path []string
	}{
		{name: "modern shape", body: modernSystemDFBody, path: []string{"BuildCacheUsage", "Items"}},
		{name: "legacy shape", body: legacySystemDFBody, path: []string{"BuildCache"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, _, err := FilterSystemDataUsage([]byte(tt.body), keepAll)
			if err != nil {
				t.Fatalf("FilterSystemDataUsage() error = %v", err)
			}
			if got := usageItemNamesForTest(t, decodeMapForTest(t, out), tt.path...); len(got) != 0 {
				t.Fatalf("%v = %v, want empty (build cache is unclassifiable)", tt.path, got)
			}
			if strings.Contains(string(out), "secret build step") {
				t.Fatalf("build cache Description survived filtering: %s", out)
			}
		})
	}
}

// TestFilterSystemDataUsageRewritesAggregates pins the aggregate decision:
// TotalCount is recomputed from the surviving items, every other total is
// zeroed because it describes the whole host and is not exactly derivable from
// what the caller can see.
func TestFilterSystemDataUsageRewritesAggregates(t *testing.T) {
	t.Parallel()
	out, _, err := FilterSystemDataUsage([]byte(modernSystemDFBody), keepNamed("mine", "img-mine", "vol-mine"))
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	payload := decodeMapForTest(t, out)

	for _, section := range []string{"ContainerUsage", "ImageUsage", "VolumeUsage"} {
		if got := numberForTest(t, payload, section, "TotalCount"); got != 1 {
			t.Errorf("%s.TotalCount = %v, want 1 (recomputed from surviving items)", section, got)
		}
		for _, aggregate := range []string{"ActiveCount", "Reclaimable", "TotalSize"} {
			if got := numberForTest(t, payload, section, aggregate); got != 0 {
				t.Errorf("%s.%s = %v, want 0 (host-wide total must not leak)", section, aggregate, got)
			}
		}
	}
	if got := numberForTest(t, payload, "BuildCacheUsage", "TotalCount"); got != 0 {
		t.Errorf("BuildCacheUsage.TotalCount = %v, want 0", got)
	}
}

func TestFilterSystemDataUsageZeroesLegacyLayersSize(t *testing.T) {
	t.Parallel()
	out, _, err := FilterSystemDataUsage([]byte(legacySystemDFBody), keepAll)
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	if got := numberForTest(t, decodeMapForTest(t, out), "LayersSize"); got != 0 {
		t.Fatalf("LayersSize = %v, want 0 (host-wide total must not leak)", got)
	}
}

// TestFilterSystemDataUsageAllFilteredYieldsEmptyArray guards against emitting
// JSON null for a fully filtered section: Docker clients index the array.
func TestFilterSystemDataUsageAllFilteredYieldsEmptyArray(t *testing.T) {
	t.Parallel()
	out, _, err := FilterSystemDataUsage([]byte(modernSystemDFBody), keepNamed())
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	if !strings.Contains(string(out), `"Items":[]`) {
		t.Fatalf("filtered body has no empty Items array: %s", out)
	}
	if strings.Contains(string(out), `"Items":null`) {
		t.Fatalf("filtered body emitted null Items: %s", out)
	}
}

func TestFilterSystemDataUsageTolerantOfMissingAndNullSections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "empty object", body: `{}`},
		// A JSON null body decodes to a nil map; writing into one would panic,
		// so this pins that no branch ever assigns to it.
		{name: "null body", body: `null`},
		{name: "type-filtered response", body: `{"ContainerUsage":{"TotalCount":1,"Items":[{"Name":"mine"}]}}`},
		{name: "null usage object", body: `{"ContainerUsage":null,"Containers":null}`},
		{name: "null items", body: `{"ContainerUsage":{"TotalCount":3,"Items":null}}`},
		{name: "usage object without items", body: `{"VolumeUsage":{"TotalCount":9,"TotalSize":5}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := FilterSystemDataUsage([]byte(tt.body), keepAll); err != nil {
				t.Fatalf("FilterSystemDataUsage(%s) error = %v", tt.body, err)
			}
		})
	}
}

// TestFilterSystemDataUsageAbsentItemsZeroesTotalCount covers the section that
// reports a count but discloses no items: the count the caller sees must match
// the items the caller receives.
func TestFilterSystemDataUsageAbsentItemsZeroesTotalCount(t *testing.T) {
	t.Parallel()
	out, _, err := FilterSystemDataUsage([]byte(`{"VolumeUsage":{"TotalCount":9,"TotalSize":5}}`), keepAll)
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	if got := numberForTest(t, decodeMapForTest(t, out), "VolumeUsage", "TotalCount"); got != 0 {
		t.Fatalf("VolumeUsage.TotalCount = %v, want 0", got)
	}
}

func TestFilterSystemDataUsageErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		keep SystemDataUsageKeepFunc
	}{
		{name: "nil keep", body: `{}`, keep: nil},
		{name: "not JSON", body: `not json`, keep: keepAll},
		{name: "array body", body: `[]`, keep: keepAll},
		{name: "usage not an object", body: `{"ContainerUsage":"nope"}`, keep: keepAll},
		{name: "items not an array", body: `{"ContainerUsage":{"Items":{}}}`, keep: keepAll},
		{name: "legacy section not an array", body: `{"Containers":{}}`, keep: keepAll},
		{name: "keep predicate error", body: modernSystemDFBody, keep: func(SystemDataUsageSection, json.RawMessage) (bool, error) {
			return false, errUnclassifiableForTest
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := FilterSystemDataUsage([]byte(tt.body), tt.keep); err == nil {
				t.Fatalf("FilterSystemDataUsage(%s) = nil error, want a failure so the caller fails closed", tt.body)
			}
		})
	}
}

var errUnclassifiableForTest = &unclassifiableError{}

type unclassifiableError struct{}

func (*unclassifiableError) Error() string { return "cannot classify item" }

// TestFilterSystemDataUsageDropsUnknownKeysAndPreservesItemBytes asserts the
// two halves that pull in opposite directions: a top-level key this build does
// not understand is removed rather than forwarded, because whatever is left in
// the decoded map reaches the client verbatim, while a kept item's bytes are
// not HTML-escaped on the way through.
//
// This test used to assert the opposite of its first half. That was wrong: an
// unrelated top-level key surviving is exactly the unfiltered enumeration
// channel the item filter exists to close, and both keep predicates already
// carried comments claiming a section they cannot classify is hidden.
func TestFilterSystemDataUsageDropsUnknownKeysAndPreservesItemBytes(t *testing.T) {
	t.Parallel()
	body := `{"SomeFutureKey":{"a":1},"ContainerUsage":{"Items":[{"Name":"mine","Command":"sh -c 'a<b && c>d'"}]}}`
	out, dropped, err := FilterSystemDataUsage([]byte(body), keepAll)
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	payload := decodeMapForTest(t, out)
	if _, ok := payload["SomeFutureKey"]; ok {
		t.Fatalf("unclassifiable top-level key reached the client: %s", out)
	}
	if _, ok := payload["ContainerUsage"]; !ok {
		t.Fatalf("known section dropped, so the test cannot tell filtering from an empty result: %s", out)
	}
	if !reflect.DeepEqual(dropped, []string{"SomeFutureKey"}) {
		t.Fatalf("dropped = %v, want [SomeFutureKey] so the caller can log it", dropped)
	}
	if !strings.Contains(string(out), `a<b && c>d`) {
		t.Fatalf("kept item bytes were escaped or rewritten: %s", out)
	}
}

// TestFilterSystemDataUsageDropsEveryUnknownShape covers the leak's real
// surface: a whole section object, a bare array, and a scalar host-wide
// aggregate are all unclassifiable, so all three go. BuilderSize is the
// reachable case today rather than a hypothetical, since the Engine API only
// removed it in v1.42 and a Docker-compat upstream may still send it.
func TestFilterSystemDataUsageDropsEveryUnknownShape(t *testing.T) {
	t.Parallel()
	body := `{"PluginUsage":{"TotalCount":2,"Items":[{"Id":"p1","Labels":{"o":"theirs"}}]},` +
		`"CheckpointUsage":[{"Id":"cp1","Labels":{"o":"theirs"}}],` +
		`"BuilderSize":777,"Images":[{"Id":"img-mine"}]}`
	out, dropped, err := FilterSystemDataUsage([]byte(body), keepAll)
	if err != nil {
		t.Fatalf("FilterSystemDataUsage() error = %v", err)
	}
	for _, leaked := range []string{"PluginUsage", "CheckpointUsage", "BuilderSize", "p1", "cp1", "theirs", "777"} {
		if strings.Contains(string(out), leaked) {
			t.Fatalf("%q survived the filter: %s", leaked, out)
		}
	}
	if !strings.Contains(string(out), "img-mine") {
		t.Fatalf("known section was dropped too, so this proves nothing: %s", out)
	}
	want := []string{"BuilderSize", "CheckpointUsage", "PluginUsage"}
	if !reflect.DeepEqual(dropped, want) {
		t.Fatalf("dropped = %v, want %v sorted", dropped, want)
	}
}

// TestFirstSightSystemDataUsageSectionsReportsEachSectionOnce pins the
// deduplication a polling dashboard depends on: the dropped set is a property
// of the daemon's API version, not of a request, so it is worth one log record
// per process and not one per scrape.
func TestFirstSightSystemDataUsageSectionsReportsEachSectionOnce(t *testing.T) {
	// Not parallel: it mutates the package-level seen set.
	unique := "SectionForFirstSightTest"
	// LoadOrStore only ever adds to unreportedSystemDataUsageKeys; it never
	// removes. Without this cleanup, a second run in the same process (e.g.
	// go test -count=2) would find the key already marked seen and fail the
	// first-sight assertion below.
	t.Cleanup(func() { unreportedSystemDataUsageKeys.Delete(unique) })
	if got := FirstSightSystemDataUsageSections([]string{unique}); !reflect.DeepEqual(got, []string{unique}) {
		t.Fatalf("first sight = %v, want [%s]", got, unique)
	}
	if got := FirstSightSystemDataUsageSections([]string{unique}); got != nil {
		t.Fatalf("second sight = %v, want nil so the record is not restated", got)
	}
	if got := FirstSightSystemDataUsageSections(nil); got != nil {
		t.Fatalf("nil input = %v, want nil", got)
	}
}

func TestClearUpstreamRepresentationHeaders(t *testing.T) {
	t.Parallel()
	header := http.Header{}
	for _, name := range []string{"Content-Encoding", "Content-Length", "Content-Range", "ETag", "Last-Modified", "Transfer-Encoding"} {
		header.Set(name, "upstream")
	}
	header.Set("Content-Type", "application/json")

	ClearUpstreamRepresentationHeaders(header)

	for name := range header {
		if name != "Content-Type" {
			t.Errorf("%s survived, want only Content-Type retained", name)
		}
	}
	if got := header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}
