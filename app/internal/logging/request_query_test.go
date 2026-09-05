package logging

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func requestWithMeta(target string) (*http.Request, *RequestMeta) {
	r := httptest.NewRequest(http.MethodPost, target, nil)
	meta := &RequestMeta{}
	return r.WithContext(WithMeta(r.Context(), meta)), meta
}

func mapIdentity(v url.Values) uintptr {
	return reflect.ValueOf(v).Pointer()
}

func TestRequestQueryParsesOncePerRequest(t *testing.T) {
	r, _ := requestWithMeta("/build?t=app%3Alatest&dockerfile=Dockerfile&networkmode=bridge&nocache=1")

	first := RequestQuery(r)
	second := RequestQuery(r)

	if got, want := first.Get("dockerfile"), "Dockerfile"; got != want {
		t.Fatalf("RequestQuery().Get(dockerfile) = %q, want %q", got, want)
	}
	if mapIdentity(first) != mapIdentity(second) {
		t.Fatal("RequestQuery() returned a freshly parsed map on the second call, want the memoized one")
	}

	allocs := testing.AllocsPerRun(100, func() {
		_ = RequestQuery(r)
	})
	if allocs != 0 {
		t.Fatalf("RequestQuery() after the first parse allocated %v times, want 0", allocs)
	}
}

func TestRequestQueryReparsesAfterRawQueryRewrite(t *testing.T) {
	r, _ := requestWithMeta("/containers/json?all=1")

	before := RequestQuery(r)
	if got, want := before.Get("all"), "1"; got != want {
		t.Fatalf("RequestQuery().Get(all) before rewrite = %q, want %q", got, want)
	}

	// ownership and visibility both rewrite RawQuery downstream of the
	// filter to scope a list to the caller's own resources; the proxy's
	// deadline classifier reads the query after them.
	r.URL.RawQuery = "all=1&filters=%7B%22label%22%3A%5B%22owner%3Dsockguard%22%5D%7D"

	after := RequestQuery(r)
	if got, want := after.Get("filters"), `{"label":["owner=sockguard"]}`; got != want {
		t.Fatalf("RequestQuery().Get(filters) after rewrite = %q, want %q", got, want)
	}
	if mapIdentity(before) == mapIdentity(after) {
		t.Fatal("RequestQuery() reused the pre-rewrite parse, want a reparse of the rewritten RawQuery")
	}
}

func TestRequestQueryIgnoresMemoLeftByAPooledMeta(t *testing.T) {
	meta := getRequestMeta()
	t.Cleanup(func() { putRequestMeta(meta) })

	stale := httptest.NewRequest(http.MethodDelete, "/containers/abc?force=1", nil)
	stale = stale.WithContext(WithMeta(stale.Context(), meta))
	if got, want := RequestQuery(stale).Get("force"), "1"; got != want {
		t.Fatalf("RequestQuery().Get(force) = %q, want %q", got, want)
	}

	// Same meta, different request: the raw-string key is what stops the
	// previous request's parse from answering this one's reads.
	next := httptest.NewRequest(http.MethodDelete, "/containers/def?v=1", nil)
	next = next.WithContext(WithMeta(next.Context(), meta))
	got := RequestQuery(next)
	if got.Get("force") != "" {
		t.Fatalf("RequestQuery() returned the previous request's force=%q", got.Get("force"))
	}
	if want := "1"; got.Get("v") != want {
		t.Fatalf("RequestQuery().Get(v) = %q, want %q", got.Get("v"), want)
	}
}

func TestRequestQueryWithoutMetaMatchesURLQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/images/create?fromImage=alpine&tag=3.19", nil)

	got := RequestQuery(r)
	if !reflect.DeepEqual(got, r.URL.Query()) {
		t.Fatalf("RequestQuery() without meta = %v, want %v", got, r.URL.Query())
	}
}

func TestRequestQueryHandlesNilRequestAndURL(t *testing.T) {
	if got := RequestQuery(nil); got != nil {
		t.Fatalf("RequestQuery(nil) = %v, want nil", got)
	}
	if got := RequestQuery(&http.Request{}); got != nil {
		t.Fatalf("RequestQuery() with a nil URL = %v, want nil", got)
	}
}

func TestParseRequestQueryReportsMalformedQuery(t *testing.T) {
	r, _ := requestWithMeta("/containers/abc?force=%zz&v=1")

	values, err := ParseRequestQuery(r)
	if err == nil {
		t.Fatal("ParseRequestQuery() err = nil, want the url.ParseQuery error")
	}
	if got, want := values.Get("v"), "1"; got != want {
		t.Fatalf("ParseRequestQuery() values.Get(v) = %q, want %q", got, want)
	}

	// The error is memoized with the values, so a caller that rejects a
	// malformed query and one that reads the partial values agree.
	memoValues, memoErr := ParseRequestQuery(r)
	if memoErr == nil || memoErr.Error() != err.Error() {
		t.Fatalf("ParseRequestQuery() memoized err = %v, want %v", memoErr, err)
	}
	if mapIdentity(memoValues) != mapIdentity(values) {
		t.Fatal("ParseRequestQuery() reparsed a malformed query, want the memoized values")
	}
	if got := RequestQuery(r).Get("v"); got != "1" {
		t.Fatalf("RequestQuery() after a malformed parse = %q, want the partial values url.URL.Query() would return", got)
	}
}
