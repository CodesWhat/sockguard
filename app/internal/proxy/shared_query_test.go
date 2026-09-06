package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

func sharedQueryRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	return r.WithContext(logging.WithMeta(r.Context(), &logging.RequestMeta{}))
}

// TestStreamClassificationSharesOneQueryParse pins this package's per-request
// repeat: dockerBoolValueOrDefault probed the query for the key's presence and
// then parsed it a second time to read the value.
func TestStreamClassificationSharesOneQueryParse(t *testing.T) {
	r := sharedQueryRequest(http.MethodGet, "/containers/abc/stats?stream=0&one-shot=1")

	if dockerBoolValueOrDefault(r, "stream", true) {
		t.Fatal("dockerBoolValueOrDefault(stream) = true, want false for stream=0")
	}

	allocs := testing.AllocsPerRun(50, func() {
		_ = dockerBoolValueOrDefault(r, "stream", true)
	})
	if allocs != 0 {
		t.Fatalf("presence probe plus value read allocated %v times, want 0 (one shared parse)", allocs)
	}
}

// TestLongLivedClassificationMatchesWithAndWithoutSharedQuery requires the
// request-deadline classifier to reach the same verdict whether or not the
// per-request state the memo lives on is attached.
func TestLongLivedClassificationMatchesWithAndWithoutSharedQuery(t *testing.T) {
	cases := []struct {
		name           string
		method         string
		target         string
		podmanUpstream bool
		want           bool
	}{
		{"stats_streams_by_default", http.MethodGet, "/containers/abc/stats", false, true},
		{"stats_one_shot_is_finite", http.MethodGet, "/containers/abc/stats?stream=0", false, false},
		{"logs_follow_streams", http.MethodGet, "/containers/abc/logs?follow=yes&stdout=1", false, true},
		{"logs_without_follow_is_finite", http.MethodGet, "/containers/abc/logs?stdout=1&tail=100", false, false},
		{"libpod_top_stream_streams", http.MethodGet, "/libpod/containers/abc/top?Stream=true", true, true},
		{"compat_top_stream_streams", http.MethodGet, "/containers/abc/top?Stream=on", true, true},
		{"compat_top_finite", http.MethodGet, "/containers/abc/top?ps_args=aux", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain := httptest.NewRequest(tc.method, tc.target, nil)
			plainGot := isLongLivedUpstreamRequestForFlavor(httptest.NewRecorder(), plain, tc.podmanUpstream)

			shared := sharedQueryRequest(tc.method, tc.target)
			sharedGot := isLongLivedUpstreamRequestForFlavor(httptest.NewRecorder(), shared, tc.podmanUpstream)

			if plainGot != sharedGot {
				t.Fatalf("classification with the shared parse = %v, want the unshared %v", sharedGot, plainGot)
			}
			if sharedGot != tc.want {
				t.Fatalf("isLongLivedUpstreamRequestForFlavor() = %v, want %v", sharedGot, tc.want)
			}
		})
	}
}

// TestDeadlineClassifierSeesRewrittenQuery is the regression guard for the one
// way a shared parse could go wrong here. ownership and visibility rewrite
// r.URL.RawQuery after the filter has already read the query, and this
// classifier runs after both of them, so it has to see the rewritten query and
// not the parse cached before the rewrite.
func TestDeadlineClassifierSeesRewrittenQuery(t *testing.T) {
	r := sharedQueryRequest(http.MethodGet, "/containers/abc/stats?stream=1")

	// The filter reads the query first, filling the memo.
	if got := logging.RequestQuery(r).Get("stream"); got != "1" {
		t.Fatalf("RequestQuery().Get(stream) = %q, want %q", got, "1")
	}

	// A middleware between the filter and here rewrites it.
	r.URL.RawQuery = "stream=0"

	if isLongLivedUpstreamRequestForFlavor(httptest.NewRecorder(), r, false) {
		t.Fatal("classifier read the pre-rewrite stream=1, want the rewritten stream=0")
	}
}
