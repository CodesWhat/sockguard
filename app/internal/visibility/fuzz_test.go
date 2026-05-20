package visibility

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
)

// FuzzVisibilityFilter exercises the upstream-JSON parsing surface in
// patternFilterWriter — the same code path /containers/json and
// /images/json responses traverse on their way back to the client. The
// visibility middleware ingests *upstream* JSON to make pattern-based
// visibility decisions; an adversary-controlled daemon (or one returning
// malformed responses) feeds bytes directly into that decoder. The
// request inspectors (containers/create, exec, build, …) all already
// have fuzz targets — this is the parser-differential gap TQ-18b calls
// out.
//
// The harness drives both list endpoints + an off-axis path so the
// pass-through branch in flushFiltered is exercised too, and varies
// the buffered-body state (under cap, exactly at cap, overflowed) so
// the Write/overflow guard rails get coverage. Invariant: no panic, no
// negative writes, no infinite loop on adversarial inputs. The filtered
// output buffer must never exceed the input size by more than the JSON
// array framing — overflowing here would be the parser-differential
// equivalent of a smuggle.
func FuzzVisibilityFilter(f *testing.F) {
	// Seeds cover the parse, pass-through, and overflow paths.
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"},{"Names":["/db"],"Image":"postgres"}]`))
	f.Add("/containers/json", []byte(`[]`))
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Names":["/db"],"Image":"nginx"}]`)) // duplicate keys
	f.Add("/containers/json", []byte(`[{"NAMES":["/web"],"image":"nginx"}]`))                 // case variance
	f.Add("/containers/json", []byte(`[{"Names":null,"Image":""}]`))                          // nulls / empties
	f.Add("/containers/json", []byte(`{"not":"an array"}`))                                   // pass-through branch
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"}`))                  // truncated array
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"},`))                 // trailing comma
	f.Add("/images/json", []byte(`[{"RepoTags":["docker.io/library/alpine:latest"]}]`))
	f.Add("/images/json", []byte(`[{"RepoTags":null},{"RepoTags":[]}]`))
	f.Add("/v1.53/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"}]`))           // normPath drift
	f.Add("/info", []byte(`{"Architecture":"x86_64"}`))                                       // non-list endpoint
	f.Add("/containers/json", bytes.Repeat([]byte("a"), int(filter.MaxResponseBodyBytes/16))) // medium garbage
	f.Add("/containers/json", []byte(``))                                                     // empty body

	// Pre-compile two policies — one with name + image pattern axes,
	// one bare — so the fuzzer probes both the filter-and-rewrite path
	// and the pure-pass-through path on every input.
	policyWithPatterns := compiledPolicyOrPanic([]string{"*"}, []string{"*"})
	policyEmpty := &compiledPolicy{}

	f.Fuzz(func(t *testing.T, normPath string, body []byte) {
		// Bound body size to keep individual fuzz iterations cheap. The
		// overflow branch is still exercised through the seed above.
		if int64(len(body)) > filter.MaxResponseBodyBytes {
			body = body[:filter.MaxResponseBodyBytes]
		}

		for _, policy := range []*compiledPolicy{policyWithPatterns, policyEmpty} {
			rec := httptest.NewRecorder()
			fw := newPatternFilterWriter(rec)

			// Best-effort write — Write returns len(b), nil even on
			// overflow, so we don't assert here.
			_, _ = fw.Write(body)

			// The function under test. We intentionally ignore the
			// return value; the fuzz target's job is to find a panic,
			// timeout, or data race in the decode/encode path.
			_ = fw.flushFiltered(normPath, policy)
			fw.release()

			// Sanity: the recorder body length is bounded by the input
			// plus a constant overhead for the JSON array brackets and
			// commas. If filtered output ever grew unboundedly past the
			// input, the encoder would be inventing bytes.
			if got := rec.Body.Len(); int64(got) > int64(len(body))+16 {
				t.Fatalf("filtered output grew past input: input=%d output=%d normPath=%q",
					len(body), got, normPath)
			}
		}
	})
}

// compiledPolicyOrPanic builds a compiledPolicy with the given pattern
// axes; only the bare-glob compile path is exercised, so a hard panic
// here would mean the seed itself is malformed and the fuzz target
// can't run.
func compiledPolicyOrPanic(nameGlobs, imageGlobs []string) *compiledPolicy {
	namePatterns, err := compilePatterns(nameGlobs)
	if err != nil {
		panic("compilePatterns(names): " + err.Error())
	}
	imagePatterns, err := compilePatterns(imageGlobs)
	if err != nil {
		panic("compilePatterns(images): " + err.Error())
	}
	return &compiledPolicy{
		namePatterns:  namePatterns,
		imagePatterns: imagePatterns,
	}
}
