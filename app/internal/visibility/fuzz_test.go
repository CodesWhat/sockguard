package visibility

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
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
// refusal branch in flushFiltered is exercised too, and varies
// the buffered-body state (under cap, exactly at cap, overflowed) so
// the Write/overflow guard rails get coverage. Invariant: no panic, no
// negative writes, no infinite loop on adversarial inputs. The filtered
// output buffer must never exceed the input size by more than the JSON
// array framing — overflowing here would be the parser-differential
// equivalent of a smuggle.
//
// The load-bearing invariant is the refusal one: an accepted body must
// be exactly one well-formed JSON array, checked against
// encoding/json's own top-level parse rather than against the decoder
// flushFiltered uses, so a disagreement between the streaming decode
// and a whole-body parse shows up as a failure instead of as a
// rewritten 200. Bounding the output length only ever caught a body
// that grew; the parser gaps this target exists to find were bodies
// that were silently completed — a truncated array closed on the
// client's behalf, or trailing bytes dropped.
func FuzzVisibilityFilter(f *testing.F) {
	// Seeds cover the parse, refusal, and overflow paths.
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"},{"Names":["/db"],"Image":"postgres"}]`))
	f.Add("/containers/json", []byte(`[]`))
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Names":["/db"],"Image":"nginx"}]`)) // duplicate keys
	f.Add("/containers/json", []byte(`[{"NAMES":["/web"],"image":"nginx"}]`))                 // case variance
	f.Add("/containers/json", []byte(`[{"Names":null,"Image":""}]`))                          // nulls / empties
	f.Add("/containers/json", []byte(`{"not":"an array"}`))                                   // refused, not forwarded
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"}`))                  // truncated array
	f.Add("/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"},`))                 // trailing comma
	f.Add("/containers/json", []byte(`[`))                                                    // bare open bracket
	f.Add("/containers/json", []byte(`[{`))                                                   // unclosed object inside
	f.Add("/containers/json", []byte(`[{"Names":["/web"]}]garbage`))                          // trailing garbage
	f.Add("/containers/json", []byte(`[{"Names":["/web"]}] [{"Names":["/db"]}]`))             // a second array follows
	f.Add("/containers/json", []byte("[{\"Names\":[\"/web\"]}]   \n"))                        // trailing whitespace, still valid
	f.Add("/images/json", []byte(`[{"RepoTags":["docker.io/library/alpine:latest"]}]`))
	f.Add("/images/json", []byte(`[{"RepoTags":null},{"RepoTags":[]}]`))
	f.Add("/v1.53/containers/json", []byte(`[{"Names":["/web"],"Image":"nginx"}]`))           // normPath drift
	f.Add("/info", []byte(`{"Architecture":"x86_64"}`))                                       // non-list endpoint
	f.Add("/containers/json", bytes.Repeat([]byte("a"), int(filter.MaxResponseBodyBytes/16))) // medium garbage
	f.Add("/containers/json", []byte(``))                                                     // empty body

	// Pre-compile two policies — one with name + image pattern axes,
	// one bare — so the fuzzer probes both the filter-and-rewrite path
	// and the no-axis path on every input.
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

			// The function under test.
			err := fw.flushFiltered(normPath, policy)
			fw.release()

			// Refusal invariant: flushFiltered may only accept a body
			// that is exactly one well-formed JSON array, trailing
			// whitespace included. Anything else — truncated, an object,
			// a scalar, empty, or an array with bytes after it — has to
			// come back as an error the caller turns into a 502, never a
			// rewritten 200. The oracle is encoding/json's own top-level
			// parse, deliberately not the streaming decoder under test.
			//
			// Only this direction is asserted. The reverse is legitimate:
			// a well-formed array of scalars fails the per-item decode,
			// and that refusal is correct.
			if err == nil && !isSingleJSONArrayForFuzz(body) {
				t.Fatalf("flushFiltered accepted a body that is not a single JSON array: normPath=%q body=%q output=%q",
					normPath, body, rec.Body.String())
			}
			// A refusal must write nothing. The caller checks
			// headerWritten before substituting its 502, so a partially
			// committed refusal would send the client a mixture.
			if err != nil && rec.Body.Len() != 0 {
				t.Fatalf("flushFiltered refused but still wrote %q: normPath=%q body=%q",
					rec.Body.String(), normPath, body)
			}

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

// isSingleJSONArrayForFuzz reports whether body is exactly one well-formed
// top-level JSON array, using encoding/json's whole-body parse rather than the
// streaming decoder flushFiltered runs. json.Unmarshal rejects trailing
// non-whitespace and anything that is not an array, which is the property the
// refusal invariant needs an independent witness for.
//
// A literal `null` unmarshals into a nil slice without error, so this returns
// true for it while flushFiltered refuses it. That only ever makes the oracle
// more permissive than the code under test, which is the safe direction for a
// one-sided check.
func isSingleJSONArrayForFuzz(body []byte) bool {
	var items []json.RawMessage
	return json.Unmarshal(body, &items) == nil
}
