package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// ---------------------------------------------------------------------------
// Oracles
// ---------------------------------------------------------------------------
//
// RejectDuplicateCaseVariantJSONKeys locates object keys by walking the raw
// bytes, so it owns a parser that a security guard depends on. Two independent
// oracles hold it in place:
//
//   - decodeCaseVariantOracle is the tree-building form the scan replaced. It
//     is the guard as it shipped, so anything it calls a duplicate the scan
//     must still reject. It is not an equality oracle: a decode collapses
//     byte-identical keys before the walk ever sees them, which is exactly the
//     blind spot the scan closes.
//   - tokenCaseVariantReference applies the scan's rule to json.Decoder's own
//     tokenizer. It shares the rule and none of the parsing, so it is the
//     equality oracle for every body encoding/json can parse — which is the
//     only class of body that matters, because all four call sites re-parse
//     with encoding/json immediately after the guard and reject there.

// decodeCaseVariantOracle decodes body into a tree and walks it, which is what
// RejectDuplicateCaseVariantJSONKeys did before it became a byte scan. It
// reports the decode failure separately from the duplicate verdict so a test
// can tell "this body does not parse" from "this body is ambiguous".
func decodeCaseVariantOracle(body []byte) (duplicate bool, decodeErr error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return false, err
	}
	return RejectDuplicateCaseVariantJSONValue(v) != nil, nil
}

// tokenCaseVariantReference is the scan's rule expressed against
// json.Decoder.Token: same sibling fold-check, same one-level data-map
// exemption, same recursion into an exempt value, same nesting cap, and like
// json.Decoder.Decode it consumes one value and ignores what follows. It is
// far slower than the byte scan (Token boxes and allocates every token), which
// is why it lives here and not in the guard.
func tokenCaseVariantReference(body []byte) error {
	type frame struct {
		object    bool
		skip      bool
		expectKey bool
		keys      []string
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var stack []frame
	nextSkip := false
	finishValue := func() {
		if top := &stack[len(stack)-1]; top.object {
			top.expectKey = true
		}
	}

	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}

		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
			top := &stack[n-1]
			key, isKey := tok.(string)
			if !isKey { // the only other token the grammar allows here is '}'
				stack = stack[:n-1]
				if len(stack) == 0 {
					return nil
				}
				finishValue()
				nextSkip = false
				continue
			}
			if !top.skip {
				for _, prev := range top.keys {
					if strings.EqualFold(prev, key) {
						return errCaseVariantScanSyntax // any non-nil: only the verdict is compared
					}
				}
				top.keys = append(top.keys, key)
			}
			nextSkip = !top.skip && isCaseSensitiveDataMapField(key)
			top.expectKey = false
			continue
		}

		if delim, isDelim := tok.(json.Delim); isDelim {
			if delim == '{' || delim == '[' {
				if len(stack) == maxJSONNestingDepth {
					return errCaseVariantScanTooDeep
				}
				stack = append(stack, frame{object: delim == '{', skip: nextSkip, expectKey: delim == '{'})
				nextSkip = false
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return nil
			}
			finishValue()
			nextSkip = false
			continue
		}

		if len(stack) == 0 {
			return nil
		}
		finishValue()
		nextSkip = false
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// caseVariantScanBodies are the inputs where the byte scan is most likely to
// drift from the rule: the data-map exemption and its one-level scope, arrays
// of structs, escaped and non-ASCII keys, byte-identical duplicates,
// encoding/json's nesting cap, trailing bytes after the first value, and
// malformed input.
var caseVariantScanBodies = []string{
	`{}`,
	`[]`,
	`null`,
	`1`,
	`"s"`,
	`true`,
	``,
	`   `,
	`{"Image":"x","HostConfig":{"Privileged":true},"Labels":{"foo":"bar"}}`,
	`{"HostConfig":{"a":1},"hostconfig":{"b":2}}`,
	`{"HostConfig":{"Privileged":true,"privileged":false}}`,
	`{"Env":[{"K":1,"k":2}]}`,
	`{"Labels":{"Foo":"1","foo":"2"}}`,
	`{"Labels":{"Foo":"1"},"labels":{"foo":"2"}}`,
	`{"Annotations":{"A":"1","a":"2"}}`,
	`{"IPAM":{"Config":[{"AuxiliaryAddresses":{},"auxiliaryaddresses":{}}]}}`,
	`{"IPAM":{"Config":[{"AuxiliaryAddresses":{"A":"1","a":"2"}}]}}`,
	`{"NetworkingConfig":{"EndpointsConfig":{"n":{"NetworkID":"a","networkid":"b"}}}}`,
	`{"NetworkingConfig":{"EndpointsConfig":{"config":{"NetworkID":"a","networkid":"b"}}}}`,
	`{"HostConfig":{"LogConfig":{"Config":{"Max-Size":"1","max-size":"2"}}}}`,
	`{"HostConfig":{"Tmpfs":{"/T":"rw","/t":"rw"}}}`,
	`{"Mounts":[{"Type":"volume","Source":"v"},{"Type":"bind","source":"/s","Source":"/t"}]}`,
	`{"HostConfig":{"Memory":9007199254740993}}`,
	`{"a":1e999}`,
	`{"a":-1.5e+10,"b":true,"c":false,"d":null}`,
	`{"Options":{"O":"1","o":"2"},"options":{}}`,
	`[[[{"A":1,"a":2}]]]`,
	`{ "A" : 1 , "B" : [ { "c" : 2 } ] }`,
	"{\n\t\"A\": 1,\r\n\t\"a\": 2\n}",
	`{"a":{}} trailing`,
	`{"A":1,"a":2}{"ignored":true}`,
	`{"a":1,`,
	`{bad}`,
	`{"a":01}`,
	`{"A":1,"a":2}`,
	`{"ß":1,"SS":2}`,
	`{"é":1,"É":2}`,
	`{"K":1,"K":2}`,
	`{"K":{"A":1},"K":{"a":2}}`,
	`{"Image":"a","image":"b"}`,
	`{"a\"b":1,"A\"B":2}`,
	`{"a\\":1,"A\\":2}`,
	`{"Labels":{"A":"1","a":"2"}}`,
	`{"emptykey":"","":1,"":2}`,
	`{"x":"a\"}\"b","X":1}`,
	`{"x":"[{,:","X":1}`,
}

// TestCaseVariantScanMatchesTokenReference is the equality check: for every
// body encoding/json can parse, the byte scan's verdict must match the same
// rule applied to json.Decoder's own tokenizer. This is what catches a
// mis-parse — a quote, escape or primitive the scan walks past incorrectly
// would put it in the wrong object and lose a duplicate.
func TestCaseVariantScanMatchesTokenReference(t *testing.T) {
	t.Parallel()
	for _, body := range caseVariantScanBodies {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			if _, decodeErr := decodeCaseVariantOracle([]byte(body)); decodeErr != nil {
				t.Skipf("body does not parse (%v); every call site rejects it at its own decode", decodeErr)
			}
			scanErr := RejectDuplicateCaseVariantJSONKeys([]byte(body))
			refErr := tokenCaseVariantReference([]byte(body))
			if (scanErr != nil) != (refErr != nil) {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, token reference error = %v", scanErr, refErr)
			}
		})
	}
}

// TestCaseVariantScanStillRejectsWhatTheTreeRejected is the containment check
// against the guard as it shipped: every body the decode-and-walk form called
// ambiguous must still be rejected. A body that used to be denied and is now
// forwarded is a filter bypass, which is the only direction that matters.
func TestCaseVariantScanStillRejectsWhatTheTreeRejected(t *testing.T) {
	t.Parallel()
	for _, body := range caseVariantScanBodies {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			duplicate, decodeErr := decodeCaseVariantOracle([]byte(body))
			if decodeErr != nil || !duplicate {
				t.Skip("the tree form did not call this body ambiguous")
			}
			if err := RejectDuplicateCaseVariantJSONKeys([]byte(body)); err == nil {
				t.Fatal("RejectDuplicateCaseVariantJSONKeys() error = nil, want the rejection the tree form gave")
			}
		})
	}
}

// TestCaseVariantScanRejectsByteIdenticalDuplicateKeys covers what the scan
// added over the tree it replaced. A repeated key is invisible to any decode —
// the map keeps one entry — yet Go merges the two objects into the struct
// sockguard inspects while a re-marshal through map[string]json.RawMessage
// forwards only the last. The first body below is that split in its
// load-bearing form: the memory limit is in the copy sockguard validates and
// absent from the copy the daemon would receive.
func TestCaseVariantScanRejectsByteIdenticalDuplicateKeys(t *testing.T) {
	t.Parallel()
	bodies := []string{
		`{"HostConfig":{"Memory":268435456},"HostConfig":{"Privileged":false}}`,
		`{"Image":"trusted","Image":"untrusted"}`,
		`{"TaskTemplate":{"ContainerSpec":{"Image":"a","Image":"b"}}}`,
		`{"a":1,"b":2,"a":3}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			if err := RejectDuplicateCaseVariantJSONKeys([]byte(body)); err == nil {
				t.Fatal("RejectDuplicateCaseVariantJSONKeys() error = nil, want a duplicate-key rejection")
			}
			// The exemption must not launder a repeated key either: the data
			// map's own leaf keys are exempt, its field name is not.
			if duplicate, decodeErr := decodeCaseVariantOracle([]byte(body)); decodeErr != nil || duplicate {
				t.Fatalf("fixture should decode cleanly and look clean to the tree form, got duplicate=%v err=%v", duplicate, decodeErr)
			}
		})
	}
}

// TestCaseVariantScanAllowsRepeatedDataMapEntries pins the other side of that
// widening: inside a case-sensitive data map the keys are user data, so two
// entries differing only in case are two legitimate entries and stay allowed.
func TestCaseVariantScanAllowsRepeatedDataMapEntries(t *testing.T) {
	t.Parallel()
	bodies := []string{
		`{"Labels":{"Foo":"1","foo":"2"}}`,
		`{"HostConfig":{"Sysctls":{"NET.x":"1","net.x":"2"}}}`,
		`{"HostConfig":{"LogConfig":{"Config":{"Max-Size":"1","max-size":"2"}}}}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			if err := RejectDuplicateCaseVariantJSONKeys([]byte(body)); err != nil {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, want nil", err)
			}
		})
	}
}

// TestCaseVariantScanEnforcesNestingCap covers the limit the scan has to carry
// itself: json.Decoder.Decode rejects more than 10000 open containers, and
// without the same cap a deeply nested body would both pass a guard that used
// to reject it and drive the scan's recursion arbitrarily deep.
func TestCaseVariantScanEnforcesNestingCap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "arrays at the cap", body: strings.Repeat("[", maxJSONNestingDepth) + strings.Repeat("]", maxJSONNestingDepth)},
		{name: "arrays one past the cap", body: strings.Repeat("[", maxJSONNestingDepth+1) + strings.Repeat("]", maxJSONNestingDepth+1), wantErr: true},
		{name: "objects at the cap", body: strings.Repeat(`{"a":`, maxJSONNestingDepth) + "1" + strings.Repeat("}", maxJSONNestingDepth)},
		{name: "objects one past the cap", body: strings.Repeat(`{"a":`, maxJSONNestingDepth+1) + "1" + strings.Repeat("}", maxJSONNestingDepth+1), wantErr: true},
		{name: "unterminated past the cap", body: strings.Repeat("[", maxJSONNestingDepth+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := RejectDuplicateCaseVariantJSONKeys([]byte(tt.body)); (err != nil) != tt.wantErr {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCaseVariantScanIsAllocationFree is the point of the rewrite: the guard
// ran ahead of a decode it could not share a tree with, so the tree it built
// was pure overhead. A body without escaped object keys must now cost nothing
// but the per-depth key buffers.
func TestCaseVariantScanIsAllocationFree(t *testing.T) {
	if err := RejectDuplicateCaseVariantJSONKeys(benchCaseVariantContainerCreateBody); err != nil {
		t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v", err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if err := RejectDuplicateCaseVariantJSONKeys(benchCaseVariantContainerCreateBody); err != nil {
			t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v", err)
		}
	})
	// One key buffer per nesting depth plus the slice that holds them. The
	// bound is the depth of the fixture, not zero, and it is deliberately
	// loose enough to survive a growth-policy change in the runtime.
	if allocs > 24 {
		t.Fatalf("RejectDuplicateCaseVariantJSONKeys() allocs = %v, want <= 24", allocs)
	}
}

// FuzzDuplicateCaseVariantKeyScan holds the byte scan to both oracles on
// arbitrary bytes: it must agree with the token reference on everything
// encoding/json can parse, and it must still reject everything the tree form
// called ambiguous. The scan runs before any policy decision at four call
// sites, so a body it accepts and the tree form rejected is a filter bypass.
func FuzzDuplicateCaseVariantKeyScan(f *testing.F) {
	for _, seed := range caseVariantScanBodies {
		f.Add([]byte(seed))
	}
	f.Add(benchCaseVariantContainerCreateBody)
	f.Add(benchCaseVariantLibpodCreateBody)
	f.Add(benchCaseVariantServiceCreateBody)
	f.Add([]byte(benchCaseVariantContainerUpdateBody))

	f.Fuzz(func(t *testing.T, body []byte) {
		scanErr := RejectDuplicateCaseVariantJSONKeys(body)

		duplicate, decodeErr := decodeCaseVariantOracle(body)
		if decodeErr != nil {
			// The body does not parse, so every call site rejects it at its
			// own decode a line later and the guard's verdict cannot matter.
			return
		}
		if duplicate && scanErr == nil {
			t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = nil for a body the tree form rejected: %q", body)
		}
		if refErr := tokenCaseVariantReference(body); (scanErr != nil) != (refErr != nil) {
			t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, token reference error = %v, body %q", scanErr, refErr, body)
		}
	})
}

// wideCaseVariantBody builds one JSON object with count distinct keys, and
// optionally appends a final key that case-folds to the first one, so a test
// can put the duplicate on either side of the pairwise/hashed switch.
func wideCaseVariantBody(count int, appendCaseVariantOfFirst bool) []byte {
	var b strings.Builder
	b.Grow(count * 12)
	b.WriteByte('{')
	for i := range count {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:0", fmt.Sprintf("k%07d", i))
	}
	if appendCaseVariantOfFirst {
		fmt.Fprintf(&b, ",%q:1", "K0000000")
	}
	b.WriteByte('}')
	return []byte(b.String())
}

// TestCaseVariantScanCrossesTheFanoutLimit pins the switch from the pairwise
// duplicate check to the hashed one. The two forms have to give the same
// verdict on both sides of caseVariantFoldFanoutLimit and across it, because
// the boundary is an implementation detail and a duplicate that lands on the
// wrong side of it would be a filter bypass.
func TestCaseVariantScanCrossesTheFanoutLimit(t *testing.T) {
	tests := []struct {
		name       string
		count      int
		duplicate  bool
		wantReject bool
	}{
		{name: "one under the limit, all distinct", count: caseVariantFoldFanoutLimit - 1},
		{name: "at the limit, all distinct", count: caseVariantFoldFanoutLimit},
		{name: "one over the limit, all distinct", count: caseVariantFoldFanoutLimit + 1},
		{name: "far over the limit, all distinct", count: 4 * caseVariantFoldFanoutLimit},
		{
			name:       "the last pairwise sibling is a case variant of the first",
			count:      caseVariantFoldFanoutLimit - 1,
			duplicate:  true,
			wantReject: true,
		},
		{
			name:       "the first hashed sibling is a case variant of the first",
			count:      caseVariantFoldFanoutLimit,
			duplicate:  true,
			wantReject: true,
		},
		{
			name:       "a much later hashed sibling is a case variant of the first",
			count:      10 * caseVariantFoldFanoutLimit,
			duplicate:  true,
			wantReject: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := wideCaseVariantBody(tt.count, tt.duplicate)
			if !json.Valid(body) {
				t.Fatalf("fixture is not valid JSON")
			}
			err := RejectDuplicateCaseVariantJSONKeys(body)
			if tt.wantReject {
				if err == nil {
					t.Fatalf("RejectDuplicateCaseVariantJSONKeys() = nil, want a duplicate-key error")
				}
				const want = `duplicate case-variant JSON keys "k0000000" and "K0000000"`
				if err.Error() != want {
					t.Fatalf("error = %q, want %q", err.Error(), want)
				}
				return
			}
			if err != nil {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, want nil", err)
			}
			// The token reference shares the rule and none of the parsing, so
			// it is the independent verdict on the same body.
			if refErr := tokenCaseVariantReference(body); refErr != nil {
				t.Fatalf("tokenCaseVariantReference() error = %v, want nil", refErr)
			}
		})
	}
}

// TestCaseVariantScanHandlesAWideObject drives the hashed path at the width
// the 1 MiB create-body cap allows: a clean 80,000-key object passes and the
// same object with a case-variant duplicate in its last position is still
// rejected. The linearity claim itself is BenchmarkCaseVariantScanWideObject
// below; a wall-clock bound here was measured at 1.9s under -race with atomic
// coverage on a hosted runner, so it is not something a test can assert.
func TestCaseVariantScanHandlesAWideObject(t *testing.T) {
	body := wideCaseVariantBody(80_000, false)
	if len(body) > maxContainerCreateBodyBytes {
		t.Fatalf("fixture is %d bytes, past the %d byte create-body cap", len(body), maxContainerCreateBodyBytes)
	}
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v", err)
	}

	// Same width, duplicate at the very end: the hashed form still has to
	// find it.
	dup := wideCaseVariantBody(80_000, true)
	if err := RejectDuplicateCaseVariantJSONKeys(dup); err == nil {
		t.Fatal("RejectDuplicateCaseVariantJSONKeys() = nil for a duplicate at position 80000, want an error")
	}
}

// BenchmarkCaseVariantScanWideObject is the linearity evidence for the
// hashed sibling path: 80,000 keys at the create-body cap ran in 13.55s
// pairwise and 10.8ms hashed on the machine that landed the change.
func BenchmarkCaseVariantScanWideObject(b *testing.B) {
	body := wideCaseVariantBody(80_000, false)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for range b.N {
		if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
			b.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v", err)
		}
	}
}

// TestCanonicalFoldKeyMatchesEqualFold is the load-bearing claim under the
// hashed path: the map can only stand in for the pairwise comparison if
// having the same canonical form is the same relation as strings.EqualFold.
// It is checked exhaustively over the BMP and the first two supplementary
// planes rather than on a sample, because a single rune whose fold class the
// canonical form splits is a key pair the guard would stop catching.
func TestCanonicalFoldKeyMatchesEqualFold(t *testing.T) {
	for r := rune(0); r <= 0x2FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF { // surrogates are not encodable
			continue
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			a, b := string(r), string(f)
			if canonicalFoldKey(a) != canonicalFoldKey(b) {
				t.Fatalf("canonicalFoldKey(%q) = %q, canonicalFoldKey(%q) = %q, want equal (same fold class)",
					a, canonicalFoldKey(a), b, canonicalFoldKey(b))
			}
			if !strings.EqualFold(a, b) {
				t.Fatalf("strings.EqualFold(%q, %q) = false but they share a fold class", a, b)
			}
		}
	}

	pairs := []struct {
		a, b string
		want bool
	}{
		{a: "HostConfig", b: "hostconfig", want: true},
		{a: "HostConfig", b: "HostConfig", want: true},
		{a: "K", b: "K", want: true},  // Kelvin sign
		{a: "S", b: "ſ", want: true},  // long s
		{a: "ſ", b: "s", want: true},  // and the other way round
		{a: "I", b: "ı", want: false}, // dotless i is its own class
		{a: "Image", b: "Images", want: false},
		{a: "\x80", b: "\x81", want: true}, // both decode to U+FFFD
		{a: "�", b: "\x80", want: true},
		{a: "\U0001F600", b: "\U0001F600", want: true},
		{a: "", b: "", want: true},
	}
	for _, p := range pairs {
		gotCanonical := canonicalFoldKey(p.a) == canonicalFoldKey(p.b)
		gotFold := strings.EqualFold(p.a, p.b)
		if gotCanonical != p.want || gotFold != p.want {
			t.Fatalf("%q vs %q: canonical=%v equalFold=%v, want %v", p.a, p.b, gotCanonical, gotFold, p.want)
		}
	}
}
