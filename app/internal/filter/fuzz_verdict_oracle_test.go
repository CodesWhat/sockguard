package filter

import (
	"bytes"
	"encoding/json"
	"testing"
)

// fuzzCompactVerdictCap bounds the bodies the whitespace differential runs on.
// Compacting shrinks a body, so a body near a per-inspector size limit could
// legitimately flip from "too large" to "allowed". Every inspector limit is
// well above this.
const fuzzCompactVerdictCap = 256

// fuzzVerdictOracle gives a panic-only inspector fuzz target a verdict check.
// run inspects body through a fresh request each call and returns the verdict.
// It asserts two invariants that hold for any pure inspector:
//
//   - determinism: the same input yields the same allow/deny class twice, so a
//     deny can never be a one-off.
//   - whitespace stability: for a valid JSON body, eliding insignificant
//     whitespace (json.Compact keeps every key, value and order) must not turn
//     a deny into an allow, or the reverse.
//
// Only the allow/deny class is compared, never the reason text, which can
// legitimately vary (offsets, map order). It returns the first verdict so a
// caller can layer a target-specific oracle on top.
func fuzzVerdictOracle(t *testing.T, label string, body []byte, run func([]byte) (string, error)) (string, error) {
	t.Helper()

	reason, err := run(body)
	again, errAgain := run(body)
	if denied(reason, err) != denied(again, errAgain) {
		t.Fatalf("%s: verdict is not deterministic: first denied=%v (%q, %v), second denied=%v (%q, %v)",
			label, denied(reason, err), reason, err, denied(again, errAgain), again, errAgain)
	}

	if len(body) <= fuzzCompactVerdictCap && json.Valid(body) {
		var compact bytes.Buffer
		if json.Compact(&compact, body) == nil && !bytes.Equal(compact.Bytes(), body) {
			cReason, cErr := run(compact.Bytes())
			if denied(reason, err) != denied(cReason, cErr) {
				t.Fatalf("%s: whitespace changed the verdict: original denied=%v (%q, %v), compact denied=%v (%q, %v)\noriginal: %q\ncompact:  %q",
					label, denied(reason, err), reason, err, denied(cReason, cErr), cReason, cErr, body, compact.Bytes())
			}
		}
	}
	return reason, err
}
