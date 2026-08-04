package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// json_mutate.go is the shared JSON document codec for code that writes into
// (rather than merely reads) a Docker API request body: today the admission-
// mutation engine (mutation.go) and internal/ownership's owner-label
// stamping. It consolidates the fold-aware map helpers both packages
// previously kept as separate, independently-maintained copies
// (internal/ownership/middleware.go's nestedObject/foldedObjects family), and
// adds the stricter document codec the admission-mutation engine requires:
// exact-duplicate-key rejection (a hazard plain map-decode cannot see, since
// it silently collapses exact duplicates to last-value-wins before any walk
// of the decoded value could notice), depth/node/EOF/root bounds, and a
// canonicalizing parse used both before and after a mutation is applied.

// mutationMaxDepth caps object/array nesting depth during the admission-
// mutation engine's own strict parse, so the existing per-surface body-size
// cap cannot be turned into pathological recursion via deeply nested (but
// still small) JSON.
const mutationMaxDepth = 128

// mutationMaxNodes bounds the total object-member + array-element count the
// strict scan will walk, derived from the body length actually read so a
// small body cannot decode into an unbounded number of nodes. The minimum
// possible encoding of one additional node is two bytes (e.g. a
// comma-separated `0` or `""`), so bodyLen+1 is always a safe, generous
// upper bound that never rejects a legitimately-shaped body within the
// existing size cap.
func mutationMaxNodes(bodyLen int) int64 {
	return int64(bodyLen) + 1
}

// parseMutationDocument strictly parses body into a single non-null JSON
// object for the admission-mutation engine, failing closed on anything that
// could let a mutation write land ambiguously:
//
//   - exact duplicate object keys at any level, including inside arrays;
//   - case-variant ("folded") duplicate struct-field keys, reusing the
//     existing, already-reviewed checkDuplicateCaseVariantKeys /
//     isCaseSensitiveDataMapField exemption every other body-mutating code
//     path in this package already relies on;
//   - a non-object or null root;
//   - trailing data after the single JSON value;
//   - nesting deeper than mutationMaxDepth or more nodes than maxNodes.
//
// Numbers are preserved as json.Number (UseNumber) so large integer fields
// (Memory limits, PID caps, CPU shares) are never corrupted by a float
// round-trip on re-encode, matching every other JSON-rewriting code path in
// this codebase.
func parseMutationDocument(body []byte, maxNodes int64) (map[string]any, error) {
	if err := scanMutationJSONStrict(body, maxNodes); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if err := requireJSONDecoderEOF(dec); err != nil {
		return nil, err
	}

	doc, ok := v.(map[string]any)
	if !ok || doc == nil {
		return nil, fmt.Errorf("request body must be a single non-null JSON object")
	}
	// The strict scan above already ruled out exact duplicates; this second
	// pass over the now-decoded value catches case-variant ("folded")
	// duplicates the way every other body-mutating path in this package
	// does. Both checks are required: the scan sees exact duplicates the
	// decode already collapsed away, and this fold check sees case-variant
	// siblings that decode to two distinct map keys the scan's per-object
	// exact-string set does not consider equal.
	if err := checkDuplicateCaseVariantKeys(v, false); err != nil {
		return nil, err
	}
	return doc, nil
}

// scanMutationJSONStrict token-scans body — without building a value tree —
// purely to catch what a map-decode cannot: an exact duplicate object key
// anywhere in the document (the decode silently keeps only the last one),
// and to bound nesting depth/node count and require a well-formed single
// object with no trailing data. It does not itself understand case-variant
// (folded) duplicates or field semantics; parseMutationDocument layers the
// existing fold check on top after decoding.
func scanMutationJSONStrict(body []byte, maxNodes int64) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("request body must be a single non-null JSON object")
	}

	nodes := int64(0)
	if err := scanJSONObjectMembers(dec, 1, &nodes, maxNodes); err != nil {
		return err
	}
	return requireJSONDecoderEOF(dec)
}

// scanJSONObjectMembers consumes one JSON object's members (the decoder has
// already consumed the opening '{'), rejecting an exact duplicate key at
// this level and recursing into each member's value. It consumes the
// closing '}' before returning.
func scanJSONObjectMembers(dec *json.Decoder, depth int, nodes *int64, maxNodes int64) error {
	if depth > mutationMaxDepth {
		return fmt.Errorf("json nesting exceeds max depth %d", mutationMaxDepth)
	}
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("decode json: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected JSON object key")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate JSON object key %q", key)
		}
		seen[key] = struct{}{}
		if err := incrementJSONNodeCount(nodes, maxNodes); err != nil {
			return err
		}
		if err := scanJSONValue(dec, depth, nodes, maxNodes); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // consume closing '}'
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

// scanJSONArrayElements consumes one JSON array's elements (the decoder has
// already consumed the opening '['), recursing into each element. It
// consumes the closing ']' before returning.
func scanJSONArrayElements(dec *json.Decoder, depth int, nodes *int64, maxNodes int64) error {
	if depth > mutationMaxDepth {
		return fmt.Errorf("json nesting exceeds max depth %d", mutationMaxDepth)
	}
	for dec.More() {
		if err := incrementJSONNodeCount(nodes, maxNodes); err != nil {
			return err
		}
		if err := scanJSONValue(dec, depth, nodes, maxNodes); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // consume closing ']'
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

// scanJSONValue consumes exactly one JSON value — scalar, object, or array —
// recursing for composite values.
func scanJSONValue(dec *json.Decoder, depth int, nodes *int64, maxNodes int64) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			return scanJSONObjectMembers(dec, depth+1, nodes, maxNodes)
		case '[':
			return scanJSONArrayElements(dec, depth+1, nodes, maxNodes)
		}
	}
	return nil
}

func incrementJSONNodeCount(nodes *int64, maxNodes int64) error {
	*nodes++
	if *nodes > maxNodes {
		return fmt.Errorf("json body exceeds node count cap")
	}
	return nil
}

// requireJSONDecoderEOF reports an error unless dec has no further tokens to
// offer — i.e. the JSON value(s) already consumed were the entire input.
// Used both to reject trailing data after the single top-level object this
// package requires, and (via json.Decoder.Decode's own EOF-checking use) to
// require a decode leaves nothing unconsumed.
func requireJSONDecoderEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing data after JSON value")
		}
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

// deepCloneJSONValue returns an independent copy of a value decoded by
// parseMutationDocument (map[string]any / []any / json.Number / string /
// bool / nil), so a warn/audit-mode mutation rule can be evaluated against a
// clone without ever risking a write to the document that will actually be
// forwarded. Scalar leaves (json.Number, string, bool, nil) are immutable
// value types in Go and are shared, not copied.
func deepCloneJSONValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCloneJSONValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deepCloneJSONValue(val)
		}
		return out
	default:
		return v
	}
}

// NestedObject returns the object stored under key in decoded, creating it
// when absent. Key matching is case-INSENSITIVE and collision-collapsing:
// Docker decodes JSON object keys case-insensitively and, on duplicate
// case-variant keys, lets the last one win. A client could otherwise smuggle
// a lowercase "labels" alongside a proxy-injected "Labels" and — because
// json.Marshal emits map keys in sorted order, placing "labels" after
// "Labels" — have Docker prefer the client's forged value over the one the
// proxy verified. To close that spoof, every key that case-folds to key is
// merged into a single object stored under the exact canonical key, and all
// variant keys are removed, so the re-encoded body carries exactly one
// unambiguous key that Docker reads verbatim.
//
// Exported so both the admission-mutation engine (mutation.go) and
// internal/ownership's owner-label stamping share one reviewed
// implementation instead of two independently-maintained copies of the same
// security-critical fold/merge logic.
func NestedObject(decoded map[string]any, key string) (map[string]any, error) {
	merged := map[string]any{}
	var variants []string
	for k, v := range decoded {
		if !strings.EqualFold(k, key) {
			continue
		}
		variants = append(variants, k)
		if v == nil {
			continue
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", key)
		}
		for kk, vv := range obj {
			merged[kk] = vv
		}
	}
	for _, k := range variants {
		delete(decoded, k)
	}
	decoded[key] = merged
	return merged, nil
}

// NestedObjectPath walks/creates a chain of nested objects via NestedObject,
// e.g. NestedObjectPath(decoded, "TaskTemplate", "ContainerSpec", "Labels").
func NestedObjectPath(decoded map[string]any, keys ...string) (map[string]any, error) {
	current := decoded
	for _, key := range keys {
		next, err := NestedObject(current, key)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

// FoldedObjects returns every object value in m whose key case-folds to key,
// in map-iteration order. Docker decodes duplicate case-variant keys and
// lets the last one win, so a read-side security check must inspect every
// variant rather than an exact-case single lookup.
func FoldedObjects(m map[string]any, key string) []map[string]any {
	var out []map[string]any
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if obj, ok := v.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

// FoldedStrings returns every string value in m whose key case-folds to key.
func FoldedStrings(m map[string]any, key string) []string {
	var out []string
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if value, ok := v.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

// FoldedArrays returns every array value in m whose key case-folds to key.
func FoldedArrays(m map[string]any, key string) [][]any {
	var out [][]any
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if values, ok := v.([]any); ok {
			out = append(out, values)
		}
	}
	return out
}

// FoldedStringEquals reports whether any string value in m whose key
// case-folds to key case-insensitively equals want (after trimming
// whitespace).
func FoldedStringEquals(m map[string]any, key, want string) bool {
	for _, value := range FoldedStrings(m, key) {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

// soleFoldedObject returns the object value of the sole key in m that
// case-folds to name. By the time this is called the document has already
// passed the exact/folded duplicate-key guard in parseMutationDocument, so
// at most one case-variant of name can exist; an absent key or a present key
// whose value is not a JSON object both report ok=false, matching
// "nothing to navigate into" rather than an error — the caller (image-remap
// application) treats a missing target as a no-op, not a failure.
func soleFoldedObject(m map[string]any, name string) (map[string]any, bool) {
	for k, v := range m {
		if !strings.EqualFold(k, name) {
			continue
		}
		obj, ok := v.(map[string]any)
		return obj, ok
	}
	return nil, false
}

// navigateFoldedObjectPath walks a chain of object levels via
// soleFoldedObject without creating missing levels — used by image-remap
// application, which must treat an absent TaskTemplate/ContainerSpec as "no
// image field to remap" rather than fabricating the structure the way
// NestedObjectPath does for label injection.
func navigateFoldedObjectPath(doc map[string]any, keys ...string) (map[string]any, bool) {
	current := doc
	for _, key := range keys {
		next, ok := soleFoldedObject(current, key)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

// foldedStringLeaf returns the value, presence, and string-typedness of the
// sole key in m that case-folds to name. present=false means the key is
// absent; isString=false with present=true means the key exists but its
// value is not a JSON string (a type-mismatch the caller must fail closed
// on, not silently skip).
func foldedStringLeaf(m map[string]any, name string) (value string, present, isString bool) {
	for k, v := range m {
		if !strings.EqualFold(k, name) {
			continue
		}
		s, ok := v.(string)
		return s, true, ok
	}
	return "", false, false
}

// setFoldedStringLeaf collapses any existing case-variant of name in m to
// the canonical spelling and sets it to newValue. At most one variant can
// exist by construction (see soleFoldedObject's doc comment).
func setFoldedStringLeaf(m map[string]any, name, newValue string) {
	for k := range m {
		if strings.EqualFold(k, name) {
			delete(m, k)
			break
		}
	}
	m[name] = newValue
}
