package filter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// maxRuleBodyMatchBytes caps what a `match.body` constraint reads. Every body
// a rule can act on is a JSON object of a few KiB, and the create inspector
// already reads at 1 MiB, so a body larger than this never satisfies a
// body-constrained allow rule. Warn and audit profiles still forward it.
const maxRuleBodyMatchBytes = 1 << 20

// bodyConstraint is one compiled `match.body` entry: the named top-level field
// of a JSON request body has to carry a value matching one of patterns. Like a
// query key, the field name is resolved case-insensitively, because the
// engines' decoders bind a struct field from any spelling. A body carrying
// two case-variant spellings never reaches this comparison: the parity scan
// in newRequestBody already calls it unreadable, so at most one variant of any
// key exists here.
type bodyConstraint struct {
	key      string
	patterns []string
}

// ValidateBodyConstraints reports why a rule's body constraint map cannot be
// compiled, or nil. Shared by the config validator and CompileRule so an
// authoring mistake gets the same wording wherever it is caught. Two names
// that fold to the same field are rejected with it: the matcher resolves a
// name case-insensitively, so two such keys would both address the single
// field the engine sees, and their patterns would AND across one value.
func ValidateBodyConstraints(body map[string][]string) error {
	folded := make(map[string]string, len(body))
	for _, key := range sortedConstraintKeys(body) {
		patterns := body[key]
		if key == "" {
			return fmt.Errorf("body field name must not be empty")
		}
		if hasControlChar(key) {
			return fmt.Errorf("body field %q must not contain control characters", key)
		}
		if len(patterns) == 0 {
			return fmt.Errorf("body field %q needs at least one pattern", key)
		}
		for _, pattern := range patterns {
			if hasControlChar(pattern) {
				return fmt.Errorf("body field %q pattern %q must not contain control characters", key, pattern)
			}
		}
		// canonicalFoldKey is a canonical form of the very fold the matcher
		// weighs names by, so a collision here is exactly a collision there.
		canonical := canonicalFoldKey(key)
		if first, dup := folded[canonical]; dup {
			return fmt.Errorf("body field names %q and %q differ only in letter case, which is ambiguous", first, key)
		}
		folded[canonical] = key
	}
	return nil
}

func compileBodyConstraints(body map[string][]string) ([]bodyConstraint, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if err := ValidateBodyConstraints(body); err != nil {
		return nil, err
	}
	compiled := make([]bodyConstraint, 0, len(body))
	for _, key := range sortedConstraintKeys(body) {
		compiled = append(compiled, bodyConstraint{key: key, patterns: slices.Clone(body[key])})
	}
	return compiled, nil
}

func sortedConstraintKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// matchesValue shares the `match.query` dialect: "*" is a run of any
// characters, empty included, and nothing else is special.
func (c bodyConstraint) matchesValue(value string) bool {
	for _, pattern := range c.patterns {
		if matchGlobSegment(pattern, value) {
			return true
		}
	}
	return false
}

// matchesField weighs one field. The field name resolves case-insensitively,
// the way both engines' decoders bind it: exactly one spelling of the name may
// be present, and it sets the same field whatever its case. A field that is
// absent, spelled two ways, or carries a value that is not a JSON string
// matches nothing: an allow rule then fails, and a deny rule stays silent
// rather than denying on a value it cannot name. A null is a field the engine
// treats as unset, so it counts as absent here.
func (c bodyConstraint) matchesField(fields map[string]json.RawMessage) bool {
	name, err := soleFoldedRawKey(fields, c.key)
	if err != nil {
		return false
	}
	value, ok := bodyStringValue(fields[name])
	if !ok {
		return false
	}
	return c.matchesValue(value)
}

// requestBody is a request's top-level JSON fields, decoded once for the whole
// rule walk. unread says the body was never read, which is not the same as an
// empty object: it is where a body too big to buffer, a body that is not a JSON
// object, and a body with no fields differ.
type requestBody struct {
	fields map[string]json.RawMessage
	unread bool
	static bool
}

// newRequestBody reads and decodes the request body for rule matching. It
// restores the body on every path, so forwarding is unaffected: an oversized
// body keeps the bytes already read in front of the rest, exactly as
// readBoundedBodyUnchecked leaves them.
//
// A body counts as unread unless it is a JSON object whose keys the engines
// read the same way: empty bodies, `null`, non-objects, bodies with a key
// repeated in one spelling or in two that case-fold together at any depth,
// and keys carrying a decoder-divergent character are all unreadable here.
// The scan is the strict form of the json_key_parity check the inspectors
// already run, so a data map's repeated siblings count too: the matcher will
// not guess what a body with a repeat says, wherever the repeat sits, just as
// it will not guess at a query that does not parse. The refusal itself belongs
// to the inspectors, which also rewrite bodies, so a request with an
// ambiguous body is not denied here unless a `match.body` rule is in play.
func newRequestBody(r *http.Request) requestBody {
	if r == nil || r.Body == nil {
		return requestBody{unread: true}
	}
	body, err := readBoundedBodyUnchecked(r, maxRuleBodyMatchBytes)
	if err != nil {
		return requestBody{unread: true}
	}
	if RejectDuplicateCaseVariantJSONKeysStrict(body) != nil {
		return requestBody{unread: true}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return requestBody{unread: true}
	}
	return requestBody{fields: fields}
}

// rulesNeedRequestBody reports whether any body-constrained rule's method and
// path already match, so a policy that never uses `match.body` pays no read and
// no request whose body no constraint can act on pays one either. routePath is
// the encoded libpod image-SCP view, checked alongside the canonical path when
// the request has that shape.
func rulesNeedRequestBody(rules []*CompiledRule, method, normalizedPath, routePath string, encodedScp bool) bool {
	upperMethod := upperHTTPMethodASCII(method)
	methodBit := httpMethodBit(upperMethod)
	for _, rule := range rules {
		if len(rule.body) == 0 {
			continue
		}
		if !rule.matchesNormalizedUpperWithBit(upperMethod, methodBit, normalizedPath) {
			if !encodedScp || !rule.matchesNormalizedUpperWithBit(upperMethod, methodBit, routePath) {
				continue
			}
		}
		return true
	}
	return false
}

// HasBody reports whether the rule carries body constraints.
func (cr *CompiledRule) HasBody() bool {
	return len(cr.body) > 0
}

// matchesBody weighs the rule's body constraints. A rule without constraints
// always passes.
//
// A body that was not read at all — too big to buffer, not a JSON object, or
// with keys the engines could read two ways — is not trusted either way, so it
// fails closed the same way a query that does not parse does: an allow rule
// does not match and a deny rule does.
//
// In static mode the body is unknown, so the rule is read pessimistically for
// exposure: a body-constrained allow counts as matching and a deny does not.
func (cr *CompiledRule) matchesBody(b *requestBody) bool {
	if len(cr.body) == 0 {
		return true
	}
	if b.static {
		return cr.Action == ActionAllow
	}
	if b.unread {
		return cr.Action == ActionDeny
	}
	for _, c := range cr.body {
		if !c.matchesField(b.fields) {
			return false
		}
	}
	return true
}

// bodyStringValue renders one top-level field's value as the text a pattern is
// matched against. Only a JSON string has one: it is decoded, so `""` is the
// empty string. A number, a bool, a null, an object or an array has no string
// value, and the engines would not accept one in its place either — a field
// typed as a string in the engine's own structs 400s when the body spells it
// any other way.
func bodyStringValue(raw json.RawMessage) (string, bool) {
	text := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(text, `"`) {
		return "", false
	}
	var decoded string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", false
	}
	return decoded, true
}

// FormatBody renders body constraints in a stable, human-readable form for rule
// listings, e.g. `name=team-app-*`. Empty when there are none.
func FormatBody(body map[string][]string) string {
	if len(body) == 0 {
		return ""
	}
	var out strings.Builder
	for _, key := range sortedConstraintKeys(body) {
		if out.Len() > 0 {
			out.WriteString(" ")
		}
		out.WriteString(key)
		out.WriteString("=")
		out.WriteString(strings.Join(body[key], "|"))
	}
	return out.String()
}
