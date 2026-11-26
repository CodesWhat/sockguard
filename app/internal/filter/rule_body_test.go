package filter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// match.body scopes a rule on a field of the request body, the write-side twin
// of match.query: naming discipline is only worth something if a create can be
// refused for naming outside its scope.

func bodyRuleRules(t *testing.T, body map[string][]string, action Action, index int) []*CompiledRule {
	t.Helper()
	scoped, err := CompileRule(Rule{
		Methods: []string{http.MethodPost},
		Pattern: "/libpod/containers/create",
		Action:  action,
		Reason:  "scoped",
		Index:   index,
		Body:    body,
	})
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}
	catchAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: index + 1})
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}
	return []*CompiledRule{scoped, catchAll}
}

func postJSON(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.ContentLength = int64(len(body))
	return req
}

func TestCompileRuleRejectsBadBodyConstraints(t *testing.T) {
	for name, body := range map[string]map[string][]string{
		"empty field name":  {"": {"team-app-*"}},
		"no patterns":       {"name": {}},
		"control character": {"name": {"team\u0000app"}},
		// The matcher's fold is Unicode simple case folding, not ToLower:
		// these two names address one field even though their lowercasings
		// differ.
		"case-folded field names": {"ſystemd": {"always"}, "systemd": {"false"}},
	} {
		if _, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/x", Action: ActionAllow, Body: body}); err == nil {
			t.Fatalf("want refusal of %s", name)
		}
	}
}

func TestEvaluateBodyConstraintScopesCreateName(t *testing.T) {
	rules := bodyRuleRules(t, map[string][]string{"name": {"team-app-*"}}, ActionAllow, 0)

	for _, tc := range []struct {
		body string
		want Action
	}{
		{`{"name":"team-app-7","image":"localhost/tool:latest"}`, ActionAllow},
		{`{"name":"other-team-7","image":"localhost/tool:latest"}`, ActionDeny},
		// podman-remote sends the empty name whenever --name is absent.
		{`{"name":"","image":"localhost/tool:latest"}`, ActionDeny},
		{`{"image":"localhost/tool:latest"}`, ActionDeny},
		// A body the rule cannot read never carries an allow.
		{`not json`, ActionDeny},
		{`[{"name":"team-app-7"}]`, ActionDeny},
	} {
		if action, _, _ := Evaluate(rules, postJSON("/libpod/containers/create", tc.body)); action != tc.want {
			t.Fatalf("body %s: action = %s, want %s", tc.body, action, tc.want)
		}
	}
}

func TestEvaluateBodyConstraintOnDenyRule(t *testing.T) {
	rules := bodyRuleRules(t, map[string][]string{"name": {"other-*"}}, ActionDeny, 0)

	if action, index, reason := Evaluate(rules, postJSON("/libpod/containers/create", `{"name":"other-team-7"}`)); action != ActionDeny || index != 0 || reason != "scoped" {
		t.Fatalf("matching field: action=%s index=%d reason=%q, want the deny rule", action, index, reason)
	}
	// A field the rule does not name falls through to the catch-all deny, not
	// to this rule: a constrained deny must not shadow what it cannot see.
	if _, index, _ := Evaluate(rules, postJSON("/libpod/containers/create", `{"name":"team-app-7"}`)); index != 1 {
		t.Fatalf("out-of-scope field: rule index = %d, want the catch-all", index)
	}
	// A body the rule cannot read matches a deny fail-closed, like a query
	// that does not parse.
	if action, index, _ := Evaluate(rules, postJSON("/libpod/containers/create", `not json`)); action != ActionDeny || index != 0 {
		t.Fatalf("unreadable body: action=%s index=%d, want the constrained deny fail-closed", action, index)
	}
}

func TestEvaluateBodyConstraintFoldsFieldNames(t *testing.T) {
	// The engines bind a struct field from any spelling of its name, so one
	// variant in any case is the same field to the matcher too: a lone `Name`
	// is the `name` the rule named.
	allow := bodyRuleRules(t, map[string][]string{"name": {"team-app-*"}}, ActionAllow, 0)
	for _, body := range []string{`{"name":"team-app-7"}`, `{"Name":"team-app-7"}`, `{"NAME":"team-app-7"}`} {
		if action, _, _ := Evaluate(allow, postJSON("/libpod/containers/create", body)); action != ActionAllow {
			t.Fatalf("body %s against a folded allow: action = %s, want allow", body, action)
		}
	}
	// The same fold closes the deny side: spelling the field differently is
	// not a way past a name deny.
	deny := bodyRuleRules(t, map[string][]string{"name": {"prod-*"}}, ActionDeny, 0)
	if action, index, _ := Evaluate(deny, postJSON("/libpod/containers/create", `{"NAME":"prod-db"}`)); action != ActionDeny || index != 0 {
		t.Fatalf("folded body against a name deny: action=%s index=%d, want the deny at index 0", action, index)
	}
	// The rule key's own case is not special either.
	upperKey := bodyRuleRules(t, map[string][]string{"Image": {"alpine*"}}, ActionAllow, 0)
	if action, _, _ := Evaluate(upperKey, postJSON("/libpod/containers/create", `{"image":"alpine:3"}`)); action != ActionAllow {
		t.Fatalf("lowercase body against an Image rule: action = %s, want allow", action)
	}
}

// Bodies the engines' decoders could read two ways are unreadable to the
// matcher, exactly as a query that fails to parse is to match.query. A
// repeated key counts at any depth, a data map's included: the matcher will
// not guess what a body with a repeat says, wherever the repeat sits.
func TestEvaluateBodyConstraintAmbiguousBodies(t *testing.T) {
	allow := bodyRuleRules(t, map[string][]string{"name": {"team-app-*"}}, ActionAllow, 0)
	deny := bodyRuleRules(t, map[string][]string{"name": {"other-*"}}, ActionDeny, 0)
	for _, body := range []string{
		``,
		`null`,
		`{"name":"team-app-7","name":"team-app-8"}`,
		`{"name":"team-app-7","Name":"other-team-7"}`,
		`{"name":"team-app-7","labels":{"k":"1","k":"2"}}`,
		`{"name":"team-app-7","labels":{"k":"1","K":"2"}}`,
	} {
		if action, _, _ := Evaluate(allow, postJSON("/libpod/containers/create", body)); action != ActionDeny {
			t.Fatalf("body %s against a scoped allow: action = %s, want deny", body, action)
		}
		if action, index, _ := Evaluate(deny, postJSON("/libpod/containers/create", body)); action != ActionDeny || index != 0 {
			t.Fatalf("body %s against a scoped deny: action=%s index=%d, want the deny fail-closed", body, action, index)
		}
	}
}

func TestEvaluateBodyConstraintStringValues(t *testing.T) {
	for _, tc := range []struct {
		field   string
		pattern string
		body    string
		want    Action
	}{
		{"systemd", "false", `{"systemd":"false"}`, ActionAllow},
		// Only a JSON string carries a value to match. A number or a bool
		// spelled into a string field fails in the engines themselves, and a
		// null is a field the engine leaves unset, so none of them pass a
		// pattern here.
		{"memory", "1024", `{"memory":1024}`, ActionDeny},
		{"privileged", "true", `{"privileged":true}`, ActionDeny},
		{"name", "team-app-*", `{"name":null}`, ActionDeny},
		{"name", "team-app-*", `{"name":{"a":1}}`, ActionDeny},
		{"name", "team-app-*", `{"name":["team-app-7"]}`, ActionDeny},
	} {
		rules := bodyRuleRules(t, map[string][]string{tc.field: {tc.pattern}}, ActionAllow, 0)
		if action, _, _ := Evaluate(rules, postJSON("/libpod/containers/create", tc.body)); action != tc.want {
			t.Fatalf("body %s against %s=%s: action = %s, want %s", tc.body, tc.field, tc.pattern, action, tc.want)
		}
	}
	// The null and the number fail the same way on the deny side: the
	// constraint does not hold, so the deny stays silent and the request
	// falls through rather than being denied over a value the engines would
	// not honor either.
	deny := bodyRuleRules(t, map[string][]string{"name": {"prod-*"}}, ActionDeny, 0)
	for _, body := range []string{`{"name":null}`, `{"name":123}`, `{"name":true}`} {
		if action, index, _ := Evaluate(deny, postJSON("/libpod/containers/create", body)); action != ActionDeny || index == 0 {
			t.Fatalf("body %s against a name deny: action=%s index=%d, want the fall-through deny, not the constrained one", body, action, index)
		}
	}
}

func TestEvaluateStaticOverReportsBodyConstraints(t *testing.T) {
	constrained, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/libpod/containers/create", Action: ActionAllow, Body: map[string][]string{"name": {"team-app-*"}}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", nil)
	if action, index, _ := EvaluateStatic([]*CompiledRule{constrained}, req); action != ActionAllow || index != 0 {
		t.Fatalf("static constrained allow: action=%s index=%d, want it read as reachable", action, index)
	}

	deny, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/libpod/containers/create", Action: ActionDeny, Reason: "constrained deny", Body: map[string][]string{"name": {"other-*"}}})
	if err != nil {
		t.Fatal(err)
	}
	allow, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/libpod/containers/create", Action: ActionAllow, Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	// A constrained deny never shadows the allow below it in static mode.
	if action, index, _ := EvaluateStatic([]*CompiledRule{deny, allow}, req); action != ActionAllow || index != 1 {
		t.Fatalf("static constrained deny: action=%s index=%d, want the allow at index 1 to own the decision", action, index)
	}
}

// TestMiddlewareBodyConstraintRunsBeforeForwarding pins the two properties the
// design depends on: the rule decision sees the body, and the upstream still
// receives every byte of it.
func TestMiddlewareBodyConstraintRunsBeforeForwarding(t *testing.T) {
	// The explicit "systemd":"false" is the create inspector's own gate, not
	// this rule's: SpecGenerator defaults the field to "true".
	body := `{"name":"team-app-7","image":"localhost/tool:latest","systemd":"false","cmd":["sleep","1"]}`
	rules := bodyRuleRules(t, map[string][]string{"name": {"team-app-*"}}, ActionAllow, 0)

	var forwarded string
	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read forwarded body: %v", err)
		}
		forwarded = string(got)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, postJSON("/libpod/containers/create", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an in-scope name", rec.Code)
	}
	if forwarded != body {
		t.Fatalf("forwarded body = %q, want the body unchanged", forwarded)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, postJSON("/libpod/containers/create", `{"name":"other-team-7"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an out-of-scope name", rec.Code)
	}
}

// TestRequestBodyNotReadForUnrelatedRequest keeps the promise that the read is
// conditional: a policy carrying body rules must not buffer the body of a
// request no body rule can act on.
func TestRequestBodyNotReadForUnrelatedRequest(t *testing.T) {
	rules := bodyRuleRules(t, map[string][]string{"name": {"team-app-*"}}, ActionAllow, 0)
	body := strings.Repeat("x", 4096)
	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", bytes.NewBufferString(body))
	req.ContentLength = int64(len(body))

	if action, _, _ := Evaluate(rules, req); action != ActionDeny {
		t.Fatalf("action = %s, want the catch-all deny", action)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("body readable after evaluation = %d bytes, want %d: the rule layer read it", len(got), len(body))
	}
}

// FuzzRuleBodyMatch holds the body matcher to two independent readings of the
// same contract. Its oracle re-derives what the engines would bind: json into
// map[string]any, a case-folded key lookup, and a string check. A readable
// body must let a "name" allow rule match exactly when that reading finds a
// string under any spelling of name, and an unreadable body must fail the
// allow closed to the catch-all deny. A crash, or the matcher crediting or
// refusing a field its own oracle disagrees about, is a policy decision made
// from a body reading the engine will not share.
func FuzzRuleBodyMatch(f *testing.F) {
	for _, seed := range []string{
		`{"name":"team-app-7"}`,
		`{"Name":"team-app-7"}`,
		`{"name":null}`,
		`{"name":123}`,
		`{"name":{"a":"team-app-7"}}`,
		`{"name":"team-app-7","Name":"other"}`,
		`{"other":1,"name":"x"}`,
		``,
		`null`,
		`{"unterminated":`,
	} {
		f.Add([]byte(seed))
	}
	f.Add([]byte(`{"name":"team-app-7"}`))
	f.Add([]byte(`{"name":"x","other":1e309}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		body = body[:len(body):len(body)]
		rules := bodyRuleRules(t, map[string][]string{"name": {"*"}}, ActionAllow, 0)

		req := postJSON("/libpod/containers/create", string(body))
		action, index, _ := Evaluate(rules, req)

		// The forwarding contract: whatever the matcher read, the engine must
		// still be able to read, whole.
		forwarded, err := io.ReadAll(req.Body)
		if err != nil || !bytes.Equal(forwarded, body) {
			t.Fatalf("body after matching reads back %q (err %v), want %q", forwarded, err, body)
		}

		// Past the matcher's cap it reads nothing, whatever the bytes are.
		if len(body) > maxRuleBodyMatchBytes {
			if action != ActionDeny || index != 1 {
				t.Fatalf("oversized body of %d bytes: action=%s index=%d, want the catch-all deny", len(body), action, index)
			}
			return
		}

		// The oracle reads like the engines do: whole-document syntax only, and
		// numbers kept whole. A float64 conversion would call 1e309 a parse
		// error the daemons (and the matcher's RawMessage) do not share.
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var fields map[string]any
		trailing := new(json.RawMessage)
		oracleOK := dec.Decode(&fields) == nil && fields != nil && dec.Decode(trailing) == io.EOF
		if !oracleOK {
			// Unreadable to any reading: the allow must fail closed.
			if action != ActionDeny || index != 1 {
				t.Fatalf("unreadable body %q: action=%s index=%d, want the catch-all deny", body, action, index)
			}
			return
		}
		if RejectDuplicateCaseVariantJSONKeysStrict(body) != nil {
			// Ambiguous to the parity scan: unreadable, fail closed.
			if action != ActionDeny || index != 1 {
				t.Fatalf("ambiguous body %q: action=%s index=%d, want the catch-all deny", body, action, index)
			}
			return
		}
		stringUnderName := false
		for key, value := range fields {
			if strings.EqualFold(key, "name") {
				if _, ok := value.(string); ok {
					stringUnderName = true
				}
			}
		}
		if want := ActionAllow; stringUnderName != (action == want) {
			t.Fatalf("body %q: oracle sees a string under name = %v, matcher action = %s", body, stringUnderName, action)
		}
	})
}
