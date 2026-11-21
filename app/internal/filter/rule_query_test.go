package filter

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func queryRequest(method, path, rawQuery string) *http.Request {
	return &http.Request{Method: method, URL: &url.URL{Path: path, RawQuery: rawQuery}}
}

func mustCompileQueryRule(t *testing.T, action Action, query map[string][]string) []*CompiledRule {
	t.Helper()
	rule, err := CompileRule(Rule{
		Methods: []string{"POST"},
		Pattern: "/containers/*/kill",
		Action:  action,
		Query:   query,
	})
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}
	return []*CompiledRule{rule}
}

func TestEvaluateQueryConstraints(t *testing.T) {
	t.Parallel()

	const killPath = "/containers/abc/kill"
	signal := map[string][]string{"signal": {"USR1", "SIGUSR1"}}

	tests := []struct {
		name      string
		action    Action
		query     map[string][]string
		method    string
		rawQuery  string
		wantMatch bool
	}{
		{name: "present and matches", action: ActionAllow, query: signal, rawQuery: "signal=USR1", wantMatch: true},
		{name: "second listed pattern", action: ActionAllow, query: signal, rawQuery: "signal=SIGUSR1", wantMatch: true},
		{name: "present but different value", action: ActionAllow, query: signal, rawQuery: "signal=KILL"},
		{name: "absent key", action: ActionAllow, query: signal, rawQuery: ""},
		{name: "other key only", action: ActionAllow, query: signal, rawQuery: "force=1"},
		{name: "key is case-sensitive", action: ActionAllow, query: signal, rawQuery: "Signal=USR1"},
		{name: "value is case-sensitive", action: ActionAllow, query: signal, rawQuery: "signal=usr1"},
		{name: "repeated key one bad value", action: ActionAllow, query: signal, rawQuery: "signal=USR1&signal=KILL"},
		{name: "repeated key bad value first", action: ActionAllow, query: signal, rawQuery: "signal=KILL&signal=USR1"},
		{name: "repeated key all good", action: ActionAllow, query: signal, rawQuery: "signal=USR1&signal=SIGUSR1", wantMatch: true},
		{name: "unlisted params ignored", action: ActionAllow, query: signal, rawQuery: "force=1&signal=USR1&x=%00", wantMatch: true},
		{name: "url-encoded value decoded", action: ActionAllow, query: map[string][]string{"signal": {"USR1"}}, rawQuery: "signal=%55SR1", wantMatch: true},
		{name: "url-encoded key decoded", action: ActionAllow, query: signal, rawQuery: "%73ignal=USR1", wantMatch: true},
		{name: "plus decodes to space", action: ActionAllow, query: map[string][]string{"n": {"a b"}}, rawQuery: "n=a+b", wantMatch: true},
		{name: "glob suffix", action: ActionAllow, query: map[string][]string{"signal": {"SIG*"}}, rawQuery: "signal=SIGTERM", wantMatch: true},
		{name: "glob suffix miss", action: ActionAllow, query: map[string][]string{"signal": {"SIG*"}}, rawQuery: "signal=TERM"},
		{name: "glob matches empty run", action: ActionAllow, query: map[string][]string{"signal": {"SIG*"}}, rawQuery: "signal=SIG", wantMatch: true},
		{name: "glob crosses slash", action: ActionAllow, query: map[string][]string{"f": {"a*c"}}, rawQuery: "f=a/b/c", wantMatch: true},
		{name: "glob in the middle", action: ActionAllow, query: map[string][]string{"f": {"a*c*e"}}, rawQuery: "f=abcde", wantMatch: true},
		{name: "question mark is literal", action: ActionAllow, query: map[string][]string{"f": {"a?c"}}, rawQuery: "f=abc"},
		{name: "regex metachars are literal", action: ActionAllow, query: map[string][]string{"f": {"a.c"}}, rawQuery: "f=abc"},
		{name: "empty pattern matches empty value", action: ActionAllow, query: map[string][]string{"f": {""}}, rawQuery: "f=", wantMatch: true},
		{name: "empty pattern matches bare key", action: ActionAllow, query: map[string][]string{"f": {""}}, rawQuery: "f", wantMatch: true},
		{name: "empty pattern rejects value", action: ActionAllow, query: map[string][]string{"f": {""}}, rawQuery: "f=x"},
		{name: "empty pattern needs the key", action: ActionAllow, query: map[string][]string{"f": {""}}, rawQuery: ""},
		{name: "empty pattern with repeated non-empty", action: ActionAllow, query: map[string][]string{"f": {""}}, rawQuery: "f=&f=x"},
		{name: "multiple keys all present", action: ActionAllow, query: map[string][]string{"signal": {"USR1"}, "force": {"1"}}, rawQuery: "signal=USR1&force=1", wantMatch: true},
		{name: "multiple keys one missing", action: ActionAllow, query: map[string][]string{"signal": {"USR1"}, "force": {"1"}}, rawQuery: "signal=USR1"},
		{name: "multiple keys one wrong", action: ActionAllow, query: map[string][]string{"signal": {"USR1"}, "force": {"1"}}, rawQuery: "signal=USR1&force=0"},
		{name: "allow with bad percent-encoding fails closed", action: ActionAllow, query: signal, rawQuery: "signal=USR1&x=%zz"},
		{name: "allow with semicolon fails closed", action: ActionAllow, query: signal, rawQuery: "signal=USR1;x=1"},
		{name: "deny with bad percent-encoding matches", action: ActionDeny, query: signal, rawQuery: "signal=USR1&x=%zz", wantMatch: true},
		{name: "deny with semicolon matches", action: ActionDeny, query: signal, rawQuery: "x=1;y=2", wantMatch: true},
		{name: "deny with valid non-matching query does not match", action: ActionDeny, query: signal, rawQuery: "signal=KILL"},
		{name: "deny with absent key does not match", action: ActionDeny, query: signal, rawQuery: ""},
		{name: "deny matches the listed value", action: ActionDeny, query: signal, rawQuery: "signal=USR1", wantMatch: true},
		{name: "wrong method never matches", action: ActionAllow, query: signal, method: "GET", rawQuery: "signal=USR1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rules := mustCompileQueryRule(t, tt.action, tt.query)
			method := tt.method
			if method == "" {
				method = "POST"
			}
			_, index, _ := Evaluate(rules, queryRequest(method, killPath, tt.rawQuery))
			if got := index == 0; got != tt.wantMatch {
				t.Fatalf("rule matched = %v, want %v for %q", got, tt.wantMatch, tt.rawQuery)
			}
		})
	}
}

// A rule without query must behave exactly as before, even on a query the
// parser rejects.
func TestEvaluateRuleWithoutQueryIgnoresQuery(t *testing.T) {
	t.Parallel()
	for _, rawQuery := range []string{"", "signal=KILL", "x=%zz", "a;b"} {
		rules := mustCompileQueryRule(t, ActionAllow, nil)
		if action, index, _ := Evaluate(rules, queryRequest("POST", "/containers/abc/kill", rawQuery)); action != ActionAllow || index != 0 {
			t.Errorf("query %q: action=%v index=%d, want allow/0", rawQuery, action, index)
		}
	}
}

// A first-match walk must fall through past an allow rule whose query does
// not hold, and stop at a deny rule that fails closed.
func TestEvaluateQueryFallsThroughInOrder(t *testing.T) {
	t.Parallel()

	allowKill, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/containers/*/kill", Action: ActionAllow, Index: 0, Query: map[string][]string{"signal": {"USR1"}}})
	if err != nil {
		t.Fatal(err)
	}
	denyAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Index: 1, Reason: "no matching allow rule"})
	if err != nil {
		t.Fatal(err)
	}
	rules := []*CompiledRule{allowKill, denyAll}

	for rawQuery, want := range map[string]Action{
		"signal=USR1":             ActionAllow,
		"":                        ActionDeny,
		"signal=USR1&signal=KILL": ActionDeny,
		"signal=%zz":              ActionDeny,
	} {
		if got, _, _ := Evaluate(rules, queryRequest("POST", "/containers/abc/kill", rawQuery)); got != want {
			t.Errorf("query %q: action = %v, want %v", rawQuery, got, want)
		}
	}

	denyKill, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/containers/*/kill", Action: ActionDeny, Index: 0, Query: map[string][]string{"signal": {"KILL"}}})
	if err != nil {
		t.Fatal(err)
	}
	allowAll, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionAllow, Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	rules = []*CompiledRule{denyKill, allowAll}
	for rawQuery, want := range map[string]Action{
		"signal=KILL":             ActionDeny,
		"signal=USR1":             ActionAllow,
		"signal=USR1&signal=KILL": ActionAllow, // deny needs every occurrence to match
		"signal=%zz":              ActionDeny,  // unparseable fails closed on a deny rule
	} {
		if got, _, _ := Evaluate(rules, queryRequest("POST", "/containers/abc/kill", rawQuery)); got != want {
			t.Errorf("deny rule, query %q: action = %v, want %v", rawQuery, got, want)
		}
	}
}

func TestEvaluateStaticReadsQueryRulesForExposure(t *testing.T) {
	t.Parallel()

	allowKill, _ := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/containers/*/kill", Action: ActionAllow, Index: 0, Query: map[string][]string{"signal": {"USR1"}}})
	rules := []*CompiledRule{allowKill}
	req := queryRequest("POST", "/containers/abc/kill", "")
	if action, _, _ := Evaluate(rules, req); action != ActionDeny {
		t.Fatalf("Evaluate without the key = %v, want deny", action)
	}
	if action, index, _ := EvaluateStatic(rules, req); action != ActionAllow || index != 0 {
		t.Fatalf("EvaluateStatic = %v/%d, want allow/0: a conditional allow is reachable", action, index)
	}

	// A conditional deny cannot shadow the allow below it.
	denyKill, _ := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/containers/*/kill", Action: ActionDeny, Index: 0, Query: map[string][]string{"signal": {"KILL"}}})
	allowAll, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionAllow, Index: 1})
	if action, index, _ := EvaluateStatic([]*CompiledRule{denyKill, allowAll}, req); action != ActionAllow || index != 1 {
		t.Fatalf("EvaluateStatic with conditional deny = %v/%d, want allow/1", action, index)
	}
}

func TestCompileRuleRejectsBadQueryConstraints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query map[string][]string
		want  string
	}{
		{name: "empty key", query: map[string][]string{"": {"x"}}, want: "empty"},
		{name: "no patterns", query: map[string][]string{"signal": {}}, want: "at least one pattern"},
		{name: "nil patterns", query: map[string][]string{"signal": nil}, want: "at least one pattern"},
		{name: "control in pattern", query: map[string][]string{"signal": {"a\nb"}}, want: "control characters"},
		{name: "control in key", query: map[string][]string{"sig\x00nal": {"a"}}, want: "control characters"},
		{name: "DEL in pattern", query: map[string][]string{"signal": {"a\x7f"}}, want: "control characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/x", Action: ActionAllow, Query: tt.query})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("CompileRule error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestFormatQuery(t *testing.T) {
	t.Parallel()
	if got := FormatQuery(nil); got != "" {
		t.Errorf("FormatQuery(nil) = %q", got)
	}
	got := FormatQuery(map[string][]string{"signal": {"USR1", "SIGUSR1"}, "force": {"1"}})
	if want := "force=1&signal=USR1|SIGUSR1"; got != want {
		t.Errorf("FormatQuery = %q, want %q", got, want)
	}
}
