package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const fuzzSuggestSentinel = "zqxsentinelzqx"

// FuzzPolicySuggest feeds the access-log parser arbitrary bytes plus one
// structured would-deny record carrying a sentinel in every field the command
// promises never to read (query, headers, body, client address, request ID).
// It must not panic, must stay inside its bounds, must only emit rules that
// start with a literal segment and carry no glob beyond a lone "*" after one,
// must print only comment and rule lines, must pass the real rule compiler
// (renderSuggestions fails otherwise) and must never print the sentinel.
func FuzzPolicySuggest(f *testing.F) {
	line := `{"msg":"request_would_deny","method":"GET","normalized_path":"/containers/0123456789ab/logs","decision":"would_deny","reason_code":"no_matching_allow_rule","profile":"ci"}`
	f.Add([]byte(line+"\n"), "GET", "/containers/0123456789ab/logs", "ci")
	f.Add([]byte(line), "DELETE", "/volumes/cache", "")
	f.Add([]byte(`{"msg":"request_would_deny","method":"GET","normalized_path":"/0123456789ab","reason_code":"no_matching_allow_rule"}`+"\n"), "GET", "/0123456789ab", "")
	f.Add([]byte(`{"msg":"request_would_deny","method":"POST","normalized_path":"/containers/**","reason_code":"no_matching_allow_rule"}`+"\n"), "POST", "/containers/**", "")
	f.Add([]byte(`{"msg":"request_would_deny","method":"GET","normalized_path":"/a/0123456789ab/0123456789cd","reason_code":"no_matching_allow_rule"}`+"\n"), "get", "/a/0123456789ab/0123456789cd", "x\ny")
	f.Add([]byte(`{"decision":"would_deny","method":"GET","normalized_path":"/info","reason_code":"matched_deny_rule"}`+"\n"), "GET", "/info", "p")
	f.Add([]byte("not json\n\n{\n"), "", "", "")
	f.Add([]byte(`{"msg":"request_would_deny","method":"GET","normalized_path":"/info/","reason_code":"no_matching_allow_rule"}`), "GET", "/info/", "a b")

	f.Fuzz(func(t *testing.T, raw []byte, method, path, profile string) {
		for _, s := range []string{string(raw), method, path, profile} {
			if strings.Contains(strings.ToLower(s), fuzzSuggestSentinel) {
				t.Skip()
			}
		}

		record, err := json.Marshal(map[string]any{
			"msg":             suggestMsgWouldDeny,
			"method":          method,
			"normalized_path": path,
			"reason_code":     "no_matching_allow_rule",
			"profile":         profile,
			"query":           "token=" + fuzzSuggestSentinel,
			"headers":         map[string]string{"Authorization": fuzzSuggestSentinel},
			"body":            fuzzSuggestSentinel,
			"client_addr":     fuzzSuggestSentinel,
			"request_id":      fuzzSuggestSentinel,
		})
		if err != nil {
			t.Fatal(err)
		}
		input := append(append(append([]byte{}, raw...), '\n'), append(record, '\n')...)

		rules, stats, err := collectSuggestions(bytes.NewReader(input))
		if err != nil {
			t.Fatalf("collectSuggestions on an in-memory reader failed: %v", err)
		}
		if len(rules) > suggestMaxRules {
			t.Fatalf("%d rules exceed the cap of %d", len(rules), suggestMaxRules)
		}
		counted := 0
		for _, r := range rules {
			counted += r.count
			assertSafeSuggestRule(t, r)
		}
		if counted > stats.WouldDeny || stats.WouldDeny > stats.Lines {
			t.Fatalf("inconsistent stats: rule hits=%d would_deny=%d lines=%d", counted, stats.WouldDeny, stats.Lines)
		}

		out, err := renderSuggestions(rules, stats)
		if err != nil {
			t.Fatalf("suggested rules failed the real compiler: %v\nrules=%+v", err, rules)
		}
		if len(out) > 8192+suggestMaxRules*2048 {
			t.Fatalf("output is %d bytes, over the bound", len(out))
		}
		if strings.Contains(strings.ToLower(out), fuzzSuggestSentinel) {
			t.Fatalf("output leaked a query, header, body or address value:\n%s", out)
		}
		for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			switch {
			case strings.HasPrefix(l, "#"), strings.HasPrefix(l, "  #"),
				l == "rules: []", l == "rules:", l == "    action: allow",
				strings.HasPrefix(l, "  - match: { method: "), strings.HasPrefix(l, "    reason: "):
			default:
				t.Fatalf("unexpected output line %q in:\n%s", l, out)
			}
		}
	})
}

// assertSafeSuggestRule checks the invariants that keep a crafted would-deny
// from becoming an allow-everything rule.
func assertSafeSuggestRule(t *testing.T, r suggestRule) {
	t.Helper()
	if r.method == "" || len(r.method) > 16 || strings.Trim(r.method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		t.Fatalf("unsafe method %q", r.method)
	}
	if len(r.path) > suggestMaxPathBytes || !strings.HasPrefix(r.path, "/") {
		t.Fatalf("unsafe path %q", r.path)
	}
	segs := strings.Split(r.path[1:], "/")
	prevStar := false
	for i, s := range segs {
		if s == "" || s == "." || s == ".." {
			t.Fatalf("empty or dot segment in %q", r.path)
		}
		if s == "*" {
			if i == 0 || prevStar {
				t.Fatalf("path %q starts with a wildcard or has consecutive ones", r.path)
			}
			prevStar = true
			continue
		}
		prevStar = false
		for j := 0; j < len(s); j++ {
			if !suggestPathByte(s[j]) {
				t.Fatalf("byte %q in segment %q of %q is outside the safe set", s[j], s, r.path)
			}
		}
	}
}
