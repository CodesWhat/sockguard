package clientacl

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

var fuzzLabelProbeMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete,
	http.MethodPatch, http.MethodOptions,
}

var fuzzLabelProbePaths = []string{
	"/", "/containers/json", "/containers/abc/exec", "/_ping", "/images/create", "/v1.45/info", "/a/b/c/d",
}

// FuzzCompileContainerLabelRules feeds client-settable
// `com.sockguard.allow.*` labels to the rule compiler. The labels come from a
// container the client controls, so a pattern the compiler wrongly accepts is
// a self-granted ACL. Beyond not panicking: a refusal returns no rules,
// acceptance means every pattern was rooted, one rule per pattern, and no
// compiled rule allows a method other than the one its label names.
func FuzzCompileContainerLabelRules(f *testing.F) {
	f.Add(DefaultLabelPrefix, "get", "/containers/**")
	f.Add(DefaultLabelPrefix, "post", "/containers/*/start, /containers/*/stop")
	f.Add(DefaultLabelPrefix, "get", "**")
	f.Add(DefaultLabelPrefix, "get", "containers/json")
	f.Add(DefaultLabelPrefix, "delete", "")
	f.Add(DefaultLabelPrefix, "bogus", "/x")
	f.Add(DefaultLabelPrefix, "GET", " , ,/a,, ")
	f.Add("", "get", "/x")
	f.Add("x.", "Post", "/a/[b")

	f.Fuzz(func(t *testing.T, prefix, suffix, value string) {
		if len(prefix)+len(suffix)+len(value) > 1<<16 {
			t.Skip()
		}
		key := prefix + suffix
		labels := map[string]string{key: value}
		// A key outside the prefix must never influence the result.
		if !strings.HasPrefix("unrelated.label", prefix) {
			labels["unrelated.label"] = "/**"
		}

		rules, hasACL, err := compileContainerLabelRules(labels, prefix)

		wantACL := false
		for k := range labels {
			if strings.HasPrefix(k, prefix) {
				wantACL = true
			}
		}
		if hasACL != wantACL {
			t.Fatalf("hasACLLabels = %v, want %v (labels %v, prefix %q)", hasACL, wantACL, labels, prefix)
		}
		if err != nil {
			if rules != nil {
				t.Fatalf("returned %d rules alongside error %v", len(rules), err)
			}
			return
		}
		if !hasACL {
			if len(rules) != 0 {
				t.Fatalf("no ACL labels but %d rules compiled", len(rules))
			}
			return
		}

		method, ok := labelMethod(key, prefix)
		if !ok {
			t.Fatalf("compiled rules for unsupported method label %q", key)
		}
		patterns := splitLabelPatterns(value)
		if len(patterns) == 0 || len(rules) != len(patterns) {
			t.Fatalf("got %d rules for patterns %q", len(rules), patterns)
		}
		for _, p := range patterns {
			if !strings.HasPrefix(p, "/") {
				t.Fatalf("accepted unrooted label pattern %q", p)
			}
		}

		for _, m := range fuzzLabelProbeMethods {
			if m == method {
				continue
			}
			for _, p := range fuzzLabelProbePaths {
				req := &http.Request{Method: m, URL: &url.URL{Path: p}}
				if action, _, _ := filter.Evaluate(rules, req); action == filter.ActionAllow {
					t.Fatalf("label %q (method %s) allowed %s %s", key, method, m, p)
				}
			}
		}

		// Fail closed: a rule compiler that errors must surface as an error,
		// never as a silently shorter rule set.
		boom := errors.New("boom")
		failing, _, failErr := compileContainerLabelRulesWith(labels, prefix,
			func(filter.Rule) (*filter.CompiledRule, error) { return nil, boom })
		if failErr == nil || failing != nil {
			t.Fatalf("compiler failure was swallowed: rules=%v err=%v", failing, failErr)
		}

		again, _, err2 := compileContainerLabelRules(labels, prefix)
		if err2 != nil || len(again) != len(rules) {
			t.Fatalf("not deterministic: %d rules then %d (err %v)", len(rules), len(again), err2)
		}
	})
}
