package glob

import (
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// TestPackageDocQuotesTheEmittedGroups keeps the dialect documented at the top
// of glob.go tied to what ToRegexString actually emits. The two drifted once
// already: the doc kept describing "/**" as "(/.*)?" after the compiler moved
// to an "s"-flagged group so a decoded control byte could not slip past a "**"
// deny.
func TestPackageDocQuotesTheEmittedGroups(t *testing.T) {
	t.Parallel()

	parsed, err := parser.ParseFile(token.NewFileSet(), "glob.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse glob.go: %v", err)
	}
	if parsed.Doc == nil {
		t.Fatal("glob.go has no package doc comment")
	}

	doc := parsed.Doc.Text()
	for _, pattern := range []string{"**", "/**"} {
		want := ToRegexString(pattern)
		if !strings.Contains(doc, `"`+want+`"`) {
			t.Fatalf("package doc does not quote %q as the compilation of %q:\n%s", want, pattern, doc)
		}
	}
}

func TestToRegexString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{name: "empty", pattern: "", want: ""},
		{name: "root", pattern: "/", want: "/"},
		{name: "literal", pattern: "/containers/json", want: "/containers/json"},
		{name: "single star", pattern: "/containers/*", want: "/containers/[^/]*"},
		{name: "double star tail", pattern: "/containers/**", want: "/containers(/(?s:.*))?"},
		{name: "double star inline", pattern: "/**/json", want: "(/(?s:.*))?/json"},
		{name: "regex chars escaped", pattern: "/path.dots+plus", want: "/path\\.dots\\+plus"},
		{name: "bare star", pattern: "*", want: "[^/]*"},
		{name: "bare double star", pattern: "**", want: "(?s:.*)"},
		{name: "triple star", pattern: "***", want: "(?s:.*)[^/]*"},
		{name: "version prefix literal", pattern: "/v1.45/containers", want: "/v1\\.45/containers"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ToRegexString(tc.pattern)
			if got != tc.want {
				t.Fatalf("ToRegexString(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
			if _, err := regexp.Compile("^" + got + "$"); err != nil {
				t.Fatalf("ToRegexString(%q) produced uncompilable regex %q: %v", tc.pattern, got, err)
			}
		})
	}
}

func FuzzToRegexString(f *testing.F) {
	seeds := []string{
		"", "/", "*", "**", "***",
		"/containers/**", "/containers/*/json", "/_ping",
		"/v1.45/containers", "/a/b/c/d/e/f/g",
		"/containers/[abc]",
		"/path with spaces", "/path(parens)", "/path{braces}",
		"/path+plus", "/path.dots.here", "/path$dollar",
		"/path^caret", "/path|pipe", "/path?question",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		regexStr := ToRegexString(pattern)
		if _, err := regexp.Compile("^" + regexStr + "$"); err != nil {
			t.Errorf("ToRegexString(%q) produced invalid regex %q: %v", pattern, regexStr, err)
		}
	})
}
