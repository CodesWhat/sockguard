package glob

import (
	"regexp"
	"testing"
)

func TestToRegexString(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{name: "empty", pattern: "", want: ""},
		{name: "root", pattern: "/", want: "/"},
		{name: "literal", pattern: "/containers/json", want: "/containers/json"},
		{name: "single star", pattern: "/containers/*", want: "/containers/[^/]*"},
		{name: "double star tail", pattern: "/containers/**", want: "/containers(/.*)?"},
		{name: "double star inline", pattern: "/**/json", want: "(/.*)?/json"},
		{name: "regex chars escaped", pattern: "/path.dots+plus", want: "/path\\.dots\\+plus"},
		{name: "bare star", pattern: "*", want: "[^/]*"},
		{name: "bare double star", pattern: "**", want: ".*"},
		{name: "triple star", pattern: "***", want: ".*[^/]*"},
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
