package filter

import (
	"regexp"
	"testing"
)

// TestGlobToRegexString locks in the contract of the exported wrapper. Other
// packages (visibility, config) build their own matchers off the regex it
// returns, so its output is part of the public glob dialect; any divergence
// from globToRegex would silently break those callers.
func TestGlobToRegexString(t *testing.T) {
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
			got := GlobToRegexString(tc.pattern)
			if got != tc.want {
				t.Fatalf("GlobToRegexString(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
			if _, err := regexp.Compile("^" + got + "$"); err != nil {
				t.Fatalf("GlobToRegexString(%q) produced uncompilable regex %q: %v", tc.pattern, got, err)
			}
		})
	}
}

// TestGlobToRegexStringMatchesGlobToRegex asserts the exported wrapper is a
// pure pass-through of the private helper. Future maintainers who change one
// must remember to change both — this test fails loudly if they don't.
func TestGlobToRegexStringMatchesGlobToRegex(t *testing.T) {
	for _, pattern := range []string{
		"",
		"/",
		"*",
		"**",
		"/containers/**",
		"/v1.45/**",
		"/path(parens)",
		"/networks/*/disconnect",
		"/path+escapes.required$",
	} {
		want := globToRegex(pattern)
		if got := GlobToRegexString(pattern); got != want {
			t.Fatalf("GlobToRegexString(%q) = %q; globToRegex(%q) = %q — wrapper diverged", pattern, got, pattern, want)
		}
	}
}

// FuzzGlobToRegexString mirrors FuzzGlobToRegex against the exported entry
// point so external API consumers regress on the same invariants.
func FuzzGlobToRegexString(f *testing.F) {
	seeds := []string{
		"/containers/**",
		"/containers/*/json",
		"/_ping",
		"/**",
		"/",
		"",
		"/v1.45/containers",
		"*",
		"**",
		"/path with spaces",
		"/path(parens)",
		"/path.dots.here",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		regexStr := GlobToRegexString(pattern)
		anchored := "^" + regexStr + "$"
		if _, err := regexp.Compile(anchored); err != nil {
			t.Errorf("GlobToRegexString(%q) produced invalid regex %q: %v", pattern, anchored, err)
		}
		// Wrapper must agree with the internal helper byte-for-byte.
		if internal := globToRegex(pattern); regexStr != internal {
			t.Errorf("GlobToRegexString(%q) = %q; globToRegex returned %q", pattern, regexStr, internal)
		}
	})
}
