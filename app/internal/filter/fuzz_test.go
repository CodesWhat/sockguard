package filter

import (
	pathpkg "path"
	"regexp"
	"testing"
)

var legacyVersionPrefix = regexp.MustCompile(`^/v\d+(\.\d+)?/`)

func legacyNormalizePath(p string) string {
	if p == "" {
		return ""
	}
	return legacyVersionPrefix.ReplaceAllString(pathpkg.Clean(p), "/")
}

// FuzzPathMatch fuzzes the full path-matching pipeline: NormalizePath + compiled
// rule matching. Ensures no panics and that a catch-all rule always matches.
func FuzzPathMatch(f *testing.F) {
	// Seed with realistic Docker API paths.
	seeds := []struct {
		method string
		path   string
	}{
		{"GET", "/containers/json"},
		{"GET", "/v1.45/containers/json"},
		{"POST", "/containers/create"},
		{"DELETE", "/v1.47/containers/abc123"},
		{"GET", "/_ping"},
		{"PUT", "/v1.45/containers/abc123/rename"},
		{"GET", "/"},
		{"GET", ""},
		{"POST", "/v999.999/images/build"},
		{"GET", "/containers/abc/def/ghi/jkl"},
		{"GET", "/containers/../images/json"},
		{"GET", "/../../etc/passwd"},
		{"GET", "//containers///json"},
		{"GET", "/v1.45/../containers/json"},
	}
	for _, s := range seeds {
		f.Add(s.method, s.path)
	}

	// Pre-compile a catch-all rule: any method, any path.
	catchAll, err := CompileRule(Rule{
		Methods: []string{"*"},
		Pattern: "/**",
		Action:  ActionDeny,
		Index:   0,
	})
	if err != nil {
		f.Fatalf("CompileRule catch-all: %v", err)
	}

	// Pre-compile a specific rule.
	containers, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		f.Fatalf("CompileRule containers: %v", err)
	}

	f.Fuzz(func(t *testing.T, method, path string) {
		// NormalizePath must never panic.
		normalized := NormalizePath(path)

		// Matches must never panic.
		catchAll.Matches(method, path)
		containers.Matches(method, path)

		// Invariant: catch-all rule matches every non-empty normalized path
		// that starts with "/" and contains no newlines. Go's regexp ".*"
		// does not match \n, and newlines are invalid in HTTP paths anyway.
		if len(normalized) > 0 && normalized[0] == '/' && !containsNewline(normalized) {
			if !catchAll.Matches(method, path) {
				t.Errorf("catch-all did not match method=%q path=%q (normalized=%q)", method, path, normalized)
			}
		}
	})
}

// FuzzGlobToRegex fuzzes glob-to-regex conversion. Every glob pattern must
// produce a valid, compilable regular expression.
func FuzzGlobToRegex(f *testing.F) {
	seeds := []string{
		"/containers/**",
		"/containers/*/json",
		"/_ping",
		"/**",
		"/",
		"",
		"/images/*/tag",
		"/networks/**",
		"/v1.45/containers",
		"*",
		"**",
		"***",
		"/a/b/c/d/e/f/g",
		"/containers/[abc]", // brackets are literal in our glob
		"/path with spaces",
		"/path(parens)",
		"/path{braces}",
		"/path+plus",
		"/path.dots.here",
		"/path$dollar",
		"/path^caret",
		"/path|pipe",
		"/path?question",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		// globToRegex must never panic.
		regexStr := globToRegex(pattern)

		// The resulting regex must always compile.
		anchored := "^" + regexStr + "$"
		compiled, err := regexp.Compile(anchored)
		if err != nil {
			t.Errorf("globToRegex(%q) produced invalid regex %q: %v", pattern, anchored, err)
			return
		}

		// Invariant: a literal ASCII pattern (no * chars) must match itself
		// exactly. Non-ASCII bytes can mismatch due to regexp.QuoteMeta
		// operating on UTF-8, which is fine — Docker paths are always ASCII.
		if !containsStar(pattern) && isASCII(pattern) {
			if !compiled.MatchString(pattern) {
				t.Errorf("literal pattern %q does not match itself via regex %q", pattern, anchored)
			}
		}
	})
}

// FuzzNormalizePath fuzzes path normalization in isolation. The result must
// stay equivalent to the legacy regex-based version-prefix stripping logic
// after path cleaning.
func FuzzNormalizePath(f *testing.F) {
	seeds := []string{
		"/containers/json",
		"/v1.45/containers/json",
		"/v1/containers/json",
		"/v999.0/images/build",
		"/_ping",
		"/v1.45/_ping",
		"",
		"/",
		"/v/containers/json",    // "/v" alone is not a version prefix
		"/v1.45",                // version prefix with no trailing path
		"/v1.45/",               // version prefix with just trailing slash
		"/version",              // starts with /v but not a version prefix
		"/v1./containers",       // malformed version
		"/v.1/containers",       // malformed version
		"/containers/../images", // path traversal
		"/../../etc/passwd",     // escape attempt
		"//containers///json",   // redundant slashes
		"/containers/./json",    // dot segment
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		normalized := NormalizePath(path)
		want := legacyNormalizePath(path)
		if normalized != want {
			t.Errorf("NormalizePath(%q) = %q, want legacy-normalized %q", path, normalized, want)
		}
	})
}

// FuzzCompileRule fuzzes rule compilation with arbitrary patterns and methods.
// If compilation succeeds, the resulting rule must not panic on matching.
func FuzzCompileRule(f *testing.F) {
	seeds := []struct {
		method  string
		pattern string
	}{
		{"GET", "/containers/**"},
		{"*", "/**"},
		{"POST", "/containers/create"},
		{"GET", "/_ping"},
		{"DELETE", "/containers/*"},
		{"GET", ""},
		{"", "/containers/json"},
		{"GET,POST", "/images/**"},
	}
	for _, s := range seeds {
		f.Add(s.method, s.pattern)
	}

	f.Fuzz(func(t *testing.T, method, pattern string) {
		rule, err := CompileRule(Rule{
			Methods: []string{method},
			Pattern: pattern,
			Action:  ActionAllow,
			Index:   0,
		})
		if err != nil {
			// Compilation failure is acceptable — just ensure no panic.
			return
		}

		// If compilation succeeded, matching must never panic.
		rule.Matches("GET", "/containers/json")
		rule.Matches("POST", "/v1.45/containers/create")
		rule.Matches(method, "/"+pattern)
		rule.Matches("", "")
	})
}

// containsStar returns true if s contains a '*' character.
func containsStar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '*' {
			return true
		}
	}
	return false
}

// containsNewline returns true if s contains a newline character.
func containsNewline(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return true
		}
	}
	return false
}

// isASCII returns true if every byte in s is in the ASCII range.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
