package filter

import (
	pathpkg "path"
	"regexp"
	"testing"
)

// podmanVersionPrefix mirrors VersionedPath's v5.8.1 route grammar. Podman
// accepts any version beginning with a digit followed by digits, ASCII letters,
// dots, or hyphens, including prerelease and four-component spellings.
var podmanVersionPrefix = regexp.MustCompile(`^/v[0-9][0-9A-Za-z.-]*/`)

// referenceNormalizePath is an independent re-implementation of NormalizePath
// used by FuzzNormalizePath as a differential oracle. Like NormalizePath it
// path-cleans then strips the version prefix and does not percent-decode; it
// calls path.Clean unconditionally so the fuzzer also exercises the
// pathNeedsClean fast path NormalizePath uses.
func referenceNormalizePath(p string) string {
	if p == "" {
		return ""
	}
	return podmanVersionPrefix.ReplaceAllString(pathpkg.Clean(p), "/")
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
		{"GET", "/containers%2Fjson"},
		{"GET", "/containers%252Fjson"},
		{"GET", "/containers/%2e%2e/images/json"},
		{"GET", "/containers/%252e%252e/images/json"},
		{"GET", "/v1.45%2Fcontainers/json"},
		{"POST", "/containers%252Fcreate"},
		{"POST", "/v1.55/session"},
		{"POST", "/v1.55/grpc"},
		{"POST", "/session"},
		{"POST", "/grpc"},
		{"GET", "/v5.0.0/libpod/containers/json"},
		{"GET", "/v5.8.1-dev/libpod/manifests/app/json"},
		{"POST", "/v5.8.1.2/libpod/images/scp/app"},
		{"GET", "/v5.8.1-dev/libpod/images/load"},
		{"POST", "/v5.8.1.2/libpod/images/import"},
		{"POST", "/v5.0.0/libpod/pods/create"},
		{"POST", "/v5.0.0/libpod/play/kube"},
		{"GET", "/v5.0.0/libpod/generate/kube"},
		{"POST", "/v1.45/libpod/containers/create"},
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
		catchAll.matches(method, path)
		containers.matches(method, path)

		// Invariant: catch-all rule matches every non-empty normalized path
		// that starts with "/" and contains no newlines. Go's regexp ".*"
		// does not match \n, and newlines are invalid in HTTP paths anyway.
		if len(normalized) > 0 && normalized[0] == '/' && !containsNewline(normalized) {
			if !catchAll.matches(method, path) {
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
		"/v1.55/session",
		"/session/**",
		"/grpc/**",
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
// stay equivalent to a reference implementation that path-cleans and strips
// the version prefix without percent-decoding.
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
		"/vX/containers/json",   // first char after v must be a digit
		"/v1.45",                // version prefix with no trailing path
		"/v1.45/",               // version prefix with just trailing slash
		"/version",              // starts with /v but not a version prefix
		"/v1./containers",       // trailing dot is in Podman's class -- strips
		"/v.1/containers",       // no digit right after v -- not a prefix
		"/containers/../images", // path traversal
		"/../../etc/passwd",     // escape attempt
		"//containers///json",   // redundant slashes
		"/containers/./json",    // dot segment
		"/containers%2Fjson",
		"/containers%252Fjson",
		"/containers/%2e/json",   // single-encoded dot — stays literal, no collapse
		"/containers/%252e/json", // double-encoded dot — must not decode to "."
		"/containers/%2e%2e/images/json",
		"/containers/%252e%252e/images/json",
		"/v1.45%2Fcontainers/json",
		"/v1.45/%252e%252e/containers/json",
		"/v1.55/session",
		"/v1.55/grpc",
		"/v1.55/containers/json",
		// Three-part semver (#148): Podman's libpod bindings send the full
		// daemon version, unlike Docker's vN / vN.N.
		"/v4.9.3/libpod/containers/json",
		"/v5.0.0/libpod/containers/json",
		"/v5.0.0/",    // three-part prefix with just trailing slash
		"/v5.0.0",     // three-part prefix with no trailing path
		"/v5.0./x",    // trailing dot is in Podman's class -- strips
		"/v1.2.3.4/x", // Podman's class has no part-count limit -- strips
		"/v5.8.1-dev/libpod/images/load",
		"/v5.8.1_rc/libpod/images/load", // underscore is not accepted
		"/v5.8.1-dev/libpod/manifests/app/json",
		"/v5.8.1_rc/libpod/manifests/app/json", // underscore is not accepted
		"/v99999999999999999999.99999999999999999999.99999999999999999999/x", // adversarial digit runs
		// Podman prerelease / dev builds (this fix): VersionedPath is
		// [0-9][0-9A-Za-z.-]*, admitting "-dev", "-rc1", trailing '.'/'-',
		// but not '+' (semver build metadata) or '_'.
		"/v5.8.1-dev/libpod/networks/x/connect",
		"/v5.8.1-rc1/libpod/containers/json",
		"/v5.8.1+build.7/libpod/containers/json", // '+' not in class -- unchanged
		"/v1.45./containers/json",                // trailing dot
		"/v1.45-/containers/json",                // trailing dash
		"/v1.45-foo/../containers/create",        // prerelease suffix + traversal
		"/v5.8.1-dev",                            // no trailing slash
		"/v5.8.1-dev/",                           // root path after prefix
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		normalized := NormalizePath(path)
		want := referenceNormalizePath(path)
		if normalized != want {
			t.Errorf("NormalizePath(%q) = %q, want reference-normalized %q", path, normalized, want)
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
		{"POST", "/session"},
		{"POST", "/grpc"},
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
		rule.matches("GET", "/containers/json")
		rule.matches("POST", "/v1.45/containers/create")
		rule.matches(method, "/"+pattern)
		rule.matches("", "")
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
