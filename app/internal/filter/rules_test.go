package filter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	pathpkg "path"
	"regexp"
	"strings"
	"testing"
	"time"
)

func assertCompileAndMatchWithin(t *testing.T, pattern, normalizedPath string, wantMatch bool, limit time.Duration) {
	t.Helper()

	compileStart := time.Now()
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: pattern,
		Action:  ActionAllow,
	})
	compileElapsed := time.Since(compileStart)
	if err != nil {
		t.Fatalf("CompileRule(%q) error = %v", pattern, err)
	}
	if compileElapsed > limit {
		t.Fatalf("CompileRule(%q) took %v, want <= %v", pattern, compileElapsed, limit)
	}

	matchStart := time.Now()
	got := rule.matchesNormalizedUpper(http.MethodGet, normalizedPath)
	matchElapsed := time.Since(matchStart)
	if matchElapsed > limit {
		t.Fatalf("rule match for %q on %d-byte path took %v, want <= %v", pattern, len(normalizedPath), matchElapsed, limit)
	}
	if got != wantMatch {
		t.Fatalf("match result = %v, want %v", got, wantMatch)
	}
}

func TestStripVersionPrefix(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "no prefix", path: "/containers/json", want: "/containers/json"},
		{name: "valid major version", path: "/v1/containers/json", want: "/containers/json"},
		{name: "valid major minor version", path: "/v1.45/containers/json", want: "/containers/json"},
		{name: "invalid missing digits after v", path: "/v/x", want: "/v/x"},
		{name: "invalid missing minor digits", path: "/v1./x", want: "/v1./x"},
		{name: "invalid no trailing slash", path: "/v1.45", want: "/v1.45"},
		{name: "version root path", path: "/v1.45/", want: "/"},
		{name: "double prefix strips only first", path: "/v1.45/v1.46/containers/json", want: "/v1.46/containers/json"},
		{name: "invalid prefix without slash after digits", path: "/v1x/containers/json", want: "/v1x/containers/json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripVersionPrefix(tt.path)
			if got != tt.want {
				t.Errorf("stripVersionPrefix(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestStripVersionPrefixMatchesLegacyRegex(t *testing.T) {
	legacyVersionPrefix := regexp.MustCompile(`^/v\d+(\.\d+)?/`)
	paths := []string{
		"",
		"/",
		"/containers/json",
		"/_ping",
		"/v/x",
		"/v1",
		"/v1/",
		"/v1/containers/json",
		"/v1.45",
		"/v1.45/",
		"/v1.45/containers/json",
		"/v1.45/_ping",
		"/v1.45/v1.46/containers/json",
		"/v1./x",
		"/v1..45/x",
		"/v.1/x",
		"/v1x/containers/json",
		"/v001.002/images/build",
		"/v999.0/../containers/json",
		"/version",
		"v1.45/containers/json",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			want := legacyVersionPrefix.ReplaceAllString(path, "/")
			got := stripVersionPrefix(path)
			if got != want {
				t.Errorf("stripVersionPrefix(%q) = %q, want legacy regex result %q", path, got, want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"no version prefix", "/containers/json", "/containers/json"},
		{"v1.45 prefix", "/v1.45/containers/json", "/containers/json"},
		{"v1 prefix", "/v1/containers/json", "/containers/json"},
		{"ping", "/_ping", "/_ping"},
		{"versioned ping", "/v1.45/_ping", "/_ping"},
		{"nested path", "/v1.47/containers/abc123/start", "/containers/abc123/start"},
		{"root path", "/", "/"},
		{"version root keeps current clean semantics", "/v1.45/", "/v1.45"},
		// Path traversal hardening
		{"dot-dot collapse", "/containers/../images/json", "/images/json"},
		{"dot-dot at root", "/../../etc/passwd", "/etc/passwd"},
		{"versioned dot-dot", "/v1.45/../containers/json", "/containers/json"},
		{"redundant slashes", "//containers///json", "/containers/json"},
		{"dot segment", "/containers/./json", "/containers/json"},
		{"encoded slash unescapes before match", "/containers%2Fjson", "/containers/json"},
		{"encoded dot-dot collapses after unescape", "/containers/%2e%2e/images/json", "/images/json"},
		{"encoded version separator strips prefix", "/v1.45%2Fcontainers/json", "/containers/json"},
		{"empty string", "", ""},
		// Fix F-3: double-encoded sequences must be fully decoded.
		{"double-encoded slash in containers/create", "%252Fcontainers%252Fcreate", "/containers/create"},
		{"double-encoded path traversal collapses", "/containers%252F..%252Fimages/json", "/images/json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePath(tt.path)
			if got != tt.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestPathNeedsClean(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "clean absolute path", path: "/containers/json", want: false},
		{name: "clean versioned path", path: "/v1.45/containers/json", want: false},
		{name: "empty string", path: "", want: false},
		{name: "root path", path: "/", want: false},
		{name: "double slash", path: "//containers/json", want: true},
		{name: "dot segment", path: "/containers/./json", want: true},
		{name: "dot dot segment", path: "/containers/../json", want: true},
		{name: "trailing slash", path: "/containers/json/", want: true},
		{name: "relative dot", path: "./containers", want: true},
		{name: "relative clean", path: "containers/json", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathNeedsClean(tt.path); got != tt.want {
				t.Fatalf("pathNeedsClean(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestPathNeedsCleanRelativeDotPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "standalone dot", path: ".", want: false},
		{name: "standalone dot dot", path: "..", want: false},
		{name: "leading relative dot dot", path: "../containers", want: false},
		{name: "repeated leading relative dot dot", path: "../../containers", want: false},
		{name: "only leading relative dot dots", path: "../..", want: false},
		{name: "leading relative dot", path: "./containers", want: true},
		{name: "relative dot dot cancels previous segment", path: "containers/..", want: true},
		{name: "relative dot dot cancels after leading dot dot", path: "../containers/..", want: true},
		{name: "rooted dot dot", path: "/..", want: true},
		{name: "rooted leading dot dot", path: "/../containers", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleaned := pathpkg.Clean(tt.path)
			if (cleaned != tt.path) != tt.want {
				t.Fatalf("bad test case: path.Clean(%q) = %q", tt.path, cleaned)
			}
			if got := pathNeedsClean(tt.path); got != tt.want {
				t.Fatalf("pathNeedsClean(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestUpperHTTPMethodASCII(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   string
	}{
		{name: "uppercase ascii", method: "GET", want: "GET"},
		{name: "lowercase ascii", method: "post", want: "POST"},
		{name: "mixed case ascii", method: "pAtCh", want: "PATCH"},
		{name: "empty", method: "", want: ""},
		{name: "non ascii fallback", method: "méthod", want: strings.ToUpper("méthod")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := upperHTTPMethodASCII(tt.method); got != tt.want {
				t.Fatalf("upperHTTPMethodASCII(%q) = %q, want %q", tt.method, got, tt.want)
			}
		})
	}
}

func TestHTTPMethodBit(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   httpMethodMask
	}{
		{name: "get", method: http.MethodGet, want: httpMethodMaskGet},
		{name: "head", method: http.MethodHead, want: httpMethodMaskHead},
		{name: "post", method: http.MethodPost, want: httpMethodMaskPost},
		{name: "put", method: http.MethodPut, want: httpMethodMaskPut},
		{name: "delete", method: http.MethodDelete, want: httpMethodMaskDelete},
		{name: "patch", method: http.MethodPatch, want: httpMethodMaskPatch},
		{name: "options", method: http.MethodOptions, want: httpMethodMaskOptions},
		{name: "connect", method: http.MethodConnect, want: httpMethodMaskConnect},
		{name: "trace", method: http.MethodTrace, want: httpMethodMaskTrace},
		{name: "unknown", method: "BREW", want: 0},
		{name: "empty", method: "", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpMethodBit(tt.method); got != tt.want {
				t.Fatalf("httpMethodBit(%q) = %d, want %d", tt.method, got, tt.want)
			}
		})
	}
}

func TestCompileRuleMatchesCustomMethods(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"brew"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if !rule.matches("BREW", "/containers/json") {
		t.Fatal("custom method should still match its configured rule")
	}
	if rule.matches("WHEN", "/containers/json") {
		t.Fatal("different custom method should not match")
	}
}

func TestLiteralPrefixForPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{name: "literal", pattern: "/containers/json", want: "/containers/json"},
		{name: "single star after slash", pattern: "/containers/*/json", want: "/containers/"},
		{name: "double star at end trims optional slash", pattern: "/containers/**", want: "/containers"},
		{name: "double star before slash keeps slash prefix", pattern: "/containers/**/json", want: "/containers/"},
		{name: "leading wildcard", pattern: "**/json", want: ""},
		{name: "match all", pattern: "/**", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := literalPrefixForPattern(tt.pattern); got != tt.want {
				t.Fatalf("literalPrefixForPattern(%q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestCompileRuleGlobStoresLiteralPrefix(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if rule.literalPrefix != "/containers" {
		t.Fatalf("literalPrefix = %q, want %q", rule.literalPrefix, "/containers")
	}
}

func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		pattern string
		match   string
		want    bool
	}{
		{"/containers/json", "/containers/json", true},
		{"/containers/json", "/containers/other", false},
		{"/containers/*", "/containers/json", true},
		{"/containers/*", "/containers/abc123", true},
		{"/containers/*", "/containers/abc/def", false},
		{"/containers/**", "/containers/json", true},
		{"/containers/**", "/containers/abc/start", true},
		{"/containers/**", "/containers/abc/def/ghi", true},
		// /** also matches the bare path (no trailing segment)
		{"/containers/**", "/containers", true},
		{"/networks/**", "/networks", true},
		{"/volumes/**", "/volumes", true},
		{"/**", "/anything/at/all", true},
		{"/**", "/", true},
		{"/_ping", "/_ping", true},
		{"/_ping", "/version", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"->"+tt.match, func(t *testing.T) {
			regex := "^" + globToRegex(tt.pattern) + "$"
			compiled := regexp.MustCompile(regex)
			got := compiled.MatchString(tt.match)
			if got != tt.want {
				t.Errorf("pattern %q match %q = %v, want %v", tt.pattern, tt.match, got, tt.want)
			}
		})
	}
}

func TestCompileRuleComplexGlobRemainsFastOnLongPaths(t *testing.T) {
	longPrefix := "/" + strings.Repeat("a/", 4096)
	longMiddle := strings.Repeat("b/", 4096)

	tests := []struct {
		name      string
		pattern   string
		path      string
		wantMatch bool
	}{
		{
			name:      "match near end of long path",
			pattern:   "/**/x/**/y/**",
			path:      longPrefix + "x/" + longMiddle + "y/tail",
			wantMatch: true,
		},
		{
			name:      "non-match scans long path without backtracking explosion",
			pattern:   "/**/x/**/y/**",
			path:      longPrefix + "x/" + longMiddle + "z/tail",
			wantMatch: false,
		},
		{
			name:      "multiple deep wildcards stay linear",
			pattern:   "/**/alpha/**/omega/**",
			path:      longPrefix + "alpha/" + longMiddle + "omega/final",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCompileAndMatchWithin(t, tt.pattern, tt.path, tt.wantMatch, 100*time.Millisecond)
		})
	}
}

func TestCompiledRulematches(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{"GET containers list", "GET", "/containers/json", true},
		{"GET container inspect", "GET", "/v1.45/containers/abc123/json", true},
		{"GET bare containers", "GET", "/containers", true},
		{"POST containers", "POST", "/containers/create", false},
		{"GET images", "GET", "/images/json", false},
		// Path traversal should be normalized before matching
		{"GET traversal escape", "GET", "/containers/../images/json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.matches(tt.method, tt.path)
			if got != tt.want {
				t.Errorf("matches(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestCompileRuleLiteralPatternUsesFastPath(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/_ping",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if rule.pattern != nil {
		t.Fatal("literal pattern should not compile a regexp")
	}
	if rule.literal != "/_ping" {
		t.Fatalf("literal = %q, want %q", rule.literal, "/_ping")
	}
	if !rule.matches("GET", "/_ping") {
		t.Fatal("literal fast path should match exact path")
	}
	if !rule.matches("GET", "/v1.45/_ping") {
		t.Fatal("literal fast path should match normalized versioned path")
	}
}

func TestCompileRuleTrailingDoubleStarUsesFastPath(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/networks/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if rule.pattern != nil {
		t.Fatal("trailing /** pattern should not compile a regexp")
	}
	if !rule.matches("GET", "/networks") {
		t.Fatal("trailing /** fast path should match the bare prefix")
	}
	if !rule.matches("GET", "/networks/user-defined/endpoints/abc") {
		t.Fatal("trailing /** fast path should match deeper paths")
	}
	if rule.matches("GET", "/networks-and-more") {
		t.Fatal("trailing /** fast path should not match sibling prefixes")
	}
}

func TestCompileRuleSingleSegmentGlobUsesFastPath(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"POST"},
		Pattern: "/containers/*/exec",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if rule.pattern != nil {
		t.Fatal("single-segment glob should not compile a regexp")
	}
	if !rule.matches("POST", "/containers/abc123/exec") {
		t.Fatal("single-segment glob fast path should match a single segment")
	}
	if rule.matches("POST", "/containers/abc/def/exec") {
		t.Fatal("single-segment glob fast path should not match across slashes")
	}
}

func TestCompileRuleMultiSegmentSingleStarUsesFastPath(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/a/*/b/*/c",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if rule.pattern != nil {
		t.Fatal("single-star-only patterns should not compile a regexp")
	}
	if !rule.matches("GET", "/a/one/b/two/c") {
		t.Fatal("single-star-only fast path should match segment-by-segment")
	}
	if rule.matches("GET", "/a/one/b/two/three/c") {
		t.Fatal("single-star-only fast path should reject extra path segments")
	}
}

func TestCompileRuleRegexCompileError(t *testing.T) {
	orig := regexpCompileHook
	regexpCompileHook = func(string) (*regexp.Regexp, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { regexpCompileHook = orig })

	_, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/**/x/**/y/**",
		Action:  ActionAllow,
	})
	if err == nil {
		t.Fatal("expected CompileRule() to fail when regexp compilation fails")
	}
}

func TestWildcardMethodRule(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"*"},
		Pattern: "/**",
		Action:  ActionDeny,
		Reason:  "catch-all deny",
		Index:   99,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if !rule.matches("GET", "/anything") {
		t.Error("wildcard method should match GET")
	}
	if !rule.matches("POST", "/anything") {
		t.Error("wildcard method should match POST")
	}
	if !rule.matches("DELETE", "/anything") {
		t.Error("wildcard method should match DELETE")
	}
}

func TestEvaluate(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/containers/**", Action: ActionAllow, Index: 1})
	r3, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 2})
	rules := []*CompiledRule{r1, r2, r3}

	tests := []struct {
		name       string
		method     string
		path       string
		wantAction Action
		wantIndex  int
	}{
		{"ping allowed", "GET", "/_ping", ActionAllow, 0},
		{"containers allowed", "GET", "/v1.45/containers/json", ActionAllow, 1},
		{"POST denied", "POST", "/containers/create", ActionDeny, 2},
		{"images denied", "GET", "/images/json", ActionDeny, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			action, index, _ := Evaluate(rules, req)
			if action != tt.wantAction {
				t.Errorf("action = %v, want %v", action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Errorf("index = %d, want %d", index, tt.wantIndex)
			}
		})
	}
}

// TestEvaluateRuleOrder asserts the first-match-wins invariant that underpins
// the default-deny security posture: a deny at index 0 must beat an allow at
// index 1 for the same path, and vice-versa.
func TestEvaluateRuleOrder(t *testing.T) {
	denyFirst, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/secret", Action: ActionDeny, Index: 0})
	allowSecond, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/secret", Action: ActionAllow, Index: 1})

	allowFirst, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/public", Action: ActionAllow, Index: 0})
	denySecond, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/public", Action: ActionDeny, Index: 1})

	tests := []struct {
		name       string
		rules      []*CompiledRule
		path       string
		wantAction Action
		wantIndex  int
	}{
		{
			// Security-critical invariant: deny-at-0 must beat allow-at-1 for the same path.
			name:       "deny before allow is denied",
			rules:      []*CompiledRule{denyFirst, allowSecond},
			path:       "/secret",
			wantAction: ActionDeny,
			wantIndex:  0,
		},
		{
			// Symmetric inverse: allow-at-0 beats deny-at-1 for the same path.
			name:       "allow before deny is allowed",
			rules:      []*CompiledRule{allowFirst, denySecond},
			path:       "/public",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			action, index, _ := Evaluate(tt.rules, req)
			if action != tt.wantAction {
				t.Errorf("action = %v, want %v", action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Errorf("index = %d, want %d", index, tt.wantIndex)
			}
		})
	}
}

func TestMethodEdgeCases(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   1,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{"empty method", "", false},
		{"lowercase get", "get", true},
		{"method with leading space", " GET", false},
		{"method with trailing space", "GET ", false},
		{"method with surrounding spaces", " GET ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.matches(tt.method, "/containers/json")
			if got != tt.want {
				t.Errorf("matches(%q, /containers/json) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	action, index, reason := Evaluate(nil, req)

	if action != ActionDeny {
		t.Errorf("expected deny, got %v", action)
	}
	if index != -1 {
		t.Errorf("expected index -1, got %d", index)
	}
	if reason != "no matching allow rule" {
		t.Errorf("expected reason 'no matching allow rule', got %q", reason)
	}
}

// matches and matchesNormalizedUpper are test-only wrappers around the real
// hot-path matcher `matchesNormalizedUpperWithBit`. Production code calls the
// With-Bit variant directly from `evaluateNormalized` so the method-to-bit
// conversion happens once per request, not once per rule. Keeping these
// wrappers out of the production surface lets the compiled binary stay
// slimmer while the tests can still express "does this rule match this
// method + path" without the bit bookkeeping.
func (cr *CompiledRule) matches(method, path string) bool {
	upperMethod := upperHTTPMethodASCII(method)
	return cr.matchesNormalizedUpperWithBit(upperMethod, httpMethodBit(upperMethod), NormalizePath(path))
}

func (cr *CompiledRule) matchesNormalizedUpper(upperMethod, normalizedPath string) bool {
	return cr.matchesNormalizedUpperWithBit(upperMethod, httpMethodBit(upperMethod), normalizedPath)
}

func TestMatchGlobSegment(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		segment string
		want    bool
	}{
		// Wildcard-only: always true.
		{name: "star matches anything", pattern: "*", segment: "abc123", want: true},
		{name: "star matches empty", pattern: "*", segment: "", want: true},
		// Literal (no wildcard).
		{name: "literal match", pattern: "json", segment: "json", want: true},
		{name: "literal mismatch", pattern: "json", segment: "yaml", want: false},
		// Patterns with single star.
		{name: "prefix star match", pattern: "abc*", segment: "abcdef", want: true},
		{name: "prefix star empty suffix match", pattern: "abc*", segment: "abc", want: true},
		{name: "prefix star mismatch", pattern: "abc*", segment: "xbc", want: false},
		{name: "suffix star match", pattern: "*def", segment: "abcdef", want: true},
		{name: "suffix star mismatch", pattern: "*def", segment: "abcxyz", want: false},
		{name: "mid star match", pattern: "a*z", segment: "abcz", want: true},
		{name: "mid star mismatch", pattern: "a*z", segment: "abcy", want: false},
		{name: "star only at start no segment chars", pattern: "*xyz", segment: "xyz", want: true},
		// Pattern with multiple stars.
		{name: "two stars match", pattern: "a*b*c", segment: "a1b2c", want: true},
		{name: "two stars mismatch", pattern: "a*b*c", segment: "a1b2x", want: false},
		// Star at end matches remainder.
		{name: "trailing star empty remainder", pattern: "abc*", segment: "abc", want: true},
		// Pattern longer than segment.
		{name: "pattern longer than segment no star", pattern: "abcde", segment: "abc", want: false},
		// Segment is longer than pattern.
		{name: "segment longer no star in pattern", pattern: "abc", segment: "abcde", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchGlobSegment(tt.pattern, tt.segment)
			if got != tt.want {
				t.Fatalf("matchGlobSegment(%q, %q) = %v, want %v", tt.pattern, tt.segment, got, tt.want)
			}
		})
	}
}

func TestMatchTrailingDoubleStar(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		path   string
		want   bool
	}{
		{name: "empty prefix always matches", prefix: "", path: "/anything", want: true},
		{name: "exact match", prefix: "/containers", path: "/containers", want: true},
		{name: "child match", prefix: "/containers", path: "/containers/json", want: true},
		{name: "sibling does not match", prefix: "/containers", path: "/containers-extra", want: false},
		{name: "unrelated path does not match", prefix: "/containers", path: "/images/json", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchTrailingDoubleStar(tt.prefix, tt.path)
			if got != tt.want {
				t.Fatalf("matchTrailingDoubleStar(%q, %q) = %v, want %v", tt.prefix, tt.path, got, tt.want)
			}
		})
	}
}

func TestMatchGlobSegmentsRootPath(t *testing.T) {
	// Exercises the len(patternSegments)==1 && matchGlobSegment(…,"") branch.
	rule, _ := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/*",
		Action:  ActionAllow,
	})
	// A single-segment glob should match the root path "/" (one empty segment).
	if !rule.matches("GET", "/") {
		t.Fatal("single-segment glob should match /")
	}
}

func TestMatchesNormalizedUpperWithBitUnknownMethod(t *testing.T) {
	// Covers the unknownMethods branch in matchesNormalizedUpperWithBit.
	rule, _ := CompileRule(Rule{
		Methods: []string{"BREW"},
		Pattern: "/_ping",
		Action:  ActionAllow,
	})

	// BREW has no known bit (returns 0), so unknownMethods lookup is used.
	if !rule.matchesNormalizedUpper("BREW", "/_ping") {
		t.Fatal("BREW method should match rule configured for BREW")
	}
	// A different unknown method must not match.
	if rule.matchesNormalizedUpper("POUR", "/_ping") {
		t.Fatal("POUR method should not match rule configured for BREW")
	}
}

func TestMatchesNormalizedUpperWithBitDefaultCase(t *testing.T) {
	// Exercises the `default: return false` branch by constructing a CompiledRule
	// with an impossible matcherKind value via direct struct initialisation.
	cr := &CompiledRule{
		matchAllMethods: true,
		matcherKind:     pathMatcherKind(255), // unknown kind
		Action:          ActionAllow,
	}
	if cr.matchesNormalizedUpperWithBit("GET", httpMethodMaskGet, "/anything") {
		t.Fatal("unknown matcherKind should return false")
	}
}

func TestMatchGlobSegmentsPatternLongerThanPath(t *testing.T) {
	// Pattern /*/b/c has 3 segments but path /a has only 1 segment.
	// literalPrefix is "/" (from the leading slash before *), which matches "/a",
	// so matchGlobSegments IS called. It returns false at line 374-376 when the
	// second pattern segment is processed but path is already exhausted.
	rule, _ := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/*/b/c",
		Action:  ActionAllow,
	})
	if rule.matches("GET", "/a") {
		t.Fatal("pattern longer than path should not match")
	}
}

func TestMatchGlobSegmentsPathLongerThanPattern(t *testing.T) {
	// Pattern /a/b but path /a/b/c — path has more segments than pattern.
	rule, _ := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/a/b",
		Action:  ActionAllow,
	})
	if rule.matches("GET", "/a/b/c") {
		t.Fatal("path longer than pattern should not match literal")
	}
}

func TestMatchesNormalizedUpperWithBitSegmentGlobLiteralPrefixMismatch(t *testing.T) {
	// segmentGlob matcher with a literalPrefix; path does NOT start with the prefix.
	rule, _ := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/*/exec",
		Action:  ActionAllow,
	})
	// Path doesn't start with /containers/ → should short-circuit via literalPrefix check.
	if rule.matches("GET", "/images/abc/exec") {
		t.Fatal("literalPrefix mismatch should not match")
	}
}

func TestMatchesNormalizedUpperWithBitRegexLiteralPrefixMismatch(t *testing.T) {
	// pathMatcherRegex with a literalPrefix that doesn't match the path.
	// Pattern with ** (not trailing) compiles to regex. "/containers/**/json" → regex.
	rule, _ := CompileRule(Rule{
		Methods: []string{"GET"},
		Pattern: "/containers/**/json",
		Action:  ActionAllow,
	})
	// Path doesn't start with /containers/ → literalPrefix short-circuit applies.
	if rule.matches("GET", "/images/abc/def/json") {
		t.Fatal("regex literalPrefix mismatch should not match")
	}
}
