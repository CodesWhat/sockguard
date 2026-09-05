package apipath

import (
	pathpkg "path"
	"regexp"
	"strings"
	"testing"
)

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
		// A trailing '.' is inside Podman's VersionedPath class ([0-9A-Za-z.-]*),
		// so it strips like any other continuation char.
		{name: "trailing dot in class still strips", path: "/v1./x", want: "/x"},
		{name: "invalid no trailing slash", path: "/v1.45", want: "/v1.45"},
		{name: "version root path", path: "/v1.45/", want: "/"},
		{name: "double prefix strips only first", path: "/v1.45/v1.46/containers/json", want: "/v1.46/containers/json"},
		// Letters after the leading digit are inside Podman's class too
		// (e.g. "5.8.1-dev"), so a trailing letter run strips as well.
		{name: "trailing letters in class still strips", path: "/v1x/containers/json", want: "/containers/json"},
		{name: "uppercase V is not a version prefix", path: "/V1.45/containers/json", want: "/V1.45/containers/json"},
		{name: "uppercase V major only is not a version prefix", path: "/V1/containers/json", want: "/V1/containers/json"},
		// Three-part semver -- Podman's libpod bindings send the full daemon
		// version (major.minor.patch), unlike Docker's vN / vN.N (#148).
		{name: "three-part semver version prefix", path: "/v5.0.0/libpod/containers/json", want: "/libpod/containers/json"},
		{name: "three-part semver with larger components", path: "/v4.9.3/libpod/containers/json", want: "/libpod/containers/json"},
		{name: "three-part semver root path", path: "/v5.0.0/", want: "/"},
		{name: "Podman accepts prerelease suffix", path: "/v5.8.1-dev/libpod/containers/json", want: "/libpod/containers/json"},
		{name: "three-part semver trailing dot still strips", path: "/v5.0./x", want: "/x"},
		{name: "three-part semver no trailing slash", path: "/v5.0.0", want: "/v5.0.0"},
		// Podman's VersionedPath regex has no part-count limit, so a
		// four-part run strips just like three-part.
		{name: "four-part version strips too", path: "/v1.2.3.4/x", want: "/x"},
		{name: "invalid version character is not stripped", path: "/v5.8.1_rc/libpod/containers/json", want: "/v5.8.1_rc/libpod/containers/json"},
		// Adversarial digit runs.
		{name: "long digit run in major", path: "/v99999999999999999999/x", want: "/x"},
		{name: "long digit run in minor", path: "/v1.99999999999999999999/x", want: "/x"},
		{name: "long digit run in patch", path: "/v1.2.99999999999999999999/x", want: "/x"},
		// Podman prerelease / dev builds (this fix): VersionedPath is
		// [0-9][0-9A-Za-z.-]*, which admits "-dev", "-rc1", trailing '.'/'-',
		// but not '+' (semver build metadata) or '_'.
		{name: "podman dev prerelease suffix strips", path: "/v5.8.1-dev/libpod/networks/x/connect", want: "/libpod/networks/x/connect"},
		{name: "podman rc prerelease suffix strips", path: "/v5.8.1-rc1/libpod/containers/json", want: "/libpod/containers/json"},
		{name: "plus is not in podman's class", path: "/v5.8.1+build.7/libpod/containers/json", want: "/v5.8.1+build.7/libpod/containers/json"},
		{name: "trailing dot before slash strips", path: "/v1.45./containers/json", want: "/containers/json"},
		{name: "trailing dash before slash strips", path: "/v1.45-/containers/json", want: "/containers/json"},
		{name: "bare v with no digits unchanged", path: "/v/containers/json", want: "/v/containers/json"},
		{name: "first char after v must be a digit", path: "/vX/containers/json", want: "/vX/containers/json"},
		{name: "podman dev prerelease no trailing slash", path: "/v5.8.1-dev", want: "/v5.8.1-dev"},
		{name: "podman dev prerelease root path", path: "/v5.8.1-dev/", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripVersionPrefix(tt.path)
			if got != tt.want {
				t.Errorf("StripVersionPrefix(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestStripVersionPrefixMatchesPodmanRouteGrammar(t *testing.T) {
	podmanVersionPrefix := regexp.MustCompile(`^/v[0-9][0-9A-Za-z.-]*/`)
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
		// Three-part semver (#148): must now strip like vN / vN.N.
		"/v5.0.0/libpod/containers/json",
		"/v4.9.3/libpod/containers/json",
		"/v1.2.3/x",
		"/v1.2.3",
		"/v1.2.3/",
		"/v1.2./x",
		"/v1.2.3.4/x",
		"/v5.8.1-dev/libpod/manifests/app/json",
		"/v5.8.1_rc/libpod/manifests/app/json",
		"/v5.8.1-dev/libpod/images/load",
		"/v5.8.1_rc/libpod/images/load",
		// Podman prerelease / dev builds (this fix).
		"/v5.8.1-dev/libpod/networks/x/connect",
		"/v5.8.1-rc1/libpod/containers/json",
		"/v5.8.1+build.7/libpod/containers/json",
		"/v1.45./containers/json",
		"/v1.45-/containers/json",
		"/vX/containers/json",
		"/v5.8.1-dev",
		"/v5.8.1-dev/",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			want := podmanVersionPrefix.ReplaceAllString(path, "/")
			got := StripVersionPrefix(path)
			if got != want {
				t.Errorf("StripVersionPrefix(%q) = %q, want Podman route result %q", path, got, want)
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
		{"empty string", "", ""},
		// NormalizePath does not percent-decode. Its input (r.URL.Path) has
		// already been decoded once by net/http — the same single decode the
		// Docker daemon applies — so any %XX still present is a double-encoded
		// escape that the daemon's router also leaves literal. Decoding it here
		// would desync sockguard's policy view from the daemon's routing view.
		{"literal percent escape is left intact", "/containers%2Fjson", "/containers%2Fjson"},
		{"encoded dot stays a literal segment", "/containers/%2e/json", "/containers/%2e/json"},
		{"encoded dot-dot stays a literal segment", "/containers/%2e%2e/images/json", "/containers/%2e%2e/images/json"},
		{"encoded version separator is not a version prefix", "/v1.45%2Fcontainers/json", "/v1.45%2Fcontainers/json"},
		{"double-encoded escape is not decoded", "%252Fcontainers%252Fcreate", "%252Fcontainers%252Fcreate"},
		{"double-encoded traversal does not collapse", "/containers%252F..%252Fimages/json", "/containers%252F..%252Fimages/json"},
		// Three-part semver version prefix (#148): Podman libpod clients send
		// the full daemon semver, unlike Docker's vN / vN.N.
		{"three-part semver libpod prefix", "/v5.0.0/libpod/containers/json", "/libpod/containers/json"},
		// Podman prerelease suffix combined with a traversal segment: Clean
		// runs first and collapses ".." against the version-looking segment
		// as an ordinary path component (it has no version semantics), so
		// the result never reaches StripVersionPrefix with a "/v..." prefix
		// at all. Assert the final result carries no ".." either way.
		{"podman prerelease prefix with traversal", "/v1.45-foo/../containers/create", "/containers/create"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePath(tt.path)
			if got != tt.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}

	// Dedicated assertion for the traversal case: no ".." segment survives.
	if got := NormalizePath("/v1.45-foo/../containers/create"); strings.Contains(got, "..") {
		t.Errorf("NormalizePath(%q) = %q still contains \"..\"", "/v1.45-foo/../containers/create", got)
	}
}

// TestNormalizePathLibpodVersionPrefixEquivalence pins the #148 fix's core
// requirement: a two-part Docker-style version prefix, a three-part Podman
// semver prefix, and no prefix at all must all normalize a /libpod/ path to
// the identical string. Before the fix, the three-part form fell through
// StripVersionPrefix unchanged, so it never converged with the other two —
// every libpod rule pattern would silently never match a versioned Podman
// client.
func TestNormalizePathLibpodVersionPrefixEquivalence(t *testing.T) {
	const want = "/libpod/containers/json"
	variants := []string{
		"/libpod/containers/json",
		"/v1.45/libpod/containers/json",
		"/v5.0.0/libpod/containers/json",
		"/v4.9.3/libpod/containers/json",
		"/v1/libpod/containers/json",
	}

	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			if got := NormalizePath(variant); got != want {
				t.Errorf("NormalizePath(%q) = %q, want %q", variant, got, want)
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

func TestHasVersionPrefix(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"no prefix", "/containers/json", false},
		{"v1.45 prefix", "/v1.45/containers/json", true},
		{"v1 major-only prefix", "/v1/containers/json", true},
		{"ping no prefix", "/_ping", false},
		{"root path no prefix", "/", false},
		{"version literal path no strip", "/version", false},
		{"uppercase V not a prefix", "/V1.45/containers/json", false},
		{"empty path", "", false},
		{"v without digits not a prefix", "/v/containers/json", false},
		{"v digits no trailing slash not a prefix", "/v1.45", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasVersionPrefix(tt.path)
			if got != tt.want {
				t.Errorf("HasVersionPrefix(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// CONDITIONALS_BOUNDARY normalize.go:51:12
// pathNeedsClean: `len(p) > 1 && p[len(p)-1] == '/'` — mutant changes to `>= 1` (i.e. `len(p) >= 1`).
// The only path where len==1 and ends with '/' is "/" itself, which is handled by the earlier guard.
// A 2-char path like "a/" must return true; a 1-char "/" must return false.
func TestPathNeedsClean_LengthBoundary(t *testing.T) {
	if pathNeedsClean("/") {
		t.Fatal("pathNeedsClean('/') must be false")
	}
	// len=2, ends with '/' → must return true
	if !pathNeedsClean("a/") {
		t.Fatal("pathNeedsClean('a/') must be true")
	}
}

// CONDITIONALS_BOUNDARY normalize.go:123:10  (StripVersionPrefix: `p[i] < '0' || p[i] > '9'`)
// mutant widens `<`/`>` to `<=`/`>=`, which would let a non-digit byte pass
// the first-character-after-"v" gate. Ensure /v1/containers/json strips
// correctly (one digit satisfies the gate; the [0-9A-Za-z.-]* loop then
// consumes nothing more before the trailing slash).
func TestStripVersionPrefix_SingleDigit(t *testing.T) {
	got := StripVersionPrefix("/v1/containers/json")
	if got != "/containers/json" {
		t.Fatalf("StripVersionPrefix('/v1/containers/json') = %q, want /containers/json", got)
	}
}

// /v1 (len 3) never reaches StripVersionPrefix's digit gate or
// character-class loop at all — it is rejected by the `len(p) < 4` fast
// path at normalize.go:118 before the version class is ever inspected. This
// pins that a too-short input returns unchanged rather than reading out of
// range.
func TestStripVersionPrefix_NoTrailingSlash(t *testing.T) {
	if got := StripVersionPrefix("/v1"); got != "/v1" {
		t.Fatalf("StripVersionPrefix('/v1') = %q, want /v1", got)
	}
}

// CONDITIONALS_BOUNDARY normalize.go:128:8  (StripVersionPrefix: `i < len(p)`)
// mutant changes `<` to `<=`, which would let the character-class loop read
// p[len(p)] once it runs to the end of the path. Verify a multi-character
// version component (the "45" in v1.45, consumed through the
// [0-9A-Za-z.-]* class at normalize.go:130) still strips correctly.
func TestStripVersionPrefix_MultiDigitMinor(t *testing.T) {
	if got := StripVersionPrefix("/v1.45/containers/json"); got != "/containers/json" {
		t.Fatalf("got %q", got)
	}
}

// TestStripVersionPrefix_BoundaryGuards pins CONDITIONALS_BOUNDARY mutants in
// StripVersionPrefix's single character-class loop — the loop that replaced
// the old digit/dot-digit consumption when #148 widened the class to
// Podman's VersionedPath, [0-9A-Za-z.-]*:
//
//   - normalize.go:128:8  — loop bound `i < len(p)` → `<=`
//   - normalize.go:130:19 — character-class digit check `c <= '9'` → `< '9'`
//     (the 'a'-'z' and 'A'-'Z' range comparisons on the same line carry the
//     same class of boundary risk)
//   - normalize.go:137:7  — trailing-slash guard `i >= len(p) || p[i] != '/'` → `>`
//
// The existing /v1 case is filtered by the length-<4 fast path (line 118) so
// it never enters the loop at all; that's why TestStripVersionPrefix_NoTrailingSlash
// passed both original and mutated source. The cases below exercise paths
// that reach the loop at the boundary the mutants depend on.
func TestStripVersionPrefix_BoundaryGuards(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		why  string
	}{
		{
			name: "class run to end of path (206:8, 215:7)",
			in:   "/v12",
			want: "/v12",
			why:  "len>=4 passes the fast-path; both digits consumed make i=len(p). Mutant `i <= len(p)` on the loop bound would re-enter the loop and read p[len(p)] → panic. Mutant `i > len(p)` on the trailing-slash guard would treat i==len(p) as in-bounds and dereference p[i] out of range. Original exits cleanly and returns the input unchanged (no trailing /).",
		},
		{
			name: "digit at the class boundary (208:19)",
			in:   "/v1.9/x",
			want: "/x",
			why:  "Original's character-class check accepts '9' (c <= '9' true) and advances past it; the trailing '/' check then passes and the prefix strips to /x. Mutant `c < '9'` rejects '9', so the loop stops one byte early with '9' unconsumed; the trailing-slash guard then sees a non-'/' byte and returns the input unchanged.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripVersionPrefix(tt.in)
			if got != tt.want {
				t.Fatalf("StripVersionPrefix(%q) = %q, want %q\n%s", tt.in, got, tt.want, tt.why)
			}
		})
	}
}

func BenchmarkNormalizePath(b *testing.B) {
	b.ReportAllocs()
	paths := []struct {
		name string
		path string
	}{
		{"bare", "/containers/json"},
		{"versioned", "/v1.45/containers/json"},
		{"versioned_three_part", "/v5.0.0/libpod/containers/json"},
		{"deep", "/v1.45/containers/abc123def/json"},
		{"traversal", "/v1.45/../containers/json"},
		{"clean", "/_ping"},
	}
	for _, p := range paths {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				NormalizePath(p.path)
			}
		})
	}
}

// Adversarial NormalizePath inputs: many segments, traversal, long paths.
func BenchmarkNormalizePathAdversarial(b *testing.B) {
	cases := []struct {
		name string
		path string
	}{
		{"long_versioned", "/v1.45/containers/abc123def456ghi789jkl012mno345pqr678/exec/0123456789abcdef/start"},
		{"many_traversals", "/v1.45/containers/../../../../../etc/passwd"},
		{"deeply_nested", "/v1.45/networks/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t"},
		{"double_slashes", "/v1.45//containers////json"},
		{"no_prefix_long", "/containers/abc123def456ghi789/exec/0123456789abcdef/start"},
		{"short_clean", "/_ping"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				NormalizePath(c.path)
			}
		})
	}
}
