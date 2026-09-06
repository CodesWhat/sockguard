package filter

import "testing"

// The two `cr.literalPrefix != ""` mutants in matchesNormalizedUpperWithBit
// stay alive on purpose, verified by hand-applying the mutation and re-running
// this package. The literal prefix is a fast reject derived from the pattern
// itself, so it is a necessary condition of the full matcher: negating the
// guard only skips the shortcut, and the segment-glob and regex matchers below
// it reach the same verdict.

// TestCompileRuleKeepsTheRegexForAPatternStartingWithAReplacementRune pins the
// lower edge of the replacement-rune check in CompileRule. A pattern whose
// very first rune decodes as U+FFFD is still a pattern the byte-walking fast
// paths disagree with the regex about, so it has to take the regex. The
// existing cases all put the replacement rune somewhere after byte 0, which
// leaves the index-zero case free to fall into the literal matcher.
func TestCompileRuleKeepsTheRegexForAPatternStartingWithAReplacementRune(t *testing.T) {
	// A rule pattern whose leading rune is a real U+FFFD. The anchored regex
	// matches both a real U+FFFD and a malformed byte, because Go's regexp
	// engine decodes any invalid byte in the subject to U+FFFD.
	rule := Rule{Methods: []string{"GET"}, Pattern: "�/x", Action: ActionAllow}

	cr, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule(%q) error = %v", rule.Pattern, err)
	}
	if cr.matcherKind != pathMatcherRegex {
		t.Fatalf("CompileRule(%q) matcherKind = %v, want pathMatcherRegex", rule.Pattern, cr.matcherKind)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "malformed byte", path: "\xff/x", want: true},
		{name: "real replacement rune", path: "�/x", want: true},
		{name: "unrelated path", path: "/x", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cr.matchesNormalizedUpperWithBit("GET", httpMethodMaskGet, tt.path)
			if got != tt.want {
				t.Fatalf("rule %q match %q = %v, want %v", rule.Pattern, tt.path, got, tt.want)
			}
		})
	}
}
