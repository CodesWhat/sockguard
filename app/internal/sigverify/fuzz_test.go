package sigverify

import (
	"regexp"
	"strings"
	"testing"
)

// FuzzCompileKeyless feeds operator-supplied keyless identity config (issuer
// and subject_pattern) to CompileKeyless. The compiled pattern is later
// matched against a registry-supplied Fulcio certificate SAN, so the anchor
// is the security property: the wrapped expression must accept a subject only
// when the operator's own pattern, compiled alone, accepts the whole subject.
func FuzzCompileKeyless(f *testing.F) {
	f.Add("https://token.actions.githubusercontent.com", `https://github\.com/acme/.+@refs/heads/main`, "https://github.com/acme/x@refs/heads/main")
	f.Add("  https://accounts.google.com  ", `ci@acme\.com`, "ci@acme.com.attacker.test")
	f.Add("", `x`, "x")
	f.Add("iss", "   ", "")
	f.Add("iss", `a|b`, "bzzz")
	f.Add("iss", `(?i)ci@acme\.com`, "CI@ACME.COM")
	f.Add("iss", `a)|(b`, "azzz")
	f.Add("iss", `[`, "[")

	f.Fuzz(func(t *testing.T, issuer, pattern, subject string) {
		if len(issuer)+len(pattern)+len(subject) > 1<<14 {
			t.Skip()
		}
		gotIssuer, re, err := CompileKeyless(issuer, pattern)
		if err != nil {
			if re != nil || gotIssuer != "" {
				t.Fatalf("values returned alongside error %v", err)
			}
			return
		}
		if gotIssuer != strings.TrimSpace(issuer) || gotIssuer == "" {
			t.Fatalf("issuer = %q for input %q", gotIssuer, issuer)
		}
		if re == nil {
			t.Fatalf("nil regexp without error")
		}

		own, ownErr := regexp.Compile(strings.TrimSpace(pattern))
		if ownErr != nil {
			t.Fatalf("pattern %q compiles only once wrapped by the anchor (%v alone): the wrapper changed its structure",
				pattern, ownErr)
		}
		if re.MatchString(subject) {
			// Anchored match means the operator's pattern covers the whole subject.
			full := false
			for _, loc := range own.FindAllStringIndex(subject, -1) {
				if loc[0] == 0 && loc[1] == len(subject) {
					full = true
				}
			}
			if !full && !wholeMatch(own, subject) {
				t.Fatalf("anchored pattern for %q matched %q but the pattern alone has no whole-string match", pattern, subject)
			}
		}
		if !re.MatchString(subject) && wholeMatch(own, subject) {
			t.Fatalf("pattern %q alone matches all of %q but the anchored form rejects it", pattern, subject)
		}
	})
}

// wholeMatch reports whether p can match all of s, using the anchored form
// built independently of CompileKeyless.
func wholeMatch(p *regexp.Regexp, s string) bool {
	anchored, err := regexp.Compile(`\A(?:` + p.String() + `)\z`)
	if err != nil {
		return false
	}
	return anchored.MatchString(s)
}
