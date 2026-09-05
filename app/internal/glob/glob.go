// Package glob converts the sockguard glob dialect to a regex string.
//
// The dialect supports:
//   - "*" matches a single path segment (no "/").
//   - "**" compiles to "(?s:.*)" and matches any sequence of characters,
//     including "/" and, through that "s" flag, newlines: a path carrying a
//     percent-encoded control byte cannot slip past a "**" pattern once
//     net/http has decoded it.
//   - "/**" compiles to an optional path group "(/(?s:.*))?" — the leading
//     slash and everything after it are optional — at ANY position, not only
//     the end. So "/containers/**" matches both "/containers" and
//     "/containers/anything", and a non-trailing "/foo/**/bar" matches
//     "/foo/bar" (the "/**" collapsing to nothing) as well as "/foo/x/y/bar".
//
// Callers that need a compiled *regexp.Regexp should wrap the result with
// "^" + ToRegexString(pattern) + "$".
package glob

import (
	"regexp"
	"strings"
)

// isSlashDoubleStar reports whether the "/**" token starts at runes[i]. All
// three runes have to be present for the token to form, so a pattern ending
// in "/*" is a literal slash followed by "[^/]*" and does not match here.
//
// ToRegexString and EveryMatchStartsWithSlash both compile the same "/**"
// token, and share this test so they can't drift apart: if ToRegexString
// changed how it recognized the token without this being updated too,
// EveryMatchStartsWithSlash would over-approximate, a caller like
// literalPrefixForPattern would keep a slash it must trim, and a deny rule
// could be skipped.
func isSlashDoubleStar(runes []rune, i int) bool {
	return i+2 < len(runes) && runes[i] == '/' && runes[i+1] == '*' && runes[i+2] == '*'
}

// EveryMatchStartsWithSlash reports whether every string
// "^" + ToRegexString(pattern) + "$" matches begins with a "/".
//
// It exists for literal-prefix derivation, where the question is whether the
// slash a "/**" opens with survives into the prefix. It does not survive on
// its own account: the group is optional, so the guarantee has to come from
// whatever follows it. "/**/json" keeps the slash, because the shortest
// string it matches is "/json". "/**" and "/**/**" do not, because both match
// the empty string, and neither does "/**json", which matches "json".
func EveryMatchStartsWithSlash(pattern string) bool {
	runes := []rune(pattern)
	i := 0
	for {
		if i >= len(runes) || runes[i] != '/' {
			return false
		}
		if isSlashDoubleStar(runes, i) {
			i += 3
			continue
		}
		return true
	}
}

// ToRegexString converts a glob pattern to a regex string.
func ToRegexString(pattern string) string {
	var b strings.Builder
	runes := []rune(pattern)
	i := 0
	for i < len(runes) {
		switch {
		case isSlashDoubleStar(runes, i):
			b.WriteString("(/(?s:.*))?")
			i += 3
		case i+1 < len(runes) && runes[i] == '*' && runes[i+1] == '*':
			b.WriteString("(?s:.*)")
			i += 2
		case runes[i] == '*':
			b.WriteString("[^/]*")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(runes[i])))
			i++
		}
	}
	return b.String()
}
