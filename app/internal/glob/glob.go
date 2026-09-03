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

// ToRegexString converts a glob pattern to a regex string.
func ToRegexString(pattern string) string {
	var b strings.Builder
	runes := []rune(pattern)
	i := 0
	for i < len(runes) {
		switch {
		case i+2 < len(runes) && runes[i] == '/' && runes[i+1] == '*' && runes[i+2] == '*':
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
