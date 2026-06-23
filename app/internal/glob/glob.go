// Package glob converts the sockguard glob dialect to a regex string.
//
// The dialect supports:
//   - "*" matches a single path segment (no "/").
//   - "**" matches any sequence of characters, including "/".
//   - "/**" compiles to an optional path group "(/.*)?" — the leading slash and
//     everything after it are optional — at ANY position, not only the end. So
//     "/containers/**" matches both "/containers" and "/containers/anything",
//     and a non-trailing "/foo/**/bar" matches "/foo/bar" (the "/**" collapsing
//     to nothing) as well as "/foo/x/y/bar".
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
			b.WriteString("(/.*)?")
			i += 3
		case i+1 < len(runes) && runes[i] == '*' && runes[i+1] == '*':
			b.WriteString(".*")
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
