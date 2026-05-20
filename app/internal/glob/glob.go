// Package glob converts the sockguard glob dialect to a regex string.
//
// The dialect supports:
//   - "*" matches a single path segment (no "/").
//   - "**" matches any sequence of characters, including "/".
//   - "/**" at the end of a pattern also matches the bare path without a
//     trailing slash (so "/containers/**" matches both "/containers" and
//     "/containers/anything").
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
