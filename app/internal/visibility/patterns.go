package visibility

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/codeswhat/sockguard/internal/filter"
)

// compiledPattern is a pre-compiled glob pattern for name or image matching.
// Patterns are compiled at startup using the same glob-to-regex dialect as the
// path-matching pipeline in internal/filter so operators see consistent
// behavior across rule patterns and visibility patterns.
type compiledPattern struct {
	raw     string
	pattern *regexp.Regexp
}

// compilePatterns compiles a slice of glob pattern strings into compiledPatterns.
// An error is returned if any pattern fails to compile; callers should treat
// this as a fatal config error and refuse to serve traffic.
func compilePatterns(globs []string) ([]compiledPattern, error) {
	out := make([]compiledPattern, 0, len(globs))
	for _, glob := range globs {
		if glob == "" {
			return nil, fmt.Errorf("visibility pattern must not be empty")
		}
		regex := filter.GlobToRegexString(glob)
		compiled, err := regexp.Compile("^" + regex + "$")
		if err != nil {
			return nil, fmt.Errorf("visibility pattern %q is invalid: %w", glob, err)
		}
		out = append(out, compiledPattern{raw: glob, pattern: compiled})
	}
	return out, nil
}

// matchesAnyPattern reports whether value matches at least one of the
// compiled patterns. An empty patterns slice means "no restriction" and
// always returns true.
func matchesAnyPattern(value string, patterns []compiledPattern) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p.pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// containerNameFromNames returns the first container name with its leading
// slash stripped, e.g. ["/traefik"] → "traefik". Returns "" if the slice is
// empty or the first entry has no usable value.
func containerNameFromNames(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

// imageShortName returns the short tag name for an image reference, i.e. the
// part after the last "/" (repository tag). For "ghcr.io/org/traefik:v2",
// the short name is "traefik:v2". For "traefik:latest", it is "traefik:latest".
func imageShortName(ref string) string {
	if idx := strings.LastIndexByte(ref, '/'); idx >= 0 {
		return ref[idx+1:]
	}
	return ref
}
