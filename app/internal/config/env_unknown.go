package config

import (
	"bytes"
	"slices"
	"strings"

	"github.com/spf13/viper"
)

// envVarPrefix is what Load's SetEnvPrefix("SOCKGUARD") plus Viper's "_"
// separator produce in front of every configuration environment variable.
// Kept next to the lookup that consumes it rather than shared with load.go,
// which spells the prefix Viper's way (without the separator).
const envVarPrefix = "SOCKGUARD_"

// A suggestion is only worth printing when it is plausibly the variable the
// operator meant: no more than maxSuggestionDistance single-character edits
// away, and those edits no more than a suggestionLengthRatio-th of the name.
// The ratio keeps a short name like SOCKGUARD_IMAGE from being "corrected" to
// an unrelated key two edits away. Two edits is the ceiling rather than three
// because three is where a neighboring key that means something else starts
// winning: SOCKGUARD_LISTEN_SOCKET_UID (a real key, but YAML-only, so it does
// land here) is exactly three edits from SOCKGUARD_LISTEN_SOCKET_MODE, and
// pointing an operator setting the socket's owner at the socket's permission
// bits is worse than saying nothing. One- and two-edit typos — a dropped
// letter, a missing underscore, a transposition — still resolve.
const (
	maxSuggestionDistance = 2
	suggestionLengthRatio = 4
)

// UnknownEnvVar is a SOCKGUARD_* environment variable that no configuration
// key binds. Suggestion is the nearest known variable name, or empty when
// nothing is close enough to be worth naming.
//
// The variable's value is deliberately absent: an operator who typos a key
// can just as easily typo one holding a registry credential or a TLS key
// path, and this travels to a log.
type UnknownEnvVar struct {
	Name       string
	Suggestion string
}

// UnknownEnvVars reports every SOCKGUARD_* variable in environ (os.Environ()
// shape, "NAME=VALUE") that Load(configPath) will not bind to a configuration
// key, sorted by name and deduplicated so each variable is reported once.
//
// configPath is the same file Load is given, and it is part of the answer
// rather than decoration: a key Viper knows only because the YAML declares it
// is a key the environment can override. Pass "" to ask about the schema
// alone.
//
// Tecnativa compatibility variables (CONTAINERS, POST, ALLOW_START, ...) carry
// no prefix at all, so they are never candidates; see compat.go.
func UnknownEnvVars(configPath string, environ []string) []UnknownEnvVar {
	known := knownEnvVars(configPath)
	knownSet := make(map[string]struct{}, len(known))
	for _, name := range known {
		knownSet[name] = struct{}{}
	}

	seen := make(map[string]struct{})
	var unknown []UnknownEnvVar
	for _, entry := range environ {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || !strings.HasPrefix(name, envVarPrefix) {
			continue
		}
		if _, isKnown := knownSet[name]; isKnown {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		unknown = append(unknown, UnknownEnvVar{
			Name:       name,
			Suggestion: nearestKnownEnvVar(name, known),
		})
	}

	slices.SortFunc(unknown, func(a, b UnknownEnvVar) int {
		return strings.Compare(a.Name, b.Name)
	})
	return unknown
}

// knownEnvVars returns, sorted, the environment variable name for every
// configuration key Load(configPath) can read one from.
//
// It reconstructs Load's own Viper state, defaults then file, because that
// state is the whole answer: Unmarshal resolves AllKeys(), and AutomaticEnv is
// consulted only for a key on that list, so a key missing from it has no
// working environment spelling however it is written. Both halves matter. The
// registerDefaults walk over Config's mapstructure tags supplies the schema,
// which is why the four YAML-only cases in the configuration reference (the
// rules block, pointer blocks like clients.global_concurrency, pointer ints
// like listen.socket_uid, and anything inside a list entry) are absent from
// it. The file supplies the rest, because declaring one of those blocks in
// YAML puts its keys on the list and an environment variable really does
// override them from there — reporting one as ignored when it is not would be
// the same failure as this warning exists to catch, pointed the other way.
//
// A file that cannot be read or parsed contributes nothing rather than
// failing: Load is about to report that same problem properly.
func knownEnvVars(configPath string) []string {
	v := viper.New()
	setLoadDefaults(v, Defaults())
	if configPath != "" {
		if data, err := ReadFile(configPath); err == nil {
			v.SetConfigType("yaml")
			_ = v.ReadConfig(bytes.NewReader(data))
		}
	}

	keys := v.AllKeys()
	names := make([]string, 0, len(keys))
	for _, key := range keys {
		// Mirrors Viper's own derivation: ToUpper over the prefixed key,
		// then SetEnvKeyReplacer's "." -> "_".
		names = append(names, envVarPrefix+strings.ToUpper(strings.ReplaceAll(key, ".", "_")))
	}
	slices.Sort(names)
	return names
}

// nearestKnownEnvVar returns the known variable name closest to name, or ""
// when the closest one is too far away to be a likely typo of it. known must
// be sorted, so that a tie resolves to the same suggestion every run.
func nearestKnownEnvVar(name string, known []string) string {
	suffix := strings.TrimPrefix(name, envVarPrefix)
	if suffix == "" {
		return ""
	}

	best := ""
	bestDistance := -1
	for _, candidate := range known {
		distance := levenshtein(suffix, strings.TrimPrefix(candidate, envVarPrefix))
		if bestDistance == -1 || distance < bestDistance {
			best, bestDistance = candidate, distance
		}
	}

	if bestDistance < 0 || bestDistance > maxSuggestionDistance {
		return ""
	}
	if bestDistance*suggestionLengthRatio > len(suffix) {
		return ""
	}
	return best
}

// levenshtein returns the edit distance between a and b. Environment variable
// names are ASCII, so bytes are compared directly.
func levenshtein(a, b string) int {
	switch {
	case a == b:
		return 0
	case len(a) == 0:
		return len(b)
	case len(b) == 0:
		return len(a)
	}

	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}

	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			substitution := previous[j-1]
			if a[i-1] != b[j-1] {
				substitution++
			}
			current[j] = min(previous[j]+1, current[j-1]+1, substitution)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}
