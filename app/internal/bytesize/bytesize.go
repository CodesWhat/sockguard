// Package bytesize parses and formats byte counts written as size strings
// such as "32MiB".
package bytesize

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

var units = []struct {
	suffix string
	mult   int64
}{
	// Longest suffixes first so "MiB" is not read as "B".
	{"gib", 1 << 30},
	{"mib", 1 << 20},
	{"kib", 1 << 10},
	{"b", 1},
}

// Parse reads a size such as "8MiB", "32 MiB", "512KiB", "1GiB" or a bare
// integer number of bytes. Units are the binary ones (KiB, MiB, GiB) and are
// case-insensitive; "B" is accepted for plain bytes. Decimal units (KB, MB)
// are refused rather than guessed, since they are routinely read both ways.
// The result must be positive and fit in an int64.
func Parse(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("empty size")
	}
	lower := strings.ToLower(raw)
	mult := int64(1)
	numPart := lower
	for _, u := range units {
		if strings.HasSuffix(lower, u.suffix) {
			mult = u.mult
			numPart = strings.TrimSpace(strings.TrimSuffix(lower, u.suffix))
			break
		}
	}
	n, err := strconv.ParseInt(numPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: want a whole number of bytes or a number with a KiB, MiB or GiB unit", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid size %q: must be positive", s)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return n * mult, nil
}

// Format renders n with the largest binary unit that divides it exactly, so a
// value Parse accepted reads back the way it was written ("32MiB"). Other
// values print as bytes.
func Format(n int64) string {
	switch {
	case n > 0 && n%(1<<30) == 0:
		return strconv.FormatInt(n>>30, 10) + "GiB"
	case n > 0 && n%(1<<20) == 0:
		return strconv.FormatInt(n>>20, 10) + "MiB"
	case n > 0 && n%(1<<10) == 0:
		return strconv.FormatInt(n>>10, 10) + "KiB"
	}
	return strconv.FormatInt(n, 10) + "B"
}
