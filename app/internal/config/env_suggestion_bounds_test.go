package config

import "testing"

// TestNearestKnownEnvVarBoundaries pins the four numeric decisions the
// suggestion picker makes: which candidate wins a distance tie, that an exact
// match is still a suggestion, and each end of the distance and length-ratio
// gates. The existing tests all sit in the interior of those gates, so any of
// the four thresholds can shift by one and still produce the same suggestion
// for a realistic typo.
func TestNearestKnownEnvVarBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		known []string
		want  string
	}{
		{
			// Ties resolve to the first candidate in sorted order, which is
			// what makes the suggestion stable across runs.
			name:  "distance tie resolves to the first sorted candidate",
			input: "SOCKGUARD_AAAB",
			known: []string{"SOCKGUARD_AAAA", "SOCKGUARD_AAAC"},
			want:  "SOCKGUARD_AAAA",
		},
		{
			name:  "exact match is still returned",
			input: "SOCKGUARD_LISTEN_SOCKET",
			known: []string{"SOCKGUARD_LISTEN_SOCKET", "SOCKGUARD_UPSTREAM_SOCKET"},
			want:  "SOCKGUARD_LISTEN_SOCKET",
		},
		{
			// distance == maxSuggestionDistance is inside the gate, and
			// distance * suggestionLengthRatio == 8 is not greater than the
			// 10-byte suffix, so this one has to survive both checks.
			name:  "distance exactly at the maximum is still suggested",
			input: "SOCKGUARD_AAAAAAAAXX",
			known: []string{"SOCKGUARD_AAAAAAAAYY"},
			want:  "SOCKGUARD_AAAAAAAAYY",
		},
		{
			name:  "distance one past the maximum is dropped",
			input: "SOCKGUARD_AAAAAAAAXXX",
			known: []string{"SOCKGUARD_AAAAAAAAYYY"},
			want:  "",
		},
		{
			// distance * suggestionLengthRatio == len(suffix) exactly, so the
			// ratio gate must let it through.
			name:  "length ratio exactly at the limit is still suggested",
			input: "SOCKGUARD_ABCX",
			known: []string{"SOCKGUARD_ABCD"},
			want:  "SOCKGUARD_ABCD",
		},
		{
			// Two edits against a five-byte suffix: 2*4 = 8 > 5, so the edits
			// are too large a share of the name to be a likely typo.
			name:  "two edits over a short suffix is too far to suggest",
			input: "SOCKGUARD_AAABB",
			known: []string{"SOCKGUARD_AAAAA"},
			want:  "",
		},
		{
			name:  "no known variables means no suggestion",
			input: "SOCKGUARD_ANYTHING",
			known: nil,
			want:  "",
		},
		{
			name:  "bare prefix has no suffix to compare",
			input: "SOCKGUARD_",
			known: []string{"SOCKGUARD_LISTEN_SOCKET"},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nearestKnownEnvVar(tt.input, tt.known); got != tt.want {
				t.Fatalf("nearestKnownEnvVar(%q, %q) = %q, want %q", tt.input, tt.known, got, tt.want)
			}
		})
	}
}

// TestLevenshteinCountsEveryRowOfTheLongerString covers the pairs where the
// last row of the dynamic-programming table is the row that carries the
// answer. A pair whose distance is already settled before the final row
// passes even when the outer loop stops one row early.
func TestLevenshteinCountsEveryRowOfTheLongerString(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "identical", a: "ABC", b: "ABC", want: 0},
		{name: "empty a", a: "", b: "ABC", want: 3},
		{name: "empty b", a: "ABC", b: "", want: 3},
		{name: "trailing insertion", a: "AA", b: "A", want: 1},
		{name: "trailing deletion", a: "A", b: "AA", want: 1},
		{name: "trailing run of insertions", a: "AAAA", b: "A", want: 3},
		{name: "substitution in the last position", a: "ABC", b: "ABD", want: 1},
		{name: "prefix plus suffix edits", a: "SOCKET", b: "SOCKETS", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := levenshtein(tt.a, tt.b); got != tt.want {
				t.Fatalf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
