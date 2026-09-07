package visibility

import "testing"

// TestRawQueryAcceptsAppendedFilters pins the empty-pair-terminates-false
// branch (`if pair == ""`) inside rawQueryAcceptsAppendedFilters, alongside
// its other two exits, so a mutation that inverts any one of the three
// conditions is caught by some row here.
func TestRawQueryAcceptsAppendedFilters(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "empty query accepts appending", query: "", want: true},
		{name: "one ordinary parameter accepts appending", query: "all=1", want: true},
		{name: "existing filters parameter must be merged, not appended", query: "filters=%7B%7D", want: false},
		{name: "trailing ampersand produces an empty pair", query: "all=1&", want: false},
		{name: "percent escape blocks the append path", query: "all=1%2C2", want: false},
		{name: "semicolon blocks the append path", query: "all=1;more=2", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawQueryAcceptsAppendedFilters(tc.query); got != tc.want {
				t.Fatalf("rawQueryAcceptsAppendedFilters(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}
