package bytesize

import (
	"math"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"8MiB", 8 << 20, false},
		{"32MiB", 32 << 20, false},
		{"32 MiB", 32 << 20, false},
		{" 32mib ", 32 << 20, false},
		{"512KiB", 512 << 10, false},
		{"1GiB", 1 << 30, false},
		{"1048576", 1 << 20, false},
		{"100B", 100, false},
		{"", 0, true},
		{"MiB", 0, true},
		{"0", 0, true},
		{"0MiB", 0, true},
		{"-1MiB", 0, true},
		{"1.5MiB", 0, true},
		{"32MB", 0, true},
		{"32KB", 0, true},
		{"abc", 0, true},
		{"9223372036854775807GiB", 0, true},
		{"99999999999999999999", 0, true},
	}
	for _, tc := range tests {
		got, err := Parse(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("Parse(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("Parse(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFormatRoundTrips(t *testing.T) {
	for _, s := range []string{"8MiB", "256MiB", "1GiB", "512KiB", "100B"} {
		n, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if got := Format(n); got != s {
			t.Errorf("Format(Parse(%q)) = %q", s, got)
		}
	}
	if got := Format(1536); got != "1536B" {
		t.Errorf("Format(1536) = %q, want 1536B", got)
	}
}

func TestParseLargestWholeUnitValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, input string
		want        int64
		wantErr     bool
	}{
		{name: "largest plain bytes", input: "9223372036854775807", want: math.MaxInt64},
		{name: "largest explicit bytes", input: "9223372036854775807B", want: math.MaxInt64},
		{name: "largest KiB", input: "9007199254740991KiB", want: 9223372036854774784},
		{name: "first KiB overflow", input: "9007199254740992KiB", wantErr: true},
		{name: "largest MiB", input: "8796093022207MiB", want: 9223372036853727232},
		{name: "first MiB overflow", input: "8796093022208MiB", wantErr: true},
		{name: "largest GiB", input: "8589934591GiB", want: 9223372035781033984},
		{name: "first GiB overflow", input: "8589934592GiB", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("Parse(%q)=(%d,%v), want %d error=%v", tt.input, got, err, tt.want, tt.wantErr)
			}
		})
	}
}
