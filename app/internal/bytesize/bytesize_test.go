package bytesize

import "testing"

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
