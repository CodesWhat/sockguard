package main

import "testing"

func TestSanitizeLogField(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "removes newline",
			in:   "GET\nPOST",
			want: "GETPOST",
		},
		{
			name: "removes carriage return",
			in:   "/containers\r/json",
			want: "/containers/json",
		},
		{
			name: "removes null",
			in:   "abc\x00def",
			want: "abcdef",
		},
		{
			name: "removes bell",
			in:   "abc\adef",
			want: "abcdef",
		},
		{
			name: "passes clean field through",
			in:   "/v1.45/containers/json?all=1",
			want: "/v1.45/containers/json?all=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeLogField(tt.in); got != tt.want {
				t.Fatalf("sanitizeLogField(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
