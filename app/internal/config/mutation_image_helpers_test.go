package config

import (
	"strings"
	"testing"
)

func TestValidateMutationImageField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantOK  bool
		wantErr string
	}{
		{"valid", "registry.example/app:1", true, ""},
		{"blank", "   ", false, "required"},
		{"oversized", strings.Repeat("a", maxMutationImageFieldBytes+1), false, "exceeds"},
		{"control byte", "app\x01", false, "control characters"},
		{"oversized and control", strings.Repeat("a", maxMutationImageFieldBytes+1) + "\x00", false, "control characters"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var errs []string
			ok := validateMutationImageField("rules[0].from", tc.value, &errs)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (errs %v)", ok, tc.wantOK, errs)
			}
			joined := strings.Join(errs, "|")
			if tc.wantErr == "" && len(errs) != 0 {
				t.Fatalf("errs = %v, want none", errs)
			}
			if tc.wantErr != "" && !strings.Contains(joined, tc.wantErr) {
				t.Fatalf("errs = %v, want one containing %q", errs, tc.wantErr)
			}
		})
	}
}

func TestValidateMutationImageLiteral(t *testing.T) {
	t.Parallel()
	if errs := validateMutationImageLiteral("to", "registry.example/app:1"); len(errs) != 0 {
		t.Fatalf("valid reference rejected: %v", errs)
	}
	errs := validateMutationImageLiteral("to", "UPPER CASE:::bad")
	if len(errs) != 1 || !strings.Contains(errs[0], "valid image reference") {
		t.Fatalf("invalid reference errs = %v, want one valid-image-reference error", errs)
	}
}

func TestMutationImageMatchesOverlap(t *testing.T) {
	t.Parallel()
	entry := func(match, from string) mutationImageOverlapEntry {
		return mutationImageOverlapEntry{match: match, from: from}
	}
	tests := []struct {
		name string
		a, b mutationImageOverlapEntry
		want bool
	}{
		{"exact equal", entry("exact", "a/b"), entry("exact", "a/b"), true},
		{"exact different", entry("exact", "a/b"), entry("exact", "a/c"), false},
		{"exact under prefix", entry("exact", "a/b:1"), entry("prefix", "a/"), true},
		{"exact outside prefix", entry("exact", "x/b:1"), entry("prefix", "a/"), false},
		{"prefix over exact", entry("prefix", "a/"), entry("exact", "a/b:1"), true},
		{"prefix beside exact", entry("prefix", "a/"), entry("exact", "x/b:1"), false},
		{"prefix nests prefix", entry("prefix", "a/"), entry("prefix", "a/b/"), true},
		{"prefix nested by prefix", entry("prefix", "a/b/"), entry("prefix", "a/"), true},
		{"disjoint prefixes", entry("prefix", "a/"), entry("prefix", "b/"), false},
		{"unknown match modes", entry("glob", "a"), entry("glob", "a"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := mutationImageMatchesOverlap(tc.a, tc.b); got != tc.want {
				t.Fatalf("mutationImageMatchesOverlap = %v, want %v", got, tc.want)
			}
		})
	}
}
