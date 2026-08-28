package boundedio

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFileEnforcesLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tests := []struct {
		name    string
		limit   int64
		want    string
		wantErr error
	}{
		{name: "exact limit", limit: 5, want: "12345"},
		{name: "oversized", limit: 4, wantErr: ErrTooLarge},
		{name: "largest limit", limit: math.MaxInt64, want: "12345"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ReadFile(path, tc.limit)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadFile(limit=%d) error = %v, want %v", tc.limit, err, tc.wantErr)
			}
			if string(data) != tc.want {
				t.Fatalf("ReadFile(limit=%d) data = %q, want %q", tc.limit, data, tc.want)
			}
		})
	}
}

func TestReadFilePreservesMissingFileError(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "missing"), 4)
	if !os.IsNotExist(err) {
		t.Fatalf("ReadFile missing error = %v, want os.IsNotExist", err)
	}
}

func TestReadFileRejectsNonPositiveLimitBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	for _, limit := range []int64{0, -1} {
		_, err := ReadFile(path, limit)
		if err == nil || !strings.Contains(err.Error(), "max bytes must be positive") {
			t.Fatalf("ReadFile(limit=%d) error = %v, want positive-limit error", limit, err)
		}
		if os.IsNotExist(err) {
			t.Fatalf("ReadFile(limit=%d) opened the path before validating the limit", limit)
		}
	}
}
