package boundedio

import (
	"errors"
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

	data, err := ReadFile(path, 5)
	if err != nil {
		t.Fatalf("ReadFile(exact limit): %v", err)
	}
	if string(data) != "12345" {
		t.Fatalf("ReadFile data = %q, want exact contents", data)
	}
	if _, err := ReadFile(path, 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadFile(over limit) error = %v, want ErrTooLarge", err)
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
