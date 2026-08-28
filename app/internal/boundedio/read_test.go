package boundedio

import (
	"errors"
	"os"
	"path/filepath"
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
