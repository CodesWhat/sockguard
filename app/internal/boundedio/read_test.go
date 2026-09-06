package boundedio

import (
	"errors"
	"io/fs"
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

// TestReadFileKeepsTheFirstErrorWhenCloseAlsoFails kills the
// CONDITIONALS_NEGATION mutant on the deferred close's `returnErr == nil`
// guard (-> returnErr != nil), which inverts which error survives: the close
// failure is reported and the error that actually stopped the read is thrown
// away. Every caller of ReadFile decides on that error, so a "close" wrapper
// around it is a diagnosis pointed at the wrong thing.
//
// The two failures have to happen together, and a regular file on a healthy
// filesystem never fails Close on request. The openReadOnly seam supplies a
// descriptor that is already closed instead: Stat and Close then both fail
// with os.ErrClosed, and only the operation named in the returned error tells
// the correct code apart from the mutant.
func TestReadFileKeepsTheFirstErrorWhenCloseAlsoFails(t *testing.T) {
	original := openReadOnly
	t.Cleanup(func() { openReadOnly = original })

	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	openReadOnly = func(p string) (*os.File, error) {
		f, err := original(p)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			t.Fatalf("closing the descriptor under test: %v", err)
		}
		return f, nil
	}

	data, err := ReadFile(path, 1024)
	if err == nil {
		t.Fatalf("ReadFile() on a closed descriptor = %q, nil; want an error", data)
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ReadFile() error = %v, want it to wrap os.ErrClosed", err)
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("ReadFile() error = %v (%T), want a *fs.PathError in the chain", err, err)
	}
	if pathErr.Op != "stat" {
		t.Fatalf("ReadFile() reported the %q failure (%v); want the stat failure that stopped the read, not the close failure that followed it",
			pathErr.Op, err)
	}
}
