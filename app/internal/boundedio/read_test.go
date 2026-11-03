package boundedio

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	openReadOnly = func(p string) (readableFile, error) {
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

// zeroThenEOFFile serves its payload, then reports (0, nil) once, then EOF.
// io.Reader permits a zero-byte read with no error; the lookahead must treat
// it as "no data yet", not as proof the file is oversized.
type zeroThenEOFFile struct {
	payload []byte
	size    int64
	reads   int
}

func (z *zeroThenEOFFile) Read(p []byte) (int, error) {
	z.reads++
	switch z.reads {
	case 1:
		return copy(p, z.payload), nil
	case 2:
		return 0, nil
	default:
		return 0, io.EOF
	}
}

func (z *zeroThenEOFFile) Close() error { return nil }

func (z *zeroThenEOFFile) Stat() (fs.FileInfo, error) {
	return fakeRegularInfo{size: z.size}, nil
}

type fakeRegularInfo struct{ size int64 }

func (fakeRegularInfo) Name() string       { return "fake" }
func (i fakeRegularInfo) Size() int64      { return i.size }
func (fakeRegularInfo) Mode() fs.FileMode  { return 0o600 }
func (fakeRegularInfo) ModTime() time.Time { return time.Time{} }
func (fakeRegularInfo) IsDir() bool        { return false }
func (fakeRegularInfo) Sys() any           { return nil }

func TestReadFileTreatsAZeroByteLookaheadReadAsNoData(t *testing.T) {
	original := openReadOnly
	t.Cleanup(func() { openReadOnly = original })

	payload := []byte("12345")
	openReadOnly = func(string) (readableFile, error) {
		return &zeroThenEOFFile{payload: payload, size: int64(len(payload))}, nil
	}

	data, err := ReadFile("ignored", 16)
	if err != nil {
		t.Fatalf("ReadFile() error = %v, want the payload", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("ReadFile() = %q, want %q", data, payload)
	}
}
