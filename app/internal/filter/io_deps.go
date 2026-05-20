package filter

import (
	"io"
	"os"
)

// ioDeps groups the filesystem and stream primitives the request inspectors
// use. Threading the struct through each inspector instead of relying on
// package-level swappable globals lets tests inject stubs without mutating
// shared state, so policy-level tests can safely run under t.Parallel().
type ioDeps struct {
	CreateTempFile  func(dir, pattern string) (*os.File, error)
	RemoveFilePath  func(name string) error
	SeekToStart     func(file *os.File) error
	ReadAllLimited  func(reader io.Reader, limit int64) ([]byte, error)
	DrainReader     func(reader io.Reader) error
	CloseReadCloser func(closer io.Closer) error
}

// defaultIODeps returns the production wiring backed by the os and io
// packages. Each call returns a fresh struct so callers can mutate individual
// fields without affecting other tests.
func defaultIODeps() ioDeps {
	return ioDeps{
		CreateTempFile: os.CreateTemp,
		RemoveFilePath: os.Remove,
		SeekToStart: func(file *os.File) error {
			_, err := file.Seek(0, io.SeekStart)
			return err
		},
		ReadAllLimited: func(reader io.Reader, limit int64) ([]byte, error) {
			return io.ReadAll(io.LimitReader(reader, limit))
		},
		DrainReader: func(reader io.Reader) error {
			_, err := io.Copy(io.Discard, reader)
			return err
		},
		CloseReadCloser: func(closer io.Closer) error {
			return closer.Close()
		},
	}
}
