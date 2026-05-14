package filter

import (
	"io"
	"os"
)

var (
	// Test hook — do not use t.Parallel() in tests that swap this.
	createTempFile = os.CreateTemp
	// Test hook — do not use t.Parallel() in tests that swap this.
	removeFilePath = os.Remove
	// Test hook — do not use t.Parallel() in tests that swap this.
	seekToStart = func(file *os.File) error {
		_, err := file.Seek(0, io.SeekStart)
		return err
	}
	// Test hook — do not use t.Parallel() in tests that swap this.
	readAllLimited = func(reader io.Reader, limit int64) ([]byte, error) {
		return io.ReadAll(io.LimitReader(reader, limit))
	}
	// Test hook — do not use t.Parallel() in tests that swap this.
	drainReader = func(reader io.Reader) error {
		_, err := io.Copy(io.Discard, reader)
		return err
	}
	// Test hook — do not use t.Parallel() in tests that swap this.
	closeReadCloser = func(closer io.Closer) error {
		return closer.Close()
	}
)
