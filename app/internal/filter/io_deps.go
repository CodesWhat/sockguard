package filter

import (
	"io"
	"os"
)

var (
	createTempFile = os.CreateTemp
	removeFilePath = os.Remove
	seekToStart    = func(file *os.File) error {
		_, err := file.Seek(0, io.SeekStart)
		return err
	}
	readAllLimited = func(reader io.Reader, limit int64) ([]byte, error) {
		return io.ReadAll(io.LimitReader(reader, limit))
	}
	drainReader = func(reader io.Reader) error {
		_, err := io.Copy(io.Discard, reader)
		return err
	}
	closeReadCloser = func(closer io.Closer) error {
		return closer.Close()
	}
)
