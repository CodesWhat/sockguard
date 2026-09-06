package boundedio

import (
	"errors"
	"fmt"
	"io"
)

// ErrTooLarge identifies a file rejected before its full contents were read.
var ErrTooLarge = errors.New("file exceeds byte limit")

// ErrNotRegular identifies an input rejected because it is not a regular file.
var ErrNotRegular = errors.New("path is not a regular file")

// openReadOnly opens path for reading. Production binds the build-tagged
// openReadOnlyFile (O_NONBLOCK on unix so a FIFO cannot stall the open, plain
// os.Open elsewhere); it is a package var, in the same shape as
// imagetrust.newLiveTrustedRootFactory, so a test can substitute a descriptor
// whose Stat, Read or Close fails and reach ReadFile's error branches. A real
// file on a healthy filesystem does not fail those calls on demand.
var openReadOnly = openReadOnlyFile

// ReadFile reads at most maxBytes from path and fails closed when more data is
// present. The one-byte lookahead distinguishes an exact-limit file from an
// oversized one without allocating for the remainder.
func ReadFile(path string, maxBytes int64) (_ []byte, returnErr error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("read %q: max bytes must be positive", path)
	}
	f, err := openReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close %q: %w", path, err)
		}
	}()
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read %q: %w", path, ErrNotRegular)
	} else if info.Size() > maxBytes {
		return nil, fmt.Errorf("read %q: %w (%d byte limit)", path, ErrTooLarge, maxBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return nil, err
	}
	var lookahead [1]byte
	n, err := f.Read(lookahead[:])
	if n > 0 {
		return nil, fmt.Errorf("read %q: %w (%d byte limit)", path, ErrTooLarge, maxBytes)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return data, nil
}
