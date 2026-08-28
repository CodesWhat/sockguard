//go:build unix

package boundedio

import (
	"os"
	"syscall"
)

func openReadOnly(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- candidate, trust, and bundle paths are explicit operator configuration; ReadFile validates the opened descriptor as a regular file.
}
