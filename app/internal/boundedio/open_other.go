//go:build !unix

package boundedio

import "os"

func openReadOnly(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- candidate, trust, and bundle paths are explicit operator configuration; ReadFile validates the opened descriptor as a regular file.
}
