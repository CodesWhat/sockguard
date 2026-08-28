//go:build linux

package boundedio

import (
	"errors"
	"testing"
)

func TestReadFileLookaheadRejectsSizeUnderreporting(t *testing.T) {
	_, err := ReadFile("/proc/self/status", 1)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadFile(/proc/self/status) error = %v, want ErrTooLarge", err)
	}
}
