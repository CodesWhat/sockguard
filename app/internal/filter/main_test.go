package filter

import (
	"fmt"
	"os"
	"testing"
)

// TestMain points TMPDIR at a directory removed after the run. Inspectors now
// leave their spool for the caller to close, and many tests call one directly
// without closing req.Body, so without this each run would leave its spools
// (one of them 512 MiB) in the shared temp directory.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sockguard-filter-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create test temp dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("TMPDIR", dir); err != nil {
		fmt.Fprintf(os.Stderr, "set TMPDIR: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
