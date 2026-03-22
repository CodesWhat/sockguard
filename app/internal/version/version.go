package version

import (
	"fmt"
	"runtime"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Commit is set at build time via -ldflags.
var Commit = "unknown"

// BuildDate is set at build time via -ldflags.
var BuildDate = "unknown"

// String returns a formatted version string.
func String() string {
	return fmt.Sprintf("sockguard %s (commit: %s, built: %s, go: %s)", Version, Commit, BuildDate, runtime.Version())
}
