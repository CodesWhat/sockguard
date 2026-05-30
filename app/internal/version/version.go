package version

// Version is set at build time via -ldflags.
var Version = "dev"

// Commit is set at build time via -ldflags.
var Commit = "unknown"

// BuildDate is set at build time via -ldflags.
var BuildDate = "unknown"
