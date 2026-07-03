//go:build ignore

// Command bannerpreview prints the sockguard startup banner to stdout so you
// can see exactly what `sockguard serve` renders on a truecolor terminal —
// without starting the proxy. The `ignore` build tag keeps it out of normal
// builds/tests/coverage; run it via scripts/show-banner.sh (which forces
// COLORTERM=truecolor) or `go run ./cmd/bannerpreview/main.go`.
package main

import (
	"os"

	"github.com/codeswhat/sockguard/internal/banner"
)

func main() {
	banner.Render(os.Stdout, banner.Info{
		Listen:    "unix:/var/run/sockguard/sockguard.sock",
		Upstream:  "/var/run/docker.sock",
		Rules:     6,
		LogFormat: "text",
		LogLevel:  "info",
		AccessLog: true,
	})
}
