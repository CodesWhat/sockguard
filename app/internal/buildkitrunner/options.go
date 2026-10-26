// Package buildkitrunner runs an external frontend with every gateway request
// routed through an authenticated Sockguard connection.
package buildkitrunner

import "io"

type Options struct {
	Host            string
	CAFile          string
	CertFile        string
	KeyFile         string
	Image           string
	RuntimeContext  string
	FrontendOptions []string
	ExportName      string
	Operations      io.Writer
	Stderr          io.Writer
}
