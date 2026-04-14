// Package ui provides stdlib-only terminal styling helpers that
// respect NO_COLOR, FORCE_COLOR, and TTY detection.
//
// Usage: construct a Printer once per writer and reuse it for all output.
// Color detection is cached at construction, so there are no repeated
// environment lookups or stat syscalls on each styled write.
package ui

import (
	"io"
	"os"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

// UTF-8 glyphs emitted regardless of color state. Every modern terminal
// handles these; pipes and files preserve them for grep/tee.
const (
	Check = "✓"
	Cross = "✗"
	Arrow = "→"
	Warn  = "⚠"
	Info  = "ℹ"
)

// Printer wraps an io.Writer with color-aware styling helpers.
type Printer struct {
	w       io.Writer
	enabled bool
}

// New returns a Printer for w. Color is enabled when:
//   - NO_COLOR is unset or empty, AND
//   - FORCE_COLOR is set to a non-empty value, OR w is a character device (TTY).
//
// NO_COLOR takes precedence over FORCE_COLOR per https://no-color.org.
func New(w io.Writer) *Printer {
	return &Printer{w: w, enabled: detectColor(w)}
}

// W returns the underlying writer.
func (p *Printer) W() io.Writer { return p.w }

// Enabled reports whether ANSI escapes will be emitted.
func (p *Printer) Enabled() bool { return p.enabled }

func (p *Printer) style(code, s string) string {
	if !p.enabled {
		return s
	}
	return code + s + ansiReset
}

func (p *Printer) Bold(s string) string   { return p.style(ansiBold, s) }
func (p *Printer) Dim(s string) string    { return p.style(ansiDim, s) }
func (p *Printer) Red(s string) string    { return p.style(ansiRed, s) }
func (p *Printer) Green(s string) string  { return p.style(ansiGreen, s) }
func (p *Printer) Yellow(s string) string { return p.style(ansiYellow, s) }
func (p *Printer) Cyan(s string) string   { return p.style(ansiCyan, s) }

func detectColor(w io.Writer) bool {
	if v, ok := os.LookupEnv("NO_COLOR"); ok && v != "" {
		return false
	}
	if v, ok := os.LookupEnv("FORCE_COLOR"); ok && v != "" {
		return true
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
