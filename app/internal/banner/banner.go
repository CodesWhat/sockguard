// Package banner renders the sockguard startup banner.
package banner

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/codeswhat/sockguard/internal/ui"
	"github.com/codeswhat/sockguard/internal/version"
)

const art = `                   ▓▓▒
                  ▓██▓▒▒
           ▓▓▒▓▓  ▓█▓▓▓▓▓
           ██▓▓▓▓▓▓█▓▓▓▓▓▓
           ▓▓▓▒▒▓▒▓▓▓▓▓▓▒▓▒
        ▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓
      ▒▒▒▓▒░▒▒▒▒▒▒▒▓▓▓▓▓▓▓▒▒▒
     ▒▒▓▓▒▒▒▒▒▒░▒▒▓▓▓▓▓▓▓▓▓▓▒
     ▒▒▓▓▓▓▓▒░▒▒▒░▒▓▓▓▒▒▓▓▓▓▓▒
 ██▓█░  ░▒▓▓▒░▓▓▓░░▓▓▓▒▒▓▓▓▓▓▒
 ███▒     ░▓▓▒░░░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒               ▓▓▓▓
 ░░░░░░░ ░ ░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▒▒▒▒▒▒▒▒▒▒    ▓▒▓▓
 ░░░░░░░░░░░░▒▓▓▓▓▓▓▓▓▓▓▓▓█▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▓▓▓▓▓
 ░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
  ░░░░░░░░░░░░▓▓▓▓▓████▒▓█▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒
    ░▒▒▒░░░░░▒▓███▒▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒
           ▓█▓▓█████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▒
           ▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▒▒
             ░▒░▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒
             ░░░░░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒
              ░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒
               ▒▒░░░▒▓▓▓▓▓▒▒▓█▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▒▒▓▒
               ▓▓▓▓▒▒▒▓▓▓▓▓▒▓▓▓▓▓▓▓▓▓▓▓▓████▓▓▓▒▒▓▓
               ▒▓▓▓██▓▓▓▓▓▓▓▓▓███▓██▓██████▓▓▓▓▓▓▓▓
               ▓▓▓▓██▓▓▓▓▓▓▓▓▓       ██████▓▓▓▓▓▓▓▓
                  ███▓▓▓▓▓▓▓▓▓             ██▓▓▓▓▓
`

// artMaxWidth is the widest character row of the banner, computed
// once at startup so runtime centering can left-pad each row by the
// same amount without warping the shape.
var artMaxWidth = func() int {
	m := 0
	for _, line := range strings.Split(strings.TrimRight(art, "\n"), "\n") {
		// Count display columns (runes), not bytes — the art uses
		// multi-byte block glyphs (░▒▓█), so len() would overcount ~3x
		// and break the centering math.
		if w := utf8.RuneCountInString(line); w > m {
			m = w
		}
	}
	return m
}()

// colorArt is a pre-rendered 24-bit (truecolor) half-block rendering of the
// sockguard logo, exactly colorArtWidth columns wide, generated from
// sockguard-logo.png by half-block (▀) truecolor sampling. It is shown only on
// truecolor terminals; everything else falls back to the monochrome `art`
// above.
//
//go:embed dog_color.ans
var colorArt string

// colorArtWidth is the fixed display width (columns) of colorArt. Its rows
// carry ANSI escapes, so this is a known constant rather than a rune count.
const colorArtWidth = 50

// Info is the runtime summary rendered beneath the ASCII art.
type Info struct {
	Listen    string
	Upstream  string
	Rules     int
	LogFormat string
	LogLevel  string
	AccessLog bool
}

// Render writes the banner and info block to w.
func Render(w io.Writer, info Info) {
	access := "off"
	if info.AccessLog {
		access = "on"
	}
	p := ui.New(w)
	cols := terminalCols(w)

	fmt.Fprintln(w)
	if p.Enabled() && truecolor() {
		// colorArt already carries per-cell ANSI; don't wrap it in Cyan.
		fmt.Fprint(w, centerArt(colorArt, cols, colorArtWidth))
	} else {
		fmt.Fprint(w, p.Cyan(centerArt(art, cols, artMaxWidth)))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s  %s\n",
		p.Bold("sockguard"),
		version.Version,
		p.Dim(fmt.Sprintf("(commit %s, built %s, %s)",
			shortCommit(version.Commit), version.BuildDate, runtime.Version())))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s\n", p.Dim("listen   "), info.Listen)
	fmt.Fprintf(w, "  %s %s\n", p.Dim("upstream "), info.Upstream)
	fmt.Fprintf(w, "  %s %d  %s\n",
		p.Dim("rules    "), info.Rules,
		p.Dim(fmt.Sprintf("(log %s/%s, access=%s)", info.LogFormat, info.LogLevel, access)))
	fmt.Fprintln(w)
}

func shortCommit(c string) string {
	const n = 7
	if len(c) > n {
		return c[:n]
	}
	return c
}

// truecolor reports whether the terminal advertises 24-bit color via
// COLORTERM. The colored banner emits 24-bit escapes, so without this we fall
// back to the monochrome art rather than send codes a 16/256-color terminal
// would mangle.
func truecolor() bool {
	switch os.Getenv("COLORTERM") {
	case "truecolor", "24bit":
		return true
	}
	return false
}

// centerArt left-pads every row of the banner so the full block is
// horizontally centered inside a terminal of `cols` columns. If cols
// is 0 (no TTY) or narrower than the art itself, the art is returned
// unchanged so piped output and narrow terminals fall back to the
// original left-aligned rendering.
func centerArt(block string, cols, width int) string {
	if cols <= width {
		return block
	}
	pad := strings.Repeat(" ", (cols-width)/2)
	var b strings.Builder
	trimmed := strings.TrimRight(block, "\n")
	trailingNewlines := len(block) - len(trimmed)
	for i, line := range strings.Split(trimmed, "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		if line != "" {
			b.WriteString(pad)
		}
		b.WriteString(line)
	}
	for i := 0; i < trailingNewlines; i++ {
		b.WriteByte('\n')
	}
	return b.String()
}
