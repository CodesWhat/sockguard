// Package banner renders the sockguard startup banner.
package banner

import (
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/codeswhat/sockguard/internal/ui"
	"github.com/codeswhat/sockguard/internal/version"
)

const art = `                ...                              ...
         .=+=..                           .=+=..
       ..=--**..                        ..=*--+.:
       .:=-:=#*:..                     .:*#+:--=..
      .:+--..+++=:..:..................=+++:.:-=:.
     :.-=--...=+=:.-+***************=::-++:..:-=+..
     ..==--....:***++++++++++++####*+***=... ---+:.
     ..==--..-+++++++++++++++++++***++++++=:.:--+:.
     ..:+=::++++++++++++++++++++++++++++++++=.-=+..
      ....:++++%@%++#@%++++++++++@@%**#@%++++=.. ..
        ..+++++*%@@@@@*+++++++++++%@@@@@*+++++-.:
       :.:=+++++#@@@@#*++.++++=-++%@@@@#+++++==..
       ..-=++++%@@#*@%#:.:::::::.+%@**@@@*+++==:..
      ..:++++++++++::%@%..:**=:.-%@=.=+++++++++=...
     ..=+==+=.:%@@%@@@.==.... .:=:-@@%@@@+..+===+:..
    ..:+===.*@@%:@*+@@:..:+...+...*@@:@*=@@@-:===+..
    ..====.#%%@@%:@==@@@*.. ...:%@@%:@=*@@@#%::===:.:
    ...==-.#%-%%@@@@@%%%%%%=.*%%%%%@@@@@@%**%=.==-..:
     ...:..+*#:.:-----::=*:::=*:::-----::.*%*..=-...
       ..-====+#@*.#@@=:-:...::=:#@@@.=:#%*:.......
     ..:+**%@#*===*+.:#%@@@@@@@@%=:::*%#:#@@@@%=..
    ..+%#*====+#@#===#@@@@@@@@@@@@=%%%@@%:+@@@@@@:.
   ..*@@@@@@@%+==+%%+==%@%%%%%%%%%+*@@@@@@*.*%%%%:.
  ..#@%%@@@@@@@@%===%@=-=+:........:%@@@@@@@=.....:
  ..**...:*#%@@@@@@===%=.:**#***++=.#@@@@@@@@@=..
   ..**:.....=%%@@@@*-..-==========.*%@@@@@@@@@-.:
    ...=#*:.. .-%%%%*.......:::... ..#%%%@@@@%%:.:
       ...:*%#=:-%%-..     :...:    ..:*#%%%#=...
           .........                  ... . ..
`

// artMaxWidth is the widest character row of the banner, computed
// once at startup so runtime centering can left-pad each row by the
// same amount without warping the shape.
var artMaxWidth = func() int {
	m := 0
	for _, line := range strings.Split(strings.TrimRight(art, "\n"), "\n") {
		if len(line) > m {
			m = len(line)
		}
	}
	return m
}()

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

	fmt.Fprintln(w)
	fmt.Fprint(w, p.Cyan(centerArt(art, terminalCols(w))))
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

// centerArt left-pads every row of the banner so the full block is
// horizontally centered inside a terminal of `cols` columns. If cols
// is 0 (no TTY) or narrower than the art itself, the art is returned
// unchanged so piped output and narrow terminals fall back to the
// original left-aligned rendering.
func centerArt(block string, cols int) string {
	if cols <= artMaxWidth {
		return block
	}
	pad := strings.Repeat(" ", (cols-artMaxWidth)/2)
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
