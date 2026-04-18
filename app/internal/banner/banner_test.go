package banner

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRenderContainsRuntimeInfo(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, Info{
		Listen:    "unix:/var/run/sockguard.sock",
		Upstream:  "/var/run/docker.sock",
		Rules:     12,
		LogFormat: "json",
		LogLevel:  "info",
		AccessLog: true,
	})

	out := buf.String()
	wants := []string{
		"unix:/var/run/sockguard.sock",
		"/var/run/docker.sock",
		"rules     12",
		"log json/info",
		"access=on",
		"sockguard ",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("Render() output missing %q\n---\n%s", w, out)
		}
	}
}

func TestRenderAccessLogOff(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, Info{AccessLog: false})
	if !strings.Contains(buf.String(), "access=off") {
		t.Errorf("Render() with AccessLog=false should contain access=off, got:\n%s", buf.String())
	}
}

func TestCenterArtNarrowTerminalLeavesArtUnchanged(t *testing.T) {
	in := "aaa\nbb\n"
	// artMaxWidth for "aaa" is 3; narrower terminals return the block
	// untouched so piped output and tight windows keep working.
	got := centerArtBlock(in, 0)
	if got != in {
		t.Errorf("cols=0 should return input unchanged, got %q", got)
	}
	got = centerArtBlock(in, 3)
	if got != in {
		t.Errorf("cols=artMaxWidth should return input unchanged, got %q", got)
	}
}

func TestCenterArtWideTerminalPadsEveryLineEqually(t *testing.T) {
	in := "xxx\nyy\n"
	// max width 3, terminal 9 → pad = (9-3)/2 = 3 on each non-empty line.
	got := centerArtBlock(in, 9)
	want := "   xxx\n   yy\n"
	if got != want {
		t.Errorf("centerArt(9) = %q, want %q", got, want)
	}
}

func TestCenterArtPreservesTrailingNewline(t *testing.T) {
	in := "xx\n\n"
	// Trailing blank line must survive so the info block that follows
	// still gets its expected leading newline spacer.
	got := centerArtBlock(in, 10)
	if !strings.HasSuffix(got, "\n\n") {
		t.Errorf("trailing blank line lost: %q", got)
	}
}

// centerArtBlock wraps centerArt with a controlled artMaxWidth so the
// tests don't depend on the real banner art's exact dimensions.
func centerArtBlock(in string, cols int) string {
	// Save-restore the package-level max width so the test stays
	// isolated from the real banner.
	old := artMaxWidth
	artMaxWidth = 0
	for _, line := range strings.Split(strings.TrimRight(in, "\n"), "\n") {
		if len(line) > artMaxWidth {
			artMaxWidth = len(line)
		}
	}
	defer func() { artMaxWidth = old }()
	return centerArt(in, cols)
}

func TestTerminalColsNonFileWriterReturnsZero(t *testing.T) {
	// bytes.Buffer is not an *os.File — should return 0 immediately.
	var buf bytes.Buffer
	if got := terminalCols(&buf); got != 0 {
		t.Fatalf("terminalCols(bytes.Buffer) = %d, want 0", got)
	}
}

func TestTerminalColsClosedFileReturnsZero(t *testing.T) {
	// An *os.File whose fd is closed will fail Stat(), so terminalCols should
	// return 0 from the stat-error branch.
	f, err := os.CreateTemp(t.TempDir(), "banner-tty-*.tmp")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	_ = f.Close()
	if got := terminalCols(f); got != 0 {
		t.Fatalf("terminalCols(closed file) = %d, want 0", got)
	}
}

func TestTerminalColsRegularFileReturnsZero(t *testing.T) {
	// A regular open file is not a character device, so terminalCols returns 0
	// from the ModeCharDevice branch.
	f, err := os.CreateTemp(t.TempDir(), "banner-tty-*.tmp")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if got := terminalCols(f); got != 0 {
		t.Fatalf("terminalCols(regular file) = %d, want 0", got)
	}
}

// TestTerminalColsTTYReturnsNonZero opens /dev/tty when available and confirms
// terminalCols returns a positive column count. Skipped in environments without
// a controlling terminal (headless CI without a PTY).
func TestTerminalColsTTY(t *testing.T) {
	f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		t.Skipf("cannot open /dev/tty (%v) — TTY ioctl branch untestable here", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	got := terminalCols(f)
	if got <= 0 {
		t.Skipf("terminalCols(/dev/tty) = %d — ioctl returned 0 (headless terminal)", got)
	}
}

func TestShortCommit(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"abcdef0", "abcdef0"},
		{"abcdef01234567", "abcdef0"},
		{"5fe1940abcdef", "5fe1940"},
	}
	for _, tt := range tests {
		if got := shortCommit(tt.in); got != tt.want {
			t.Errorf("shortCommit(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
