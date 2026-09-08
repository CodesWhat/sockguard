package banner

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// Three mutants in banner.go stay alive on purpose, all verified by
// hand-applying the mutation and re-running this package:
//
//   - artMaxWidth's `w > m`: `>=` updates the running maximum on a tie, which
//     stores the same value. Only the `<` direction is a real change, and
//     TestArtMaxWidthIsTheWidestArtRow below kills that one.
//   - shortCommit's `len(c) > n`: at len(c) == n, c[:n] is c.
//   - centerArt's `cols <= width`: at cols == width the pad is the empty
//     string and the rebuild re-joins the same lines and restores the same
//     trailing newlines, so it returns the input byte for byte.

// TestRenderLabelsOnlyTheFirstListenerLine pins the shape of the listener
// block: the "listen" label belongs to the first entry and every entry after
// it is indented under it. Checking only that each address appears leaves the
// label free to move to every row or to none.
func TestRenderLabelsOnlyTheFirstListenerLine(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, Info{
		Listeners: []string{"one unix:/a.sock", "two tcp://127.0.0.1:2375"},
		Upstream:  "/var/run/docker.sock",
	})
	out := buf.String()

	if got := strings.Count(out, "listen"); got != 1 {
		t.Fatalf("Render() wrote %d listen labels, want exactly 1\n---\n%s", got, out)
	}
	if !strings.Contains(out, "  listen    one unix:/a.sock\n") {
		t.Fatalf("Render() did not label the first listener\n---\n%s", out)
	}
	if !strings.Contains(out, "\n            two tcp://127.0.0.1:2375\n") {
		t.Fatalf("Render() did not indent the second listener under the label\n---\n%s", out)
	}
}

// TestRenderKeepsTheListenRowWithNoListeners covers the placeholder row. A
// banner with no listeners still prints the label, so the block never
// disappears entirely and an operator can tell "none" from "not rendered".
func TestRenderKeepsTheListenRowWithNoListeners(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, Info{})
	out := buf.String()

	if got := strings.Count(out, "listen"); got != 1 {
		t.Fatalf("Render() wrote %d listen labels for an empty listener list, want exactly 1\n---\n%s", got, out)
	}
	if !strings.Contains(out, "  listen    \n") {
		t.Fatalf("Render() dropped the empty listen row\n---\n%s", out)
	}
}

// TestArtMaxWidthIsTheWidestArtRow recomputes the art's widest row from the
// art itself. artMaxWidth feeds the centering math, and a package-level
// initializer that silently settles on 0 would left-align the banner on every
// terminal without any other test noticing.
func TestArtMaxWidthIsTheWidestArtRow(t *testing.T) {
	want := 0
	for _, line := range strings.Split(strings.TrimRight(art, "\n"), "\n") {
		if w := utf8.RuneCountInString(line); w > want {
			want = w
		}
	}
	if want == 0 {
		t.Fatal("banner art has no non-empty rows; the fixture itself is wrong")
	}
	if artMaxWidth != want {
		t.Fatalf("artMaxWidth = %d, want %d (widest row of art)", artMaxWidth, want)
	}
}
