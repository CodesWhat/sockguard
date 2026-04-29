package ui

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestNonTTYDisablesColorByDefault(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	var buf bytes.Buffer
	p := New(&buf)
	if p.Enabled() {
		t.Fatal("bytes.Buffer is not a TTY; color should be disabled")
	}
	if got := p.Red("err"); got != "err" {
		t.Errorf("Red(non-TTY) = %q, want plain %q", got, "err")
	}
}

func TestForceColorEnablesOnNonTTY(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	var buf bytes.Buffer
	p := New(&buf)
	if !p.Enabled() {
		t.Fatal("FORCE_COLOR should enable color even for non-TTY")
	}
	got := p.Green("ok")
	if !strings.Contains(got, "ok") || !strings.Contains(got, "\x1b[32m") || !strings.Contains(got, ansiReset) {
		t.Errorf("Green should wrap text with green ANSI + reset, got %q", got)
	}
}

func TestNoColorBeatsForceColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "1")
	var buf bytes.Buffer
	p := New(&buf)
	if p.Enabled() {
		t.Fatal("NO_COLOR should take precedence over FORCE_COLOR")
	}
}

func TestEmptyNoColorDoesNotDisable(t *testing.T) {
	// Per https://no-color.org, only a non-empty NO_COLOR disables color.
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	var buf bytes.Buffer
	p := New(&buf)
	if !p.Enabled() {
		t.Fatal("empty NO_COLOR should not disable color; FORCE_COLOR should still win")
	}
}

func TestWReturnsUnderlyingWriter(t *testing.T) {
	var buf bytes.Buffer
	p := New(&buf)
	if p.W() != &buf {
		t.Fatal("W() should return the writer passed to New()")
	}
}

// TestDetectColorStatErrorReturnsFalse exercises the branch in detectColor where
// the writer is an *os.File but Stat() fails. We use /dev/null opened with a
// closed file descriptor so the file object is valid but the fd is gone.
func TestDetectColorStatErrorReturnsFalse(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")

	// Open a real file, close it, then pass the *os.File whose fd is now
	// invalid — Stat() will fail with "bad file descriptor".
	f, err := os.CreateTemp(t.TempDir(), "ui-test-*.tmp")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	// Close the underlying fd so Stat() will fail.
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := detectColor(f)
	if got {
		t.Fatal("detectColor should return false when Stat() fails")
	}
}

// TestDetectColorCharDevice exercises the character-device branch of detectColor.
// It opens /dev/tty when available; if it cannot be opened (e.g. in a CI
// environment without a controlling terminal), the test is skipped gracefully.
func TestDetectColorCharDevice(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")

	f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		t.Skipf("cannot open /dev/tty (%v) — TTY branch untestable in this environment", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	got := detectColor(f)
	if !got {
		t.Fatal("detectColor(/dev/tty) should return true for a character device")
	}
}

func TestDetectColorCharDeviceWithoutTTYStillReturnsTrue(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")

	f, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(/dev/null): %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if !detectColor(f) {
		t.Fatal("detectColor(/dev/null) should return true for a character device")
	}
}

func TestAllStylesWrapWithReset(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	var buf bytes.Buffer
	p := New(&buf)
	for name, got := range map[string]string{
		"Bold":   p.Bold("x"),
		"Dim":    p.Dim("x"),
		"Red":    p.Red("x"),
		"Green":  p.Green("x"),
		"Yellow": p.Yellow("x"),
		"Cyan":   p.Cyan("x"),
	} {
		if !strings.HasPrefix(got, "\x1b[") || !strings.HasSuffix(got, ansiReset) {
			t.Errorf("%s = %q; want ANSI-wrapped with reset suffix", name, got)
		}
	}
}
