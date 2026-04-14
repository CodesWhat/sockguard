package ui

import (
	"bytes"
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
