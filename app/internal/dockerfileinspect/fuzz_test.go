package dockerfileinspect

import (
	"strings"
	"testing"
)

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// FuzzDockerfileInspect feeds raw client Dockerfile text to the three
// heuristics that gate RUN and BuildKit syntax-frontend overrides. The RUN
// scan is a deny control, so beyond not panicking it checks the properties a
// bypass would have to break: a literal RUN first line is always seen,
// keyword case and a leading BOM never change a verdict, and the helpers
// agree with each other.
func FuzzDockerfileInspect(f *testing.F) {
	f.Add([]byte("FROM alpine\nRUN echo hi\n"))
	f.Add([]byte("FROM alpine\nCOPY . /app\n"))
	f.Add([]byte("# syntax=docker/dockerfile:1\nFROM alpine\n"))
	f.Add([]byte("// syntax=example.com/frontend\nFROM scratch\n"))
	f.Add([]byte(`{"syntax":"evil/frontend"}`))
	f.Add([]byte("# escape=`\nFROM alpine\nR`\nUN id\n"))
	f.Add([]byte("FROM a\nONBUILD RUN id\n"))
	f.Add([]byte("FROM a\nCOPY <<EOF /x\nRUN no\nEOF\n"))
	f.Add([]byte("\xef\xbb\xbf#!/bin/sh\n# syntax=x\n"))
	f.Add([]byte("RUN a \\\r\r\n b\r\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}

		hasRun := ContainsRunInstruction(raw)
		frontend := SyntaxFrontend(raw)

		if ContainsRunInstruction(raw) != hasRun || SyntaxFrontend(raw) != frontend {
			t.Fatalf("not deterministic for %q", raw)
		}

		// A plain RUN line at the top is an instruction under every reading.
		if !ContainsRunInstruction(append([]byte("RUN true\n"), raw...)) {
			t.Fatalf("a leading RUN line was missed in front of %q", raw)
		}

		// Only one BOM is dropped, so a second one is content, not a no-op.
		if !strings.HasPrefix(string(raw), "\ufeff") {
			withBOM := append([]byte{0xef, 0xbb, 0xbf}, raw...)
			if ContainsRunInstruction(withBOM) != hasRun {
				t.Fatalf("a UTF-8 BOM changed the RUN verdict for %q", raw)
			}
			if SyntaxFrontend(withBOM) != frontend {
				t.Fatalf("a UTF-8 BOM changed the syntax frontend for %q", raw)
			}
		}

		// Instruction keywords are case-insensitive in every builder.
		if ContainsRunInstruction(asciiLower(raw)) != hasRun {
			t.Fatalf("ASCII keyword case changed the RUN verdict for %q", raw)
		}

		for _, line := range strings.Split(string(raw), "\n") {
			got := Instruction(line)
			if got != strings.ToUpper(got) {
				t.Fatalf("Instruction(%q) = %q, not uppercase", line, got)
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				if got != "" {
					t.Fatalf("Instruction(%q) = %q, want empty for blank/comment", line, got)
				}
				continue
			}
			if got == "" {
				t.Fatalf("Instruction(%q) empty for a non-comment line", line)
			}
			if got == "RUN" && !ContainsRunInstruction([]byte(trimmed)) &&
				!strings.HasSuffix(strings.TrimRight(trimmed, " \t"), `\`) &&
				!strings.HasSuffix(strings.TrimRight(trimmed, " \t"), "`") {
				t.Fatalf("Instruction says RUN but ContainsRunInstruction misses %q", trimmed)
			}
		}
	})
}
