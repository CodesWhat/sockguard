package dockerfileinspect

import (
	"strings"
	"testing"
)

func TestSyntaxFrontend(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no directive", "FROM alpine\n", ""},
		{"syntax directive", "# syntax=docker/dockerfile:1\nFROM alpine\n", "docker/dockerfile:1"},
		{"syntax with spaces", "#   syntax  =  docker/dockerfile:1  \nFROM alpine\n", "docker/dockerfile:1"},
		{"escape directive keeps scanning", "# escape=`\n# syntax=docker/dockerfile:1\nFROM alpine\n", "docker/dockerfile:1"},
		{"blank line ends directive block", "\n# syntax=docker/dockerfile:1\nFROM alpine\n", ""},
		{"instruction ends directive block", "FROM alpine\n# syntax=docker/dockerfile:1\n", ""},
		{"plain comment ends directive block", "# just a comment\n# syntax=docker/dockerfile:1\n", ""},
		{"unknown directive ends directive block", "# foo=bar\n# syntax=docker/dockerfile:1\n", ""},
		{"empty syntax value ignored", "# syntax=\nFROM alpine\n", ""},
		{"empty input", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SyntaxFrontend([]byte(tc.in)); got != tc.want {
				t.Fatalf("SyntaxFrontend(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestContainsRunInstruction(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"simple run", "FROM alpine\nRUN echo hi\n", true},
		{"no run", "FROM alpine\nCOPY . .\n", false},
		{"onbuild run", "ONBUILD RUN echo hi\n", true},
		{"bare onbuild not run", "ONBUILD\n", false},
		{"continuation line run", "FROM alpine\nRUN echo \\\n  hi\n", true},
		{"trailing continuation at eof", "FROM alpine\nRUN echo \\\n  hi", true},
		{"keyword split across backslash escape", "FROM alpine\nR\\\nUN echo evil\n", true},
		{"keyword split across backtick escape directive", "# escape=`\nFROM alpine\nR`\nUN echo evil\n", true},
		{"backslash not a continuation under backtick escape", "# escape=`\nR\\\nUN echo hi\n", false},
		{"comment before instruction ignored", "# comment\nFROM alpine\n", false},
		{"empty input", "", false},
		{"only blank lines", "\n\n\n", false},
		// A comment line that itself ends in the continuation character must
		// still be treated as a whole, standalone comment and skipped
		// entirely — it must NOT be joined with the next line. Joining would
		// garble the following real instruction (prefixing it with "#..."),
		// which Instruction() would then read as a comment and silently miss
		// the RUN it contains.
		{"comment ending in escape is not joined with next line", "# comment\\\nRUN true\n", true},
		// A dangling continuation at EOF that never gets a following line to
		// join with must still be evaluated as whatever instruction it
		// started (fail-safe): the loop's post-loop tail check has to look at
		// the leftover logical line rather than discarding it outright.
		{"dangling continuation at eof with no completing line", "FROM alpine\nRUN echo \\", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContainsRunInstruction([]byte(tc.in)); got != tc.want {
				t.Fatalf("ContainsRunInstruction(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestInstruction(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"run", "RUN echo hi", "RUN"},
		{"lowercase run", "run echo hi", "RUN"},
		{"onbuild run", "ONBUILD RUN echo hi", "ONBUILD RUN"},
		{"onbuild run with exactly two fields", "ONBUILD RUN", "ONBUILD RUN"},
		{"bare onbuild", "ONBUILD", "ONBUILD"},
		{"blank", "", ""},
		{"comment", "# hello", ""},
		{"whitespace only", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Instruction(tc.in); got != tc.want {
				t.Fatalf("Instruction(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestContainsRunInstructionContinuationAllocations(t *testing.T) {
	raw := []byte("FROM scratch\nENV x=\\\n" + strings.Repeat("x\\\n", 1024) + "x\n")
	allocations := testing.AllocsPerRun(5, func() {
		if ContainsRunInstruction(raw) {
			t.Fatal("continued ENV must not be classified as RUN")
		}
	})
	if allocations >= 64 {
		t.Fatalf("allocations per scan = %.0f, want fewer than 64", allocations)
	}
	t.Logf("allocations per scan = %.0f", allocations)
}

func TestContainsRunInstructionContinuationCompatibility(t *testing.T) {
	longEnv := "FROM scratch\nENV x=\\\n" + strings.Repeat("x\\\n", 1024) + "x\n"
	cases := []struct {
		name, in string
		want     bool
	}{
		{"long ENV followed by RUN", longEnv + "RUN true\n", true},
		{"long ENV followed by split ONBUILD RUN", longEnv + "ONB\\\nUILD R\\\nUN true\n", true},
		{"backtick split ONBUILD RUN", "# escape=`\nONB`\nUILD R`\nUN true\n", true},
		{"dangling non RUN continuation", "ENV x=\\", false},
		{"dangling split RUN", "R\\\nUN\\", true},
		{"empty continuation fragments", "R\\\n\\\n\\\nUN true\n", true},
		{"only empty continuation fragments", "\\\n\\\n", false},
		{"empty fragment then standalone comment", "\\\n# comment\\\nRUN true\n", true},
		{"blank lines outside and inside continuation", "\nR\\\n\n  \nUN true\n\n", true},
		{"comment during keyword continuation stays joined", "R\\\n# comment\nUN true\n", false},
		{"continued comment during RUN arguments", "RUN echo \\\n# comment\\\nhello\n", true},
		{"comment after non RUN continuation then RUN", "ENV x=\\\n# comment\nRUN true\n", true},
		{"multiple non RUN instructions", "FROM scratch\nENV x=1\nCOPY . /app\nONBUILD COPY . /app\n", false},
		{"COPY heredoc with escaped payload", "COPY <<EOF /file\ntext\\\nmore\n# comment\nEOF\n", false},
		{"ADD heredoc with RUN looking payload", "ADD <<EOF /file\n# comment\nRUN payload\nEOF\n", true},
		{"COPY heredoc with joined RUN looking payload", "COPY <<EOF /file\ntext\\\nRUN payload\nEOF\n", false},
		{"ADD heredoc followed by real RUN", "ADD <<EOF /file\ntext\\\nmore\n# comment\nEOF\nRUN true\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContainsRunInstruction([]byte(tc.in)); got != tc.want {
				t.Fatalf("ContainsRunInstruction() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSyntaxFrontendBuildKitFormats(t *testing.T) {
	const frontend = "example.invalid/inert-compiler:review"
	const directive = "# syntax=" + frontend + "\n"
	cases := []struct{ name, in, want string }{
		{"BOM", "\ufeff" + directive + "FROM scratch\n", frontend},
		{"shebang", "#!/usr/bin/env builder\n" + directive, frontend},
		{"BOM and shebang", "\ufeff#!/usr/bin/env builder\n" + directive, frontend},
		{"slash directive", "// syntax=" + frontend + "\n", frontend},
		{"JSON object", `{"syntax":"` + frontend + `"}`, frontend},
		{"check before syntax", "# check=skip=all\n" + directive, frontend},
		{"slash directive block", "// escape=`\n// ChEcK=skip=all\n// SyNtAx=" + frontend + "\n", frontend},
		{"BOM shebang JSON", "\ufeff#!builder\n" + `{"syntax":"` + frontend + `"}`, frontend},
		{"ASCII whitespace and case", "#\tSyNtAx\t=\t" + frontend + " \r\n", frontend},
		{"Unicode space after comment prefix", "#\u00a0syntax=" + frontend + "\n", frontend},
		{"frontend command arguments", directive[:len(directive)-1] + " argument\n", frontend},
		{"tab inside frontend retained", "# syntax=" + frontend + "\targument\n", frontend + "\targument"},
		{"indented comment not directive", " " + directive, ""},
		{"Unicode key whitespace not accepted", "# syntax\u00a0=" + frontend + "\n", ""},
		{"second BOM not removed", "\ufeff\ufeff" + directive, ""},
		{"second shebang ends block", "#!builder\n#!builder\n" + directive, ""},
		{"shebang without newline", "#!builder", ""},
		{"BOM after shebang not removed", "#!builder\n\ufeff" + directive, ""},
		{"blank line after shebang", "#!builder\n\n" + directive, ""},
		{"instruction before syntax", "FROM scratch\n" + directive, ""},
		{"plain comment before syntax", "# comment\n" + directive, ""},
		{"unknown before syntax", "# other=value\n" + directive, ""},
		{"duplicate escape before syntax", "# escape=`\n# ESCAPE=`\n" + directive, ""},
		{"duplicate check before syntax", "# check=skip=all\n# check=skip=all\n" + directive, ""},
		{"duplicate syntax retains first", directive + "# syntax=example.invalid/other\n", frontend},
		{"empty escape terminates", "# escape=\n" + directive, ""},
		{"empty syntax terminates", "# syntax=\n" + directive, ""},
		{"empty check terminates", "# check=\n" + directive, ""},
		{"whitespace only syntax", "# syntax=   \n" + directive, ""},
		{"whitespace only escape recognized upstream", "# escape=   \n" + directive, frontend},
		{"mixed prefixes end block", "# check=skip=all\n// syntax=" + frontend + "\n", ""},
		{"slash after blank line", "\n// syntax=" + frontend + "\n", ""},
		{"slash after ordinary comment", "// comment\n// syntax=" + frontend + "\n", ""},
		{"malformed JSON", `{"syntax":"` + frontend + `"`, ""},
		{"nonstring JSON syntax", `{"syntax":42}`, ""},
		{"JSON syntax case sensitive", `{"Syntax":"` + frontend + `"}`, ""},
		{"JSON empty syntax", `{"syntax":""}`, ""},
		{"JSON array", `[{"syntax":"` + frontend + `"}]`, ""},
		{"JSON trailing instruction", `{"syntax":"` + frontend + `"}` + "\nFROM scratch\n", ""},
		{"JSON after ordinary comment", "# comment\n" + `{"syntax":"` + frontend + `"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SyntaxFrontend([]byte(tc.in)); got != tc.want {
				t.Fatalf("SyntaxFrontend(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
