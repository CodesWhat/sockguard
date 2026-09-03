package dockerfileinspect

import "testing"

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
