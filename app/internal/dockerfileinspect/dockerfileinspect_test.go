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
		// BuildKit's line assembly, one row per rule. Inside a continuation it
		// drops comment lines and blank lines, and it keeps a continuation
		// line's leading whitespace.
		{"comment line inside a continuation is dropped", "FROM alpine\nR\\\n#\nUN id\n", true},
		{"indented comment inside a continuation is dropped", "FROM alpine\nR\\\n  # note\nUN id\n", true},
		{"blank line inside a continuation is dropped", "FROM alpine\nR\\\n\nUN id\n", true},
		{"continuation line keeps its leading whitespace", "FROM alpine\nRUN\\\n id\n", true},
		{"indented continuation does not rejoin a split keyword", "FROM alpine\nR\\\n  UN id\n", false},
		// The escape character continues a line only when it isn't itself
		// escaped, and spaces or tabs may follow it.
		{"escaped escape does not continue the line", "FROM alpine\nENV a=b\\\\\nRUN id\n", true},
		{"whitespace after the escape still continues", "FROM alpine\nR\\ \t\nUN id\n", true},
		{"crlf line endings", "FROM alpine\r\nR\\\r\nUN id\r\n", true},
		// The escape directive is read after a UTF-8 BOM, and after a check
		// directive on BuildKit versions that know one.
		{"escape directive after a bom", "\ufeff# escape=`\nFROM alpine\nR`\nUN id\n", true},
		{"escape directive after a check directive", "# check=skip=all\n# escape=`\nFROM alpine\nR`\nUN id\n", true},
		{"backslash still continues where check is not a directive", "# check=skip=all\n# escape=`\nFROM alpine\nR\\\nUN id\n", true},
		// Heredocs on ADD and COPY. A terminator made only of word characters
		// can't be a comment, be blank, or end in the escape, so the line scan
		// reads past it correctly. Any other spelling of a heredoc word is one
		// the scan can't follow, and the build is treated as having a RUN.
		{"heredoc with a plain terminator and no run", "FROM alpine\nCOPY <<EOF /x\nhello \\\nEOF\n", false},
		{"run after a heredoc with a plain terminator", "FROM alpine\nCOPY <<-'EOF' /x\nhello \\\n\tEOF\nRUN id\n", true},
		{"heredoc terminator ending in the escape", "FROM alpine\nCOPY <<'A\\' /x\nbody\nA\\\nRUN id\n", true},
		{"heredoc terminator that reads as a comment", "FROM alpine\nADD <<#A /x\nbody\\\n#A\nRUN id\n", true},
		{"heredoc word spelled with an escape", "FROM alpine\nCOPY <\\<EOF /x\nbody\nEOF\n", true},
		{"onbuild copy heredoc with an unreadable terminator", "FROM alpine\nONBUILD COPY <<\"A B\" /x\nbody\n", true},
		// Parsers that predate BuildKit's directive handling strip one CR per
		// line, know only the escape directive, and read its value's first
		// character.
		{"escape followed by two carriage returns", "FROM alpine\nCMD a \\\r\r\nRUN id\n", true},
		{"escape directive with text after the backtick", "# escape=`x\nFROM alpine\nCMD a \\\nRUN id\n", true},
		{"backtick escape directive with trailing text still joins on backtick", "# escape=`x\nFROM alpine\nR`\nUN id\n", true},
		{"escape directive after a syntax directive is ignored by older parsers", "# syntax=docker/dockerfile:1\n# escape=`\nFROM alpine\nR\\\nUN id\n", true},
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
		{"JSON key capitalized", `{"Syntax":"` + frontend + `"}`, frontend},
		{"JSON key upper case", `{"SYNTAX":"` + frontend + `"}`, frontend},
		{"JSON key mixed case", `{"sYnTaX":"` + frontend + `"}`, frontend},
		{"JSON mixed case key after empty exact key", `{"syntax":"","SYNTAX":"` + frontend + `"}`, frontend},
		{"JSON nonstring mixed case key", `{"Syntax":42}`, ""},
		{"JSON sibling number out of float range", `{"syntax":"` + frontend + `","x":1e999}`, frontend},
		{"JSON similar key not syntax", `{"syntaxes":"` + frontend + `"}`, ""},
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
