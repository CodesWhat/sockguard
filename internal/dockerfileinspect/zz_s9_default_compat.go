package dockerfileinspect

import "strings"

// SyntaxFrontend returns the value of a BuildKit `# syntax=` parser directive
// when one is in force in raw, else "". Directives are only honored by
// Docker at the very top of the file — the first blank line, regular
// comment, instruction, or unrecognized directive ends the directive block —
// so this mirrors that to avoid both bypasses and false positives on later
// comments. A `# syntax=` directive delegates parsing to an external
// frontend image that can treat arbitrary tokens as shell execution, so a
// caller whose RUN-instruction scan is a trust boundary (classic /build's
// allow_run_instructions gate, BuildKit Solve's Dockerfile hold-and-inspect)
// must treat its presence as "cannot be inspected," not as content to scan
// through.
func SyntaxFrontend(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			return ""
		}
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(trimmed, "#")), "=")
		if !ok {
			return ""
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "syntax":
			if v := strings.TrimSpace(value); v != "" {
				return v
			}
		case "escape":

		default:
			return ""
		}
	}
	return ""
}

// ContainsRunInstruction reports whether raw (a Dockerfile's raw bytes)
// contains a RUN or ONBUILD RUN instruction, joining escape-continued logical
// lines before classifying each one.
//
// Continuation joins the fragments directly, with NO separator inserted —
// Docker removes the escape character plus the newline and concatenates the
// surrounding text. Inserting a space here would let a Dockerfile split the
// keyword across the escape (`R\`+newline+`UN echo evil`, which Docker reads
// as `RUN echo evil`) and read back as the instruction `R`, bypassing the RUN
// gate. Any whitespace that precedes the escape is preserved by trimming only
// the escape character, so `RUN echo \`+newline+`hi` still joins as
// `RUN echo hi`. The continuation character honors a leading `# escape=`
// parser directive (Docker allows `\` — the default — or a backtick), so a
// Dockerfile that declares a backtick escape cannot hide a keyword split
// behind a `\` our parser would ignore.
func ContainsRunInstruction(raw []byte) bool {
	cont := escapeChar(raw)
	lines := strings.Split(string(raw), "\n")
	var logical string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if logical == "" && strings.HasPrefix(trimmed, "#") {
			continue
		}

		if logical == "" {
			logical = trimmed
		} else {
			logical += trimmed
		}

		if strings.HasSuffix(logical, cont) {
			logical = strings.TrimSuffix(logical, cont)
			continue
		}

		instruction := Instruction(logical)
		if instruction == "RUN" || instruction == "ONBUILD RUN" {
			return true
		}
		logical = ""
	}

	if logical == "" {
		return false
	}
	instruction := Instruction(logical)
	return instruction == "RUN" || instruction == "ONBUILD RUN"
}

// escapeChar returns the line-continuation character in force for raw: the
// backslash Docker uses by default, or a backtick when a leading `# escape=“
// parser directive selects it. Docker honors an escape directive only in the
// same top-of-file directive block SyntaxFrontend scans, and accepts only `\`
// or a backtick as the value; anything else leaves the default in force.
func escapeChar(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			return `\`
		}
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(trimmed, "#")), "=")
		if !ok {
			return `\`
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "escape":
			if strings.TrimSpace(value) == "`" {
				return "`"
			}
			return `\`
		case "syntax":

		default:
			return `\`
		}
	}
	return `\`
}

// Instruction returns the uppercased Dockerfile instruction keyword line
// begins with ("RUN", "FROM", "ONBUILD RUN", ...), or "" for a blank/comment
// line.
func Instruction(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}

	fields := strings.Fields(trimmed)
	first := strings.ToUpper(fields[0])
	if first != "ONBUILD" || len(fields) < 2 {
		return first
	}
	return first + " " + strings.ToUpper(fields[1])
}
