// Package dockerfileinspect holds the Dockerfile-content heuristics classic
// POST /build inspection (internal/filter/build.go) and BuildKit gRPC
// mediation's Dockerfile hold-and-inspect (internal/buildkitproxy, issue
// #185 phase 5) both need: detecting a BuildKit syntax frontend override,
// and detecting a RUN (or ONBUILD RUN) instruction.
//
// This logic used to live as unexported functions in internal/filter/build.go
// alone. Phase 5's synthesis requires BuildKit's Dockerfile hold-and-inspect
// path to "run the same RUN-instruction / policy inspection the classic
// /build path applies... reuse that logic — do not duplicate the parser" —
// but internal/buildkitproxy is a dependency-light leaf package that must
// never import internal/filter (see buildkitproxy/registry.go's package doc
// and solve.go's registryHostFromImageRef comment for the same constraint
// applied to other internal/filter-owned logic). Extracting the parser into
// this standalone, stdlib-only leaf package lets both sides depend on ONE
// implementation without either importing the other: internal/filter's
// build.go now delegates its three unexported wrapper functions here instead
// of implementing the logic itself, and internal/buildkitproxy imports this
// package directly.
package dockerfileinspect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

var syntaxDirectivePattern = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$`)

// SyntaxFrontend returns the frontend selected by BuildKit v0.32.0's
// DetectSyntax, or "" when no nonempty frontend is selected. It recognizes
// leading # and // directive blocks and complete JSON objects, after removing
// one initial UTF-8 BOM and shebang. Blank lines, ordinary comments,
// instructions, malformed or unknown directives, and duplicate keys end a
// directive block. A selected frontend can interpret arbitrary input, so
// callers restricting RUN must reject it before inspecting instructions.
func SyntaxFrontend(raw []byte) string {
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	if bytes.HasPrefix(raw, []byte("#!")) {
		_, raw, _ = bytes.Cut(raw, []byte("\n"))
	}
	for _, prefix := range []string{"#", "//"} {
		if frontend := syntaxDirective(raw, prefix); frontend != "" {
			return frontend
		}
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err == nil {
		frontend, _ := document["syntax"].(string)
		return frontend
	}
	return ""
}

func syntaxDirective(raw []byte, prefix string) string {
	// Keep the scanner and expression boundaries aligned with BuildKit's
	// frontend/dockerfile/parser/directives.go at v0.32.0.
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	seen := make(map[string]bool, 3)
	for scanner.Scan() {
		line, ok := bytes.CutPrefix(scanner.Bytes(), []byte(prefix))
		if !ok {
			return ""
		}
		match := syntaxDirectivePattern.FindSubmatch(bytes.TrimLeftFunc(line, unicode.IsSpace))
		if len(match) == 0 {
			return ""
		}
		key := strings.ToLower(string(match[1]))
		switch key {
		case "syntax", "escape", "check":
		default:
			return ""
		}
		if seen[key] {
			return ""
		}
		seen[key] = true
		if key == "syntax" {
			frontend, _, _ := strings.Cut(string(match[2]), " ")
			return frontend
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
	var logical strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if logical.Len() == 0 && strings.HasPrefix(trimmed, "#") {
			continue
		}

		continued := strings.HasSuffix(trimmed, cont)
		if continued {
			trimmed = strings.TrimSuffix(trimmed, cont)
		}
		logical.WriteString(trimmed)
		if continued {
			continue
		}

		instruction := Instruction(logical.String())
		if instruction == "RUN" || instruction == "ONBUILD RUN" {
			return true
		}
		logical.Reset()
	}

	if logical.Len() == 0 {
		return false
	}
	instruction := Instruction(logical.String())
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
			// recognized directive; keep scanning the leading block
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
