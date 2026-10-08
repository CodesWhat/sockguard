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
	"maps"
	"regexp"
	"slices"
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
// callers restricting RUN must reject it before inspecting instructions. The
// JSON form's key is matched in any letter case.
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
		// BuildKit v0.11 to v0.13 (Docker 24 to 26) decode the object into a
		// struct with a `json:"syntax"` tag, which encoding/json matches in any
		// letter case. Go through the keys in sorted order so a document with
		// several spellings answers the same way every time.
		for _, key := range slices.Sorted(maps.Keys(document)) {
			if !strings.EqualFold(key, "syntax") {
				continue
			}
			if frontend, _ := document[key].(string); frontend != "" {
				return frontend
			}
		}
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
// contains a RUN or ONBUILD RUN instruction. It assembles logical lines the
// way BuildKit's Dockerfile parser does before classifying each one, because
// a line the two assemble differently is a RUN BuildKit runs and this scan
// never sees:
//
//   - One leading UTF-8 BOM is dropped.
//   - A line that is blank, or whose first non-space character is #, is
//     dropped wherever it falls, including inside a continuation.
//   - The escape character continues a line when it is the last character
//     before optional trailing spaces and tabs and is not itself escaped.
//     The escape and what follows it are removed and the next kept line is
//     appended with no separator, so a keyword split across the escape
//     (R, escape, newline, UN) reads back as RUN.
//   - The first line of an instruction has its leading whitespace removed. A
//     continuation line keeps its own, so RUN, escape, newline, " id" is
//     "RUN id".
//
// The escape character comes from the leading parser-directive block. Which
// lines belong to that block differs by BuildKit version (see escapeChars),
// so the scan runs once per candidate and reports a RUN if any of them finds
// one.
func ContainsRunInstruction(raw []byte) bool {
	raw = bytes.TrimPrefix(raw, utf8BOM)
	lines := strings.Split(string(raw), "\n")
	for _, escape := range escapeChars(lines) {
		if containsRunWithEscape(lines, escape) {
			return true
		}
	}
	return false
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func containsRunWithEscape(lines []string, escape string) bool {
	var logical string
	continued := false

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		leading := strings.TrimLeftFunc(line, unicode.IsSpace)
		if leading == "" || strings.HasPrefix(leading, "#") {
			continue
		}
		if !continued {
			line = leading
		}

		fragment, more := trimContinuation(line, escape)
		logical += fragment
		if more {
			continued = true
			continue
		}

		if isRunInstruction(logical) {
			return true
		}
		logical, continued = "", false
	}

	// A continuation left open at EOF is still whatever instruction it began.
	return isRunInstruction(logical)
}

// trimContinuation removes a trailing line continuation from line and reports
// whether there was one. Two escape characters in a row are an escaped
// escape, not a continuation.
func trimContinuation(line, escape string) (string, bool) {
	body, ok := strings.CutSuffix(strings.TrimRight(line, " \t"), escape)
	if !ok || strings.HasSuffix(body, escape) {
		return line, false
	}
	return body, true
}

func isRunInstruction(logical string) bool {
	instruction := Instruction(logical)
	return instruction == "RUN" || instruction == "ONBUILD RUN"
}

// escapeChars returns every line-continuation character a supported BuildKit
// could have in force for lines: the backslash Docker uses by default, or a
// backtick when a leading `# escape=` parser directive selects it. BuildKit
// honors an escape directive only in the top-of-file directive block, which
// ends at the first line that isn't a known directive, and accepts only `\`
// or a backtick as the value.
//
// `# check=` is a directive on BuildKit versions that know it and an ordinary
// comment that ends the block on versions that don't, so an escape directive
// that follows one is in force on some versions only. Both readings are
// returned when they disagree.
func escapeChars(lines []string) []string {
	strict := escapeChar(lines, false)
	lenient := escapeChar(lines, true)
	if strict == lenient {
		return []string{strict}
	}
	return []string{strict, lenient}
}

func escapeChar(lines []string, checkIsDirective bool) string {
	for _, line := range lines {
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
		case "check":
			if !checkIsDirective {
				return `\`
			}
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
