package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

const (
	// suggestMaxLineBytes bounds one access-log line. A longer line is counted
	// and skipped, never buffered.
	suggestMaxLineBytes = 64 * 1024
	// suggestMaxLines bounds how many lines are read from the input.
	suggestMaxLines = 1_000_000
	// suggestMaxRules bounds the size of the emitted snippet. Distinct
	// method+path pairs beyond it are counted and left out.
	suggestMaxRules = 500
	// suggestMaxPathBytes bounds one normalized path.
	suggestMaxPathBytes = 512

	suggestMsgWouldDeny = "request_would_deny"
)

var policySuggestFrom string

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy authoring helpers",
}

var policySuggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "Suggest allow rules from warn or audit access-log traffic",
	Long: `Read JSON access-log lines recorded under a warn or audit rollout, group the
requests that would have been denied by method and normalized path, and print a
YAML rules snippet to stdout.

Every rule is a suggestion that needs operator review. Nothing is written to a
config file and nothing activates itself. Only the method and the normalized
path are read: query strings, headers, bodies, client addresses and request
IDs never reach the output. Container and other resource IDs (12 to 64 hex
characters) are generalized to "*"; names are kept literal. Input is bounded in
line length and line count, and the output is compiled with the real rule
compiler before it is printed.`,
	Args: cobra.NoArgs,
	RunE: runPolicySuggest,
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policySuggestCmd)
	policySuggestCmd.Flags().StringVar(&policySuggestFrom, "from", "", "access-log file of JSON lines, or - for stdin")
	_ = policySuggestCmd.MarkFlagRequired("from")
}

type suggestStats struct {
	Lines        int
	WouldDeny    int
	Skipped      int
	Truncated    bool
	DroppedRules int
}

type suggestKey struct {
	method string
	path   string
}

type suggestRule struct {
	suggestKey
	count int
}

func runPolicySuggest(cmd *cobra.Command, _ []string) error {
	var in io.Reader
	if policySuggestFrom == "-" {
		in = cmd.InOrStdin()
	} else {
		f, err := os.Open(policySuggestFrom) // #nosec G304 -- access log path is an explicit local CLI flag.
		if err != nil {
			return fmt.Errorf("access log: %w", err)
		}
		defer func() { _ = f.Close() }()
		in = f
	}

	rules, stats, err := collectSuggestions(in)
	if err != nil {
		return err
	}
	out, err := renderSuggestions(rules, stats)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(cmd.OutOrStdout(), out); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "read %d lines, %d would-deny, %d suggested rules, %d skipped\n",
		stats.Lines, stats.WouldDeny, len(rules), stats.Skipped)
	return nil
}

// collectSuggestions reads bounded JSON access-log lines and returns the
// deduplicated, deterministically ordered rule suggestions.
func collectSuggestions(r io.Reader) ([]suggestRule, suggestStats, error) {
	var stats suggestStats
	counts := map[suggestKey]int{}
	br := bufio.NewReaderSize(r, 16*1024)

	for {
		line, tooLong, err := readBoundedLine(br, suggestMaxLineBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, stats, fmt.Errorf("access log: %w", err)
		}
		atEOF := errors.Is(err, io.EOF)
		if atEOF && len(line) == 0 && !tooLong {
			break
		}
		if stats.Lines >= suggestMaxLines {
			stats.Truncated = true
			break
		}
		stats.Lines++

		if tooLong {
			stats.Skipped++
		} else if key, ok, wouldDeny := parseSuggestLine(line); wouldDeny {
			stats.WouldDeny++
			if ok {
				counts[key]++
			} else {
				stats.Skipped++
			}
		}
		if atEOF {
			break
		}
	}

	rules := make([]suggestRule, 0, len(counts))
	for k, n := range counts {
		rules = append(rules, suggestRule{suggestKey: k, count: n})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].path != rules[j].path {
			return rules[i].path < rules[j].path
		}
		return rules[i].method < rules[j].method
	})
	if len(rules) > suggestMaxRules {
		stats.DroppedRules = len(rules) - suggestMaxRules
		rules = rules[:suggestMaxRules]
	}
	return rules, stats, nil
}

// readBoundedLine returns one line without its newline. A line longer than max
// is drained and reported with tooLong set, with no content kept.
func readBoundedLine(br *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, isPrefix, rerr := br.ReadLine()
		if rerr != nil {
			return bytes.TrimRight(buf, "\r"), tooLong, rerr
		}
		if !tooLong {
			if len(buf)+len(chunk) > max {
				tooLong = true
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if !isPrefix {
			return buf, tooLong, nil
		}
	}
}

// parseSuggestLine decodes only the fields the suggestion needs. wouldDeny is
// false for any line that is not a would-deny record. ok is false when it is
// one but its path or method cannot be turned into a safe rule.
func parseSuggestLine(line []byte) (key suggestKey, ok bool, wouldDeny bool) {
	var rec struct {
		Msg      string `json:"msg"`
		Method   string `json:"method"`
		Path     string `json:"normalized_path"`
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return key, false, false
	}
	if rec.Msg != suggestMsgWouldDeny && rec.Decision != logging.DecisionWouldDeny {
		return key, false, false
	}
	method := strings.ToUpper(rec.Method)
	if !safeSuggestMethod(method) {
		return key, false, true
	}
	path, pathOK := generalizeSuggestPath(rec.Path)
	if !pathOK {
		return key, false, true
	}
	return suggestKey{method: method, path: path}, true, true
}

func safeSuggestMethod(m string) bool {
	if m == "" || len(m) > 16 {
		return false
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 'A' || m[i] > 'Z' {
			return false
		}
	}
	return true
}

// generalizeSuggestPath replaces resource IDs with "*" and refuses any path
// that carries glob syntax or characters outside a conservative set, so a
// logged value can never widen or break the emitted rule.
func generalizeSuggestPath(p string) (string, bool) {
	if p == "" || len(p) > suggestMaxPathBytes || p[0] != '/' {
		return "", false
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		if i == len(segs)-1 && s == "" && len(segs) > 1 {
			return "", false
		}
		for j := 0; j < len(s); j++ {
			if !suggestPathByte(s[j]) {
				return "", false
			}
		}
		if s == "." || s == ".." {
			return "", false
		}
		if isHexID(s) {
			segs[i] = "*"
		}
	}
	return "/" + strings.Join(segs, "/"), true
}

func suggestPathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '-' || c == '_' || c == '.' || c == '~' || c == ':'
}

func isHexID(s string) bool {
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func renderSuggestions(rules []suggestRule, stats suggestStats) (string, error) {
	cfgRules := make([]config.RuleConfig, len(rules))
	for i, r := range rules {
		cfgRules[i] = config.RuleConfig{
			Match:  config.MatchConfig{Method: r.method, Path: r.path},
			Action: "allow",
			Reason: "suggested from warn/audit traffic",
		}
	}
	// The real compiler is the gate: nothing is printed that it rejects.
	if _, err := compileConfiguredRules(cfgRules); err != nil {
		return "", fmt.Errorf("suggested rules failed validation: %w", err)
	}

	var b strings.Builder
	b.WriteString("# SUGGESTION ONLY. Generated from warn/audit access-log traffic.\n")
	b.WriteString("# Review every rule before use. Nothing here is active until you copy it into your config.\n")
	b.WriteString("# Only method and normalized path were read; query values, headers and bodies are never included.\n")
	if stats.DroppedRules > 0 {
		fmt.Fprintf(&b, "# %d further distinct rules were left out (limit %d).\n", stats.DroppedRules, suggestMaxRules)
	}
	if stats.Truncated {
		fmt.Fprintf(&b, "# Input was cut at %d lines.\n", suggestMaxLines)
	}
	if len(rules) == 0 {
		b.WriteString("rules: []\n")
		return b.String(), nil
	}
	b.WriteString("rules:\n")
	for i, r := range rules {
		note := ""
		if r.method != "GET" && r.method != "HEAD" {
			note = " Write method: confirm this call is really needed."
		}
		fmt.Fprintf(&b, "  # Suggestion, requires review: seen %d time(s) as would-deny.%s\n", r.count, note)
		fmt.Fprintf(&b, "  - match: { method: %s, path: %q }\n", cfgRules[i].Match.Method, cfgRules[i].Match.Path)
		b.WriteString("    action: allow\n")
		fmt.Fprintf(&b, "    reason: %q\n", cfgRules[i].Reason)
	}
	return b.String(), nil
}
