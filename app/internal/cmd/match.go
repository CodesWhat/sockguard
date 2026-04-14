package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/ui"
)

const (
	matchOutputText = "text"
	matchOutputJSON = "json"
)

var (
	matchMethod string
	matchPath   string
	matchOutput string
)

var matchCmd = &cobra.Command{
	Use:   "match",
	Short: "Evaluate one request against the configured rules",
	Long:  "Load the effective configuration, normalize the request path, and report which rule would decide the request.",
	RunE:  runMatch,
}

type matchResult struct {
	Config         string           `json:"config"`
	Method         string           `json:"method"`
	Path           string           `json:"path"`
	NormalizedPath string           `json:"normalized_path"`
	Decision       string           `json:"decision"`
	Reason         string           `json:"reason,omitempty"`
	CompatMode     bool             `json:"compat_mode,omitempty"`
	MatchedRule    *matchedRuleInfo `json:"matched_rule,omitempty"`
}

type matchedRuleInfo struct {
	Index  int    `json:"index"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

func init() {
	rootCmd.AddCommand(matchCmd)

	matchCmd.Flags().StringVarP(&matchMethod, "method", "X", "", "HTTP method to evaluate")
	matchCmd.Flags().StringVar(&matchPath, "path", "", "request path to evaluate")
	matchCmd.Flags().StringVarP(&matchOutput, "output", "o", matchOutputText, "output format: text or json")
	_ = matchCmd.MarkFlagRequired("method")
	_ = matchCmd.MarkFlagRequired("path")
}

func runMatch(cmd *cobra.Command, args []string) error {
	output := strings.ToLower(strings.TrimSpace(matchOutput))
	if output != matchOutputText && output != matchOutputJSON {
		return fmt.Errorf("unsupported output format %q (must be text or json)", matchOutput)
	}

	method := strings.ToUpper(strings.TrimSpace(matchMethod))
	path := strings.TrimSpace(matchPath)
	if method == "" {
		return fmt.Errorf("method is required")
	}
	if path == "" {
		return fmt.Errorf("path is required")
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	compatActive := config.ApplyCompat(cfg, discardLogger)

	compiled, err := validateAndCompileRules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	req := &http.Request{
		Method: method,
		URL:    &url.URL{Path: path},
	}
	decision, matchedRuleIndex, reason := filter.Evaluate(compiled, req)

	result := matchResult{
		Config:         cfgFile,
		Method:         method,
		Path:           path,
		NormalizedPath: filter.NormalizePath(path),
		Decision:       string(decision),
		Reason:         reason,
		CompatMode:     compatActive,
	}
	if matchedRuleIndex >= 0 && matchedRuleIndex < len(cfg.Rules) {
		rule := cfg.Rules[matchedRuleIndex]
		result.MatchedRule = &matchedRuleInfo{
			Index:  matchedRuleIndex + 1,
			Method: rule.Match.Method,
			Path:   rule.Match.Path,
			Action: rule.Action,
			Reason: rule.Reason,
		}
	}

	if output == matchOutputJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}

	writeMatchText(cmd.OutOrStdout(), result)
	return nil
}

func writeMatchText(w io.Writer, result matchResult) {
	p := ui.New(w)
	// Pad the label text *before* styling so ANSI escapes don't eat
	// visible width and break alignment when colors are enabled.
	label := func(s string) string { return p.Dim(fmt.Sprintf("%-16s", s)) }

	fmt.Fprintf(w, "%s %s\n", label("Config:"), result.Config)
	fmt.Fprintf(w, "%s %s\n", label("Method:"), result.Method)
	fmt.Fprintf(w, "%s %s\n", label("Path:"), result.Path)
	fmt.Fprintf(w, "%s %s\n", label("Normalized path:"), result.NormalizedPath)
	if result.CompatMode {
		fmt.Fprintf(w, "%s %s\n", label("Mode:"), "tecnativa compatibility")
	}
	fmt.Fprintln(w)

	decision := result.Decision
	if result.Decision == string(filter.ActionAllow) {
		decision = p.Green(decision)
	} else {
		decision = p.Red(decision)
	}
	fmt.Fprintf(w, "%s %s\n", label("Decision:"), decision)
	if result.MatchedRule == nil {
		fmt.Fprintf(w, "%s %s\n", label("Matched rule:"), "none")
	} else {
		action := result.MatchedRule.Action
		if result.MatchedRule.Action == string(filter.ActionAllow) {
			action = p.Green(action)
		} else {
			action = p.Red(action)
		}
		fmt.Fprintf(w, "%s #%d\n", label("Matched rule:"), result.MatchedRule.Index)
		fmt.Fprintf(w, "%s %s %s %s\n", label("Rule:"), action, result.MatchedRule.Method, result.MatchedRule.Path)
	}
	if result.Reason != "" {
		fmt.Fprintf(w, "%s %s\n", label("Reason:"), result.Reason)
	}
}
