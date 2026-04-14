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
	fmt.Fprintf(w, "Config:          %s\n", result.Config)
	fmt.Fprintf(w, "Method:          %s\n", result.Method)
	fmt.Fprintf(w, "Path:            %s\n", result.Path)
	fmt.Fprintf(w, "Normalized path: %s\n", result.NormalizedPath)
	if result.CompatMode {
		fmt.Fprintln(w, "Mode:            tecnativa compatibility")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Decision:        %s\n", result.Decision)
	if result.MatchedRule == nil {
		fmt.Fprintln(w, "Matched rule:    none")
	} else {
		fmt.Fprintf(w, "Matched rule:    #%d\n", result.MatchedRule.Index)
		fmt.Fprintf(w, "Rule:            %s %s %s\n", result.MatchedRule.Action, result.MatchedRule.Method, result.MatchedRule.Path)
	}
	if result.Reason != "" {
		fmt.Fprintf(w, "Reason:          %s\n", result.Reason)
	}
}
