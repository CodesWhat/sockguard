package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/ui"
)

const (
	matchOutputText = "text"
	matchOutputJSON = "json"
)

var (
	matchMethod   string
	matchPath     string
	matchOutput   string
	matchProfile  string
	matchSourceIP string
)

var matchCmd = &cobra.Command{
	Use:   "match",
	Short: "Evaluate one request against the configured rules",
	Long:  "Load the effective configuration, normalize the request path, and report which rule would decide the request. A query string on --path (for example /containers/abc/kill?signal=USR1) is evaluated against rules that carry match.query constraints.",
	RunE:  runMatch,
}

type matchResult struct {
	Config         string           `json:"config"`
	Method         string           `json:"method"`
	Path           string           `json:"path"`
	Query          string           `json:"query,omitempty"`
	NormalizedPath string           `json:"normalized_path"`
	Decision       string           `json:"decision"`
	Reason         string           `json:"reason,omitempty"`
	CompatMode     bool             `json:"compat_mode,omitempty"`
	MatchedRule    *matchedRuleInfo `json:"matched_rule,omitempty"`

	// Selection names the rule set that decided the request: the root rules or
	// one client profile, and how it was chosen.
	Selection *matchSelection `json:"selection,omitempty"`
	// RolloutMode is the selected profile's mode. PassThrough is set when a
	// deny under a warn or audit profile would still reach Docker.
	RolloutMode string `json:"rollout_mode,omitempty"`
	PassThrough bool   `json:"pass_through,omitempty"`
	// Ownership and Response are read from configuration for the selected
	// scope. NotInspected lists what this offline run did not look at.
	Ownership    *matchOwnership      `json:"ownership,omitempty"`
	Response     *matchResponsePolicy `json:"response,omitempty"`
	NotInspected []string             `json:"not_inspected"`
}

type matchedRuleInfo struct {
	Index  int    `json:"index"`
	Method string `json:"method"`
	Path   string `json:"path"`
	// Query holds the rule's match.query constraints. When it is set the rule
	// decided this request, so every constraint held.
	Query        map[string][]string `json:"query,omitempty"`
	QueryMatched bool                `json:"query_matched,omitempty"`
	// QueryParseError is set when the request's query string did not parse and
	// a deny rule with constraints matched it fail-closed.
	QueryParseError bool   `json:"query_parse_error,omitempty"`
	Action          string `json:"action"`
	Reason          string `json:"reason,omitempty"`
}

func init() {
	rootCmd.AddCommand(matchCmd)

	matchCmd.Flags().StringVarP(&matchMethod, "method", "X", "", "HTTP method to evaluate")
	matchCmd.Flags().StringVar(&matchPath, "path", "", "request path to evaluate")
	matchCmd.Flags().StringVar(&matchProfile, "profile", "", "evaluate against this clients.profiles entry instead of the root rules")
	matchCmd.Flags().StringVar(&matchSourceIP, "source-ip", "", "select the profile the proxy would pick for this client IP (source_ip_profiles, then default_profile)")
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
	// Real HTTP request paths are always absolute. Reject paths that
	// don't start with "/" so users don't accidentally run a match
	// against a half-written input and get a misleading default-deny
	// result that looks authoritative.
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must start with %q", "/")
	}

	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		return fmt.Errorf("config preflight: %w", err)
	}

	// config.Load treats a missing file as "use defaults" to keep the
	// serve path flexible, but match is a check tool: if the user
	// pointed us at a file that doesn't exist, evaluating against the
	// built-in defaults would silently answer the wrong question.
	if cfgFile != "" {
		if _, err := os.Stat(cfgFile); err != nil {
			return fmt.Errorf("config file: %w", err)
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	compatActive := config.ApplyCompat(cfg, discardLogger)

	compiled, err := validateAndCompileRules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	// A request target carries its query after the first "?", so split it off
	// the way the server would before any rule sees the path.
	rawQuery := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, rawQuery = path[:i], path[i+1:]
	}

	req := &http.Request{
		Method: method,
		URL:    &url.URL{Path: path, RawQuery: rawQuery},
	}
	profile, selection, err := selectMatchProfile(cfg, matchProfile, matchSourceIP)
	if err != nil {
		return fmt.Errorf("profile selection: %w", err)
	}
	rules, ruleConfigs := compiled, cfg.Rules
	rolloutMode := config.RolloutEnforce
	if profile != nil {
		profilePolicies, err := compileClientProfiles(cfg)
		if err != nil {
			return fmt.Errorf("config validation: %w", err)
		}
		rules, ruleConfigs = profilePolicies[profile.Name].Rules, profile.Rules
		rolloutMode, _ = config.ParseRolloutMode(profile.Mode)
	}
	decision, matchedRuleIndex, reason := filter.Evaluate(rules, req)
	normalizedPath := filter.NormalizePath(path)
	gatedDecision, acknowledgmentReason, hardDeny := filter.EnforceReadExfiltrationAcknowledgment(
		decision,
		method,
		normalizedPath,
		cfg.InsecureAllowReadExfiltration,
	)
	if hardDeny {
		decision = gatedDecision
		if acknowledgmentReason != "" {
			reason = acknowledgmentReason
		}
	}

	result := matchResult{
		Config:         cfgFile,
		Method:         method,
		Path:           path,
		Query:          rawQuery,
		NormalizedPath: normalizedPath,
		Decision:       string(decision),
		Reason:         reason,
		CompatMode:     compatActive,
		Selection:      &selection,
		Ownership:      explainMatchOwnership(cfg, profile),
		Response:       explainMatchResponse(cfg, profile),
		NotInspected:   matchNotInspected(cfg, selection),
	}
	if profile != nil {
		result.RolloutMode = string(rolloutMode)
		result.PassThrough = decision == filter.ActionDeny && !hardDeny && rolloutMode != config.RolloutEnforce
	}
	_, parseErr := url.ParseQuery(rawQuery)
	if matchedRuleIndex >= 0 && matchedRuleIndex < len(ruleConfigs) {
		rule := ruleConfigs[matchedRuleIndex]
		result.MatchedRule = &matchedRuleInfo{
			Index:  matchedRuleIndex + 1,
			Method: rule.Match.Method,
			Path:   rule.Match.Path,
			Query:  rule.Match.Query,
			// The rule decided the request, so any query constraints it
			// carries were satisfied, unless the query did not parse: then a
			// deny rule matched fail-closed without evaluating them.
			QueryMatched:    len(rule.Match.Query) > 0 && parseErr == nil,
			QueryParseError: len(rule.Match.Query) > 0 && parseErr != nil,
			Action:          rule.Action,
			Reason:          rule.Reason,
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
	if result.Query != "" {
		fmt.Fprintf(w, "%s %s\n", label("Query:"), result.Query)
	}
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
		if q := filter.FormatQuery(result.MatchedRule.Query); q != "" {
			note := "constraints matched"
			if result.MatchedRule.QueryParseError {
				note = "query failed to parse, rule matched fail-closed"
			}
			fmt.Fprintf(w, "%s %s (%s)\n", label("Rule query:"), q, note)
		}
	}
	if result.Reason != "" {
		fmt.Fprintf(w, "%s %s\n", label("Reason:"), result.Reason)
	}
	fmt.Fprintln(w)
	writeMatchExplanation(w, p, label, result)
}
