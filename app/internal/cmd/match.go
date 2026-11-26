package cmd

import (
	"encoding/json"
	"errors"
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
	matchBodyArg  string
	matchOutput   string
	matchProfile  string
	matchSourceIP string
	matchBodyFile string
)

var matchCmd = &cobra.Command{
	Use:   "match",
	Short: "Evaluate one request against the configured rules",
	Long:  "Load the effective configuration, normalize the request path, and report which rule would decide the request. A query string on --path (for example /containers/abc/kill?signal=USR1) is evaluated against rules that carry match.query constraints. A JSON object on --body is evaluated against rules that carry match.body constraints. --body-file (or - for stdin) also runs the request-body inspectors on a sample body, offline, and reports their verdict.",
	RunE:  runMatch,
}

type matchResult struct {
	Config         string           `json:"config"`
	Method         string           `json:"method"`
	Path           string           `json:"path"`
	Query          string           `json:"query,omitempty"`
	RequestBody    string           `json:"request_body,omitempty"`
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
	Body         *matchBody           `json:"body,omitempty"`
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
	QueryParseError bool `json:"query_parse_error,omitempty"`
	// Body holds the rule's match.body constraints. BodyMatched says the
	// evaluation read the body and the constraints held; BodyUnreadable says
	// the body the evaluation read was not readable to matching, absent, too
	// big to buffer, or keys the engines read two ways, and the rule matched
	// fail-closed without weighing them.
	Body           map[string][]string `json:"body,omitempty"`
	BodyMatched    bool                `json:"body_matched,omitempty"`
	BodyUnreadable bool                `json:"body_unreadable,omitempty"`
	Action         string              `json:"action"`
	Reason         string              `json:"reason,omitempty"`
}

func init() {
	rootCmd.AddCommand(matchCmd)

	matchCmd.Flags().StringVarP(&matchMethod, "method", "X", "", "HTTP method to evaluate")
	matchCmd.Flags().StringVar(&matchPath, "path", "", "request path to evaluate")
	matchCmd.Flags().StringVar(&matchBodyArg, "body", "", "JSON request body to evaluate against match.body constraints")
	matchCmd.Flags().StringVar(&matchProfile, "profile", "", "evaluate against this clients.profiles entry instead of the root rules")
	matchCmd.Flags().StringVar(&matchSourceIP, "source-ip", "", "select the profile the proxy would pick for this client IP (source_ip_profiles, then default_profile)")
	matchCmd.Flags().StringVar(&matchBodyFile, "body-file", "", "also run the request-body inspectors on this file (- reads stdin), offline")
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
	// One request carries one body. --body feeds the rule evaluation and
	// --body-file the inspectors; together they would judge a rule against
	// one body and the inspectors another, so the verdicts could not describe
	// any single request.
	if strings.TrimSpace(matchBodyArg) != "" && strings.TrimSpace(matchBodyFile) != "" {
		return errors.New("use only one of --body and --body-file")
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

	// A --body is checked here rather than left to the rule layer, because a
	// half-written JSON argument would otherwise read as an unreadable body and
	// the tool would report a fail-closed deny as if it were authoritative.
	var bodyReader io.ReadCloser
	if strings.TrimSpace(matchBodyArg) != "" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(matchBodyArg), &fields); err != nil {
			return fmt.Errorf("body must be a JSON object: %w", err)
		}
		if fields == nil {
			return errors.New("body must be a JSON object, not null")
		}
		bodyReader = io.NopCloser(strings.NewReader(matchBodyArg))
	}

	req := &http.Request{
		Method:        method,
		URL:           &url.URL{Path: path, RawQuery: rawQuery},
		Body:          bodyReader,
		ContentLength: int64(len(matchBodyArg)),
	}
	profile, selection, err := selectMatchProfile(cfg, matchProfile, matchSourceIP)
	if err != nil {
		return fmt.Errorf("profile selection: %w", err)
	}
	rules, ruleConfigs := compiled, cfg.Rules
	policyConfig := cfg.RequestBody.ToFilterOptions()
	rolloutMode := config.RolloutEnforce
	if profile != nil {
		profilePolicies, err := compileClientProfiles(cfg)
		if err != nil {
			return fmt.Errorf("config validation: %w", err)
		}
		rules, ruleConfigs = profilePolicies[profile.Name].Rules, profile.Rules
		policyConfig = profilePolicies[profile.Name].PolicyConfig
		rolloutMode, _ = config.ParseRolloutMode(profile.Mode)
	}
	decision, matchedRuleIndex, reason, bodyState := filter.EvaluateWithBodyState(rules, req)
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

	var body *matchBody
	if matchBodyFile != "" {
		body, err = inspectMatchBody(cmd, matchBodyFile, req, offlinePolicyConfig(cfg, policyConfig), cfg.Mutations.ToFilterOptions(), decision)
		if err != nil {
			return err
		}
		if body.Decision == matchBodyDeny {
			decision = filter.ActionDeny
			reason = body.Reason
			hardDeny = hardDeny || body.Hard
		}
	}

	result := matchResult{
		Config:         cfgFile,
		Method:         method,
		Path:           path,
		Query:          rawQuery,
		RequestBody:    strings.TrimSpace(matchBodyArg),
		NormalizedPath: normalizedPath,
		Decision:       string(decision),
		Reason:         reason,
		CompatMode:     compatActive,
		Selection:      &selection,
		Ownership:      explainMatchOwnership(cfg, profile),
		Response:       explainMatchResponse(cfg, profile),
		Body:           body,
		NotInspected:   matchNotInspected(cfg, selection, body),
	}
	if profile != nil {
		result.RolloutMode = string(rolloutMode)
		result.PassThrough = decision == filter.ActionDeny && !hardDeny && rolloutMode != config.RolloutEnforce
	}
	_, parseErr := url.ParseQuery(rawQuery)
	if matchedRuleIndex >= 0 && matchedRuleIndex < len(ruleConfigs) {
		rule := ruleConfigs[matchedRuleIndex]
		// The evaluation's own witness decides this, not whether --body was
		// given: a body the walk could not read (absent, too big to buffer,
		// or keys the engines read two ways) let the rule match fail-closed
		// without weighing the constraints at all.
		bodyMatched, bodyUnreadable := false, false
		if len(rule.Match.Body) > 0 {
			bodyUnreadable = !bodyState.Readable()
			bodyMatched = bodyState.Readable()
		}
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
			Body:            rule.Match.Body,
			BodyMatched:     bodyMatched,
			BodyUnreadable:  bodyUnreadable,
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
	if result.RequestBody != "" {
		fmt.Fprintf(w, "%s %s\n", label("Body arg:"), result.RequestBody)
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
		if b := filter.FormatBody(result.MatchedRule.Body); b != "" {
			note := "constraints matched"
			switch {
			case result.MatchedRule.BodyUnreadable && result.RequestBody == "":
				note = "no --body given, rule matched fail-closed"
			case result.MatchedRule.BodyUnreadable:
				note = "body unreadable to matching, rule matched fail-closed"
			}
			fmt.Fprintf(w, "%s %s (%s)\n", label("Rule body:"), b, note)
		}
	}
	if result.Reason != "" {
		fmt.Fprintf(w, "%s %s\n", label("Reason:"), result.Reason)
	}
	fmt.Fprintln(w)
	writeMatchExplanation(w, p, label, result)
}
