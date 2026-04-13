package config

import (
	"log/slog"
	"os"
	"strings"
)

var compatVars = []string{
	"CONTAINERS", "IMAGES", "NETWORKS", "VOLUMES", "INFO",
	"POST", "PING", "VERSION", "EVENTS",
	"ALLOW_START", "ALLOW_STOP", "ALLOW_RESTART",
	"ALLOW_PAUSE", "ALLOW_UNPAUSE", "ALLOW_CREATE",
	"ALLOW_EXEC", "ALLOW_KILL", "ALLOW_DELETE", "ALLOW_PRUNE",
}

var compatCategoryRules = []struct {
	envKey string
	method string
	path   string
}{
	{envKey: "INFO", method: "GET", path: "/info"},
	{envKey: "CONTAINERS", method: "GET", path: "/containers/**"},
	{envKey: "IMAGES", method: "GET", path: "/images/**"},
	{envKey: "NETWORKS", method: "GET", path: "/networks/**"},
	{envKey: "VOLUMES", method: "GET", path: "/volumes/**"},
}

var compatGranularPostRules = []struct {
	envKey string
	method string
	path   string
}{
	{envKey: "ALLOW_CREATE", method: "POST", path: "/containers/create"},
	{envKey: "ALLOW_DELETE", method: "DELETE", path: "/containers/*"},
	{envKey: "ALLOW_EXEC", method: "POST", path: "/containers/*/exec"},
	{envKey: "ALLOW_KILL", method: "POST", path: "/containers/*/kill"},
	{envKey: "ALLOW_PAUSE", method: "POST", path: "/containers/*/pause"},
	{envKey: "ALLOW_PRUNE", method: "POST", path: "/containers/prune"},
	{envKey: "ALLOW_RESTART", method: "POST", path: "/containers/*/restart"},
	{envKey: "ALLOW_START", method: "POST", path: "/containers/*/start"},
	{envKey: "ALLOW_STOP", method: "POST", path: "/containers/*/stop"},
	{envKey: "ALLOW_UNPAUSE", method: "POST", path: "/containers/*/unpause"},
}

// ApplyCompat detects Tecnativa-style env vars and generates equivalent
// RuleConfig entries. Returns true if any Tecnativa vars were detected.
// Activates only when the effective ruleset still matches the built-in
// defaults — regardless of whether those defaults came from the fallback
// path or from a YAML file that happens to be byte-identical to them (the
// shipped image's `/etc/sockguard/sockguard.yaml` is literally the
// defaults, so an earlier `rulesExplicitlyConfigured` guard here silently
// broke the README Quick Start for anyone using the published image with
// the Tecnativa-style env example).
func ApplyCompat(cfg *Config, logger *slog.Logger) bool {
	if !rulesMatchDefaults(cfg.Rules) {
		return false
	}

	if !hasCompatEnvVars() {
		return false
	}

	logger.Info("tecnativa compatibility mode active", "note", "generating rules from environment variables")
	warnInvalidCompatEnvVars(logger)

	rules := generatePingRules()
	rules = append(rules, generateVersionRules()...)
	rules = append(rules, generateEventsRules()...)
	rules = append(rules, generateCategoryRules()...)
	postRules := generatePostRules()
	if usesCompatBlanketPostFallback(postRules) {
		logger.Warn("tecnativa POST compatibility fallback grants blanket write access",
			"method", "POST,PUT,DELETE",
			"path", "/**",
			"note", "set granular ALLOW_* env vars to narrow write access",
		)
	}
	rules = append(rules, postRules...)
	rules = append(rules, catchAllDenyRule())

	cfg.Rules = rules

	for i, r := range rules {
		logger.Debug("compat rule generated",
			"index", i+1,
			"method", r.Match.Method,
			"path", r.Match.Path,
			"action", r.Action,
		)
	}

	return true
}

func hasCompatEnvVars() bool {
	for _, key := range compatVars {
		if _, ok := os.LookupEnv(key); ok {
			return true
		}
	}
	return false
}

func warnInvalidCompatEnvVars(logger *slog.Logger) {
	for _, key := range compatVars {
		rawVal, envSet := os.LookupEnv(key)
		if !envSet {
			continue
		}
		if _, parsed := lookupEnvBool(key); !parsed {
			logger.Warn("ignoring compat env var with unparseable boolean value",
				"var", key,
				"value", rawVal,
				"accepted_values", "1, true, yes, 0, false, no",
			)
		}
	}
}

func generatePingRules() []RuleConfig {
	if v, ok := lookupEnvBool("PING"); ok && !v {
		return nil
	}
	return []RuleConfig{
		newAllowRule("GET", "/_ping"),
		newAllowRule("HEAD", "/_ping"),
	}
}

func generateVersionRules() []RuleConfig {
	if v, ok := lookupEnvBool("VERSION"); ok && !v {
		return nil
	}
	return []RuleConfig{newAllowRule("GET", "/version")}
}

func generateEventsRules() []RuleConfig {
	if v, ok := lookupEnvBool("EVENTS"); ok && !v {
		return nil
	}
	return []RuleConfig{newAllowRule("GET", "/events")}
}

func generateCategoryRules() []RuleConfig {
	var rules []RuleConfig
	for _, rule := range compatCategoryRules {
		if v, _ := lookupEnvBool(rule.envKey); v {
			rules = append(rules, newAllowRule(rule.method, rule.path))
		}
	}
	return rules
}

func generatePostRules() []RuleConfig {
	postEnabled, _ := lookupEnvBool("POST")
	if !postEnabled {
		return nil
	}

	var rules []RuleConfig
	for _, rule := range compatGranularPostRules {
		if v, ok := lookupEnvBool(rule.envKey); ok && v {
			rules = append(rules, newAllowRule(rule.method, rule.path))
		}
	}
	if len(rules) > 0 {
		return rules
	}
	return []RuleConfig{newAllowRule("POST,PUT,DELETE", "/**")}
}

func usesCompatBlanketPostFallback(rules []RuleConfig) bool {
	if len(rules) != 1 {
		return false
	}

	rule := rules[0]
	return rule.Match.Method == "POST,PUT,DELETE" &&
		rule.Match.Path == "/**" &&
		rule.Action == "allow"
}

func catchAllDenyRule() RuleConfig {
	return RuleConfig{
		Match:  MatchConfig{Method: "*", Path: "/**"},
		Action: "deny",
		Reason: "no matching allow rule",
	}
}

func newAllowRule(method, path string) RuleConfig {
	return RuleConfig{
		Match:  MatchConfig{Method: method, Path: path},
		Action: "allow",
	}
}

// rulesMatchDefaults checks if rules are the same as Defaults().Rules.
func rulesMatchDefaults(rules []RuleConfig) bool {
	defaultRules := Defaults().Rules
	if len(rules) != len(defaultRules) {
		return false
	}

	for i := range rules {
		if rules[i].Match.Method != defaultRules[i].Match.Method ||
			rules[i].Match.Path != defaultRules[i].Match.Path ||
			rules[i].Action != defaultRules[i].Action ||
			rules[i].Reason != defaultRules[i].Reason {
			return false
		}
	}

	return true
}

// lookupEnvBool reads an env var and parses it as a boolean.
// Returns (value, found). Accepts 1/true/yes as true, 0/false/no as false.
func lookupEnvBool(key string) (bool, bool) {
	val, ok := os.LookupEnv(key)
	if !ok {
		return false, false
	}
	switch strings.ToLower(val) {
	case "1", "true", "yes":
		return true, true
	case "0", "false", "no":
		return false, true
	default:
		return false, false
	}
}
