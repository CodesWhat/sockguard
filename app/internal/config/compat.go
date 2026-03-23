package config

import (
	"log/slog"
	"os"
	"reflect"
	"strings"
)

// ApplyCompat detects Tecnativa-style env vars and generates equivalent
// RuleConfig entries. Returns true if any Tecnativa vars were detected.
// Only activates when cfg.Rules matches the defaults (user hasn't provided custom YAML).
func ApplyCompat(cfg *Config, logger *slog.Logger) bool {
	// Only apply if rules are still the defaults
	if !rulesMatchDefaults(cfg.Rules) {
		return false
	}

	// Check if any Tecnativa env vars are set
	compatVars := []string{
		"CONTAINERS", "IMAGES", "NETWORKS", "VOLUMES", "INFO",
		"POST", "PING", "VERSION", "EVENTS",
		"ALLOW_START", "ALLOW_STOP", "ALLOW_RESTART",
		"ALLOW_PAUSE", "ALLOW_UNPAUSE", "ALLOW_CREATE",
		"ALLOW_EXEC", "ALLOW_KILL", "ALLOW_DELETE", "ALLOW_PRUNE",
	}

	found := false
	for _, v := range compatVars {
		if _, ok := os.LookupEnv(v); ok {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	logger.Info("tecnativa compatibility mode active", "note", "generating rules from environment variables")

	// Warn about env vars that are set but have unparseable values
	for _, v := range compatVars {
		rawVal, envSet := os.LookupEnv(v)
		if !envSet {
			continue
		}
		if _, parsed := lookupEnvBool(v); !parsed {
			logger.Warn("ignoring compat env var with unparseable boolean value",
				"var", v,
				"value", rawVal,
				"accepted_values", "1, true, yes, 0, false, no",
			)
		}
	}

	var rules []RuleConfig

	// Always-on defaults (disabled with =0)
	if v, ok := lookupEnvBool("PING"); !ok || v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow",
		})
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "HEAD", Path: "/_ping"}, Action: "allow",
		})
	}
	if v, ok := lookupEnvBool("VERSION"); !ok || v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/version"}, Action: "allow",
		})
	}
	if v, ok := lookupEnvBool("EVENTS"); !ok || v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/events"}, Action: "allow",
		})
	}

	// Category toggles (default false)
	if v, _ := lookupEnvBool("INFO"); v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/info"}, Action: "allow",
		})
	}
	if v, _ := lookupEnvBool("CONTAINERS"); v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/containers/**"}, Action: "allow",
		})
	}
	if v, _ := lookupEnvBool("IMAGES"); v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/images/**"}, Action: "allow",
		})
	}
	if v, _ := lookupEnvBool("NETWORKS"); v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/networks/**"}, Action: "allow",
		})
	}
	if v, _ := lookupEnvBool("VOLUMES"); v {
		rules = append(rules, RuleConfig{
			Match: MatchConfig{Method: "GET", Path: "/volumes/**"}, Action: "allow",
		})
	}

	// POST-dependent granular controls
	postEnabled, _ := lookupEnvBool("POST")
	if postEnabled {
		granularVars := map[string]struct {
			method string
			path   string
		}{
			"ALLOW_START":   {method: "POST", path: "/containers/*/start"},
			"ALLOW_STOP":    {method: "POST", path: "/containers/*/stop"},
			"ALLOW_RESTART": {method: "POST", path: "/containers/*/restart"},
			"ALLOW_PAUSE":   {method: "POST", path: "/containers/*/pause"},
			"ALLOW_UNPAUSE": {method: "POST", path: "/containers/*/unpause"},
			"ALLOW_CREATE":  {method: "POST", path: "/containers/create"},
			"ALLOW_EXEC":    {method: "POST", path: "/containers/*/exec"},
			"ALLOW_KILL":    {method: "POST", path: "/containers/*/kill"},
			"ALLOW_DELETE":  {method: "DELETE", path: "/containers/*"},
			"ALLOW_PRUNE":   {method: "POST", path: "/containers/prune"},
		}

		hasGranular := false
		for envKey, rule := range granularVars {
			if v, ok := lookupEnvBool(envKey); ok && v {
				hasGranular = true
				rules = append(rules, RuleConfig{
					Match:  MatchConfig{Method: rule.method, Path: rule.path},
					Action: "allow",
				})
			}
		}

		// If POST=1 with no granular vars, blanket POST/PUT/DELETE allow
		if !hasGranular {
			rules = append(rules, RuleConfig{
				Match:  MatchConfig{Method: "POST,PUT,DELETE", Path: "/**"},
				Action: "allow",
			})
		}
	}

	// Catch-all deny
	rules = append(rules, RuleConfig{
		Match:  MatchConfig{Method: "*", Path: "/**"},
		Action: "deny",
		Reason: "no matching allow rule",
	})

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

// rulesMatchDefaults checks if rules are the same as Defaults().Rules.
func rulesMatchDefaults(rules []RuleConfig) bool {
	return reflect.DeepEqual(rules, Defaults().Rules)
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
