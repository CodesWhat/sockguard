package config

import (
	"log/slog"
	"os"
	"strings"
)

var compatVars = []string{
	"AUTH", "BUILD", "COMMIT", "CONFIGS", "CONTAINERS",
	"DISTRIBUTION", "EVENTS", "EXEC", "GRPC", "IMAGES",
	"INFO", "NETWORKS", "NODES", "PING", "PLUGINS",
	"POST", "SECRETS", "SERVICES", "SESSION", "SWARM",
	"SYSTEM", "TASKS", "VERSION", "VOLUMES",
	"ALLOW_START", "ALLOW_STOP", "ALLOW_RESTART",
	"ALLOW_RESTARTS", "ALLOW_PAUSE", "ALLOW_UNPAUSE", "ALLOW_CREATE",
	"ALLOW_EXEC", "ALLOW_KILL", "ALLOW_DELETE", "ALLOW_PRUNE",
}

var compatSectionRules = []struct {
	envKey       string
	path         string
	defaultAllow bool
}{
	{envKey: "PING", path: "/_ping", defaultAllow: true},
	{envKey: "VERSION", path: "/version", defaultAllow: true},
	{envKey: "EVENTS", path: "/events", defaultAllow: true},
	{envKey: "AUTH", path: "/auth/**"},
	{envKey: "BUILD", path: "/build/**"},
	{envKey: "COMMIT", path: "/commit/**"},
	{envKey: "CONFIGS", path: "/configs/**"},
	{envKey: "CONTAINERS", path: "/containers/**"},
	{envKey: "DISTRIBUTION", path: "/distribution/**"},
	{envKey: "EXEC", path: "/exec/**"},
	{envKey: "EXEC", path: "/containers/*/exec"},
	{envKey: "GRPC", path: "/grpc/**"},
	{envKey: "IMAGES", path: "/images/**"},
	{envKey: "INFO", path: "/info"},
	{envKey: "NETWORKS", path: "/networks/**"},
	{envKey: "NODES", path: "/nodes/**"},
	{envKey: "PLUGINS", path: "/plugins/**"},
	{envKey: "SECRETS", path: "/secrets/**"},
	{envKey: "SERVICES", path: "/services/**"},
	{envKey: "SESSION", path: "/session/**"},
	{envKey: "SWARM", path: "/swarm/**"},
	{envKey: "SYSTEM", path: "/system/**"},
	{envKey: "TASKS", path: "/tasks/**"},
	{envKey: "VOLUMES", path: "/volumes/**"},
}

var compatGranularPostRules = []struct {
	envKeys []string
	method  string
	path    string
}{
	{envKeys: []string{"ALLOW_CREATE"}, method: "POST", path: "/containers/create"},
	{envKeys: []string{"ALLOW_DELETE"}, method: "DELETE", path: "/containers/*"},
	{envKeys: []string{"ALLOW_EXEC"}, method: "POST", path: "/containers/*/exec"},
	{envKeys: []string{"ALLOW_KILL", "ALLOW_RESTARTS", "ALLOW_RESTART"}, method: "POST", path: "/containers/*/kill"},
	{envKeys: []string{"ALLOW_PAUSE"}, method: "POST", path: "/containers/*/pause"},
	{envKeys: []string{"ALLOW_PRUNE"}, method: "POST", path: "/containers/prune"},
	{envKeys: []string{"ALLOW_RESTARTS", "ALLOW_RESTART"}, method: "POST", path: "/containers/*/restart"},
	{envKeys: []string{"ALLOW_START"}, method: "POST", path: "/containers/*/start"},
	{envKeys: []string{"ALLOW_STOP", "ALLOW_RESTARTS", "ALLOW_RESTART"}, method: "POST", path: "/containers/*/stop"},
	{envKeys: []string{"ALLOW_UNPAUSE"}, method: "POST", path: "/containers/*/unpause"},
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

	rules := generateSectionRules()
	rules = append(rules, generateGranularPostRules()...)
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

func generateSectionRules() []RuleConfig {
	var rules []RuleConfig
	methods := compatReadMethods()
	for _, rule := range compatSectionRules {
		if compatEnvEnabled(rule.envKey, rule.defaultAllow) {
			rules = append(rules, newAllowRule(methods, rule.path))
		}
	}
	return rules
}

func generateGranularPostRules() []RuleConfig {
	var rules []RuleConfig
	for _, rule := range compatGranularPostRules {
		if compatAnyEnvEnabled(rule.envKeys...) {
			rules = append(rules, newAllowRule(rule.method, rule.path))
		}
	}
	return rules
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

func compatReadMethods() string {
	if postEnabled, _ := lookupEnvBool("POST"); postEnabled {
		return "*"
	}
	return "GET,HEAD"
}

func compatEnvEnabled(key string, defaultValue bool) bool {
	rawValue, envSet := os.LookupEnv(key)
	if !envSet {
		return defaultValue
	}
	if value, ok := parseCompatBool(rawValue); ok {
		return value
	}
	return false
}

func compatAnyEnvEnabled(keys ...string) bool {
	for _, key := range keys {
		if value, ok := lookupEnvBool(key); ok && value {
			return true
		}
	}
	return false
}

func applyCompatEnvAliases(cfg *Config) {
	if _, ok := os.LookupEnv("SOCKGUARD_UPSTREAM_SOCKET"); !ok {
		if socketPath, ok := os.LookupEnv("SOCKET_PATH"); ok && strings.TrimSpace(socketPath) != "" {
			cfg.Upstream.Socket = strings.TrimSpace(socketPath)
		}
	}

	if _, ok := os.LookupEnv("SOCKGUARD_LOG_LEVEL"); ok {
		return
	}

	rawLevel, ok := os.LookupEnv("LOG_LEVEL")
	if !ok {
		return
	}

	cfg.Log.Level = normalizeCompatLogLevel(rawLevel)
}

func normalizeCompatLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return "debug"
	case "info", "notice":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error", "err", "crit", "alert", "emerg":
		return "error"
	default:
		return strings.ToLower(strings.TrimSpace(level))
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
	return parseCompatBool(val)
}

func parseCompatBool(val string) (bool, bool) {
	switch strings.ToLower(val) {
	case "1", "true", "yes":
		return true, true
	case "0", "false", "no":
		return false, true
	default:
		return false, false
	}
}
