package config

import (
	"log/slog"
	"os"
	"slices"
	"strings"
)

// Compat flavor names, reported in the activation log's "flavor" attribute.
const (
	compatFlavorTecnativa   = "tecnativa"
	compatFlavorLinuxServer = "linuxserver"
)

// tecnativaCompatVars are the variables Tecnativa's docker-socket-proxy (and
// sockguard's own historical extensions) define.
var tecnativaCompatVars = []string{
	"AUTH", "BUILD", "COMMIT", "CONFIGS", "CONTAINERS",
	"DISTRIBUTION", "EVENTS", "EXEC", "GRPC", "IMAGES",
	"INFO", "NETWORKS", "NODES", "PING", "PLUGINS",
	"POST", "SECRETS", "SERVICES", "SESSION", "SWARM",
	"SYSTEM", "TASKS", "VERSION", "VOLUMES",
	"ALLOW_START", "ALLOW_STOP", "ALLOW_RESTART",
	"ALLOW_RESTARTS", "ALLOW_PAUSE", "ALLOW_UNPAUSE", "ALLOW_CREATE",
	"ALLOW_EXEC", "ALLOW_KILL", "ALLOW_DELETE", "ALLOW_PRUNE",
}

// linuxServerOnlyCompatVars are the rule-generating variables only
// LinuxServer's socket-proxy defines (ls107: the deny-guard ALLOW_* set and
// every LIBPOD_* variable). Setting any of them, to any value, selects the
// LinuxServer flavor. TIMEOUT_CLIENT, TIMEOUT_SERVER and DISABLE_IPV6 are
// deliberately absent: they generate no rules, so they cannot pick a flavor.
var linuxServerOnlyCompatVars = []string{
	"ALLOW_ARCHIVE", "ALLOW_CHANGES", "ALLOW_EXPORT", "ALLOW_LOGS", "ALLOW_TOP",
	"LIBPOD_CONTAINERS", "LIBPOD_EVENTS", "LIBPOD_EXEC", "LIBPOD_GENERATE",
	"LIBPOD_IMAGES", "LIBPOD_INFO", "LIBPOD_MANIFESTS", "LIBPOD_NETWORKS",
	"LIBPOD_PING", "LIBPOD_PLAY", "LIBPOD_PODS", "LIBPOD_SECRETS",
	"LIBPOD_SYSTEM", "LIBPOD_VERSION", "LIBPOD_VOLUMES",
	"LIBPOD_ALLOW_START", "LIBPOD_ALLOW_STOP", "LIBPOD_ALLOW_RESTARTS",
	"LIBPOD_ALLOW_PAUSE", "LIBPOD_ALLOW_UNPAUSE",
	"LIBPOD_ALLOW_POD_START", "LIBPOD_ALLOW_POD_STOP", "LIBPOD_ALLOW_POD_RESTARTS",
	"LIBPOD_ALLOW_POD_PAUSE", "LIBPOD_ALLOW_POD_UNPAUSE",
}

var compatVars = slices.Concat(tecnativaCompatVars, linuxServerOnlyCompatVars)

// unmappedCompatVars are LinuxServer variables that generate no rules. They
// are recognized so a migrator gets pointed at the sockguard key that does the
// same job, instead of the variable silently doing nothing.
var unmappedCompatVars = []struct {
	name        string
	replacement string
}{
	{name: "TIMEOUT_CLIENT", replacement: "upstream.request_timeout and upstream.hijack_inactivity_timeout"},
	{name: "TIMEOUT_SERVER", replacement: "upstream.request_timeout and upstream.hijack_inactivity_timeout"},
	{name: "DISABLE_IPV6", replacement: "listen.address"},
}

// linuxServerGuards are LinuxServer's deny guards. haproxy evaluates them
// before any allow, so with the variable not enabled the matching sub-resource
// is refused even when its whole section is open.
var linuxServerGuards = []struct {
	envKey string
	paths  []string
}{
	{envKey: "ALLOW_ARCHIVE", paths: guardPaths("archive")},
	{envKey: "ALLOW_CHANGES", paths: guardPaths("changes")},
	{envKey: "ALLOW_EXPORT", paths: guardPaths("export")},
	{envKey: "ALLOW_LOGS", paths: guardPaths("logs")},
	{envKey: "ALLOW_TOP", paths: guardPaths("top")},
	{envKey: "ALLOW_PAUSE", paths: guardPaths("pause")},
	{envKey: "EXEC", paths: []string{"/containers/*/exec", "/libpod/containers/*/exec"}},
}

func guardPaths(sub string) []string {
	return []string{"/containers/*/" + sub, "/libpod/containers/*/" + sub, "/libpod/pods/*/" + sub}
}

// linuxServerGranularRules are the LinuxServer-flavor POST allows for
// container and pod lifecycle actions. Each path carries every variable that
// grants it, so ALLOW_START and LIBPOD_ALLOW_START open the one rule rather
// than generating two.
var linuxServerGranularRules = []struct {
	envKeys []string
	path    string
}{
	{envKeys: []string{"ALLOW_START"}, path: "/libpod/containers/*/start"},
	{envKeys: []string{"ALLOW_STOP", "ALLOW_RESTARTS", "ALLOW_RESTART"}, path: "/libpod/containers/*/stop"},
	{envKeys: []string{"ALLOW_RESTARTS", "ALLOW_RESTART"}, path: "/libpod/containers/*/restart"},
	{envKeys: []string{"ALLOW_RESTARTS", "ALLOW_RESTART"}, path: "/libpod/containers/*/kill"},
	{envKeys: []string{"ALLOW_PAUSE"}, path: "/libpod/containers/*/pause"},
	{envKeys: []string{"ALLOW_UNPAUSE"}, path: "/libpod/containers/*/unpause"},
	{envKeys: []string{"ALLOW_START"}, path: "/libpod/pods/*/start"},
	{envKeys: []string{"ALLOW_STOP", "ALLOW_RESTARTS", "ALLOW_RESTART"}, path: "/libpod/pods/*/stop"},
	{envKeys: []string{"ALLOW_RESTARTS", "ALLOW_RESTART"}, path: "/libpod/pods/*/restart"},
	{envKeys: []string{"ALLOW_RESTARTS", "ALLOW_RESTART"}, path: "/libpod/pods/*/kill"},
	{envKeys: []string{"ALLOW_PAUSE"}, path: "/libpod/pods/*/pause"},
	{envKeys: []string{"ALLOW_UNPAUSE"}, path: "/libpod/pods/*/unpause"},
}

// linuxServerLibpodGranularRules are LinuxServer's LIBPOD_ALLOW_* variables.
var linuxServerLibpodGranularRules = []struct {
	envKeys []string
	path    string
}{
	{envKeys: []string{"LIBPOD_ALLOW_START"}, path: "/libpod/containers/*/start"},
	{envKeys: []string{"LIBPOD_ALLOW_STOP", "LIBPOD_ALLOW_RESTARTS"}, path: "/libpod/containers/*/stop"},
	{envKeys: []string{"LIBPOD_ALLOW_RESTARTS"}, path: "/libpod/containers/*/restart"},
	{envKeys: []string{"LIBPOD_ALLOW_RESTARTS"}, path: "/libpod/containers/*/kill"},
	{envKeys: []string{"LIBPOD_ALLOW_PAUSE"}, path: "/libpod/containers/*/pause"},
	{envKeys: []string{"LIBPOD_ALLOW_UNPAUSE"}, path: "/libpod/containers/*/unpause"},
	{envKeys: []string{"LIBPOD_ALLOW_POD_START"}, path: "/libpod/pods/*/start"},
	{envKeys: []string{"LIBPOD_ALLOW_POD_STOP", "LIBPOD_ALLOW_POD_RESTARTS"}, path: "/libpod/pods/*/stop"},
	{envKeys: []string{"LIBPOD_ALLOW_POD_RESTARTS"}, path: "/libpod/pods/*/restart"},
	{envKeys: []string{"LIBPOD_ALLOW_POD_RESTARTS"}, path: "/libpod/pods/*/kill"},
	{envKeys: []string{"LIBPOD_ALLOW_POD_PAUSE"}, path: "/libpod/pods/*/pause"},
	{envKeys: []string{"LIBPOD_ALLOW_POD_UNPAUSE"}, path: "/libpod/pods/*/unpause"},
}

// linuxServerLibpodSectionRules are LinuxServer's LIBPOD_* sections. PING and
// VERSION default on, every other section off, as in the upstream image.
var linuxServerLibpodSectionRules = []struct {
	envKey       string
	path         string
	defaultAllow bool
}{
	{envKey: "LIBPOD_PING", path: "/libpod/_ping", defaultAllow: true},
	{envKey: "LIBPOD_VERSION", path: "/libpod/version", defaultAllow: true},
	{envKey: "LIBPOD_CONTAINERS", path: "/libpod/containers/**"},
	{envKey: "LIBPOD_EVENTS", path: "/libpod/events"},
	{envKey: "LIBPOD_EXEC", path: "/libpod/exec/**"},
	{envKey: "LIBPOD_GENERATE", path: "/libpod/generate/**"},
	{envKey: "LIBPOD_IMAGES", path: "/libpod/images/**"},
	{envKey: "LIBPOD_INFO", path: "/libpod/info"},
	{envKey: "LIBPOD_MANIFESTS", path: "/libpod/manifests/**"},
	{envKey: "LIBPOD_NETWORKS", path: "/libpod/networks/**"},
	{envKey: "LIBPOD_PLAY", path: "/libpod/play/**"},
	{envKey: "LIBPOD_PODS", path: "/libpod/pods/**"},
	{envKey: "LIBPOD_SECRETS", path: "/libpod/secrets/**"},
	{envKey: "LIBPOD_SYSTEM", path: "/libpod/system/**"},
	{envKey: "LIBPOD_VOLUMES", path: "/libpod/volumes/**"},
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
	{envKeys: []string{"ALLOW_DELETE"}, method: "DELETE", path: "/containers/**"},
	{envKeys: []string{"ALLOW_EXEC"}, method: "POST", path: "/containers/*/exec"},
	{envKeys: []string{"ALLOW_KILL", "ALLOW_RESTARTS", "ALLOW_RESTART"}, method: "POST", path: "/containers/*/kill"},
	{envKeys: []string{"ALLOW_PAUSE"}, method: "POST", path: "/containers/*/pause"},
	{envKeys: []string{"ALLOW_PRUNE"}, method: "POST", path: "/containers/prune"},
	{envKeys: []string{"ALLOW_RESTARTS", "ALLOW_RESTART"}, method: "POST", path: "/containers/*/restart"},
	{envKeys: []string{"ALLOW_START"}, method: "POST", path: "/containers/*/start"},
	{envKeys: []string{"ALLOW_STOP", "ALLOW_RESTARTS", "ALLOW_RESTART"}, method: "POST", path: "/containers/*/stop"},
	{envKeys: []string{"ALLOW_UNPAUSE"}, method: "POST", path: "/containers/*/unpause"},
}

// ApplyCompat detects Tecnativa and LinuxServer style env vars and generates
// equivalent RuleConfig entries. Returns true if any compat vars were detected.
// Activates only when the effective ruleset still matches the built-in
// defaults — regardless of whether those defaults came from the fallback
// path or from a YAML file that happens to be byte-identical to them (the
// shipped image's `/etc/sockguard/sockguard.yaml` is literally the
// defaults, so an earlier `rulesExplicitlyConfigured` guard here silently
// broke the README Quick Start for anyone using the published image with
// the Tecnativa-style env example).
//
// Setting any LinuxServer-only variable (see linuxServerOnlyCompatVars)
// selects the LinuxServer flavor: deny guards first, then granular and section
// allows including the libpod ones. Otherwise the Tecnativa rules are
// generated exactly as they always were.
func ApplyCompat(cfg *Config, logger *slog.Logger) bool {
	warnUnmappedCompatEnvVars(logger)

	if !hasCompatEnvVars() {
		return false
	}

	if !rulesMatchDefaults(cfg.Rules) {
		logger.Warn("compat env vars ignored because rules are configured",
			"vars", strings.Join(CompatEnvironmentVariables(), ","),
			"note", "remove the rules to use compat env vars, or remove the env vars",
		)
		return false
	}

	flavor := compatFlavorTecnativa
	if linuxServerFlavorActive() {
		flavor = compatFlavorLinuxServer
	}

	logger.Info(flavor+" compatibility mode active",
		"note", "generating rules from environment variables",
		"flavor", flavor,
		"vars", strings.Join(compatEnvVarSettings(), ","),
	)
	warnInvalidCompatEnvVars(logger)
	if flavor == compatFlavorTecnativa && compatEnvEnabled("CONTAINERS", false) {
		logger.Info("LinuxServer guards are not applied: CONTAINERS=1 allows logs, archive, export, top, changes and exec on containers",
			"note", "set any LinuxServer guard variable (for example ALLOW_LOGS=0, the LinuxServer image default) to select the LinuxServer flavor, which denies those until ALLOW_LOGS, ALLOW_ARCHIVE, ALLOW_EXPORT, ALLOW_TOP, ALLOW_CHANGES or EXEC is enabled",
			"flavor", flavor,
		)
	}

	var rules []RuleConfig
	if flavor == compatFlavorLinuxServer {
		rules = generateLinuxServerRules()
	} else {
		rules = generateSectionRules()
		rules = append(rules, generateGranularPostRules()...)
	}
	rules = append(rules, catchAllDenyRule())

	cfg.Rules = rules
	cfg.compatGeneratedRules = true

	// The ContainerRemove relaxation below keys on the Tecnativa vars only
	// (ALLOW_DELETE, CONTAINERS+POST). LinuxServer has no delete variable, and
	// the libpod sections are not part of it.
	// ALLOW_DELETE and the broader CONTAINERS=1 + POST=1 section grant both
	// predate Sockguard's query inspector and admit the full Tecnativa
	// container-remove call surface. Preserve that compatibility behavior
	// without changing native defaults or user-authored rules.
	if compatEnvEnabled("ALLOW_DELETE", false) ||
		(compatEnvEnabled("CONTAINERS", false) && compatEnvEnabled("POST", false)) {
		cfg.RequestBody.ContainerRemove.AllowForce = true
		cfg.RequestBody.ContainerRemove.AllowRemoveVolumes = true
		cfg.RequestBody.ContainerRemove.AllowRemoveLinks = true
	}

	// GRPC=1 / SESSION=1 open the opaque BuildKit /grpc and /session tunnels
	// (see buildkitTunnelEndpoints in cmd/rules.go), which now require the
	// dedicated insecure_accept_opaque_buildkit_tunnels acknowledgment rather
	// than sailing through as ordinary compat rules. Preserve the Tecnativa
	// drop-in migration promise — these vars keep working exactly as before —
	// by auto-setting the new key when either is enabled, while nudging the
	// operator toward setting it explicitly going forward.
	//
	// Except when request_body.buildkit is configured (top level or on any
	// client profile — buildkitMediationConfigured in validate.go). The
	// acknowledgment and a mediation policy are mutually exclusive
	// (validateBuildkitAckMutualExclusion), and ApplyCompat runs before
	// validation, so auto-setting it there refuses startup over a key the
	// operator never wrote: they migrated to request_body.buildkit and still
	// carry GRPC=1 from their old Tecnativa environment.
	//
	// Skipping keeps the fail-closed posture rather than relaxing it. The
	// acknowledgment has no request-time effect at all — it gates startup
	// admission only, while what actually happens to a /session or /grpc
	// request is decided by filter.BuildkitOptions.TunnelConfigured, which
	// comes from request_body.buildkit (see filter_options.go). With a
	// TOP-LEVEL policy the compat rules for those two paths are still
	// admitted, by validateBuildkitTunnelRulesForPolicy's buildkitConfigured
	// arm instead of its acknowledgment arm, and that is the tighter of the
	// two: every message on the tunnel goes through buildkitproxy.Mediator's
	// per-method policy rather than being wholesale admitted uninspected.
	//
	// With the policy on a client PROFILE only, that admission check still
	// refuses, and must: it reads the top-level request_body.buildkit, the
	// compat rules it is checking are top-level, and those rules apply to
	// every client that matches no profile — letting a profile's policy admit
	// them would open an uninspected tunnel for exactly the clients that
	// profile does not cover. Skipping the ack is still right there, because
	// the refusal an operator gets then names the GRPC/SESSION vars that
	// generated the rule and the cures that work (see
	// compatBuildkitTunnelOrigin in cmd/rules.go), where the mutual-exclusion
	// error auto-setting it produced named a key they never wrote and told
	// them to unset it, which compat would only set again.
	if compatEnvEnabled("GRPC", false) || compatEnvEnabled("SESSION", false) {
		switch {
		case buildkitMediationConfigured(cfg):
			// Says "skipped", not "left unset": this branch also runs when the
			// operator set the acknowledgment themselves, and compat neither
			// changes nor clears that value. The attribute carries what the
			// flag actually is so the two cases are distinguishable in a log.
			logger.Info("request_body.buildkit is configured, so the GRPC/SESSION compat acknowledgment of the opaque BuildKit tunnel is skipped; an insecure_accept_opaque_buildkit_tunnels you set yourself is left untouched",
				"compat_vars", "GRPC, SESSION",
				"reason", "request_body.buildkit is configured, and the two are mutually exclusive",
				"insecure_accept_opaque_buildkit_tunnels", cfg.InsecureAcceptOpaqueBuildkitTunnels,
			)
		case !cfg.InsecureAcceptOpaqueBuildkitTunnels:
			cfg.InsecureAcceptOpaqueBuildkitTunnels = true
			logger.Warn("GRPC/SESSION compat env vars open the opaque BuildKit tunnel; set insecure_accept_opaque_buildkit_tunnels: true explicitly going forward",
				"deprecated_vars", "GRPC, SESSION",
				"replacement_key", "insecure_accept_opaque_buildkit_tunnels",
			)
		}
	}

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

// linuxServerFlavorActive reports whether any LinuxServer-only rule-generating
// variable is present in the environment, whatever its value. Presence is
// enough because copying the upstream image's own defaults (ALLOW_LOGS=0) is the
// clearest signal the operator wants its guard semantics.
func linuxServerFlavorActive() bool {
	for _, key := range linuxServerOnlyCompatVars {
		if _, ok := os.LookupEnv(key); ok {
			return true
		}
	}
	return false
}

func warnUnmappedCompatEnvVars(logger *slog.Logger) {
	for _, v := range unmappedCompatVars {
		if _, ok := os.LookupEnv(v.name); !ok {
			continue
		}
		logger.Warn("recognized LinuxServer env var has no effect in sockguard",
			"var", v.name,
			"use_instead", v.replacement,
		)
	}
}

func hasCompatEnvVars() bool {
	return len(CompatEnvironmentVariables()) > 0
}

// CompatEnvironmentVariables returns the Tecnativa rule-generating
// environment variables present in the process environment. Signed policy
// startup and reload use this to reject any unsigned policy mutations.
func CompatEnvironmentVariables() []string {
	var found []string
	for _, key := range compatVars {
		if _, ok := os.LookupEnv(key); ok {
			found = append(found, key)
		}
	}
	return found
}

// compatEnvVarSettings returns "KEY=value" for every Tecnativa env var
// CompatEnvironmentVariables found set, in the same order. These are all
// policy-shaping booleans (POST, CONTAINERS, ALLOW_START, ...), never
// credentials, so the activation log can name what actually armed compat
// mode instead of just noting that something did.
func compatEnvVarSettings() []string {
	keys := CompatEnvironmentVariables()
	settings := make([]string, 0, len(keys))
	for _, key := range keys {
		val, _ := os.LookupEnv(key)
		settings = append(settings, key+"="+val)
	}
	return settings
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
	return generateSectionRulesFor(false)
}

// generateSectionRulesFor builds the Docker section allows. The LinuxServer
// flavor skips the Tecnativa {EXEC, /containers/*/exec} row: haproxy matches
// only ^/exec for EXEC, and /containers/x/exec needs CONTAINERS, so EXEC=1
// alone must not open it.
func generateSectionRulesFor(linuxServer bool) []RuleConfig {
	var rules []RuleConfig
	methods := compatReadMethods()
	for _, rule := range compatSectionRules {
		if linuxServer && rule.path == "/containers/*/exec" {
			continue
		}
		if compatEnvEnabled(rule.envKey, rule.defaultAllow) {
			rules = append(rules, newAllowRule(methods, rule.path))
		}
	}
	return rules
}

// generateLinuxServerRules builds the LinuxServer-flavor rules without the
// trailing catch-all: guard denies, granular allows, then section allows.
// sockguard is first-match-wins, so the guards sit ahead of everything and a
// guard beats a granular allow for the same action (ALLOW_PAUSE off denies
// LIBPOD_ALLOW_PAUSE=1), exactly as haproxy's deny-before-allow order does.
func generateLinuxServerRules() []RuleConfig {
	var rules []RuleConfig
	for _, guard := range linuxServerGuards {
		if compatEnvEnabled(guard.envKey, false) {
			continue
		}
		for _, path := range guard.paths {
			rules = append(rules, RuleConfig{
				Match:  MatchConfig{Method: "*", Path: path},
				Action: "deny",
				Reason: "linuxserver compat: " + guard.envKey + " is not enabled",
			})
		}
	}

	rules = append(rules, generateGranularPostRules()...)
	for _, rule := range linuxServerGranularRules {
		keys := append([]string(nil), rule.envKeys...)
		for _, libpodRule := range linuxServerLibpodGranularRules {
			if libpodRule.path == rule.path {
				keys = append(keys, libpodRule.envKeys...)
			}
		}
		if compatAnyEnvEnabled(keys...) {
			rules = append(rules, newAllowRule("POST", rule.path))
		}
	}

	rules = append(rules, generateSectionRulesFor(true)...)
	methods := compatReadMethods()
	for _, rule := range linuxServerLibpodSectionRules {
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
