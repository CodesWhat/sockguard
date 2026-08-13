package config

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/codeswhat/sockguard/internal/buildkitproxy"

	"github.com/codeswhat/sockguard/internal/certmatch"
	"github.com/codeswhat/sockguard/internal/filter"

	"github.com/codeswhat/sockguard/internal/glob"
	"github.com/codeswhat/sockguard/internal/logging"

	"github.com/codeswhat/sockguard/internal/pkipin"
	"github.com/codeswhat/sockguard/internal/upstream"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/viper"
	"log/slog"
	"net"
	"net/netip"
	"net/url"

	"os"
	"path"
	"reflect"

	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	mapstructure "github.com/go-viper/mapstructure/v2"
)

// ToPolicy converts BuildkitRequestBodyConfig into buildkitproxy.Policy,
// mirroring how RequestBodyConfig.ToFilterOptions translates into the filter
// package's options types: buildkitproxy defines the destination type and
// never imports this package back — translation flows one direction only.
//
// build is the SIBLING request_body.build block (RequestBodyConfig.Build /
// ClientProfileConfig's own RequestBody.Build), threaded through so
// BuildkitSolveRequestBodyConfig.toPolicy can reuse its AllowHostNetwork/
// AllowRemoteContext verbatim into buildkitproxy.SolvePolicy — see
// BuildkitSolveRequestBodyConfig's doc comment for why those two fields are
// not duplicated on this struct. Every call site passes the RequestBodyConfig
// this BuildkitRequestBodyConfig itself came from (never a different scope's
// Build block) so the reused flags stay scoped to the same profile/top-level
// config the Buildkit block itself belongs to.
//
// Phase 1 shipped no runtime mediator to hand this Policy to (see
// filter.BuildkitOptions's doc comment); Phase 3 (issue #185) is the first
// phase whose mediator (bridge.go's forwardControlMediated) actually reads
// SolvePolicy's new fields. Policy.Configured backs both cmd/rules.go's
// startup admission check and the mutual-exclusion validation against
// InsecureAcceptOpaqueBuildkitTunnels.
func (c BuildkitRequestBodyConfig) ToPolicy(build BuildRequestBodyConfig) buildkitproxy.Policy {
	return buildkitproxy.Policy{
		Control: c.Control.toPolicy(build),
		Session: c.Session.toPolicy(),
	}
}

func (c BuildkitControlRequestBodyConfig) toPolicy(build BuildRequestBodyConfig) buildkitproxy.ControlPolicy {
	return buildkitproxy.ControlPolicy{
		AllowInfo:        c.AllowInfo,
		AllowListWorkers: c.AllowListWorkers,
		AllowStatus:      c.AllowStatus,
		Solve:            c.Solve.toPolicy(build),
	}
}

func (c BuildkitSolveRequestBodyConfig) toPolicy(build BuildRequestBodyConfig) buildkitproxy.SolvePolicy {
	return buildkitproxy.SolvePolicy{
		Allow:                     c.Allow,
		AllowHostNetwork:          build.AllowHostNetwork,
		AllowRemoteContext:        build.AllowRemoteContext,
		AllowRunInstructions:      build.AllowRunInstructions,
		AllowedCacheImportTypes:   c.AllowedCacheImportTypes,
		AllowedCacheExportTypes:   c.AllowedCacheExportTypes,
		AllowedCacheRegistries:    normalizeRegistryHostList(c.AllowedCacheRegistries),
		AllowedExporters:          c.AllowedExporters,
		AllowedExporterRegistries: normalizeRegistryHostList(c.AllowedExporterRegistries),
	}
}

// normalizeRegistryHostList normalizes every entry through
// normalizeAllowedRegistryHost so buildkitproxy's runtime registry-host
// comparisons — solve.go's registryHostFromImageRef (which always lowercases
// and canonicalizes the host it extracts from a client-supplied image ref)
// AND, since issue #185 phase 4, session_mediation.go's normalizeAuthHost
// (which applies the identical lowercase/index.docker.io normalization to
// moby.filesync.v1.Auth's bare Host field) — are compared against the SAME
// canonical form an operator's config-side allowlist entries are stored in —
// otherwise "Registry:5000" in config would never match "registry:5000"
// extracted at runtime. This mirrors internal/filter's
// newImagePullPolicy/normalizeRegistryHost precedent for the exact same
// registry-host allowlist shape (buildkitproxy must not import
// internal/filter or vice versa — see registry.go's package doc — so each
// side keeps its own copy of the same normalization rule).
// validateRegistryHostEntries already rejects any entry that fails to
// normalize, so the skip-on-!ok below is only a defensive no-op against
// what should be unreachable in a Validate()-passed Config.
func normalizeRegistryHostList(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if normalized, ok := normalizeAllowedRegistryHost(v); ok {
			out = append(out, normalized)
		}
	}
	return out
}

func (c BuildkitSessionRequestBodyConfig) toPolicy() buildkitproxy.SessionPolicy {
	return buildkitproxy.SessionPolicy{
		Health: c.Health,
		Auth: buildkitproxy.AuthPolicy{
			Allow:             c.Auth.Allow,
			AllowedRegistries: normalizeRegistryHostList(c.Auth.AllowedRegistries),
			AllowedRealms:     c.Auth.AllowedRealms,
			AllowedScopes:     c.Auth.AllowedScopes,
		},
		Secrets: buildkitproxy.SecretsPolicy{
			Allow:      c.Secrets.Allow,
			AllowedIDs: c.Secrets.AllowedIDs,
		},
		SSH: buildkitproxy.SSHPolicy{
			Allow:      c.SSH.Allow,
			AllowedIDs: c.SSH.AllowedIDs,
		},
		FileSync: buildkitproxy.FileSyncPolicy{
			Allow:         c.FileSync.Allow,
			MaxFiles:      c.FileSync.MaxFiles,
			MaxTotalBytes: c.FileSync.MaxTotalBytes,
			MaxPathLength: c.FileSync.MaxPathLength,
			MaxFileBytes:  c.FileSync.MaxFileBytes,
		},
		FileSend: buildkitproxy.FileSendPolicy{Allow: c.FileSend.Allow, MaxBytes: c.FileSend.MaxBytes},
		Upload:   buildkitproxy.UploadPolicy{Allow: c.Upload.Allow, MaxBytes: c.Upload.MaxBytes},
	}
}

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

	if compatEnvEnabled("GRPC", false) || compatEnvEnabled("SESSION", false) {
		if !cfg.InsecureAcceptOpaqueBuildkitTunnels {
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

// HardenedListenSocketMode is the only supported unix-socket permission mode
// (string form, as it appears in YAML).
const HardenedListenSocketMode = "0600"

// HardenedListenSocketFileMode is the os.FileMode equivalent of
// HardenedListenSocketMode, exported so listener creation paths derive the
// umask from a single source of truth.
const HardenedListenSocketFileMode = os.FileMode(0o600)

// GroupReadableListenSocketMode is the second (and only other) unix-socket
// permission mode a listener may opt into, in addition to
// HardenedListenSocketMode. It requires an explicit SocketGID — see
// validateSocketOwnership — so a group-shared socket is always an
// affirmative, per-listener operator choice rather than a default.
const GroupReadableListenSocketMode = "0660"

// GroupReadableListenSocketFileMode is the os.FileMode equivalent of
// GroupReadableListenSocketMode.
const GroupReadableListenSocketFileMode = os.FileMode(0o660)

// Multi-listener (#149) naming/scoping constants.
const (
	// DefaultListenerName is the synthetic name given to the legacy
	// Config.Listen block when EffectiveListeners synthesizes it into a
	// single-entry list.
	DefaultListenerName = "default"
	// AdminListenerName is reserved: no entry in Config.Listeners may use
	// this name, so Admin.MountOn's namespace (main listener names) can
	// never collide with the dedicated admin listener.
	AdminListenerName = "admin"
	// WildcardProfile, as the sole element of a ListenerConfig's
	// AllowedProfiles, preserves the legacy "every profile admitted"
	// behavior. It cannot be combined with concrete profile names and is a
	// reserved profile name (clients.profiles entries may not use it).
	WildcardProfile = "*"
	// MaxListeners bounds Config.Listeners: a small, operator-authored cap
	// that keeps validation's all-pairs uniqueness check, metrics
	// cardinality, and log/health fan-out proportionate.
	MaxListeners = 32
)

// ListenerNamePattern is the validation regex for ListenerConfig.Name:
// lowercase alphanumeric plus hyphen, starting with a letter, up to 63
// characters — safe to use unescaped as a Prometheus label value, a log
// field, and a reload-diff key.
var listenerNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ValidListenerName reports whether name matches ListenerNamePattern.
func ValidListenerName(name string) bool {
	return listenerNamePattern.MatchString(name)
}

// EffectiveListeners is the single read path every downstream consumer
// (validation, serve wiring, reload diff, banner, metrics, audit) must use
// instead of reading Config.Listen or Config.Listeners directly. When
// Listeners is empty it synthesizes the legacy Listen block into a
// single-entry list named DefaultListenerName with AllowedProfiles
// [WildcardProfile] — byte-for-byte equivalent to today's global behavior —
// so every config that sets only listen: continues to behave identically.
func (c *Config) EffectiveListeners() []ListenerConfig {
	if len(c.Listeners) > 0 {
		return c.Listeners
	}
	return []ListenerConfig{{
		Name:            DefaultListenerName,
		ListenConfig:    c.Listen,
		AllowedProfiles: []string{WildcardProfile},
	}}
}

// Wildcard reports whether l's AllowedProfiles is exactly [WildcardProfile],
// i.e. this listener admits every resolved profile (and the unprofiled
// default-policy path), matching legacy single-listener behavior.
func (l ListenerConfig) Wildcard() bool {
	return len(l.AllowedProfiles) == 1 && l.AllowedProfiles[0] == WildcardProfile
}

// Config represents the sockguard configuration.
type Config struct {
	Listen                        ListenConfig       `mapstructure:"listen"`
	Listeners                     []ListenerConfig   `mapstructure:"listeners"`
	Upstream                      UpstreamConfig     `mapstructure:"upstream"`
	Log                           LogConfig          `mapstructure:"log"`
	Response                      ResponseConfig     `mapstructure:"response"`
	RequestBody                   RequestBodyConfig  `mapstructure:"request_body"`
	Clients                       ClientsConfig      `mapstructure:"clients"`
	Ownership                     OwnershipConfig    `mapstructure:"ownership"`
	Health                        HealthConfig       `mapstructure:"health"`
	Metrics                       MetricsConfig      `mapstructure:"metrics"`
	Admin                         AdminConfig        `mapstructure:"admin"`
	Reload                        ReloadConfig       `mapstructure:"reload"`
	PolicyBundle                  PolicyBundleConfig `mapstructure:"policy_bundle"`
	Mutations                     MutationsConfig    `mapstructure:"mutations"`
	Rules                         []RuleConfig       `mapstructure:"rules"`
	InsecureAllowBodyBlindWrites  bool               `mapstructure:"insecure_allow_body_blind_writes"`
	InsecureAllowReadExfiltration bool               `mapstructure:"insecure_allow_read_exfiltration"`

	// explicitLegacyListen records whether the legacy listen.* fields were
	// set explicitly — a YAML key, a SOCKGUARD_LISTEN_* environment
	// variable, or the --listen-socket CLI flag — as opposed to left at
	// their zero/default value. It is populated by Load/LoadBytes (via a
	// provenance-only Viper pass) and by applyFlagOverrides in
	// internal/cmd, and consulted by validateListeners to detect the
	// "both listen and listeners configured" ambiguity (#149). Unexported
	// so it never round-trips through mapstructure/YAML/JSON; a Config
	// built directly (most tests) simply reads as "not explicit", which
	// only matters once Listeners is also non-empty.
	explicitLegacyListen bool

	// explicitNetworkEndpointConfig records whether
	// request_body.network.endpoint_config was set explicitly — a YAML key
	// or a matching SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_*
	// environment variable — as opposed to left at its defaulted value
	// (EndpointConfigRequestBodyConfig.AllowAliases defaults to true, so the
	// merged struct is never the Go zero value even when the operator never
	// wrote the block — see EndpointConfigRequestBodyConfig's doc comment).
	// Populated by Load/LoadBytes via a provenance-only Viper pass mirroring
	// explicitLegacyListen, and consulted by validateNetworkEndpointConfig
	// to reject request_body.network.allow_endpoint_config: true combined
	// with an explicit endpoint_config block (#186). Unexported so it never
	// round-trips through mapstructure/YAML/JSON.
	explicitNetworkEndpointConfig bool

	// InsecureAcceptOpaqueBuildkitTunnels acknowledges opening POST /session,
	// POST /grpc, or a direct BuildKit Control-service method path. Both
	// endpoints are unversioned opaque hijacked streams: dockerd's embedded
	// BuildKit frontend/session bridge, still used by current Buildx (0.36.0)
	// even though Engine API 1.53 deprecated them. Unlike the bounded exec
	// escape hatch InsecureAllowBodyBlindWrites covers, these streams carry
	// secrets, SSH agent forwarding, and arbitrary file sync with no request
	// body sockguard can inspect or bound — so they get their own dedicated
	// acknowledgment rather than folding into insecure_allow_body_blind_writes.
	// Default false: a rule admitting either endpoint fails startup unless this
	// is set. Tecnativa GRPC=1/SESSION=1 compat vars still work (see
	// ApplyCompat) but log a deprecation warning naming this key. A single
	// global setting, not per-profile — see cmd/rules.go.
	//
	// Deprecated: request_body.buildkit (issue #185) now mediates both
	// endpoints with full per-message inspection instead of admitting them
	// wholesale. This flag stays functional — existing configs keep working —
	// but setting it to true logs a startup deprecation warning
	// (cmd/serve.go's warnIfOpaqueBuildkitTunnelDeprecated) steering operators
	// toward request_body.buildkit, and it will be removed in a future major
	// release. The two are mutually exclusive (see
	// validateBuildkitAckMutualExclusion in validate.go), so the warning only
	// ever fires for a config using this flag on its own.
	InsecureAcceptOpaqueBuildkitTunnels bool `mapstructure:"insecure_accept_opaque_buildkit_tunnels"`
}

// MarkLegacyListenExplicit records that the legacy listen.* block was set
// through a channel Load's provenance pass cannot see — currently the
// --listen-socket CLI flag, which is applied to an already-loaded Config in
// internal/cmd. Safe to call unconditionally; it only ever turns the flag on.
func (c *Config) MarkLegacyListenExplicit() {
	c.explicitLegacyListen = true
}

// ExplicitLegacyListen reports whether the legacy listen.* block was set
// explicitly, for tests and validation.
func (c *Config) ExplicitLegacyListen() bool {
	return c.explicitLegacyListen
}

// ExplicitNetworkEndpointConfig reports whether
// request_body.network.endpoint_config was set explicitly, for tests and
// validation (#186's allow_endpoint_config/endpoint_config mutual-exclusion
// check — see validateNetworkEndpointConfig).
func (c *Config) ExplicitNetworkEndpointConfig() bool {
	return c.explicitNetworkEndpointConfig
}

// ListenConfig configures a single proxy listener (unix socket or TCP).
type ListenConfig struct {
	Socket     string `mapstructure:"socket"`
	SocketMode string `mapstructure:"socket_mode"`
	Address    string `mapstructure:"address"`
	// InsecureAllowPlainTCP opts a non-loopback TCP listener into unencrypted
	// transport. A non-loopback plaintext listener requires this AND
	// InsecureAllowUnauthenticatedClients — two deliberate acknowledgments so
	// the dangerous mode cannot be reached by a single fat-fingered flag.
	InsecureAllowPlainTCP bool `mapstructure:"insecure_allow_plain_tcp"`
	// InsecureAllowUnauthenticatedClients is the second acknowledgment a
	// non-loopback plaintext listener requires: without mutual TLS any host
	// that can reach the port can impersonate a client.
	InsecureAllowUnauthenticatedClients bool            `mapstructure:"insecure_allow_unauthenticated_clients"`
	TLS                                 ListenTLSConfig `mapstructure:"tls"`
	// SocketUID and SocketGID optionally chown a freshly created unix socket
	// after bind. Pointers distinguish "omitted" from UID/GID 0. Only
	// meaningful when Socket is set. Combined with SocketMode they gate the
	// 0600 (default, no explicit ownership required) vs 0660 (requires
	// SocketGID) posture — see validateSocketOwnership.
	SocketUID *int `mapstructure:"socket_uid"`
	SocketGID *int `mapstructure:"socket_gid"`
}

// ListenerConfig is one entry in Config.Listeners: a named, independently
// scoped main (Docker-API) listener. See Config.EffectiveListeners.
type ListenerConfig struct {
	// Name identifies the listener for logs, metrics, health, audit, and
	// reload diagnostics. Must match ListenerNamePattern, be unique within
	// Listeners, and must not be AdminListenerName ("admin").
	Name         string `mapstructure:"name"`
	ListenConfig `mapstructure:",squash"`
	// AllowedProfiles scopes this listener to a subset of clients.profiles.
	// Required and non-empty on every explicit entry. The single-element
	// list [WildcardProfile] ("*") preserves the legacy global behavior:
	// every resolved profile, plus the unprofiled/default-policy path, is
	// admitted. A concrete list is an admission gate evaluated AFTER normal
	// profile resolution (certificate > unix peer > source IP > default):
	// an otherwise-valid client resolved to a profile outside this list is
	// denied with reason listener_profile_not_allowed, never retried
	// against a weaker selector.
	AllowedProfiles []string `mapstructure:"allowed_profiles"`
}

// ListenTLSConfig configures mutual TLS for TCP listeners.
type ListenTLSConfig struct {
	CertFile            string   `mapstructure:"cert_file"`
	KeyFile             string   `mapstructure:"key_file"`
	ClientCAFile        string   `mapstructure:"client_ca_file"`
	CommonNames         []string `mapstructure:"common_names"`
	DNSNames            []string `mapstructure:"dns_names"`
	IPAddresses         []string `mapstructure:"ip_addresses"`
	URISANs             []string `mapstructure:"uri_sans"`
	PublicKeySHA256Pins []string `mapstructure:"public_key_sha256_pins"`
}

// UpstreamConfig configures the upstream Docker daemon(s) sockguard proxies to.
//
// The legacy single-daemon shorthand is upstream.socket (a local unix socket).
// upstream.endpoints adds an ordered list of remote (TCP+TLS) or local daemons
// for the SAME logical daemon/swarm, health-checked with automatic failover to
// the first reachable endpoint. When endpoints is empty, socket is used. When
// endpoints is non-empty, it takes precedence and socket is ignored.
type UpstreamConfig struct {
	Socket string `mapstructure:"socket"`
	// RequestTimeout bounds the total lifetime of a single proxied upstream
	// request as a Go duration string (e.g. "30s"). ResponseHeaderTimeout only
	// caps the wait for response headers; a daemon that sends headers and then
	// hangs the body can still pin a request indefinitely. A non-disabled value
	// converts that hang into a fast 504 for ordinary finite requests.
	// Long-lived endpoints (/events, log/stats streams, image pull/build/push,
	// container export/get, container archive i.e. docker cp, and the blocking
	// /containers/{id}/wait) are exempt so the deadline never severs a
	// legitimately long response.
	//
	// Default is "60s" (changed from unlimited default prior to v1.5). Set
	// "off" to explicitly disable the deadline; the legacy empty string ("")
	// remains valid for backward compatibility with configs written before
	// "off" existed. Use RequestTimeoutDisabled to check either spelling — it
	// is the single source of truth validate.go and cmd/serve.go both consult.
	// Any other value must parse as a positive Go duration; 0 and negative
	// durations are validation errors.
	//
	// Caveat: SOCKGUARD_UPSTREAM_REQUEST_TIMEOUT="" (an explicitly empty env
	// var) is treated as UNSET by Viper and falls through to the "60s"
	// default rather than disabling it — only the literal "off" reliably
	// disables the deadline via environment variable. An explicit
	// request_timeout: "" in YAML does correctly disable it, since YAML
	// values bypass Viper's env-emptiness gate. Prefer "off" in both
	// channels.
	RequestTimeout string `mapstructure:"request_timeout"`
	// Endpoints is an ordered failover set. The first entry is the preferred
	// primary; later entries are tried when earlier ones fail their health
	// probe. Every endpoint MUST address the same logical daemon/swarm —
	// container IDs, exec sessions, and owner labels are daemon-local, so
	// failover only makes sense across redundant endpoints (a swarm VIP plus
	// its managers, an HA pair behind keepalived), not distinct daemons.
	Endpoints []UpstreamEndpoint `mapstructure:"endpoints"`
	// Failover tunes the active health-probe loop that drives endpoint
	// selection. Ignored unless endpoints is set.
	Failover UpstreamFailover `mapstructure:"failover"`
}

// RequestTimeoutDisabled reports whether the per-request upstream deadline is
// explicitly disabled: the canonical "off" sentinel or the legacy empty
// string, both of which mean "no deadline". Centralizing the check here
// means validate.go and cmd/serve.go read the same definition of "disabled"
// and cannot drift on it. Comparison is exact-case, matching the existing
// enum style elsewhere in config (log.level, response.deny_verbosity) — "OFF"
// or "Off" is not recognized and falls through to duration parsing, where it
// fails validation.
func (u UpstreamConfig) RequestTimeoutDisabled() bool {
	return u.RequestTimeout == "" || u.RequestTimeout == "off"
}

// UpstreamEndpoint is one daemon in an ordered failover set.
type UpstreamEndpoint struct {
	// Address is a Docker-style upstream address: a unix socket
	// ("unix:///var/run/docker.sock" or a bare path) or a remote daemon
	// ("tcp://host:2376").
	Address string `mapstructure:"address"`
	// TLS configures the client certificate, key, and CA used to dial a remote
	// daemon over TLS. Required for tcp:// endpoints unless an insecure opt-in
	// below is set. Meaningless for unix sockets.
	TLS UpstreamTLSConfig `mapstructure:"tls"`
	// InsecureAllowPlainTCP permits a tcp:// endpoint with no TLS material,
	// exposing the Docker API in plaintext to anyone on the path. Mirrors the
	// listener-side insecure_allow_plain_tcp acknowledgement.
	InsecureAllowPlainTCP bool `mapstructure:"insecure_allow_plain_tcp"`
	// InsecureSkipTLSVerify disables verification of the remote daemon's server
	// certificate (self-signed homelab daemons). Dangerous in production: it
	// defeats authentication of the upstream.
	InsecureSkipTLSVerify bool `mapstructure:"insecure_skip_tls_verify"`
}

// UpstreamTLSConfig is the client-side TLS material for dialing a remote daemon.
type UpstreamTLSConfig struct {
	// CAFile verifies the remote daemon's server certificate. Empty uses the
	// system roots.
	CAFile string `mapstructure:"ca_file"`
	// CertFile and KeyFile present a client certificate to the daemon (mutual
	// TLS). Both set together or both empty.
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	// ServerName overrides the SNI / verified hostname. Empty derives it from
	// the address host.
	ServerName string `mapstructure:"server_name"`
}

// UpstreamFailover tunes the endpoint health-probe loop.
type UpstreamFailover struct {
	// HealthInterval is the active probe period (Go duration, e.g. "5s"). Empty
	// uses the resolver default. A negative duration disables continuous
	// probing (a single startup probe still runs).
	HealthInterval string `mapstructure:"health_interval"`
	// HealthTimeout bounds each probe (Go duration, e.g. "2s"). Empty uses the
	// resolver default.
	HealthTimeout string `mapstructure:"health_timeout"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level     string         `mapstructure:"level"`
	Format    string         `mapstructure:"format"`
	Output    string         `mapstructure:"output"`
	AccessLog bool           `mapstructure:"access_log"`
	Audit     AuditLogConfig `mapstructure:"audit"`
}

// AuditLogConfig configures the dedicated audit-event pipeline.
type AuditLogConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Format  string `mapstructure:"format"`
	Output  string `mapstructure:"output"`
}

// ResponseConfig configures HTTP responses returned by sockguard itself.
type ResponseConfig struct {
	DenyVerbosity         string   `mapstructure:"deny_verbosity"`
	RedactContainerEnv    bool     `mapstructure:"redact_container_env"`
	RedactMountPaths      bool     `mapstructure:"redact_mount_paths"`
	RedactNetworkTopology bool     `mapstructure:"redact_network_topology"`
	RedactSensitiveData   bool     `mapstructure:"redact_sensitive_data"`
	VisibleResourceLabels []string `mapstructure:"visible_resource_labels"`
	// NamePatterns is a list of glob patterns matched against container Names[0]
	// (leading "/" stripped) and image RepoTags short names. Resources whose
	// name does not match at least one pattern are hidden. Empty means no
	// name-based filtering.
	NamePatterns []string `mapstructure:"name_patterns"`
	// ImagePatterns is a list of glob patterns matched against container Image
	// field and image RepoTags full references. Resources whose image reference
	// does not match at least one pattern are hidden. Empty means no image-based
	// filtering.
	ImagePatterns []string `mapstructure:"image_patterns"`
	// RedactHostTopology redacts GET /info fields that fingerprint the host's
	// container runtime plumbing: Containerd, FirewallBackend,
	// DiscoveredDevices, and NRI. Separate from RedactNetworkTopology (which
	// covers swarm/network addressing) — this is host-process/device topology.
	// Default false; hardened presets enable it.
	RedactHostTopology bool `mapstructure:"redact_host_topology"`
	// AllowAttestationStatements permits GET /images/{name}/attestations
	// responses that include the full in-toto statement content
	// (?statement=true). Engine API 1.53 added this endpoint; broad allow
	// rules such as "/images/**" (portainer.yaml) admit it at the rule-engine
	// layer without knowing it exists, so this response-layer gate closes
	// that gap independent of the rule set. Default false.
	AllowAttestationStatements bool `mapstructure:"allow_attestation_statements"`
}

// RequestBodyConfig configures request-body inspection policies.
type RequestBodyConfig struct {
	ContainerCreate       ContainerCreateRequestBodyConfig       `mapstructure:"container_create"`
	LibpodContainerCreate LibpodContainerCreateRequestBodyConfig `mapstructure:"libpod_container_create"`
	// Exec configures body inspection for BOTH the Docker-compat exec
	// create/start endpoints AND their libpod equivalents
	// (POST /libpod/containers/*/exec, POST /libpod/exec/*/start). There is
	// deliberately no separate libpod_exec block: libpod exec bodies are
	// decoded by the identical Go handler Docker-compat exec bodies are
	// (confirmed against Podman's own route table, see exec.go), so a split
	// config would just be a configure-one-forget-other trap (#148 design
	// doc, decision C3).
	Exec             ExecRequestBodyConfig             `mapstructure:"exec"`
	ImagePull        ImagePullRequestBodyConfig        `mapstructure:"image_pull"`
	Build            BuildRequestBodyConfig            `mapstructure:"build"`
	ContainerUpdate  ContainerUpdateRequestBodyConfig  `mapstructure:"container_update"`
	ContainerArchive ContainerArchiveRequestBodyConfig `mapstructure:"container_archive"`
	ImageLoad        ImageLoadRequestBodyConfig        `mapstructure:"image_load"`
	Volume           VolumeRequestBodyConfig           `mapstructure:"volume"`
	Network          NetworkRequestBodyConfig          `mapstructure:"network"`
	Secret           SecretRequestBodyConfig           `mapstructure:"secret"`
	Config           ConfigRequestBodyConfig           `mapstructure:"config"`
	Service          ServiceRequestBodyConfig          `mapstructure:"service"`
	Swarm            SwarmRequestBodyConfig            `mapstructure:"swarm"`
	Node             NodeRequestBodyConfig             `mapstructure:"node"`
	Plugin           PluginRequestBodyConfig           `mapstructure:"plugin"`
	// Buildkit configures the (currently deny-only — see issue #185 phase 1)
	// BuildKit gRPC mediation policy for POST /session and POST /grpc. An
	// absent block denies both endpoints internally even when an outer HTTP
	// rule allows them — there is no separate enabled toggle to drift out of
	// sync with the sub-blocks below. See BuildkitRequestBodyConfig's doc
	// comment for the full posture and validateBuildkitAckMutualExclusion in
	// validate.go for its interaction with InsecureAcceptOpaqueBuildkitTunnels.
	Buildkit BuildkitRequestBodyConfig `mapstructure:"buildkit"`
	// LibpodPodCreate configures body inspection for POST /libpod/pods/create
	// (Podman's native pod-create endpoint; pods have no Docker-compat
	// equivalent, so this is its own top-level key rather than reusing
	// container_create). #148.
	LibpodPodCreate LibpodPodCreateRequestBodyConfig `mapstructure:"libpod_pod_create"`
	// LibpodVolume, LibpodNetwork, and LibpodSecret configure body/query
	// inspection for the libpod-native volume/network/secret create
	// endpoints (POST /libpod/volumes/create, /libpod/networks/create,
	// /libpod/secrets/create). They reuse the EXISTING
	// Volume/Network/SecretRequestBodyConfig types — libpod's wire shapes
	// for these resources differ from Docker's (see libpod_volume.go,
	// libpod_network.go, libpod_secret.go for the decode structs and which
	// fields have no libpod analog), but the policy knobs an operator
	// reasons about are the same, so a second parallel type would only add
	// schema noise. #148.
	LibpodVolume  VolumeRequestBodyConfig  `mapstructure:"libpod_volume"`
	LibpodNetwork NetworkRequestBodyConfig `mapstructure:"libpod_network"`
	LibpodSecret  SecretRequestBodyConfig  `mapstructure:"libpod_secret"`
}

// LibpodPodCreateRequestBodyConfig configures body inspection for
// POST /libpod/pods/create. Cross-owner namespace-sharing checks and label
// injection for ownership are deferred to a follow-up PR (#148 design doc
// C6) — this config only covers the raw request-body gates below.
type LibpodPodCreateRequestBodyConfig struct {
	// AllowHostNetwork permits a pod-level NetNS of {"nsmode":"host"} — the
	// pod (and every container that joins it) shares the host network
	// namespace. Mirrors container_create.allow_host_network's posture for
	// the pod-wide equivalent. Default false.
	AllowHostNetwork bool `mapstructure:"allow_host_network"`
	// AllowSharedPIDNamespace permits "pid" in the pod's shared_namespaces
	// list, letting every container in the pod see (and signal) every other
	// container's processes — the pod-wide analog of container_create's
	// PidMode: host, scoped to the pod rather than the host. Default false.
	AllowSharedPIDNamespace bool `mapstructure:"allow_shared_pid_namespace"`
	// AllowedInfraImageRegistries allowlists the registry the pod's
	// infra_image reference resolves to, reusing the same host-allowlist
	// shape as image_pull.allowed_registries. An empty infra_image (Podman's
	// built-in default pause image) is always allowed regardless of this
	// list. Default empty: any explicit infra_image is denied.
	AllowedInfraImageRegistries []string `mapstructure:"allowed_infra_image_registries"`
}

// ContainerCreateRequestBodyConfig configures body inspection for
// POST /containers/create requests.
type ContainerCreateRequestBodyConfig struct {
	AllowPrivileged          bool                   `mapstructure:"allow_privileged"`
	AllowHostNetwork         bool                   `mapstructure:"allow_host_network"`
	AllowHostPID             bool                   `mapstructure:"allow_host_pid"`
	AllowHostIPC             bool                   `mapstructure:"allow_host_ipc"`
	AllowedBindMounts        []string               `mapstructure:"allowed_bind_mounts"`
	AllowAllDevices          bool                   `mapstructure:"allow_all_devices"`
	AllowedDevices           []string               `mapstructure:"allowed_devices"`
	AllowDeviceRequests      bool                   `mapstructure:"allow_device_requests"`
	AllowedDeviceRequests    []AllowedDeviceRequest `mapstructure:"allowed_device_requests"`
	AllowDeviceCgroupRules   bool                   `mapstructure:"allow_device_cgroup_rules"`
	AllowedDeviceCgroupRules []string               `mapstructure:"allowed_device_cgroup_rules"`

	RequireNoNewPrivileges     bool     `mapstructure:"require_no_new_privileges"`
	RequireNonRootUser         bool     `mapstructure:"require_non_root_user"`
	RequireReadonlyRootfs      bool     `mapstructure:"require_readonly_rootfs"`
	RequireDropAllCapabilities bool     `mapstructure:"require_drop_all_capabilities"`
	AllowAllCapabilities       bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities        []string `mapstructure:"allowed_capabilities"`
	RequireMemoryLimit         bool     `mapstructure:"require_memory_limit"`
	RequireCPULimit            bool     `mapstructure:"require_cpu_limit"`
	// RequireCPULimitHard, unlike RequireCPULimit, only accepts a genuine
	// CPU-time cap: HostConfig.NanoCpus or CpuQuota. CpuShares (and CpuPeriod
	// set without CpuQuota) only set relative priority under contention — an
	// uncontended host still lets the container consume every CPU it can
	// schedule onto — so neither satisfies this stricter check. Independent
	// of RequireCPULimit: enabling this alone is sufficient; you do not also
	// need RequireCPULimit: true. Default false (opt-in).
	RequireCPULimitHard     bool     `mapstructure:"require_cpu_limit_hard"`
	RequirePidsLimit        bool     `mapstructure:"require_pids_limit"`
	AllowedSeccompProfiles  []string `mapstructure:"allowed_seccomp_profiles"`
	DenyUnconfinedSeccomp   bool     `mapstructure:"deny_unconfined_seccomp"`
	AllowedAppArmorProfiles []string `mapstructure:"allowed_apparmor_profiles"`
	DenyUnconfinedAppArmor  bool     `mapstructure:"deny_unconfined_apparmor"`
	AllowHostUserNS         bool     `mapstructure:"allow_host_userns"`
	AllowHostCgroupNS       bool     `mapstructure:"allow_host_cgroupns"`
	// RestrictNamespaceSharing gates HostConfig.NetworkMode/PidMode/IpcMode/
	// UsernsMode values of the form "container:<ref>" (join another
	// container's namespace) against AllowedNamespaceSharingContainers.
	// Default false: container:<ref> values continue to pass through
	// unchecked exactly as before this knob existed — AllowHostNetwork/PID/
	// IPC/UserNS above only ever match the literal "host" value and still
	// only do; this is an independent, orthogonal gate.
	RestrictNamespaceSharing bool `mapstructure:"restrict_namespace_sharing"`
	// AllowedNamespaceSharingContainers allowlists the container:<ref>
	// targets permitted when RestrictNamespaceSharing is true. Only
	// consulted when RestrictNamespaceSharing is true; empty denies every
	// container: ref.
	AllowedNamespaceSharingContainers []string `mapstructure:"allowed_namespace_sharing_containers"`
	// DenyNamespacePathMode denies HostConfig.NetworkMode values with an
	// "ns:" prefix (case-insensitive): Docker's raw host-namespace-file
	// attachment form, which bypasses the "host" literal check entirely.
	// Default false.
	DenyNamespacePathMode     bool             `mapstructure:"deny_namespace_path_mode"`
	AllowSysctls              bool             `mapstructure:"allow_sysctls"`
	RequiredLabels            []string         `mapstructure:"required_labels"`
	AllowedRuntimes           []string         `mapstructure:"allowed_runtimes"`
	ImageTrust                ImageTrustConfig `mapstructure:"image_trust"`
	DenySelinuxDisable        bool             `mapstructure:"deny_selinux_disable"`
	DenySelinuxLabelOverride  bool             `mapstructure:"deny_selinux_label_override"`
	DenyUnconfinedSystemPaths bool             `mapstructure:"deny_unconfined_system_paths"`
	// AllowTmpfsPrivilegedOptions permits tmpfs mount options that re-enable
	// exec/dev/suid semantics inside the tmpfs (HostConfig.Mounts[].
	// TmpfsOptions.Options, Engine API 1.46+): "exec", "dev", "suid". Docker's
	// own tmpfs default already sets noexec/nodev/nosuid; a client-supplied
	// Options entry can override that default per-mount, so it is denied
	// unless explicitly allowed. Default false.
	AllowTmpfsPrivilegedOptions bool `mapstructure:"allow_tmpfs_privileged_options"`
}

// LibpodContainerCreateRequestBodyConfig configures body inspection for
// POST /libpod/containers/create requests — Podman's native SpecGenerator
// create endpoint, distinct from the Docker-compat container_create block
// above. Field names mirror ContainerCreateRequestBodyConfig where the
// underlying semantics map onto a libpod equivalent (see design doc #148),
// so operator knowledge transfers between the two surfaces; two fields
// (AllowSystemdMode, AllowCustomIDMappings) have no Docker analog.
type LibpodContainerCreateRequestBodyConfig struct {
	AllowPrivileged   bool     `mapstructure:"allow_privileged"`
	AllowHostNetwork  bool     `mapstructure:"allow_host_network"`
	AllowHostPID      bool     `mapstructure:"allow_host_pid"`
	AllowHostIPC      bool     `mapstructure:"allow_host_ipc"`
	AllowHostUserNS   bool     `mapstructure:"allow_host_userns"`
	AllowedBindMounts []string `mapstructure:"allowed_bind_mounts"`
	AllowAllDevices   bool     `mapstructure:"allow_all_devices"`
	AllowedDevices    []string `mapstructure:"allowed_devices"`

	// RestrictNamespaceSharing/AllowedNamespaceSharingContainers gate
	// netns/pidns/ipcns/userns/utsns objects of the form
	// {"nsmode":"container","value":"<ref>"}, mirroring
	// ContainerCreateRequestBodyConfig.RestrictNamespaceSharing.
	RestrictNamespaceSharing          bool     `mapstructure:"restrict_namespace_sharing"`
	AllowedNamespaceSharingContainers []string `mapstructure:"allowed_namespace_sharing_containers"`

	AllowAllCapabilities   bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities    []string `mapstructure:"allowed_capabilities"`
	AllowedSeccompProfiles []string `mapstructure:"allowed_seccomp_profiles"`
	DenyUnconfinedSeccomp  bool     `mapstructure:"deny_unconfined_seccomp"`

	AllowedAppArmorProfiles []string `mapstructure:"allowed_apparmor_profiles"`
	DenyUnconfinedAppArmor  bool     `mapstructure:"deny_unconfined_apparmor"`

	DenySelinuxDisable bool `mapstructure:"deny_selinux_disable"`

	RequireNonRootUser    bool `mapstructure:"require_non_root_user"`
	RequireReadonlyRootfs bool `mapstructure:"require_readonly_rootfs"`
	RequireMemoryLimit    bool `mapstructure:"require_memory_limit"`
	RequireCPULimit       bool `mapstructure:"require_cpu_limit"`
	RequireCPULimitHard   bool `mapstructure:"require_cpu_limit_hard"`
	RequirePidsLimit      bool `mapstructure:"require_pids_limit"`

	AllowSysctls bool `mapstructure:"allow_sysctls"`

	ImageTrust ImageTrustConfig `mapstructure:"image_trust"`

	// AllowSystemdMode permits a "systemd" value other than "false"
	// (SpecGenerator's own default, sent even when --systemd was never
	// passed). No Docker Engine API analog. Default false: fail-closed.
	AllowSystemdMode bool `mapstructure:"allow_systemd_mode"`

	// AllowCustomIDMappings permits a non-default idmappings.UIDMap/GIDMap
	// or --userns=auto. A blunt gate for v1.6; default false.
	AllowCustomIDMappings bool `mapstructure:"allow_custom_id_mappings"`
}

// ImageTrustConfig configures cosign signature verification for images
// referenced in POST /containers/create.
type ImageTrustConfig struct {
	// Mode controls enforcement: off | warn | enforce. Default: off.
	Mode string `mapstructure:"mode"`
	// AllowedSigningKeys lists PEM-encoded public keys that are trusted to
	// sign images. Keyed verification is attempted before keyless.
	AllowedSigningKeys []SigningKeyConfig `mapstructure:"allowed_signing_keys"`
	// AllowedKeyless lists Fulcio-issued OIDC identity patterns. Each entry
	// must specify an exact issuer URL and a regex against the cert's SAN.
	AllowedKeyless []KeylessConfig `mapstructure:"allowed_keyless"`
	// RequireRekorInclusion requires a Rekor tlog inclusion proof for keyless
	// verification. Default true.
	RequireRekorInclusion bool `mapstructure:"require_rekor_inclusion"`
	// VerifyTimeout overrides the default 10s per-verification timeout.
	VerifyTimeout string `mapstructure:"verify_timeout"`
}

// SigningKeyConfig is one entry in image_trust.allowed_signing_keys.
type SigningKeyConfig struct {
	// PEM is the PEM-encoded public key (ECDSA, RSA, or ed25519).
	PEM string `mapstructure:"pem"`
}

// KeylessConfig is one entry in image_trust.allowed_keyless.
type KeylessConfig struct {
	// Issuer is the exact OIDC issuer URL to match against the Fulcio cert.
	Issuer string `mapstructure:"issuer"`
	// SubjectPattern is a Go regexp matched against the cert's SAN.
	SubjectPattern string `mapstructure:"subject_pattern"`
}

// AllowedDeviceRequest is a single entry in the allowed_device_requests allowlist.
// Driver is required and must exactly match the request's Driver field (after
// lowercasing). AllowedCapabilities is a list of capability-sets; the request's
// capability sets must each be a subset of at least one allowlisted set.
// MaxCount, when non-nil, bounds the request Count; -1 means "all" and is only
// permitted when MaxCount is also -1.
type AllowedDeviceRequest struct {
	Driver              string     `mapstructure:"driver"`
	AllowedCapabilities [][]string `mapstructure:"allowed_capabilities"`
	MaxCount            *int       `mapstructure:"max_count"`
}

// ExecRequestBodyConfig configures body inspection for exec creation/start.
type ExecRequestBodyConfig struct {
	AllowPrivileged bool       `mapstructure:"allow_privileged"`
	AllowRootUser   bool       `mapstructure:"allow_root_user"`
	AllowedCommands [][]string `mapstructure:"allowed_commands"`
	// AllowedEnvVars, when non-empty, restricts the exec-create Env array to
	// these variable names — matched by name only (the substring before the
	// first "="), exact string comparison, case-sensitive; the value is
	// never inspected. Default empty means no restriction at all: unlike
	// AllowedCommands (whose empty default denies every exec), an empty
	// AllowedEnvVars is a deliberate zero-behavior-change default so
	// enabling exec command allowlisting does not also silently start
	// denying every exec session's environment.
	AllowedEnvVars []string `mapstructure:"allowed_env_vars"`
	// DeniedEnvVars variable names are always blocked and are checked
	// before AllowedEnvVars, so a name present in both lists is denied
	// (fail closed on operator misconfiguration). Default empty means
	// nothing is blocked.
	DeniedEnvVars []string `mapstructure:"denied_env_vars"`
	// AllowedEnvValues optionally pins selected exec environment entries to
	// exact NAME=VALUE strings. A variable name represented here is denied
	// unless the complete entry exactly matches one of its configured values;
	// values are compared but never included in denial reasons or logs. Names
	// not represented here continue to follow AllowedEnvVars/DeniedEnvVars.
	AllowedEnvValues []string `mapstructure:"allowed_env_values"`
}

// ImagePullRequestBodyConfig configures inspection for POST /images/create.
type ImagePullRequestBodyConfig struct {
	AllowImports       bool     `mapstructure:"allow_imports"`
	AllowAllRegistries bool     `mapstructure:"allow_all_registries"`
	AllowOfficial      bool     `mapstructure:"allow_official"`
	AllowedRegistries  []string `mapstructure:"allowed_registries"`
}

// BuildRequestBodyConfig configures inspection for POST /build.
type BuildRequestBodyConfig struct {
	AllowRemoteContext   bool `mapstructure:"allow_remote_context"`
	AllowHostNetwork     bool `mapstructure:"allow_host_network"`
	AllowRunInstructions bool `mapstructure:"allow_run_instructions"`
}

// ContainerUpdateRequestBodyConfig configures inspection for
// POST /containers/*/update.
type ContainerUpdateRequestBodyConfig struct {
	AllowPrivileged      bool `mapstructure:"allow_privileged"`
	AllowAllDevices      bool `mapstructure:"allow_all_devices"`
	AllowCapabilities    bool `mapstructure:"allow_capabilities"`
	AllowResourceUpdates bool `mapstructure:"allow_resource_updates"`
	AllowRestartPolicy   bool `mapstructure:"allow_restart_policy"`

	// RequireMemoryLimit/RequireCPULimit/RequireCPULimitHard/RequirePidsLimit
	// revalidate the container's EFFECTIVE resource state (current values
	// merged with the request's explicit fields, using Docker's own update
	// merge semantics) against the same requirements container_create.require_*
	// enforces at create time. Names are copied verbatim from
	// ContainerCreateRequestBodyConfig so operator knowledge transfers. All
	// default false (opt-in, v1.x-safe).
	//
	// Evaluated ONLY when AllowResourceUpdates is true: when it is false, the
	// existing blanket deny of every resource-control field already preserves
	// the create-time guarantee, so there is nothing for these flags to add.
	// Enabling any of these while AllowResourceUpdates is false is accepted
	// (not a config error) but inert; sockguard logs a startup/reload warning
	// since it is very likely operator confusion.
	//
	// Ratchet behavior: because the check runs against the merged EFFECTIVE
	// state rather than only the fields the request touches, a container that
	// predates a newly-enabled requirement (e.g. one created with no memory
	// limit) will have its NEXT guarded update denied until a compliant value
	// is supplied — even an update that does not itself touch resources. See
	// the migration note in docs/content/docs/configuration.mdx.
	RequireMemoryLimit  bool `mapstructure:"require_memory_limit"`
	RequireCPULimit     bool `mapstructure:"require_cpu_limit"`
	RequireCPULimitHard bool `mapstructure:"require_cpu_limit_hard"`
	RequirePidsLimit    bool `mapstructure:"require_pids_limit"`
}

// ContainerArchiveRequestBodyConfig configures inspection for
// PUT /containers/*/archive.
type ContainerArchiveRequestBodyConfig struct {
	AllowedPaths       []string `mapstructure:"allowed_paths"`
	AllowSetID         bool     `mapstructure:"allow_setid"`
	AllowDeviceNodes   bool     `mapstructure:"allow_device_nodes"`
	AllowEscapingLinks bool     `mapstructure:"allow_escaping_links"`
}

// ImageLoadRequestBodyConfig configures inspection for POST /images/load.
type ImageLoadRequestBodyConfig struct {
	AllowAllRegistries bool     `mapstructure:"allow_all_registries"`
	AllowOfficial      bool     `mapstructure:"allow_official"`
	AllowedRegistries  []string `mapstructure:"allowed_registries"`
	AllowUntagged      bool     `mapstructure:"allow_untagged"`
}

// VolumeRequestBodyConfig configures inspection for POST /volumes/create.
type VolumeRequestBodyConfig struct {
	AllowCustomDrivers bool `mapstructure:"allow_custom_drivers"`
	AllowDriverOpts    bool `mapstructure:"allow_driver_opts"`
}

// NetworkRequestBodyConfig configures inspection for network write endpoints.
type NetworkRequestBodyConfig struct {
	AllowCustomDrivers     bool `mapstructure:"allow_custom_drivers"`
	AllowSwarmScope        bool `mapstructure:"allow_swarm_scope"`
	AllowIngress           bool `mapstructure:"allow_ingress"`
	AllowAttachable        bool `mapstructure:"allow_attachable"`
	AllowConfigOnly        bool `mapstructure:"allow_config_only"`
	AllowConfigFrom        bool `mapstructure:"allow_config_from"`
	AllowCustomIPAMDrivers bool `mapstructure:"allow_custom_ipam_drivers"`
	AllowCustomIPAMConfig  bool `mapstructure:"allow_custom_ipam_config"`
	AllowIPAMOptions       bool `mapstructure:"allow_ipam_options"`
	AllowDriverOptions     bool `mapstructure:"allow_driver_options"`
	AllowEndpointConfig    bool `mapstructure:"allow_endpoint_config"`
	// EndpointConfig narrows allow_endpoint_config into independent per-field
	// gates (#186) — see EndpointConfigRequestBodyConfig's doc comment for
	// the field mapping and precedence rules. Only consulted when
	// allow_endpoint_config is false/unset; setting both is a config
	// validation error (validateNetworkEndpointConfig). Has no libpod analog
	// — never consulted by the libpod_network inspector, see libpod_network.go.
	EndpointConfig       EndpointConfigRequestBodyConfig `mapstructure:"endpoint_config"`
	AllowDisconnectForce bool                            `mapstructure:"allow_disconnect_force"`
	// AllowDisableIPv4 permits POST /networks/create with EnableIPv4 explicitly
	// false (Engine API 1.48+). Docker defaults EnableIPv4 to true (unset and
	// true both pass); a client-set false disables IPv4 addressing entirely,
	// an unusual and rarely-intended posture, so it requires this opt-in.
	// Default false.
	AllowDisableIPv4 bool `mapstructure:"allow_disable_ipv4"`
}

// EndpointConfigRequestBodyConfig configures granular per-field admission for
// Docker's EndpointSettings object — the payload carried by both
// POST /networks/*/connect's EndpointConfig and POST /containers/create's
// NetworkingConfig.EndpointsConfig entries (request_body.network's
// allow_endpoint_config governs both, see filter_options.go's cross-wire).
//
// Precedence (#186): request_body.network.allow_endpoint_config: true is the
// legacy whole-object escape hatch and, when set, admits every field
// unchanged — this block is not consulted at all in that case, and setting
// both is rejected at config-load time (validateNetworkEndpointConfig) to
// avoid silent ambiguity. When allow_endpoint_config is false/unset, each
// field below gates independently. EndpointSettings fields with no gate here
// — Links (joining another container's linked alias namespace) and
// DriverOpts — have no individual escape hatch under the granular form:
// they are always denied, fail-closed, unless allow_endpoint_config: true is
// used instead.
type EndpointConfigRequestBodyConfig struct {
	// AllowStaticAddressing permits IPAMConfig.IPv4Address/IPv6Address and the
	// deprecated top-level Gateway/IPAddress/IPPrefixLen/IPv6Gateway/
	// GlobalIPv6Address/GlobalIPv6PrefixLen fields. Default false.
	AllowStaticAddressing bool `mapstructure:"allow_static_addressing"`
	// AllowLinkLocalIPs permits IPAMConfig.LinkLocalIPs, independent of
	// AllowStaticAddressing. Default false.
	AllowLinkLocalIPs bool `mapstructure:"allow_link_local_ips"`
	// AllowMACPinning permits MacAddress — shared by network connect's
	// EndpointConfig and container-create's deprecated top-level MacAddress
	// field. Default false.
	AllowMACPinning bool `mapstructure:"allow_mac_pinning"`
	// AllowGwPriority permits GwPriority (Engine API 1.55+, which network
	// provides the container's default gateway when attached to more than
	// one). Default false.
	AllowGwPriority bool `mapstructure:"allow_gw_priority"`
	// AllowAliases permits Aliases. Default true: this reproduces
	// allow_endpoint_config's long-standing behavior of never gating Aliases
	// at all — Docker Compose sets Aliases: [serviceName] on every endpoint
	// it creates, so denying them by default would break every multi-network
	// Compose recreate. Set explicitly to false to deny Aliases under the
	// granular form; there is no equivalent opt-out under
	// allow_endpoint_config: true, which always admits Aliases.
	AllowAliases bool `mapstructure:"allow_aliases"`
}

// SecretRequestBodyConfig configures inspection for POST /secrets/create.
type SecretRequestBodyConfig struct {
	AllowCustomDrivers   bool `mapstructure:"allow_custom_drivers"`
	AllowTemplateDrivers bool `mapstructure:"allow_template_drivers"`
}

// ConfigRequestBodyConfig configures inspection for POST /configs/create.
type ConfigRequestBodyConfig struct {
	AllowCustomDrivers   bool `mapstructure:"allow_custom_drivers"`
	AllowTemplateDrivers bool `mapstructure:"allow_template_drivers"`
}

// ServiceRequestBodyConfig configures inspection for service create/update.
type ServiceRequestBodyConfig struct {
	AllowHostNetwork           bool     `mapstructure:"allow_host_network"`
	AllowedBindMounts          []string `mapstructure:"allowed_bind_mounts"`
	AllowAllRegistries         bool     `mapstructure:"allow_all_registries"`
	AllowOfficial              bool     `mapstructure:"allow_official"`
	AllowedRegistries          []string `mapstructure:"allowed_registries"`
	AllowAllCapabilities       bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities        []string `mapstructure:"allowed_capabilities"`
	AllowSysctls               bool     `mapstructure:"allow_sysctls"`
	RequireNonRootUser         bool     `mapstructure:"require_non_root_user"`
	RequireNoNewPrivileges     bool     `mapstructure:"require_no_new_privileges"`
	RequireReadonlyRootfs      bool     `mapstructure:"require_readonly_rootfs"`
	RequireDropAllCapabilities bool     `mapstructure:"require_drop_all_capabilities"`
	// DenyUnconfinedSeccomp denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode is "unconfined". Default false (opt-in).
	DenyUnconfinedSeccomp bool `mapstructure:"deny_unconfined_seccomp"`
	// DenyCustomSeccompProfiles denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode is "custom". A "custom" profile can
	// encode an allow-everything policy equivalent to "unconfined"; enable this
	// alongside deny_unconfined_seccomp for full seccomp confinement enforcement.
	// Default false (opt-in).
	DenyCustomSeccompProfiles bool `mapstructure:"deny_custom_seccomp_profiles"`
	// DenyUnconfinedAppArmor denies service create/update when
	// ContainerSpec.Privileges.AppArmor.Mode is "disabled" (the swarm equivalent
	// of "unconfined" AppArmor). Default false (opt-in).
	DenyUnconfinedAppArmor bool `mapstructure:"deny_unconfined_apparmor"`
	// DenySelinuxDisable denies service create/update when
	// ContainerSpec.Privileges.SELinuxContext.Disable is true — the swarm
	// equivalent of the container-create deny_selinux_disable. Default false (opt-in).
	DenySelinuxDisable bool `mapstructure:"deny_selinux_disable"`
	// DenySelinuxLabelOverride denies service create/update that customizes the
	// SELinux context via ContainerSpec.Privileges.SELinuxContext.{User,Role,Type,
	// Level} — the swarm equivalent of container-create deny_selinux_label_override.
	// Default false (opt-in).
	DenySelinuxLabelOverride bool             `mapstructure:"deny_selinux_label_override"`
	ImageTrust               ImageTrustConfig `mapstructure:"image_trust"`

	// RequireCPULimit / RequireCPULimitHard require
	// TaskTemplate.Resources.Limits.NanoCPUs to be positive on service create,
	// ordinary update, and any spec that could become active via rollback
	// (manual ?rollback=previous or an automatic UpdateConfig.FailureAction:
	// rollback). Scope is deliberately CPU-only, matching the container-create
	// CPU-limit parity this closes; service memory/PIDs parity is deferred.
	// Swarm's TaskTemplate.Resources.Limits has no CpuShares/CpuQuota-style
	// soft/hard split the way containers do, so both flags collapse to the
	// same NanoCPUs>0 predicate — kept as two knobs for schema parity with
	// container_create/container_update so a policy can be mirrored field-name
	// for field-name. RequireCPULimitHard alone is sufficient; it does not
	// require RequireCPULimit. Both default false (opt-in).
	RequireCPULimit     bool `mapstructure:"require_cpu_limit"`
	RequireCPULimitHard bool `mapstructure:"require_cpu_limit_hard"`
}

// SwarmRequestBodyConfig configures inspection for swarm writes.
type SwarmRequestBodyConfig struct {
	AllowForceNewCluster          bool     `mapstructure:"allow_force_new_cluster"`
	AllowExternalCA               bool     `mapstructure:"allow_external_ca"`
	AllowedJoinRemoteAddrs        []string `mapstructure:"allowed_join_remote_addrs"`
	AllowTokenRotation            bool     `mapstructure:"allow_token_rotation"`
	AllowManagerUnlockKeyRotation bool     `mapstructure:"allow_manager_unlock_key_rotation"`
	AllowAutoLockManagers         bool     `mapstructure:"allow_auto_lock_managers"`
	AllowSigningCAUpdate          bool     `mapstructure:"allow_signing_ca_update"`
	AllowUnlock                   bool     `mapstructure:"allow_unlock"`
}

// NodeRequestBodyConfig configures inspection for POST /nodes/*/update.
type NodeRequestBodyConfig struct {
	AllowNameChange         bool     `mapstructure:"allow_name_change"`
	AllowRoleChange         bool     `mapstructure:"allow_role_change"`
	AllowAvailabilityChange bool     `mapstructure:"allow_availability_change"`
	AllowLabelMutation      bool     `mapstructure:"allow_label_mutation"`
	AllowedLabelKeys        []string `mapstructure:"allowed_label_keys"`
}

// PluginRequestBodyConfig configures inspection for plugin write endpoints.
type PluginRequestBodyConfig struct {
	AllowHostNetwork      bool     `mapstructure:"allow_host_network"`
	AllowHostIPC          bool     `mapstructure:"allow_host_ipc"`
	AllowHostPID          bool     `mapstructure:"allow_host_pid"`
	AllowAllDevices       bool     `mapstructure:"allow_all_devices"`
	AllowedBindMounts     []string `mapstructure:"allowed_bind_mounts"`
	AllowedDevices        []string `mapstructure:"allowed_devices"`
	AllowAllCapabilities  bool     `mapstructure:"allow_all_capabilities"`
	AllowedCapabilities   []string `mapstructure:"allowed_capabilities"`
	AllowAllRegistries    bool     `mapstructure:"allow_all_registries"`
	AllowOfficial         bool     `mapstructure:"allow_official"`
	AllowedRegistries     []string `mapstructure:"allowed_registries"`
	AllowedSetEnvPrefixes []string `mapstructure:"allowed_set_env_prefixes"`
}

// BuildkitRequestBodyConfig configures sockguard's BuildKit gRPC mediation
// policy (issue #185) for the two opaque tunnel endpoints POST /session and
// POST /grpc. As of phase 1 this is schema and policy ONLY — there is no
// runtime mediator yet, so a configured block still results in both
// endpoints being denied at request time (see
// filter.buildkitPolicy.inspect); the policy this struct describes is what
// later phases will actually enforce once the h2c-terminating mediator
// exists.
//
// Presence, not an "enabled" flag, is what matters: an absent block (the
// Go zero value, identical to what a config that never mentions "buildkit:"
// at all decodes to) denies /session and /grpc internally even when an
// outer HTTP rule allows them. Every leaf below follows the same
// "empty/false allowed_* = deny" convention as the rest of RequestBodyConfig
// — see e.g. ImagePullRequestBodyConfig.AllowedRegistries.
//
// Works at the top level (RequestBodyConfig here) and per client profile
// (ClientProfileConfig.RequestBody carries the identical type) exactly like
// every other request_body.* block; there is no merge between the two —
// see ClientProfileConfig's doc comment.
type BuildkitRequestBodyConfig struct {
	// Control gates moby.buildkit.v1.Control, reached over POST /grpc.
	Control BuildkitControlRequestBodyConfig `mapstructure:"control"`
	// Session gates the services buildkitd calls back into the client for,
	// reached over POST /session.
	Session BuildkitSessionRequestBodyConfig `mapstructure:"session"`
}

// BuildkitControlRequestBodyConfig gates moby.buildkit.v1.Control's Solve/
// Status/Info/ListWorkers RPCs. Every other Control method (Prune,
// DiskUsage, ListenBuildHistory, UpdateBuildHistory, the nested
// Control/Session bidirectional stream) has no enabling knob at all in
// v1.7 — see buildkitproxy.DeniedExamples — matching the #185 sign-off's
// "hard-deny the rest, no enabling knobs" compatibility boundary.
type BuildkitControlRequestBodyConfig struct {
	// AllowInfo permits the passthrough Control/Info RPC (worker/buildkit
	// version metadata; no policy-relevant fields). Default false.
	AllowInfo bool `mapstructure:"allow_info"`
	// AllowListWorkers permits the passthrough Control/ListWorkers RPC
	// (worker capability metadata; no policy-relevant fields). Default
	// false.
	AllowListWorkers bool `mapstructure:"allow_list_workers"`
	// AllowStatus permits the mediated Control/Status RPC. Once the
	// mediator exists, a Status call is only ever admitted for a Ref that
	// belongs to a Solve already admitted on the same client/profile (#185
	// synthesis) — there is no independent allowlist here because Status
	// has nothing to allowlist beyond that ownership check. Default false.
	AllowStatus bool `mapstructure:"allow_status"`
	// Solve gates the mediated Control/Solve RPC.
	Solve BuildkitSolveRequestBodyConfig `mapstructure:"solve"`
}

// BuildkitSolveRequestBodyConfig gates moby.buildkit.v1.Control/Solve.
//
// Deliberately has no allow_run_instructions/allow_host_network/
// allow_remote_context fields of its own: per the #185 synthesis, "the
// existing request_body.build knobs ... apply to both classic /build and
// BuildKit Solve" — BuildRequestBodyConfig's AllowHostNetwork/
// AllowRemoteContext are reused verbatim (threaded through by
// BuildkitRequestBodyConfig.ToPolicy, which takes the sibling
// request_body.build block as a parameter for exactly this reuse), the same
// way network.allow_endpoint_config (not a duplicate
// container_create.allow_endpoint_config) governs both network connect and
// container-create's embedded EndpointsConfig. Duplicating those flags here
// would let an operator widen one path and forget the other.
//
// AllowRunInstructions has NO Phase 3 (issue #185) equivalent at all: unlike
// classic POST /build, a dockerfile.v0-frontend Solve never puts the
// Dockerfile's RUN instructions in the SolveRequest message itself — see
// buildkitproxy.SolvePolicy's doc comment for why that is out of scope until
// the file-sync mediation phase.
//
// The allowlists below (AllowedCacheImportTypes onward) are new in Phase 3:
// once policy.go's mediator decodes a Solve, it validates
// SolveRequest.Cache's imports/exports and SolveRequest.Exporters against
// them — empty = deny, the standard RequestBodyConfig convention.
type BuildkitSolveRequestBodyConfig struct {
	// Allow permits the Control/Solve RPC at all. Default false.
	Allow bool `mapstructure:"allow"`

	// AllowedCacheImportTypes/AllowedCacheExportTypes gate the "Type" of each
	// entry in a Solve's Cache.Imports/.Exports (e.g. "registry", "local",
	// "gha", "s3", "inline"). Default empty (deny all).
	AllowedCacheImportTypes []string `mapstructure:"allowed_cache_import_types"`
	AllowedCacheExportTypes []string `mapstructure:"allowed_cache_export_types"`
	// AllowedCacheRegistries gates the registry host of a "registry"-typed
	// cache import/export's ref attribute — shared between imports and
	// exports since both name the same kind of remote cache manifest
	// location. Default empty (deny all).
	AllowedCacheRegistries []string `mapstructure:"allowed_cache_registries"`

	// AllowedExporters gates the "Type" of each entry in a Solve's Exporters
	// (e.g. "image", "oci", "docker", "local", "tar"). Default empty (deny
	// all).
	AllowedExporters []string `mapstructure:"allowed_exporters"`
	// AllowedExporterRegistries gates the registry host an "image"-typed
	// exporter pushes to. Default empty (deny all).
	AllowedExporterRegistries []string `mapstructure:"allowed_exporter_registries"`
}

// BuildkitSessionRequestBodyConfig gates the services buildkitd calls back
// into the client for over POST /session. moby.buildkit.v1.frontend.LLBBridge,
// moby.exporter.v1.Exporter, and
// moby.buildkit.v1.sourcepolicy.policysession.PolicyVerifier have no
// enabling knob at all — see buildkitproxy.DeniedExamples.
type BuildkitSessionRequestBodyConfig struct {
	// Health permits the passthrough grpc.health.v1.Health/{Check,Watch}
	// RPCs. Default false.
	Health bool `mapstructure:"health"`
	// Auth gates moby.filesync.v1.Auth's four RPCs (Credentials,
	// FetchToken, GetTokenAuthority, VerifyTokenAuthority) — "Auth/*" in
	// the #185 synthesis; one Allow flag governs all four, since a client
	// implementation cannot meaningfully use one without the others.
	Auth BuildkitAuthRequestBodyConfig `mapstructure:"auth"`
	// Secrets gates moby.buildkit.secrets.v1.Secrets/GetSecret.
	Secrets BuildkitSecretsRequestBodyConfig `mapstructure:"secrets"`
	// SSH gates moby.sshforward.v1.SSH's CheckAgent and ForwardAgent RPCs —
	// "SSH/{CheckAgent,ForwardAgent}" in the #185 synthesis.
	SSH BuildkitSSHRequestBodyConfig `mapstructure:"ssh"`
	// FileSync gates moby.filesync.v1.FileSync/DiffCopy.
	// FileSync/TarStream has no enabling knob — see
	// buildkitproxy.DeniedExamples.
	FileSync BuildkitFileSyncRequestBodyConfig `mapstructure:"file_sync"`
	// FileSend gates moby.filesync.v1.FileSend/DiffCopy.
	FileSend BuildkitFileSendRequestBodyConfig `mapstructure:"file_send"`
	// Upload gates moby.upload.v1.Upload/Pull.
	Upload BuildkitUploadRequestBodyConfig `mapstructure:"upload"`
}

// BuildkitAuthRequestBodyConfig gates moby.filesync.v1.Auth. Per the #185
// synthesis ("registry/realm/scope allowlists"), once the mediator exists a
// call is admitted only when its registry host, realm, and scope each match
// one of the corresponding allowlists below (empty = deny, the standard
// RequestBodyConfig convention) — Allow alone does not admit every host.
type BuildkitAuthRequestBodyConfig struct {
	Allow             bool     `mapstructure:"allow"`
	AllowedRegistries []string `mapstructure:"allowed_registries"`
	AllowedRealms     []string `mapstructure:"allowed_realms"`
	AllowedScopes     []string `mapstructure:"allowed_scopes"`
}

// BuildkitSecretsRequestBodyConfig gates
// moby.buildkit.secrets.v1.Secrets/GetSecret. Per the #185 synthesis
// ("exact ID allowlists"), once the mediator exists a call is admitted only
// when its secret ID exactly matches an entry in AllowedIDs (empty = deny).
type BuildkitSecretsRequestBodyConfig struct {
	Allow      bool     `mapstructure:"allow"`
	AllowedIDs []string `mapstructure:"allowed_ids"`
}

// BuildkitSSHRequestBodyConfig gates moby.sshforward.v1.SSH. Per the #185
// synthesis ("exact ID allowlists"), once the mediator exists a call is
// admitted only when its SSH agent ID exactly matches an entry in
// AllowedIDs (empty = deny).
type BuildkitSSHRequestBodyConfig struct {
	Allow      bool     `mapstructure:"allow"`
	AllowedIDs []string `mapstructure:"allowed_ids"`
}

// BuildkitFileSyncRequestBodyConfig gates moby.filesync.v1.FileSync/DiffCopy.
// The Dockerfile hold-and-inspect behavior the #185 synthesis describes
// reuses request_body.build's allow_run_instructions (threaded through by
// BuildkitRequestBodyConfig.ToPolicy into buildkitproxy.SolvePolicy, the
// same way request_body.build's allow_host_network/allow_remote_context are
// reused for Solve — see BuildkitSolveRequestBodyConfig's doc comment); this
// block has no allow_run_instructions field of its own for the identical
// "don't let an operator widen one path and forget the other" reason. The
// four caps below are Phase 5's own per-profile override of
// buildkitproxy.Limits' hardcoded FileSync ceilings — zero (unset) leaves
// the hardcoded default in place; see buildkitproxy.FileSyncPolicy's doc
// comment for that zero-means-default convention.
type BuildkitFileSyncRequestBodyConfig struct {
	Allow bool `mapstructure:"allow"`
	// MaxFiles caps the number of files/dirs a single FileSync/DiffCopy
	// stream may declare. Zero uses buildkitproxy.Limits.MaxFileSyncFiles.
	MaxFiles int `mapstructure:"max_files"`
	// MaxTotalBytes caps the cumulative bytes relayed across an entire
	// FileSync/DiffCopy stream. Zero uses
	// buildkitproxy.Limits.MaxFileSyncTotalBytes.
	MaxTotalBytes int64 `mapstructure:"max_total_bytes"`
	// MaxPathLength caps the byte length of any single file path or symlink
	// target. Zero uses buildkitproxy.Limits.MaxFileSyncPathLength.
	MaxPathLength int `mapstructure:"max_path_length"`
	// MaxFileBytes caps the bytes belonging to any ONE file within a
	// FileSync/DiffCopy stream, including the Dockerfile hold-and-inspect
	// buffer. Zero uses buildkitproxy.Limits.MaxFileSyncFileBytes.
	MaxFileBytes int64 `mapstructure:"max_file_bytes"`
}

// BuildkitFileSendRequestBodyConfig gates moby.filesync.v1.FileSend/DiffCopy.
// FileSend content is never inspected — only capped; see
// buildkitproxy.rawByteCapValidator's doc comment for why.
type BuildkitFileSendRequestBodyConfig struct {
	Allow bool `mapstructure:"allow"`
	// MaxBytes caps the cumulative bytes relayed for a single FileSend/
	// DiffCopy stream. Zero uses buildkitproxy.Limits.MaxFileSendBytes.
	MaxBytes int64 `mapstructure:"max_bytes"`
}

// BuildkitUploadRequestBodyConfig gates moby.upload.v1.Upload/Pull. Upload
// content is never inspected — only capped.
type BuildkitUploadRequestBodyConfig struct {
	Allow bool `mapstructure:"allow"`
	// MaxBytes caps the cumulative bytes relayed for a single Upload/Pull
	// stream. Zero uses buildkitproxy.Limits.MaxUploadBytes.
	MaxBytes int64 `mapstructure:"max_bytes"`
}

// ClientsConfig configures coarse per-client access controls.
type ClientsConfig struct {
	AllowedCIDRs              []string                                   `mapstructure:"allowed_cidrs"`
	ContainerLabels           ClientContainerLabelsConfig                `mapstructure:"container_labels"`
	DefaultProfile            string                                     `mapstructure:"default_profile"`
	SourceIPProfiles          []ClientSourceIPProfileAssignmentConfig    `mapstructure:"source_ip_profiles"`
	ClientCertificateProfiles []ClientCertificateProfileAssignmentConfig `mapstructure:"client_certificate_profiles"`
	UnixPeerProfiles          []ClientUnixPeerProfileAssignmentConfig    `mapstructure:"unix_peer_profiles"`
	Profiles                  []ClientProfileConfig                      `mapstructure:"profiles"`
	// GlobalConcurrency configures a system-wide priority-aware concurrency
	// gate shared across all profiles. Nil disables it.
	GlobalConcurrency *GlobalConcurrencyConfig `mapstructure:"global_concurrency"`
}

// GlobalConcurrencyConfig configures the system-wide concurrency cap that
// gates admission via per-profile priority shares (low=50%, normal=80%,
// high=100% of MaxInflight). Profiles below their priority's threshold are
// admitted; above it they receive 429 with reason `priority_floor`. The
// per-profile concurrency cap still applies on top of this gate.
type GlobalConcurrencyConfig struct {
	// MaxInflight is the system-wide ceiling on simultaneous in-flight
	// requests. Must be > 0.
	MaxInflight int64 `mapstructure:"max_inflight"`
}

// ClientContainerLabelsConfig configures opt-in per-client ACLs loaded from
// the calling container's labels after resolving the caller by source IP.
type ClientContainerLabelsConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	LabelPrefix string `mapstructure:"label_prefix"`
}

// ClientSourceIPProfileAssignmentConfig maps one or more source CIDRs to a
// named client profile.
type ClientSourceIPProfileAssignmentConfig struct {
	Profile string   `mapstructure:"profile"`
	CIDRs   []string `mapstructure:"cidrs"`
}

// ClientCertificateProfileAssignmentConfig maps one or more mTLS client
// certificate common names to a named client profile.
type ClientCertificateProfileAssignmentConfig struct {
	Profile             string   `mapstructure:"profile"`
	CommonNames         []string `mapstructure:"common_names"`
	DNSNames            []string `mapstructure:"dns_names"`
	IPAddresses         []string `mapstructure:"ip_addresses"`
	URISANs             []string `mapstructure:"uri_sans"`
	SPIFFEIDs           []string `mapstructure:"spiffe_ids"`
	PublicKeySHA256Pins []string `mapstructure:"public_key_sha256_pins"`
}

// ClientUnixPeerProfileAssignmentConfig maps one or more unix peer
// credential selectors to a named client profile.
type ClientUnixPeerProfileAssignmentConfig struct {
	Profile string   `mapstructure:"profile"`
	UIDs    []uint32 `mapstructure:"uids"`
	GIDs    []uint32 `mapstructure:"gids"`
	PIDs    []int32  `mapstructure:"pids"`
}

// ClientProfileConfig defines a named per-client request policy profile.
//
// Mode is the rollout posture for the profile's deny decisions. One of
// "enforce" (default), "warn", or "audit". See RolloutMode for semantics.
type ClientProfileConfig struct {
	Name        string                      `mapstructure:"name"`
	Mode        string                      `mapstructure:"mode"`
	Response    ClientProfileResponseConfig `mapstructure:"response"`
	RequestBody RequestBodyConfig           `mapstructure:"request_body"`
	Rules       []RuleConfig                `mapstructure:"rules"`
	Limits      LimitsConfig                `mapstructure:"limits"`
}

// LimitsConfig groups per-profile rate-limit and concurrency-cap settings.
// Both sub-blocks are optional; omitting both disables all limiting for the
// profile, preserving backward compatibility with pre-v0.7.0 configurations.
type LimitsConfig struct {
	// Rate configures token-bucket rate limiting. Omit to disable.
	Rate *RateLimitConfig `mapstructure:"rate"`
	// Concurrency configures the simultaneous-request cap. Omit to disable.
	Concurrency *ConcurrencyConfig `mapstructure:"concurrency"`
	// Priority is the profile's tier for the system-wide priority-aware
	// fairness gate (see clients.global_concurrency). One of "low", "normal",
	// or "high"; empty defaults to "normal". The field is honored only when
	// clients.global_concurrency is configured.
	Priority string `mapstructure:"priority"`
}

// RateLimitConfig configures a token-bucket rate limiter.
//
// TokensPerSecond is the continuous refill rate. Burst is the bucket capacity
// (maximum tokens that may accumulate). If Burst is zero it defaults to
// TokensPerSecond (smooth rate with no burst allowance). If Burst is less than
// TokensPerSecond after the zero-default replacement it is invalid — startup
// fails with a clear error.
//
// EndpointCosts optionally weights specific endpoints higher than the default
// 1 token per request. Use it to apply tighter budgets to expensive Docker
// operations such as build, image pull, and exec without lowering the base
// rate for every endpoint.
type RateLimitConfig struct {
	TokensPerSecond float64              `mapstructure:"tokens_per_second"`
	Burst           float64              `mapstructure:"burst"`
	EndpointCosts   []EndpointCostConfig `mapstructure:"endpoint_costs"`
}

// EndpointCostConfig assigns a per-request token cost to endpoints matching
// the given path glob (and optional HTTP method set).
//
// Path uses the same glob dialect as filter rules and is matched against the
// normalized request path (Docker API version prefix stripped). Methods is
// optional; an empty slice matches all methods. Cost must be >= 1 and may
// not exceed the effective burst capacity. First match in declaration order
// wins; unmatched requests cost 1 token.
type EndpointCostConfig struct {
	Path    string   `mapstructure:"path"`
	Methods []string `mapstructure:"methods"`
	Cost    float64  `mapstructure:"cost"`
}

// ConcurrencyConfig configures the per-client concurrent-request cap.
type ConcurrencyConfig struct {
	// MaxInflight is the maximum number of simultaneous in-flight requests
	// allowed for a single client. Must be > 0.
	MaxInflight int64 `mapstructure:"max_inflight"`
}

// ClientProfileResponseConfig configures per-profile visibility control on
// Docker read endpoints.
type ClientProfileResponseConfig struct {
	VisibleResourceLabels []string `mapstructure:"visible_resource_labels"`
	// NamePatterns is a per-profile glob pattern list matched against container
	// names and image short names. See ResponseConfig.NamePatterns.
	NamePatterns []string `mapstructure:"name_patterns"`
	// ImagePatterns is a per-profile glob pattern list matched against container
	// Image fields and image RepoTags. See ResponseConfig.ImagePatterns.
	ImagePatterns []string `mapstructure:"image_patterns"`
}

// OwnershipConfig configures per-proxy resource ownership labeling and
// enforcement.
type OwnershipConfig struct {
	Owner              string `mapstructure:"owner"`
	LabelKey           string `mapstructure:"label_key"`
	AllowUnownedImages bool   `mapstructure:"allow_unowned_images"`
	// AllowCrossOwnerNamespaceSharing restores the pre-v1.5 pass-through
	// behavior for POST /containers/create when Owner is configured. By
	// default (false — a security-relevant default, see CHANGELOG),
	// sockguard resolves every HostConfig.NetworkMode/PidMode/IpcMode/
	// UsernsMode "container:<ref>" namespace-sharing target and denies the
	// request if the referenced container belongs to a different owner —
	// joining a foreign container's namespace is a full cross-tenant
	// compromise (shared sockets, process visibility, shared /dev/shm),
	// strictly worse than the access ownership already gates on every other
	// endpoint. Set true to restore the old unchecked behavior. Same-owner
	// refs always pass; an unlabeled target is treated as untrusted and
	// denied too (consistent with every other container-targeting ownership
	// check), so only a same-owner ref is allowed when this is false.
	AllowCrossOwnerNamespaceSharing bool `mapstructure:"allow_cross_owner_namespace_sharing"`
}

// HealthConfig configures the health check endpoint.
type HealthConfig struct {
	Enabled   bool                  `mapstructure:"enabled"`
	Path      string                `mapstructure:"path"`
	Watchdog  HealthWatchdogConfig  `mapstructure:"watchdog"`
	Readiness HealthReadinessConfig `mapstructure:"readiness"`
}

// HealthWatchdogConfig configures active upstream socket monitoring.
type HealthWatchdogConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Interval string `mapstructure:"interval"`
}

// HealthReadinessConfig configures the optional readiness endpoint. Unlike the
// watchdog (which dials the upstream socket — a liveness signal), readiness
// issues a real GET /containers/json against the upstream Docker API, so a
// daemon that accepts connections but no longer answers the API is reported
// unready. Disabled by default; the whole health.* block is reload-immutable.
type HealthReadinessConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Path     string `mapstructure:"path"`
	Interval string `mapstructure:"interval"`
	Timeout  string `mapstructure:"timeout"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// AdminConfig configures the admin HTTP endpoints (POST <path> for
// candidate-config validation, GET <policy_version_path> for the active
// policy generation counter).
//
// By default the admin endpoints ride the main listener and therefore
// inherit its CIDR allowlist, mTLS, and rate-limit posture. When Listen is
// configured (Listen.Socket OR Listen.Address set), sockguard starts a
// dedicated http.Server on that address that serves ONLY the admin
// endpoints. The main Docker-API listener never sees admin traffic in that
// mode, and admin traffic never sees the Docker-API filter chain. Operators
// running production traffic alongside an automation/CI control plane
// should prefer the dedicated listener so the two surfaces are isolated
// at the OS/socket layer.
//
// Enabled is opt-in because a misconfigured admin path on a
// network-reachable listener would otherwise let any client submit YAML for
// parsing.
type AdminConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	Path            string `mapstructure:"path"`
	MaxRequestBytes int64  `mapstructure:"max_request_bytes"`
	// PolicyVersionPath is the GET endpoint that reports the active policy
	// generation counter and metadata (rules / profiles / compat-active /
	// content hash). It shares the admin layer with Path, so it inherits the
	// listener CIDR allowlist, mTLS, and rate-limit posture. Default
	// /admin/policy/version. Must differ from Path, health.path, and
	// metrics.path when those endpoints are enabled.
	PolicyVersionPath string `mapstructure:"policy_version_path"`
	// Listen optionally moves the admin endpoints to a dedicated listener
	// instead of sharing the main proxy listener. Configure either Socket
	// (unix) or Address (TCP, optionally wrapped in TLS). When unset, the
	// admin endpoints continue to ride the main listener.
	Listen AdminListenConfig `mapstructure:"listen"`
	// MountOn names the effective main listener (see Config.EffectiveListeners)
	// that carries in-band admin traffic when Listen is NOT configured. It
	// disambiguates "admin rides the main listener" once there is more than
	// one effective main listener — mounting admin on every listener by
	// default would silently widen the admin attack surface in proportion
	// to listener count. Required when Enabled && !Listen.Configured() &&
	// there are 2+ effective main listeners; ignored (may be left empty)
	// when there is exactly one, preserving today's zero-config behavior
	// byte-for-byte.
	MountOn string `mapstructure:"mount_on"`
}

// AdminListenConfig configures the dedicated admin listener. It embeds
// ListenConfig so operators have a single mental model for the two
// listeners; the behavioral differences are limited to defaults and
// the fact that the admin listener never carries Docker-API traffic.
//
// Configured reports whether a dedicated admin listener has been requested.
// When false the admin endpoints fall back to riding the main listener.
type AdminListenConfig struct {
	ListenConfig `mapstructure:",squash"`
	// InsecureAllowWideOpen is the third acknowledgment a wide-open admin
	// listener requires. The embedded insecure_allow_plain_tcp /
	// insecure_allow_unauthenticated_clients flags opt a non-loopback TCP
	// admin listener out of TLS, but unlike the main listener — where
	// unauthenticated requests still face the full policy filter chain — the
	// admin endpoints accept candidate YAML and expose policy metadata with
	// client CIDRs as their ONLY admission control. A non-loopback plaintext
	// admin listener with no clients.allowed_cidrs is therefore a validation
	// error unless this flag explicitly accepts that exposure.
	InsecureAllowWideOpen bool `mapstructure:"insecure_allow_wide_open"`
}

// Configured reports whether an admin listener address has been requested.
// It is the single source of truth used by both validation and serve wiring
// to decide whether to spin up the dedicated admin http.Server.
func (cfg AdminListenConfig) Configured() bool {
	return cfg.Socket != "" || cfg.Address != ""
}

// ReloadConfig configures the hot-reload pipeline.
//
// When Enabled, sockguard watches the config file via fsnotify and reloads
// on SIGHUP. A reload that mutates any immutable field — listen.*,
// upstream.socket, upstream.endpoints, upstream.failover, log.*, health.*,
// metrics.*, admin.* — is rejected; the running config is preserved and the
// operator must restart sockguard to pick the new values up. (upstream.endpoints
// and upstream.failover are pinned because the long-lived Resolver and its
// health loop are built once at startup; upstream.request_timeout stays mutable.)
//
// Debounce collapses bursts of filesystem events (editors commonly emit
// chmod + write + rename + create per save) into a single reload trigger.
// Default "250ms".
//
// Reload is opt-in because enabling it changes the meaning of SIGHUP:
// historically SIGHUP terminated sockguard; with reload enabled, SIGHUP
// triggers a config reload and never terminates the process. Operators
// that script around the old behavior must update their tooling before
// flipping this on.
type ReloadConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Debounce string `mapstructure:"debounce"`
	// PollInterval is an optional fallback that periodically stats the
	// config file and triggers a reload when its size, modification time, or
	// inode has changed since the last check. Useful on filesystems where
	// fsnotify is unreliable (Synology / DSM btrfs bind-mounts, some FUSE
	// backends, NFS) — inotify events on the host don't always propagate
	// into the container, so a SIGHUP or this poll is the only way the
	// watcher learns the file moved. Empty string disables polling (default);
	// typical values are "5s"–"15s". SIGHUP remains the canonical reload
	// trigger for unreliable propagation backends.
	PollInterval string `mapstructure:"poll_interval"`
}

// PolicyBundleConfig configures verification of signed policy bundles.
//
// When Enabled, sockguard reads the YAML config file bytes and the sigstore
// bundle JSON at SignaturePath, then asks the policybundle verifier to
// confirm the bundle signs the YAML's sha256 digest under one of the
// configured trust paths (AllowedSigningKeys or AllowedKeyless). Both
// startup load and SIGHUP / fsnotify-driven reloads consult the verifier;
// an unsigned or invalid bundle fails startup and rejects reloads with the
// reject_signature metrics reason. The verified signer fingerprint or
// identity is published on GET /admin/policy/version so operators can
// confirm exactly who vouched for the running policy.
//
// SignaturePath is reload-mutable so an operator can re-sign without
// rotating the YAML; the other fields (enable / trust material / Rekor
// requirement / timeout) are reload-immutable for the same reasons as the
// listener / TLS material: changing the trust root mid-reload would
// silently expand the set of accepted signers.
type PolicyBundleConfig struct {
	Enabled               bool                     `mapstructure:"enabled"`
	SignaturePath         string                   `mapstructure:"signature_path"`
	AllowedSigningKeys    []PolicyBundleSigningKey `mapstructure:"allowed_signing_keys"`
	AllowedKeyless        []PolicyBundleKeyless    `mapstructure:"allowed_keyless"`
	RequireRekorInclusion bool                     `mapstructure:"require_rekor_inclusion"`
	VerifyTimeout         string                   `mapstructure:"verify_timeout"`
}

// PolicyBundleSigningKey is one entry in policy_bundle.allowed_signing_keys.
type PolicyBundleSigningKey struct {
	// PEM is the PEM-encoded public key (ECDSA, RSA, or ed25519).
	PEM string `mapstructure:"pem"`
}

// PolicyBundleKeyless is one entry in policy_bundle.allowed_keyless.
type PolicyBundleKeyless struct {
	// Issuer is the exact OIDC issuer URL to match against the Fulcio cert.
	Issuer string `mapstructure:"issuer"`
	// SubjectPattern is a Go regexp matched against the cert's SAN.
	SubjectPattern string `mapstructure:"subject_pattern"`
}

// MutationsConfig configures declarative fail-closed admission mutations
// (#151): a bounded set of config-driven rules that inject owner-independent
// labels or remap image references on a matched request body before the
// existing container_create/service body inspectors, image-trust
// verification, and ownership stamping run. See docs/content/docs for the
// full schema and security model.
//
// Mutations are deliberately not part of clients.profiles: v1 has one
// mutation authority and no global/profile merge rules — every configured
// rule applies identically regardless of which client profile matched the
// request. This block is decoded with a strict subtree decode (see
// decodeMutationsStrict in load.go) that rejects unknown keys and disables
// weak/YAML-typing coercion, unlike the rest of this legacy schema.
type MutationsConfig struct {
	Rules []MutationRuleConfig `mapstructure:"rules"`
}

// MutationRuleConfig is one declarative admission-mutation rule. Exactly one
// of InjectLabels/RemapImage must be set; validate.go enforces this and the
// remaining bounds (rule/label counts, key/value sizes, surface/action
// compatibility, overlap rejection, owner-label-key reservation).
type MutationRuleConfig struct {
	// ID uniquely identifies the rule for logging/audit correlation.
	// Required; must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$.
	ID string `mapstructure:"id"`
	// Mode is the rule's rollout posture: "enforce" (default when empty),
	// "warn", or "audit". See config.ParseRolloutMode for semantics.
	Mode string `mapstructure:"mode"`
	// Surfaces lists the request surfaces this rule applies to, from
	// "container_create", "service_create", "service_update". No duplicates.
	Surfaces []string `mapstructure:"surfaces"`
	// InjectLabels configures a label-map merge mutation. Mutually exclusive
	// with RemapImage.
	InjectLabels *InjectLabelsMutationConfig `mapstructure:"inject_labels"`
	// RemapImage configures a single string-field image replace mutation.
	// Mutually exclusive with InjectLabels.
	RemapImage *ImageRemapMutationConfig `mapstructure:"remap_image"`
}

// InjectLabelsMutationConfig unconditionally sets/replaces the configured
// labels on every request matching the rule's surfaces. Valid only on
// surfaces that carry a label map (container_create, service_create).
type InjectLabelsMutationConfig struct {
	Labels map[string]string `mapstructure:"labels"`
}

// ImageRemapMutationConfig rewrites a matched image reference. Match is
// "exact" (the whole reference must equal From) or "prefix" (From must
// prefix the reference; the remainder is preserved after To).
type ImageRemapMutationConfig struct {
	Match string `mapstructure:"match"`
	From  string `mapstructure:"from"`
	To    string `mapstructure:"to"`
}

// RuleConfig represents a single access control rule in config.
type RuleConfig struct {
	Match  MatchConfig `mapstructure:"match"`
	Action string      `mapstructure:"action"`
	Reason string      `mapstructure:"reason"`
}

// MatchConfig represents the match criteria for a rule.
type MatchConfig struct {
	Method string `mapstructure:"method"`
	Path   string `mapstructure:"path"`
}

// Defaults returns a Config with sensible defaults.
//
// The default listener is loopback TCP 127.0.0.1:2375 so local development
// stays simple without exposing the Docker API proxy on the network. To expose
// Sockguard on non-loopback TCP you must either configure listen.tls for mTLS
// or explicitly opt into legacy plaintext mode with both
// listen.insecure_allow_plain_tcp=true and
// listen.insecure_allow_unauthenticated_clients=true.
func Defaults() Config {
	return Config{
		Listen: ListenConfig{
			Address:    "127.0.0.1:2375",
			SocketMode: HardenedListenSocketMode,
		},
		Upstream: UpstreamConfig{
			Socket: "/var/run/docker.sock",

			RequestTimeout: "60s",
		},
		Log: LogConfig{
			Level:     "info",
			Format:    "json",
			Output:    "stderr",
			AccessLog: true,
			Audit: AuditLogConfig{
				Enabled: false,
				Format:  "json",
				Output:  "stderr",
			},
		},
		Response: ResponseConfig{

			DenyVerbosity:         "minimal",
			RedactContainerEnv:    true,
			RedactMountPaths:      true,
			RedactNetworkTopology: true,
			RedactSensitiveData:   true,
		},
		RequestBody: RequestBodyConfig{

			ContainerCreate: ContainerCreateRequestBodyConfig{
				ImageTrust: ImageTrustConfig{RequireRekorInclusion: true},
			},
			LibpodContainerCreate: LibpodContainerCreateRequestBodyConfig{
				ImageTrust: ImageTrustConfig{RequireRekorInclusion: true},
			},
			ImagePull: ImagePullRequestBodyConfig{
				AllowOfficial: true,
			},
			ImageLoad: ImageLoadRequestBodyConfig{
				AllowOfficial: true,
			},
			Service: ServiceRequestBodyConfig{
				AllowOfficial: true,
				ImageTrust:    ImageTrustConfig{RequireRekorInclusion: true},
			},
			Plugin: PluginRequestBodyConfig{
				AllowOfficial: true,
			},

			Network: NetworkRequestBodyConfig{
				EndpointConfig: EndpointConfigRequestBodyConfig{
					AllowAliases: true,
				},
			},
			LibpodNetwork: NetworkRequestBodyConfig{
				EndpointConfig: EndpointConfigRequestBodyConfig{
					AllowAliases: true,
				},
			},
		},
		Clients: ClientsConfig{
			ContainerLabels: ClientContainerLabelsConfig{
				LabelPrefix: "com.sockguard.allow.",
			},
		},
		Ownership: OwnershipConfig{
			LabelKey:           "com.sockguard.owner",
			AllowUnownedImages: true,
		},
		Health: HealthConfig{
			Enabled: true,
			Path:    "/health",
			Watchdog: HealthWatchdogConfig{
				Enabled:  false,
				Interval: "5s",
			},
			Readiness: HealthReadinessConfig{
				Enabled:  false,
				Path:     "/ready",
				Interval: "10s",
				Timeout:  "5s",
			},
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Path:    "/metrics",
		},
		Admin: AdminConfig{
			Enabled:           false,
			Path:              "/admin/validate",
			MaxRequestBytes:   524288,
			PolicyVersionPath: "/admin/policy/version",
			Listen: AdminListenConfig{
				ListenConfig: ListenConfig{

					SocketMode: HardenedListenSocketMode,
				},
			},
		},
		Reload: ReloadConfig{
			Enabled:      false,
			Debounce:     "250ms",
			PollInterval: "",
		},
		PolicyBundle: PolicyBundleConfig{
			Enabled:               false,
			RequireRekorInclusion: true,
		},
		Rules: []RuleConfig{
			{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"},
			{Match: MatchConfig{Method: "HEAD", Path: "/_ping"}, Action: "allow"},
			{Match: MatchConfig{Method: "GET", Path: "/version"}, Action: "allow"},
			{Match: MatchConfig{Method: "GET", Path: "/events"}, Action: "allow"},
			{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
		},
		InsecureAllowReadExfiltration: false,
	}
}

// ToFilterOptions converts request-body config into filter middleware policy
// options. Runtime-only fields, such as exec-start upstream inspection, are
// intentionally left for the caller to attach.
func (c RequestBodyConfig) ToFilterOptions() filter.PolicyConfig {

	containerCreate := c.ContainerCreate.ToFilterOptions()
	containerCreate.AllowEndpointConfig = c.Network.AllowEndpointConfig
	containerCreate.EndpointConfig = c.Network.EndpointConfig.ToFilterOptions()

	return filter.PolicyConfig{
		ContainerCreate:       containerCreate,
		LibpodContainerCreate: c.LibpodContainerCreate.ToFilterOptions(),
		Exec:                  c.Exec.ToFilterOptions(),
		ImagePull:             c.ImagePull.ToFilterOptions(),
		Build:                 c.Build.ToFilterOptions(),
		ContainerUpdate:       c.ContainerUpdate.ToFilterOptions(),
		ContainerArchive:      c.ContainerArchive.ToFilterOptions(),
		ImageLoad:             c.ImageLoad.ToFilterOptions(),
		Volume:                c.Volume.ToFilterOptions(),
		Network:               c.Network.ToFilterOptions(),
		Secret:                c.Secret.ToFilterOptions(),
		Config:                c.Config.ToFilterOptions(),
		Service:               c.Service.ToFilterOptions(),
		Swarm:                 c.Swarm.ToFilterOptions(),
		Node:                  c.Node.ToFilterOptions(),
		Plugin:                c.Plugin.ToFilterOptions(),
		LibpodPodCreate:       c.LibpodPodCreate.ToFilterOptions(),
		LibpodVolume:          c.LibpodVolume.ToFilterOptions(),
		LibpodNetwork:         c.LibpodNetwork.ToFilterOptions(),
		LibpodSecret:          c.LibpodSecret.ToFilterOptions(),

		Buildkit: filter.BuildkitOptions{TunnelConfigured: c.Buildkit.ToPolicy(c.Build).Configured()},
	}
}

// ToFilterOptions converts libpod_pod_create config into filter middleware
// options. #148.
func (c LibpodPodCreateRequestBodyConfig) ToFilterOptions() filter.LibpodPodCreateOptions {
	return filter.LibpodPodCreateOptions{
		AllowHostNetwork:            c.AllowHostNetwork,
		AllowSharedPIDNamespace:     c.AllowSharedPIDNamespace,
		AllowedInfraImageRegistries: c.AllowedInfraImageRegistries,
	}
}

func (c ContainerCreateRequestBodyConfig) ToFilterOptions() filter.ContainerCreateOptions {
	return filter.ContainerCreateOptions{
		AllowPrivileged:                   c.AllowPrivileged,
		AllowHostNetwork:                  c.AllowHostNetwork,
		AllowHostPID:                      c.AllowHostPID,
		AllowHostIPC:                      c.AllowHostIPC,
		AllowedBindMounts:                 c.AllowedBindMounts,
		AllowAllDevices:                   c.AllowAllDevices,
		AllowedDevices:                    c.AllowedDevices,
		AllowDeviceRequests:               c.AllowDeviceRequests,
		AllowedDeviceRequests:             toFilterAllowedDeviceRequests(c.AllowedDeviceRequests),
		AllowDeviceCgroupRules:            c.AllowDeviceCgroupRules,
		AllowedDeviceCgroupRules:          c.AllowedDeviceCgroupRules,
		RequireNoNewPrivileges:            c.RequireNoNewPrivileges,
		RequireNonRootUser:                c.RequireNonRootUser,
		RequireReadonlyRootfs:             c.RequireReadonlyRootfs,
		RequireDropAllCapabilities:        c.RequireDropAllCapabilities,
		AllowAllCapabilities:              c.AllowAllCapabilities,
		AllowedCapabilities:               c.AllowedCapabilities,
		RequireMemoryLimit:                c.RequireMemoryLimit,
		RequireCPULimit:                   c.RequireCPULimit,
		RequireCPULimitHard:               c.RequireCPULimitHard,
		RequirePidsLimit:                  c.RequirePidsLimit,
		AllowedSeccompProfiles:            c.AllowedSeccompProfiles,
		DenyUnconfinedSeccomp:             c.DenyUnconfinedSeccomp,
		AllowedAppArmorProfiles:           c.AllowedAppArmorProfiles,
		DenyUnconfinedAppArmor:            c.DenyUnconfinedAppArmor,
		AllowHostUserNS:                   c.AllowHostUserNS,
		AllowHostCgroupNS:                 c.AllowHostCgroupNS,
		RestrictNamespaceSharing:          c.RestrictNamespaceSharing,
		AllowedNamespaceSharingContainers: c.AllowedNamespaceSharingContainers,
		DenyNamespacePathMode:             c.DenyNamespacePathMode,
		AllowSysctls:                      c.AllowSysctls,
		RequiredLabels:                    c.RequiredLabels,
		AllowedRuntimes:                   c.AllowedRuntimes,
		ImageTrust:                        c.ImageTrust.toFilterOptions(),
		DenySelinuxDisable:                c.DenySelinuxDisable,
		DenySelinuxLabelOverride:          c.DenySelinuxLabelOverride,
		DenyUnconfinedSystemPaths:         c.DenyUnconfinedSystemPaths,
		AllowTmpfsPrivilegedOptions:       c.AllowTmpfsPrivilegedOptions,
	}
}

func (c LibpodContainerCreateRequestBodyConfig) ToFilterOptions() filter.LibpodContainerCreateOptions {
	return filter.LibpodContainerCreateOptions{
		AllowPrivileged:                   c.AllowPrivileged,
		AllowHostNetwork:                  c.AllowHostNetwork,
		AllowHostPID:                      c.AllowHostPID,
		AllowHostIPC:                      c.AllowHostIPC,
		AllowHostUserNS:                   c.AllowHostUserNS,
		AllowedBindMounts:                 c.AllowedBindMounts,
		AllowAllDevices:                   c.AllowAllDevices,
		AllowedDevices:                    c.AllowedDevices,
		RestrictNamespaceSharing:          c.RestrictNamespaceSharing,
		AllowedNamespaceSharingContainers: c.AllowedNamespaceSharingContainers,
		AllowAllCapabilities:              c.AllowAllCapabilities,
		AllowedCapabilities:               c.AllowedCapabilities,
		AllowedSeccompProfiles:            c.AllowedSeccompProfiles,
		DenyUnconfinedSeccomp:             c.DenyUnconfinedSeccomp,
		AllowedAppArmorProfiles:           c.AllowedAppArmorProfiles,
		DenyUnconfinedAppArmor:            c.DenyUnconfinedAppArmor,
		DenySelinuxDisable:                c.DenySelinuxDisable,
		RequireNonRootUser:                c.RequireNonRootUser,
		RequireReadonlyRootfs:             c.RequireReadonlyRootfs,
		RequireMemoryLimit:                c.RequireMemoryLimit,
		RequireCPULimit:                   c.RequireCPULimit,
		RequireCPULimitHard:               c.RequireCPULimitHard,
		RequirePidsLimit:                  c.RequirePidsLimit,
		AllowSysctls:                      c.AllowSysctls,
		ImageTrust:                        c.ImageTrust.toFilterOptions(),
		AllowSystemdMode:                  c.AllowSystemdMode,
		AllowCustomIDMappings:             c.AllowCustomIDMappings,
	}
}

func (c ImageTrustConfig) toFilterOptions() filter.ImageTrustOptions {
	var keys []filter.SigningKeyOptions
	if len(c.AllowedSigningKeys) > 0 {
		keys = make([]filter.SigningKeyOptions, 0, len(c.AllowedSigningKeys))
		for _, k := range c.AllowedSigningKeys {
			keys = append(keys, filter.SigningKeyOptions{PEM: k.PEM})
		}
	}
	var kl []filter.KeylessOptions
	if len(c.AllowedKeyless) > 0 {
		kl = make([]filter.KeylessOptions, 0, len(c.AllowedKeyless))
		for _, k := range c.AllowedKeyless {
			kl = append(kl, filter.KeylessOptions{
				Issuer:         k.Issuer,
				SubjectPattern: k.SubjectPattern,
			})
		}
	}
	return filter.ImageTrustOptions{
		Mode:                  c.Mode,
		AllowedSigningKeys:    keys,
		AllowedKeyless:        kl,
		RequireRekorInclusion: c.RequireRekorInclusion,
		VerifyTimeout:         c.VerifyTimeout,
	}
}

func (c ExecRequestBodyConfig) ToFilterOptions() filter.ExecOptions {
	return filter.ExecOptions{
		AllowPrivileged:  c.AllowPrivileged,
		AllowRootUser:    c.AllowRootUser,
		AllowedCommands:  c.AllowedCommands,
		AllowedEnvVars:   c.AllowedEnvVars,
		DeniedEnvVars:    c.DeniedEnvVars,
		AllowedEnvValues: c.AllowedEnvValues,
	}
}

func (c ImagePullRequestBodyConfig) ToFilterOptions() filter.ImagePullOptions {
	return filter.ImagePullOptions{
		AllowImports:       c.AllowImports,
		AllowAllRegistries: c.AllowAllRegistries,
		AllowOfficial:      c.AllowOfficial,
		AllowedRegistries:  c.AllowedRegistries,
	}
}

func (c BuildRequestBodyConfig) ToFilterOptions() filter.BuildOptions {
	return filter.BuildOptions{
		AllowRemoteContext:   c.AllowRemoteContext,
		AllowHostNetwork:     c.AllowHostNetwork,
		AllowRunInstructions: c.AllowRunInstructions,
	}
}

func (c ContainerUpdateRequestBodyConfig) ToFilterOptions() filter.ContainerUpdateOptions {
	return filter.ContainerUpdateOptions{
		AllowPrivileged:      c.AllowPrivileged,
		AllowAllDevices:      c.AllowAllDevices,
		AllowCapabilities:    c.AllowCapabilities,
		AllowResourceUpdates: c.AllowResourceUpdates,
		AllowRestartPolicy:   c.AllowRestartPolicy,
		RequireMemoryLimit:   c.RequireMemoryLimit,
		RequireCPULimit:      c.RequireCPULimit,
		RequireCPULimitHard:  c.RequireCPULimitHard,
		RequirePidsLimit:     c.RequirePidsLimit,
	}
}

func (c ContainerArchiveRequestBodyConfig) ToFilterOptions() filter.ContainerArchiveOptions {
	return filter.ContainerArchiveOptions{
		AllowedPaths:       c.AllowedPaths,
		AllowSetID:         c.AllowSetID,
		AllowDeviceNodes:   c.AllowDeviceNodes,
		AllowEscapingLinks: c.AllowEscapingLinks,
	}
}

func (c ImageLoadRequestBodyConfig) ToFilterOptions() filter.ImageLoadOptions {
	return filter.ImageLoadOptions{
		AllowAllRegistries: c.AllowAllRegistries,
		AllowOfficial:      c.AllowOfficial,
		AllowedRegistries:  c.AllowedRegistries,
		AllowUntagged:      c.AllowUntagged,
	}
}

func (c VolumeRequestBodyConfig) ToFilterOptions() filter.VolumeOptions {
	return filter.VolumeOptions{
		AllowCustomDrivers: c.AllowCustomDrivers,
		AllowDriverOpts:    c.AllowDriverOpts,
	}
}

func (c NetworkRequestBodyConfig) ToFilterOptions() filter.NetworkOptions {
	return filter.NetworkOptions{
		AllowCustomDrivers:     c.AllowCustomDrivers,
		AllowSwarmScope:        c.AllowSwarmScope,
		AllowIngress:           c.AllowIngress,
		AllowAttachable:        c.AllowAttachable,
		AllowConfigOnly:        c.AllowConfigOnly,
		AllowConfigFrom:        c.AllowConfigFrom,
		AllowCustomIPAMDrivers: c.AllowCustomIPAMDrivers,
		AllowCustomIPAMConfig:  c.AllowCustomIPAMConfig,
		AllowIPAMOptions:       c.AllowIPAMOptions,
		AllowDriverOptions:     c.AllowDriverOptions,
		AllowEndpointConfig:    c.AllowEndpointConfig,
		EndpointConfig:         c.EndpointConfig.ToFilterOptions(),
		AllowDisconnectForce:   c.AllowDisconnectForce,
		AllowDisableIPv4:       c.AllowDisableIPv4,
	}
}

// ToFilterOptions converts the granular endpoint_config block (#186) into
// filter.EndpointConfigOptions. AllowAliases is inverted to DenyAliases: the
// filter package's zero value must preserve the historical unconditional-
// allow behavior for Aliases (DenyAliases false), while this config type's
// zero value must not silently deny Aliases either — it defaults true via
// config.Defaults() — so the two types intentionally use opposite polarity
// for this one field. See EndpointConfigRequestBodyConfig's doc comment.
func (c EndpointConfigRequestBodyConfig) ToFilterOptions() filter.EndpointConfigOptions {
	return filter.EndpointConfigOptions{
		AllowStaticAddressing: c.AllowStaticAddressing,
		AllowLinkLocalIPs:     c.AllowLinkLocalIPs,
		AllowMACPinning:       c.AllowMACPinning,
		AllowGwPriority:       c.AllowGwPriority,
		DenyAliases:           !c.AllowAliases,
	}
}

func (c SecretRequestBodyConfig) ToFilterOptions() filter.SecretOptions {
	return filter.SecretOptions{
		AllowCustomDrivers:   c.AllowCustomDrivers,
		AllowTemplateDrivers: c.AllowTemplateDrivers,
	}
}

func (c ConfigRequestBodyConfig) ToFilterOptions() filter.ConfigOptions {
	return filter.ConfigOptions{
		AllowCustomDrivers:   c.AllowCustomDrivers,
		AllowTemplateDrivers: c.AllowTemplateDrivers,
	}
}

func (c ServiceRequestBodyConfig) ToFilterOptions() filter.ServiceOptions {
	return filter.ServiceOptions{
		AllowHostNetwork:           c.AllowHostNetwork,
		AllowedBindMounts:          c.AllowedBindMounts,
		AllowAllRegistries:         c.AllowAllRegistries,
		AllowOfficial:              c.AllowOfficial,
		AllowedRegistries:          c.AllowedRegistries,
		AllowAllCapabilities:       c.AllowAllCapabilities,
		AllowedCapabilities:        c.AllowedCapabilities,
		AllowSysctls:               c.AllowSysctls,
		RequireNonRootUser:         c.RequireNonRootUser,
		RequireNoNewPrivileges:     c.RequireNoNewPrivileges,
		RequireReadonlyRootfs:      c.RequireReadonlyRootfs,
		RequireDropAllCapabilities: c.RequireDropAllCapabilities,
		DenyUnconfinedSeccomp:      c.DenyUnconfinedSeccomp,
		DenyCustomSeccompProfiles:  c.DenyCustomSeccompProfiles,
		DenyUnconfinedAppArmor:     c.DenyUnconfinedAppArmor,
		DenySelinuxDisable:         c.DenySelinuxDisable,
		DenySelinuxLabelOverride:   c.DenySelinuxLabelOverride,
		ImageTrust:                 c.ImageTrust.toFilterOptions(),
		RequireCPULimit:            c.RequireCPULimit,
		RequireCPULimitHard:        c.RequireCPULimitHard,
	}
}

func (c SwarmRequestBodyConfig) ToFilterOptions() filter.SwarmOptions {
	return filter.SwarmOptions{
		AllowForceNewCluster:          c.AllowForceNewCluster,
		AllowExternalCA:               c.AllowExternalCA,
		AllowedJoinRemoteAddrs:        c.AllowedJoinRemoteAddrs,
		AllowTokenRotation:            c.AllowTokenRotation,
		AllowManagerUnlockKeyRotation: c.AllowManagerUnlockKeyRotation,
		AllowAutoLockManagers:         c.AllowAutoLockManagers,
		AllowSigningCAUpdate:          c.AllowSigningCAUpdate,
		AllowUnlock:                   c.AllowUnlock,
	}
}

func (c NodeRequestBodyConfig) ToFilterOptions() filter.NodeOptions {
	return filter.NodeOptions{
		AllowNameChange:         c.AllowNameChange,
		AllowRoleChange:         c.AllowRoleChange,
		AllowAvailabilityChange: c.AllowAvailabilityChange,
		AllowLabelMutation:      c.AllowLabelMutation,
		AllowedLabelKeys:        c.AllowedLabelKeys,
	}
}

func (c PluginRequestBodyConfig) ToFilterOptions() filter.PluginOptions {
	return filter.PluginOptions{
		AllowHostNetwork:      c.AllowHostNetwork,
		AllowHostIPC:          c.AllowHostIPC,
		AllowHostPID:          c.AllowHostPID,
		AllowAllDevices:       c.AllowAllDevices,
		AllowedBindMounts:     c.AllowedBindMounts,
		AllowedDevices:        c.AllowedDevices,
		AllowAllCapabilities:  c.AllowAllCapabilities,
		AllowedCapabilities:   c.AllowedCapabilities,
		AllowAllRegistries:    c.AllowAllRegistries,
		AllowOfficial:         c.AllowOfficial,
		AllowedRegistries:     c.AllowedRegistries,
		AllowedSetEnvPrefixes: c.AllowedSetEnvPrefixes,
	}
}

// ToFilterOptions converts the mutations config block into filter.MutationOptions.
// Unlike RequestBodyConfig.ToFilterOptions, this carries global state (see
// MutationsConfig's doc comment: mutations are not part of clients.profiles),
// so cmd/serve.go attaches the result to filter.Options.Mutation directly
// rather than through PolicyConfig.
func (c MutationsConfig) ToFilterOptions() filter.MutationOptions {
	if len(c.Rules) == 0 {
		return filter.MutationOptions{}
	}
	rules := make([]filter.MutationRuleOptions, 0, len(c.Rules))
	for _, r := range c.Rules {
		opt := filter.MutationRuleOptions{
			ID:       r.ID,
			Mode:     r.Mode,
			Surfaces: r.Surfaces,
		}
		if r.InjectLabels != nil {
			opt.InjectLabels = &filter.InjectLabelsMutationOptions{Labels: r.InjectLabels.Labels}
		}
		if r.RemapImage != nil {

			opt.RemapImage = &filter.ImageRemapMutationOptions{
				Match: strings.ToLower(strings.TrimSpace(r.RemapImage.Match)),
				From:  r.RemapImage.From,
				To:    r.RemapImage.To,
			}
		}
		rules = append(rules, opt)
	}
	return filter.MutationOptions{Rules: rules}
}

// toFilterAllowedDeviceRequests converts config AllowedDeviceRequest slices to
// the filter package's AllowedDeviceRequestEntry type. Returns nil when the
// input is empty so reflect.DeepEqual comparisons against zero-value structs
// remain correct.
func toFilterAllowedDeviceRequests(entries []AllowedDeviceRequest) []filter.AllowedDeviceRequestEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]filter.AllowedDeviceRequestEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, filter.AllowedDeviceRequestEntry{
			Driver:              e.Driver,
			AllowedCapabilities: e.AllowedCapabilities,
			MaxCount:            e.MaxCount,
		})
	}
	return out
}

// Load reads config from the given YAML file path, applies env var overrides,
// and returns the merged Config. A missing file is OK; parse errors are not.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	defaults := Defaults()
	setLoadDefaults(v, defaults)

	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			if _, statErr := os.Stat(configPath); statErr != nil && os.IsNotExist(statErr) {

			} else {
				return nil, err
			}
		}
	}

	v.SetEnvPrefix("SOCKGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	applyCompatEnvAliases(&cfg)

	if err := decodeMutationsStrict(v, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	cfg.explicitLegacyListen = explicitLegacyListenFile(configPath)
	cfg.explicitNetworkEndpointConfig = explicitNetworkEndpointConfigFile(configPath)

	return &cfg, nil
}

// legacyListenKeys are the dotted config paths under listen: whose presence
// (via YAML, a SOCKGUARD_LISTEN_* env var, or — separately, via
// Config.MarkLegacyListenExplicit — the --listen-socket CLI flag) marks the
// legacy singular listener as explicitly configured rather than left at its
// zero-value default. Used only for the listen/listeners mutual-exclusivity
// check (#149); listed exhaustively rather than derived by reflection
// because the check must distinguish "present with any value, including a
// zero value" from "absent", which registerDefaults' walk does not track.
var legacyListenKeys = []string{
	"listen.socket",
	"listen.address",
	"listen.socket_mode",
	"listen.socket_uid",
	"listen.socket_gid",
	"listen.insecure_allow_plain_tcp",
	"listen.insecure_allow_unauthenticated_clients",
	"listen.tls.cert_file",
	"listen.tls.key_file",
	"listen.tls.client_ca_file",
	"listen.tls.common_names",
	"listen.tls.dns_names",
	"listen.tls.ip_addresses",
	"listen.tls.uri_sans",
	"listen.tls.public_key_sha256_pins",
}

// explicitLegacyListenFile reports whether any legacyListenKeys entry was
// set via the YAML file at configPath or a SOCKGUARD_LISTEN_* environment
// variable. It uses a second, defaults-free Viper instance so
// registerDefaults' leaf registrations (which would make every key
// unconditionally "set") cannot mask the answer.
func explicitLegacyListenFile(configPath string) bool {
	pv := viper.New()
	if configPath != "" {
		pv.SetConfigFile(configPath)
		_ = pv.ReadInConfig()
	}
	pv.SetEnvPrefix("SOCKGUARD")
	pv.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	pv.AutomaticEnv()
	return explicitLegacyListenSet(pv)
}

// explicitLegacyListenBytes is explicitLegacyListenFile's LoadBytes
// counterpart: no environment overlay, matching LoadBytes' own contract
// (env vars never affect a candidate/signed YAML body).
func explicitLegacyListenBytes(data []byte) bool {
	pv := viper.New()
	pv.SetConfigType("yaml")
	if len(data) > 0 {
		if err := pv.ReadConfig(bytes.NewReader(data)); err != nil {
			return false
		}
	}
	return explicitLegacyListenSet(pv)
}

func explicitLegacyListenSet(pv *viper.Viper) bool {
	return explicitKeysSet(pv, legacyListenKeys)
}

// networkEndpointConfigKeys are the dotted config paths under
// request_body.network.endpoint_config whose presence (via YAML or a
// SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_* environment variable)
// marks the granular endpoint-config block as explicitly configured, for the
// allow_endpoint_config/endpoint_config mutual-exclusion check (#186). See
// explicitNetworkEndpointConfigFile/Bytes and legacyListenKeys' doc comment
// for why zero-value comparison cannot answer this question on its own.
var networkEndpointConfigKeys = []string{
	"request_body.network.endpoint_config.allow_static_addressing",
	"request_body.network.endpoint_config.allow_link_local_ips",
	"request_body.network.endpoint_config.allow_mac_pinning",
	"request_body.network.endpoint_config.allow_gw_priority",
	"request_body.network.endpoint_config.allow_aliases",
}

// explicitNetworkEndpointConfigFile is explicitLegacyListenFile's #186
// counterpart: reports whether any request_body.network.endpoint_config.*
// key was set via the YAML file at configPath or a matching
// SOCKGUARD_REQUEST_BODY_NETWORK_ENDPOINT_CONFIG_* environment variable,
// using a second, defaults-free Viper instance so registerDefaults' leaf
// registrations cannot mask the answer.
func explicitNetworkEndpointConfigFile(configPath string) bool {
	pv := viper.New()
	if configPath != "" {
		pv.SetConfigFile(configPath)
		_ = pv.ReadInConfig()
	}
	pv.SetEnvPrefix("SOCKGUARD")
	pv.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	pv.AutomaticEnv()
	return explicitKeysSet(pv, networkEndpointConfigKeys)
}

// explicitNetworkEndpointConfigBytes is explicitNetworkEndpointConfigFile's
// LoadBytes counterpart: no environment overlay, matching LoadBytes' own
// contract (env vars never affect a candidate/signed YAML body).
func explicitNetworkEndpointConfigBytes(data []byte) bool {
	pv := viper.New()
	pv.SetConfigType("yaml")
	if len(data) > 0 {
		if err := pv.ReadConfig(bytes.NewReader(data)); err != nil {
			return false
		}
	}
	return explicitKeysSet(pv, networkEndpointConfigKeys)
}

// explicitKeysSet reports whether any of keys is set on pv — shared by the
// legacy-listen and network-endpoint-config provenance checks above.
func explicitKeysSet(pv *viper.Viper, keys []string) bool {
	for _, key := range keys {
		if pv.IsSet(key) {
			return true
		}
	}
	return false
}

// decodeMutationsStrict re-decodes the mutations subtree with a strict
// mapstructure.DecoderConfig — ErrorUnused true, WeaklyTypedInput false, no
// decode hook — overwriting the lenient Config-wide decode's cfg.Mutations.
// Every other block in this schema tolerates unknown keys and weak/YAML
// type coercion for backward compatibility; mutations does not, because a
// declarative admission-mutation rule that silently ignores a typo'd key or
// coerces "id: 0" (a YAML integer) into the string "0" is a fail-open
// footgun this feature specifically exists to avoid. See MutationsConfig's
// doc comment.
func decodeMutationsStrict(v *viper.Viper, cfg *Config) error {
	strict := func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = true
		c.WeaklyTypedInput = false
		c.DecodeHook = nil
	}

	var mutations MutationsConfig
	if err := v.UnmarshalKey("mutations", &mutations, strict); err != nil {
		return fmt.Errorf("decode mutations config: %w", err)
	}
	cfg.Mutations = mutations
	return nil
}

// setLoadDefaults registers every default value with the Viper instance.
// Shared by Load (file-based, with env overlay) and LoadBytes (in-memory,
// no env overlay) so the two paths cannot drift as the schema grows.
//
// Defaults are derived by reflection off Config's mapstructure tags (see
// registerDefaults) rather than a hand-maintained list of v.SetDefault
// calls, so a newly added field can no longer silently lose its Viper
// registration — and with it, its SOCKGUARD_* environment-variable override
// — by omission. That exact failure mode has shipped three times
// (allow_sysctls, the service-hardening rails, the SELinux/
// deny_unconfined_system_paths trio); see load_defaults_completeness_test.go.
func setLoadDefaults(v *viper.Viper, defaults Config) {
	registerDefaults(v, "", reflect.ValueOf(defaults))
}

// registerDefaults recursively walks val — a struct value reflecting some
// (sub)tree of Config — and registers every leaf field as a Viper default
// under the dotted key built from its mapstructure tags.
//
// A field is recursed into only when it is a plain (non-pointer, non-slice)
// struct; every other kind — bool, string, numeric, []string, []T, and
// pointer-to-struct fields alike — is a leaf, registered whole via
// v.SetDefault. A ",squash" mapstructure tag (AdminListenConfig's embedded
// ListenConfig) recurses at the same key prefix instead of nesting one
// level deeper, matching how the mapstructure decoder treats it.
//
// Two exclusions preserve pre-existing behavior exactly rather than
// "fixing" it as a side effect of the walk:
//   - The top-level Rules field is skipped: it is populated post-unmarshal
//     by the `if len(cfg.Rules) == 0` fallback in Load/LoadBytes below, not
//     by a Viper default.
//   - A nil pointer leaf (clients.global_concurrency; limits.rate and
//     limits.concurrency inside clients.profiles[], which never reach this
//     branch because Profiles is itself a slice leaf) is skipped rather
//     than registered with a zero value, because those blocks are not
//     env-var-configurable today — registering one would silently make
//     every deploy see a present-but-empty block instead of an absent one.
func registerDefaults(v *viper.Viper, prefix string, val reflect.Value) {
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name, squash := mapstructureTag(field)

		if prefix == "" && name == "rules" {
			continue
		}

		key := prefix
		if !squash {
			if prefix == "" {
				key = name
			} else {
				key = prefix + "." + name
			}
		}

		fv := val.Field(i)
		if fv.Kind() == reflect.Struct {
			registerDefaults(v, key, fv)
			continue
		}
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			continue
		}

		v.SetDefault(key, fv.Interface())
	}
}

// mapstructureTag splits a struct field's mapstructure tag into its key
// name and whether it carries the ",squash" option.
func mapstructureTag(field reflect.StructField) (name string, squash bool) {
	tag := field.Tag.Get("mapstructure")
	parts := strings.Split(tag, ",")
	name = parts[0]
	for _, opt := range parts[1:] {
		if opt == "squash" {
			squash = true
		}
	}
	return name, squash
}

// LoadBytes parses YAML config from the provided bytes and returns the merged
// Config with defaults applied. Unlike Load, env-var overrides are NOT applied,
// which makes it the loader for two distinct callers:
//   - the admin /admin/validate endpoint, which validates a candidate YAML body
//     in isolation, so the result depends only on what the caller submitted; and
//   - the signed-policy-bundle path, where the on-disk YAML is authoritative.
//     Parsing the verified bytes here (rather than re-reading the file with the
//     SOCKGUARD_* overlay) guarantees the applied config equals the signed
//     config: environment variables cannot silently override signed policy (#16).
//
// An empty body returns the built-in defaults — useful for CI pipelines that
// want to confirm the proxy's defaults still validate. Malformed YAML returns
// an error.
func LoadBytes(data []byte) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	defaults := Defaults()
	setLoadDefaults(v, defaults)

	if len(data) > 0 {
		if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if err := decodeMutationsStrict(v, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Rules) == 0 {
		cfg.Rules = defaults.Rules
	}

	cfg.explicitLegacyListen = explicitLegacyListenBytes(data)
	cfg.explicitNetworkEndpointConfig = explicitNetworkEndpointConfigBytes(data)

	return &cfg, nil
}

var validateLogOutput = logging.ValidateOutput

// RolloutMode controls how a profile's deny decisions are applied. It is the
// operator-facing knob behind a staged policy rollout: a new policy can be
// configured with mode=audit to collect "what would have been blocked" data
// without affecting consumers, promoted to mode=warn so denied requests are
// loudly logged but still pass through, and finally moved to mode=enforce
// once the operator is confident no legitimate traffic is being caught.
type RolloutMode string

const (
	// RolloutEnforce is the default. Deny decisions block the request and the
	// proxy writes a 4xx response.
	RolloutEnforce RolloutMode = "enforce"
	// RolloutWarn lets the request pass through to the upstream Docker
	// daemon, emits a WARN-level audit record carrying the would-be deny
	// reason, and increments the deny / throttle counters with mode=warn so
	// operators can compare warn volume against historical enforce volume.
	RolloutWarn RolloutMode = "warn"
	// RolloutAudit is identical to warn except the audit record is emitted at
	// INFO level. Use it during silent dry-runs where warn-level log volume
	// would page on-call.
	RolloutAudit RolloutMode = "audit"
)

// String returns the canonical lowercase form of the mode.
func (m RolloutMode) String() string { return string(m) }

// ParseRolloutMode normalizes the operator-supplied value. An empty string is
// treated as RolloutEnforce so omitting the field in YAML is equivalent to
// configuring mode=enforce. Unknown values return (RolloutEnforce, false) so
// the validator can surface a clear error.
func ParseRolloutMode(s string) (RolloutMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "enforce":
		return RolloutEnforce, true
	case "warn":
		return RolloutWarn, true
	case "audit":
		return RolloutAudit, true
	default:
		return RolloutEnforce, false
	}
}

// Enabled reports whether any listen.tls setting has been configured.
func (cfg ListenTLSConfig) Enabled() bool {
	return cfg.CertFile != "" ||
		cfg.KeyFile != "" ||
		cfg.ClientCAFile != "" ||
		len(cfg.CommonNames) > 0 ||
		len(cfg.DNSNames) > 0 ||
		len(cfg.IPAddresses) > 0 ||
		len(cfg.URISANs) > 0 ||
		len(cfg.PublicKeySHA256Pins) > 0
}

// Complete reports whether listen.tls has the full certificate, key, and
// client CA configuration required to enable mutual TLS.
func (cfg ListenTLSConfig) Complete() bool {
	return cfg.CertFile != "" && cfg.KeyFile != "" && cfg.ClientCAFile != ""
}

// BuildMutualTLSServerConfig builds a TLS server config that requires and
// verifies client certificates for TCP listeners. Error messages reference
// the "listen.tls" config field path. To produce errors keyed to a different
// field (e.g. "admin.listen.tls"), use BuildMutualTLSServerConfigForField.
func BuildMutualTLSServerConfig(cfg ListenTLSConfig) (*tls.Config, error) {
	return BuildMutualTLSServerConfigForField("listen.tls", cfg)
}

// BuildMutualTLSServerConfigForField is BuildMutualTLSServerConfig with an
// explicit field prefix used in error messages. Validation paths use this to
// produce errors that reference the operator's actual config field path
// (e.g. "admin.listen.tls") without post-hoc string substitution.
func BuildMutualTLSServerConfigForField(fieldPrefix string, cfg ListenTLSConfig) (*tls.Config, error) {
	clientIdentity, err := compileClientCertificateIdentityConstraints(fieldPrefix, cfg)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load %s cert/key pair: %w", fieldPrefix, err)
	}

	clientCAPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read %s client_ca_file: %w", fieldPrefix, err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("parse %s client_ca_file: no PEM certificates found", fieldPrefix)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	if clientIdentity.hasSelectors() {
		tlsConfig.VerifyConnection = clientIdentity.verifyConnection
	}

	return tlsConfig, nil
}

type compiledClientCertificateIdentityConstraints struct {
	fieldPrefix         string
	commonNames         []string
	dnsNames            []string
	ipAddresses         []netip.Addr
	uriSANs             []string
	publicKeySHA256Pins []string
}

func compileClientCertificateIdentityConstraints(fieldPrefix string, cfg ListenTLSConfig) (compiledClientCertificateIdentityConstraints, error) {
	compiled := compiledClientCertificateIdentityConstraints{
		fieldPrefix:         fieldPrefix,
		commonNames:         make([]string, 0, len(cfg.CommonNames)),
		dnsNames:            make([]string, 0, len(cfg.DNSNames)),
		ipAddresses:         make([]netip.Addr, 0, len(cfg.IPAddresses)),
		uriSANs:             make([]string, 0, len(cfg.URISANs)),
		publicKeySHA256Pins: make([]string, 0, len(cfg.PublicKeySHA256Pins)),
	}

	values, err := normalizeNonEmptyStrings(fieldPrefix+".common_names", cfg.CommonNames)
	if err != nil {
		return compiled, err
	}
	compiled.commonNames = append(compiled.commonNames, values...)

	values, err = normalizeNonEmptyStrings(fieldPrefix+".dns_names", cfg.DNSNames)
	if err != nil {
		return compiled, err
	}
	compiled.dnsNames = append(compiled.dnsNames, values...)

	for _, raw := range cfg.IPAddresses {
		trimmed := strings.TrimSpace(raw)
		addr, err := netip.ParseAddr(trimmed)
		if err != nil || !addr.IsValid() {
			return compiled, fmt.Errorf("%s.ip_addresses entries must be valid IP addresses, got %q", fieldPrefix, raw)
		}
		compiled.ipAddresses = append(compiled.ipAddresses, addr.Unmap())
	}

	for _, raw := range cfg.URISANs {
		trimmed := strings.TrimSpace(raw)
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.String() == "" {
			return compiled, fmt.Errorf("%s.uri_sans entries must be valid URIs, got %q", fieldPrefix, raw)
		}
		compiled.uriSANs = append(compiled.uriSANs, parsed.String())
	}

	for _, raw := range cfg.PublicKeySHA256Pins {
		pin, err := normalizeSubjectPublicKeySHA256Pin(raw)
		if err != nil {
			return compiled, fmt.Errorf("%s.public_key_sha256_pins entries must be lowercase or uppercase hex SHA-256 digests, got %q", fieldPrefix, raw)
		}
		compiled.publicKeySHA256Pins = append(compiled.publicKeySHA256Pins, pin)
	}

	return compiled, nil
}

func (c compiledClientCertificateIdentityConstraints) hasSelectors() bool {
	return len(c.commonNames) > 0 ||
		len(c.dnsNames) > 0 ||
		len(c.ipAddresses) > 0 ||
		len(c.uriSANs) > 0 ||
		len(c.publicKeySHA256Pins) > 0
}

func (c compiledClientCertificateIdentityConstraints) verifyConnection(state tls.ConnectionState) error {
	prefix := c.fieldPrefix
	if prefix == "" {
		prefix = "listen.tls"
	}
	leaf, err := verifiedClientCertificateLeaf(state)
	if err != nil {
		return fmt.Errorf("verify %s client certificate identity: %w", prefix, err)
	}
	if !c.matches(leaf) {
		return fmt.Errorf("verify %s client certificate identity: client certificate not allowed", prefix)
	}
	return nil
}

func (c compiledClientCertificateIdentityConstraints) matches(cert *x509.Certificate) bool {
	if cert == nil || !c.hasSelectors() {
		return false
	}
	if len(c.commonNames) > 0 && !containsExactString(c.commonNames, strings.TrimSpace(cert.Subject.CommonName)) {
		return false
	}
	if len(c.dnsNames) > 0 && !intersectsStrings(c.dnsNames, cert.DNSNames) {
		return false
	}
	if len(c.ipAddresses) > 0 && !certmatch.IntersectsIPAddrs(c.ipAddresses, cert.IPAddresses) {
		return false
	}
	if len(c.uriSANs) > 0 && !intersectsStrings(c.uriSANs, certmatch.CertificateURIStrings(cert)) {
		return false
	}
	if len(c.publicKeySHA256Pins) > 0 && !containsPinConstantTime(c.publicKeySHA256Pins, subjectPublicKeySHA256Hex(cert)) {
		return false
	}
	return true
}

// containsPinConstantTime reports whether candidate matches any configured
// public-key pin using a constant-time byte comparison. It evaluates every pin
// (no early return) so neither the per-byte digest comparison nor the position
// of a matching pin within the set is observable through timing.
func containsPinConstantTime(pins []string, candidate string) bool {
	candidateBytes := []byte(candidate)
	matched := 0
	for _, pin := range pins {
		matched |= subtle.ConstantTimeCompare([]byte(pin), candidateBytes)
	}
	return matched == 1
}

func verifiedClientCertificateLeaf(state tls.ConnectionState) (*x509.Certificate, error) {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("no verified client certificate")
	}
	return state.VerifiedChains[0][0], nil
}

func normalizeNonEmptyStrings(field string, values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, fmt.Errorf("%s entries must be non-empty", field)
		}
		normalized = append(normalized, trimmed)
	}
	return normalized, nil
}

func normalizeSubjectPublicKeySHA256Pin(raw string) (string, error) {
	return pkipin.NormalizeSubjectPublicKeySHA256Pin(raw)
}

func containsExactString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func intersectsStrings(allowed []string, actual []string) bool {
	for _, candidate := range actual {
		if containsExactString(allowed, candidate) {
			return true
		}
	}
	return false
}

func subjectPublicKeySHA256Hex(cert *x509.Certificate) string {
	return pkipin.SubjectPublicKeySHA256Hex(cert)
}

// IsLoopbackTCPAddress reports whether address resolves to a loopback TCP host.
func IsLoopbackTCPAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsNonLoopbackTCPAddress reports whether address is a valid non-loopback TCP
// host:port pair.
func IsNonLoopbackTCPAddress(address string) bool {
	return !IsLoopbackTCPAddress(address)
}

// ValidationError holds multiple validation errors.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation failed:\n  - %s", strings.Join(e.Errors, "\n  - "))
}

// Validate checks a Config for correctness, returning a ValidationError
// if any problems are found.
func Validate(cfg *Config) error {
	errs := validateBasic(cfg)
	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

func validateBasic(cfg *Config) []string {
	var errs []string
	errs = append(errs, validateListeners(cfg)...)
	errs = append(errs, validateUpstream(cfg)...)
	errs = append(errs, validateLogging(cfg)...)
	errs = append(errs, validateResponse(cfg)...)
	errs = append(errs, validateHealthMetrics(cfg)...)
	if cfg.Admin.Enabled {
		errs = append(errs, validateAdmin(cfg)...)
	}
	errs = append(errs, validateReload(cfg)...)
	errs = append(errs, validatePolicyBundle(cfg)...)
	errs = append(errs, validateRequestBody(cfg)...)
	errs = append(errs, validateMutationsConfig(cfg)...)
	errs = append(errs, validateRules(cfg)...)
	return errs
}

// validateListeners validates either the legacy singular listen: block or,
// when non-empty, the explicit listeners: list — never both. The two modes
// are mutually exclusive: cfg.explicitLegacyListen (populated by Load's
// provenance pass, or by Config.MarkLegacyListenExplicit for the
// --listen-socket CLI flag) records whether listen.* was set through any
// channel other than its zero-value default, so a config that sets both is
// rejected rather than silently picking a winner.
func validateListeners(cfg *Config) []string {
	var errs []string
	if len(cfg.Listeners) > 0 {
		if cfg.explicitLegacyListen {
			errs = append(errs, "listen and listeners are mutually exclusive; migrate the listen: block into a single-entry listeners: list")
		}
		errs = append(errs, validateExplicitListeners(cfg)...)
		errs = append(errs, validateExplicitListenersBindUniqueness(cfg)...)
		return errs
	}
	return validateLegacyListen(cfg)
}

func validateLegacyListen(cfg *Config) []string {
	var errs []string
	if cfg.Listen.Socket == "" && cfg.Listen.Address == "" {
		errs = append(errs, "at least one listener is required (listen.socket or listen.address)")
	}
	if cfg.Listen.Socket != "" {
		errs = append(errs, validateSocketOwnership("listen", cfg.Listen)...)
	}
	if cfg.Listen.Socket == "" && cfg.Listen.Address != "" {
		errs = append(errs, validateTCPListenerSecurity(cfg)...)
	}
	return errs
}

// validateExplicitListeners validates each entry of the explicit
// listeners: list: name shape/uniqueness/reservation, the listeners cap,
// exactly-one-of-socket-or-address (stricter than the legacy implicit
// socket-wins fallback — new entries reject ambiguity outright), per-entry
// TLS/plaintext-ack/ownership security, and the allowed_profiles scope.
func validateExplicitListeners(cfg *Config) []string {
	var errs []string

	if len(cfg.Listeners) > MaxListeners {
		errs = append(errs, fmt.Sprintf("listeners must contain at most %d entries, got %d", MaxListeners, len(cfg.Listeners)))
	}

	profileNames := clientProfileNameSet(cfg)
	seenNames := make(map[string]struct{}, len(cfg.Listeners))

	for i, l := range cfg.Listeners {
		indexPrefix := fmt.Sprintf("listeners[%d]", i)
		name := l.Name

		switch {
		case name == "":
			errs = append(errs, requiredFieldError(indexPrefix+".name"))
		case !ValidListenerName(name):
			errs = append(errs, fmt.Sprintf("%s.name %q must match ^[a-z][a-z0-9-]{0,62}$", indexPrefix, name))
		case name == AdminListenerName:
			errs = append(errs, fmt.Sprintf("%s.name must not be %q (reserved for the dedicated admin listener)", indexPrefix, AdminListenerName))
		default:
			if _, dup := seenNames[name]; dup {
				errs = append(errs, uniqueValueError("listeners[*].name", name))
			}
			seenNames[name] = struct{}{}
		}

		label := indexPrefix
		if name != "" {
			label = fmt.Sprintf("listeners[%s]", name)
		}

		hasSocket := l.Socket != ""
		hasAddress := l.Address != ""
		switch {
		case hasSocket && hasAddress:
			errs = append(errs, fmt.Sprintf("%s: exactly one of socket or address is required, got both", label))
		case !hasSocket && !hasAddress:
			errs = append(errs, fmt.Sprintf("%s: exactly one of socket or address is required", label))
		case hasSocket:
			errs = append(errs, validateSocketOwnership(label, l.ListenConfig)...)
			if l.TLS.Enabled() {
				errs = append(errs, label+".tls is only valid for TCP listeners")
			}
		default:
			errs = append(errs, validateListenerTCPSecurity(label, l.ListenConfig)...)
			if l.SocketUID != nil {
				errs = append(errs, label+".socket_uid is only valid for unix listeners")
			}
			if l.SocketGID != nil {
				errs = append(errs, label+".socket_gid is only valid for unix listeners")
			}
		}

		errs = append(errs, validateAllowedProfiles(label, l.AllowedProfiles, profileNames)...)
	}

	return errs
}

// validateExplicitListenersBindUniqueness enforces all-pairs distinctness of
// every configured bind target — every listeners[*] socket path pairwise
// distinct, every listeners[*] TCP address pairwise distinct, and each
// checked again against the dedicated admin listener when configured. O(n^2)
// over an operator-authored, small (single-digit to low-dozens) list.
func validateExplicitListenersBindUniqueness(cfg *Config) []string {
	type bindTarget struct {
		label      string
		kind       string // "socket" or "address"
		value      string
		comparison string
	}
	newBindTarget := func(label, kind, value string) bindTarget {
		comparison := value
		if kind == "address" {
			comparison = normalizeTCPBindTarget(value)
		}
		return bindTarget{label: label, kind: kind, value: value, comparison: comparison}
	}

	var targets []bindTarget
	for _, l := range cfg.Listeners {
		label := fmt.Sprintf("listeners[%s]", l.Name)
		if l.Socket != "" {
			targets = append(targets, newBindTarget(label, "socket", l.Socket))
		}
		if l.Address != "" {
			targets = append(targets, newBindTarget(label, "address", l.Address))
		}
	}
	if cfg.Admin.Listen.Configured() {
		if cfg.Admin.Listen.Socket != "" {
			targets = append(targets, newBindTarget("admin.listen", "socket", cfg.Admin.Listen.Socket))
		}
		if cfg.Admin.Listen.Address != "" {
			targets = append(targets, newBindTarget("admin.listen", "address", cfg.Admin.Listen.Address))
		}
	}

	var errs []string
	for i := 0; i < len(targets); i++ {
		for j := i + 1; j < len(targets); j++ {
			if targets[i].kind != targets[j].kind || targets[i].comparison != targets[j].comparison {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s.%s and %s.%s must be distinct, both are %q",
				targets[i].label, targets[i].kind, targets[j].label, targets[j].kind, targets[i].value))
		}
	}
	return errs
}

// normalizeTCPBindTarget canonicalizes only representations known to name the
// same literal endpoint without DNS or interface lookups: IP spelling,
// case-insensitive hostnames, and leading zeroes on numeric ports. Wildcard
// versus specific addresses and all other kernel-dependent conflicts remain
// the bind barrier's responsibility.
func normalizeTCPBindTarget(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if parsed, parseErr := netip.ParseAddr(host); parseErr == nil {
		host = parsed.String()
	} else {
		host = strings.ToLower(host)
	}
	if parsed, parseErr := strconv.ParseUint(port, 10, 16); parseErr == nil {
		port = strconv.FormatUint(parsed, 10)
	}
	return net.JoinHostPort(host, port)
}

// validateAllowedProfiles validates one listener's allowed_profiles scope:
// required and non-empty, the wildcard "*" cannot combine with concrete
// names, entries must be unique, and concrete names must reference a
// configured clients.profiles entry.
func validateAllowedProfiles(label string, allowed []string, profileNames map[string]struct{}) []string {
	field := label + ".allowed_profiles"
	if len(allowed) == 0 {
		return []string{containsAtLeastOneError(field, `profile name (or the wildcard "*")`)}
	}

	var errs []string
	hasWildcard := false
	for _, p := range allowed {
		if p == WildcardProfile {
			hasWildcard = true
			break
		}
	}
	if hasWildcard {
		if len(allowed) > 1 {
			errs = append(errs, fmt.Sprintf("%s: %q cannot be combined with concrete profile names", field, WildcardProfile))
		}
		return errs
	}

	seen := make(map[string]struct{}, len(allowed))
	for _, p := range allowed {
		if _, dup := seen[p]; dup {
			errs = append(errs, uniqueValueError(field, p))
			continue
		}
		seen[p] = struct{}{}
		if _, ok := profileNames[p]; !ok {
			errs = append(errs, configuredMatchError(field, "client profile", p))
		}
	}
	return errs
}

// clientProfileNameSet returns the set of configured clients.profiles names,
// trimmed. It is a lightweight companion to validateClientProfile's own
// duplicate-detecting walk (validateClientsConfig) — listener validation
// only needs membership, not the full per-profile diagnostics.
func clientProfileNameSet(cfg *Config) map[string]struct{} {
	names := make(map[string]struct{}, len(cfg.Clients.Profiles))
	for _, p := range cfg.Clients.Profiles {
		if name := strings.TrimSpace(p.Name); name != "" {
			names[name] = struct{}{}
		}
	}
	return names
}

// validateSocketOwnership validates a unix-socket listener's socket_mode and
// optional socket_uid/socket_gid. Exactly two modes are supported:
// HardenedListenSocketMode ("0600", the default — no ownership fields
// required) and GroupReadableListenSocketMode ("0660" — requires an
// explicit socket_gid so a group-shared socket is always an affirmative,
// per-listener operator choice). Applies to legacy listen:, each
// listeners[*] entry, and (additively, via validateAdminListener)
// admin.listen.
func validateSocketOwnership(prefix string, listen ListenConfig) []string {
	var errs []string

	switch strings.TrimSpace(listen.SocketMode) {
	case HardenedListenSocketMode:

	case GroupReadableListenSocketMode:
		if listen.SocketGID == nil {
			errs = append(errs, fmt.Sprintf(
				"%s.socket_mode %q requires %s.socket_gid to be set explicitly; omit socket_gid and use %q for the default owner-only mode",
				prefix, GroupReadableListenSocketMode, prefix, HardenedListenSocketMode,
			))
		}
	default:
		errs = append(errs, fmt.Sprintf(
			"%s.socket_mode must be %q or %q (the latter requires %s.socket_gid), got %q",
			prefix, HardenedListenSocketMode, GroupReadableListenSocketMode, prefix, listen.SocketMode,
		))
	}

	if listen.SocketUID != nil && *listen.SocketUID < 0 {
		errs = append(errs, fmt.Sprintf("%s.socket_uid must be >= 0, got %d", prefix, *listen.SocketUID))
	}
	if listen.SocketGID != nil && *listen.SocketGID < 0 {
		errs = append(errs, fmt.Sprintf("%s.socket_gid must be >= 0, got %d", prefix, *listen.SocketGID))
	}

	return errs
}

// validateListenerTCPSecurity is validateTCPListenerSecurity generalized to
// an arbitrary field prefix and ListenConfig value, so it can validate any
// listeners[*] entry's TCP/TLS/plaintext-ack posture with the same
// constructive checks the legacy listen: block gets.
func validateListenerTCPSecurity(prefix string, listen ListenConfig) []string {
	var errs []string

	if listen.TLS.Enabled() && !listen.TLS.Complete() {
		errs = append(errs, requiresError(prefix+".tls", "cert_file, key_file, and client_ca_file together"))
		return errs
	}

	if listen.TLS.Complete() {
		if _, err := BuildMutualTLSServerConfigForField(prefix+".tls", listen.TLS); err != nil {
			errs = append(errs, err.Error())
		}
	}

	errs = append(errs, plainTCPListenerErrors("TCP listener", prefix, listen)...)

	return errs
}

// validateAdminMountOn validates Admin.MountOn: required when admin rides a
// main listener (no dedicated admin.listen) and there are 2+ effective main
// listeners; when set, must name one of them. Ignored (may be empty) with a
// dedicated admin listener or exactly one effective main listener, matching
// today's zero-config "admin rides the sole main listener" behavior.
func validateAdminMountOn(cfg *Config) []string {
	if cfg.Admin.Listen.Configured() {
		return nil
	}
	effective := cfg.EffectiveListeners()
	if len(effective) <= 1 {
		return nil
	}
	if cfg.Admin.MountOn == "" {
		return []string{"admin.mount_on is required when admin.enabled=true, admin.listen is not configured, and there is more than one effective main listener"}
	}
	for _, l := range effective {
		if l.Name == cfg.Admin.MountOn {
			return nil
		}
	}
	return []string{configuredMatchError("admin.mount_on", "listener name", cfg.Admin.MountOn)}
}

// plainTCPListenerErrors validates a non-loopback TCP listener that is not
// protected by mutual TLS. label is the human noun ("TCP listener" /
// "TCP admin listener") and prefix is the config path ("listen" /
// "admin.listen"). Legacy plaintext beyond loopback is permitted only behind
// BOTH insecure opt-ins: insecure_allow_plain_tcp acknowledges the unencrypted
// transport and insecure_allow_unauthenticated_clients acknowledges that any
// host able to reach the port can impersonate a client. Requiring two
// deliberate acknowledgments means a single fat-fingered flag cannot reach the
// dangerous mode.
func plainTCPListenerErrors(label, prefix string, listen ListenConfig) []string {
	if !IsNonLoopbackTCPAddress(listen.Address) || listen.TLS.Complete() {
		return nil
	}
	if listen.InsecureAllowPlainTCP && listen.InsecureAllowUnauthenticatedClients {
		return nil
	}
	return []string{fmt.Sprintf(
		"non-loopback %s %q requires %s.tls mutual TLS configuration, or — for legacy plaintext on a private trusted network — both %s.insecure_allow_plain_tcp=true and %s.insecure_allow_unauthenticated_clients=true (one acknowledgment without the other is rejected)",
		label, listen.Address, prefix, prefix, prefix,
	)}
}

func validateUpstream(cfg *Config) []string {
	var errs []string

	if len(cfg.Upstream.Endpoints) == 0 && cfg.Upstream.Socket == "" {
		errs = append(errs, "upstream requires either upstream.socket or at least one upstream.endpoints entry")
	}
	for i, ep := range cfg.Upstream.Endpoints {
		if err := upstream.ValidateSpec(endpointSpec(ep)); err != nil {
			errs = append(errs, fmt.Sprintf("upstream.endpoints[%d]: %v", i, err))
		}
	}
	if !cfg.Upstream.RequestTimeoutDisabled() {
		timeout, err := time.ParseDuration(cfg.Upstream.RequestTimeout)
		if err != nil || timeout <= 0 {
			errs = append(errs, fmt.Sprintf(`upstream.request_timeout must be a positive duration or "off" to disable, got %q`, cfg.Upstream.RequestTimeout))
		}
	}
	if d := cfg.Upstream.Failover.HealthInterval; d != "" {

		if parsed, err := time.ParseDuration(d); err != nil {
			errs = append(errs, fmt.Sprintf("upstream.failover.health_interval must be a Go duration, got %q", d))
		} else if parsed == 0 {
			errs = append(errs, "upstream.failover.health_interval must be non-zero: use a negative duration to disable probing, or omit it for the 5s default")
		}
	}
	if d := cfg.Upstream.Failover.HealthTimeout; d != "" {
		if t, err := time.ParseDuration(d); err != nil || t <= 0 {
			errs = append(errs, fmt.Sprintf("upstream.failover.health_timeout must be a positive duration, got %q", d))
		}
	}
	return errs
}

// endpointSpec adapts a config UpstreamEndpoint to an upstream.EndpointSpec.
func endpointSpec(ep UpstreamEndpoint) upstream.EndpointSpec {
	return upstream.EndpointSpec{
		Address:               ep.Address,
		CAFile:                ep.TLS.CAFile,
		CertFile:              ep.TLS.CertFile,
		KeyFile:               ep.TLS.KeyFile,
		ServerName:            ep.TLS.ServerName,
		InsecureAllowPlainTCP: ep.InsecureAllowPlainTCP,
		InsecureSkipTLSVerify: ep.InsecureSkipTLSVerify,
	}
}

func validateLogging(cfg *Config) []string {
	var errs []string
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, enumValueError("log.level", cfg.Log.Level, "debug", "info", "warn", "error"))
	}
	switch cfg.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, enumValueError("log.format", cfg.Log.Format, "json", "text"))
	}
	if err := validateLogOutput(cfg.Log.Output); err != nil {
		errs = append(errs, err.Error())
	}
	if cfg.Log.Audit.Enabled {
		if cfg.Log.Audit.Format != "json" {
			errs = append(errs, fmt.Sprintf("log.audit.format must be json, got %q", cfg.Log.Audit.Format))
		}
		if err := validateLogOutputField("log.audit.output", cfg.Log.Audit.Output); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

func validateResponse(cfg *Config) []string {
	var errs []string
	switch cfg.Response.DenyVerbosity {
	case "minimal", "verbose":
	default:
		errs = append(errs, enumValueError("response.deny_verbosity", cfg.Response.DenyVerbosity, "minimal", "verbose"))
	}
	errs = append(errs, validateVisibleResourceLabels("response.visible_resource_labels", cfg.Response.VisibleResourceLabels)...)
	return errs
}

func validateHealthMetrics(cfg *Config) []string {
	var errs []string
	if cfg.Health.Enabled && !strings.HasPrefix(cfg.Health.Path, "/") {
		errs = append(errs, fmt.Sprintf("health.path must start with /, got %q", cfg.Health.Path))
	}
	if cfg.Health.Watchdog.Enabled {
		interval, err := time.ParseDuration(cfg.Health.Watchdog.Interval)
		if err != nil || interval <= 0 {
			errs = append(errs, fmt.Sprintf("health.watchdog.interval must be a positive duration, got %q", cfg.Health.Watchdog.Interval))
		}
	}
	if cfg.Health.Readiness.Enabled {
		if !strings.HasPrefix(cfg.Health.Readiness.Path, "/") {
			errs = append(errs, fmt.Sprintf("health.readiness.path must start with /, got %q", cfg.Health.Readiness.Path))
		}
		if interval, err := time.ParseDuration(cfg.Health.Readiness.Interval); err != nil || interval <= 0 {
			errs = append(errs, fmt.Sprintf("health.readiness.interval must be a positive duration, got %q", cfg.Health.Readiness.Interval))
		}
		if timeout, err := time.ParseDuration(cfg.Health.Readiness.Timeout); err != nil || timeout <= 0 {
			errs = append(errs, fmt.Sprintf("health.readiness.timeout must be a positive duration, got %q", cfg.Health.Readiness.Timeout))
		}
		if cfg.Health.Enabled && cfg.Health.Readiness.Path == cfg.Health.Path {
			errs = append(errs, fmt.Sprintf("health.readiness.path must not equal health.path, got %q", cfg.Health.Readiness.Path))
		}
		if cfg.Metrics.Enabled && cfg.Health.Readiness.Path == cfg.Metrics.Path {
			errs = append(errs, fmt.Sprintf("health.readiness.path must not equal metrics.path, got %q", cfg.Health.Readiness.Path))
		}
		if cfg.Admin.Enabled && cfg.Health.Readiness.Path == cfg.Admin.Path {
			errs = append(errs, fmt.Sprintf("health.readiness.path must not equal admin.path, got %q", cfg.Health.Readiness.Path))
		}
	}
	if cfg.Metrics.Enabled && !strings.HasPrefix(cfg.Metrics.Path, "/") {
		errs = append(errs, fmt.Sprintf("metrics.path must start with /, got %q", cfg.Metrics.Path))
	}
	if cfg.Health.Enabled && cfg.Metrics.Enabled && cfg.Health.Path == cfg.Metrics.Path {
		errs = append(errs, fmt.Sprintf("metrics.path must not equal health.path when both endpoints are enabled, got %q", cfg.Metrics.Path))
	}
	return errs
}

func validateAdmin(cfg *Config) []string {
	var errs []string
	if !strings.HasPrefix(cfg.Admin.Path, "/") {
		errs = append(errs, fmt.Sprintf("admin.path must start with /, got %q", cfg.Admin.Path))
	}
	if cfg.Admin.MaxRequestBytes <= 0 {
		errs = append(errs, fmt.Sprintf("admin.max_request_bytes must be > 0, got %d", cfg.Admin.MaxRequestBytes))
	}
	if cfg.Health.Enabled && cfg.Admin.Path == cfg.Health.Path {
		errs = append(errs, fmt.Sprintf("admin.path must not equal health.path when both endpoints are enabled, got %q", cfg.Admin.Path))
	}
	if cfg.Metrics.Enabled && cfg.Admin.Path == cfg.Metrics.Path {
		errs = append(errs, fmt.Sprintf("admin.path must not equal metrics.path when both endpoints are enabled, got %q", cfg.Admin.Path))
	}
	if !strings.HasPrefix(cfg.Admin.PolicyVersionPath, "/") {
		errs = append(errs, fmt.Sprintf("admin.policy_version_path must start with /, got %q", cfg.Admin.PolicyVersionPath))
	}
	if cfg.Admin.PolicyVersionPath == cfg.Admin.Path {
		errs = append(errs, fmt.Sprintf("admin.policy_version_path must not equal admin.path, got %q", cfg.Admin.PolicyVersionPath))
	}
	if cfg.Health.Enabled && cfg.Admin.PolicyVersionPath == cfg.Health.Path {
		errs = append(errs, fmt.Sprintf("admin.policy_version_path must not equal health.path when both endpoints are enabled, got %q", cfg.Admin.PolicyVersionPath))
	}
	if cfg.Metrics.Enabled && cfg.Admin.PolicyVersionPath == cfg.Metrics.Path {
		errs = append(errs, fmt.Sprintf("admin.policy_version_path must not equal metrics.path when both endpoints are enabled, got %q", cfg.Admin.PolicyVersionPath))
	}
	errs = append(errs, validateAdminListener(cfg)...)
	errs = append(errs, validateAdminMountOn(cfg)...)
	return errs
}

func validateReload(cfg *Config) []string {
	if !cfg.Reload.Enabled {
		return nil
	}
	var errs []string
	if cfg.Reload.Debounce != "" {
		if d, err := time.ParseDuration(cfg.Reload.Debounce); err != nil {
			errs = append(errs, fmt.Sprintf("reload.debounce must be a valid Go duration string, got %q", cfg.Reload.Debounce))
		} else if d < 0 {
			errs = append(errs, fmt.Sprintf("reload.debounce must be >= 0, got %q", cfg.Reload.Debounce))
		}
	}
	if cfg.Reload.PollInterval != "" {
		if d, err := time.ParseDuration(cfg.Reload.PollInterval); err != nil {
			errs = append(errs, fmt.Sprintf("reload.poll_interval must be a valid Go duration string, got %q", cfg.Reload.PollInterval))
		} else if d < 0 {
			errs = append(errs, fmt.Sprintf("reload.poll_interval must be >= 0, got %q", cfg.Reload.PollInterval))
		}
	}
	return errs
}

func validateRules(cfg *Config) []string {
	var errs []string
	if len(cfg.Rules) == 0 {
		errs = append(errs, containsAtLeastOneError("rules", "rule"))
	}
	for i, r := range cfg.Rules {
		if r.Match.Method == "" {
			errs = append(errs, fmt.Sprintf("rule %d: match.method is required", i+1))
		}
		if r.Match.Path == "" {
			errs = append(errs, fmt.Sprintf("rule %d: match.path is required", i+1))
		} else if strings.Contains(r.Match.Path, "%") {
			errs = append(errs, literalPercentRuleError(fmt.Sprintf("rule %d", i+1), r.Match.Path))
		}
		switch r.Action {
		case "allow", "deny":
		default:
			errs = append(errs, fmt.Sprintf("rule %d: %s", i+1, enumValueError("action", r.Action, "allow", "deny")))
		}
	}
	return errs
}

// literalPercentRuleError reports a rule path pattern that contains a literal
// '%'. sockguard matches the request path as the daemon routes it — decoded
// exactly once by the HTTP layer — so a '%XX' in a pattern only ever matches a
// doubly-encoded request, never normal traffic. The rule the author meant is
// therefore silently dead, a security-intent gap, so it fails config
// validation rather than logging a warning.
func literalPercentRuleError(label, pattern string) string {
	return fmt.Sprintf(
		"%s: match.path %q contains a literal '%%'; sockguard matches the path as the daemon routes it (decoded once at the HTTP layer), so a '%%XX' here matches only a doubly-encoded request and never normal traffic — write the decoded form",
		label, pattern,
	)
}

// validateAdminListener validates the optional dedicated admin listener. It
// only runs when cfg.Admin.Enabled is true; an unconfigured Listen sub-block
// (Socket == "" && Address == "") is the documented "ride the main listener"
// mode and is intentionally a no-op here.
//
// Errors mirror the main-listener validators: a socket listener must use the
// hardened owner-only socket mode, a partially-configured TLS block is
// rejected, a complete TLS block is constructively validated by loading the
// material, and a non-loopback plaintext TCP listener requires the same
// two-flag insecure opt-in (admin.listen.insecure_allow_plain_tcp=true plus
// admin.listen.insecure_allow_unauthenticated_clients=true) that the main
// listener requires. The admin listener must also point at a different
// socket/address than the main listener — otherwise the two http.Servers
// would race for the same bind and the dedicated-listener model would be a
// silent lie.
func validateAdminListener(cfg *Config) []string {
	listen := cfg.Admin.Listen
	if !listen.Configured() {
		return nil
	}

	var errs []string

	if listen.Socket != "" && listen.Address != "" {
		errs = append(errs, "admin.listen.socket and admin.listen.address are mutually exclusive; configure one")
	}

	if listen.Socket != "" {
		errs = append(errs, validateSocketOwnership("admin.listen", listen.ListenConfig)...)
		if cfg.Listen.Socket != "" && cfg.Listen.Socket == listen.Socket {
			errs = append(errs, fmt.Sprintf("admin.listen.socket must differ from listen.socket, got %q", listen.Socket))
		}
	}

	if listen.Address != "" {
		if listen.TLS.Enabled() && !listen.TLS.Complete() {
			errs = append(errs, requiresError("admin.listen.tls", "cert_file, key_file, and client_ca_file together"))
		} else if listen.TLS.Complete() {
			if _, err := BuildMutualTLSServerConfigForField("admin.listen.tls", listen.TLS); err != nil {
				errs = append(errs, err.Error())
			}
		}

		errs = append(errs, plainTCPListenerErrors("TCP admin listener", "admin.listen", listen.ListenConfig)...)

		if !listen.TLS.Complete() && !IsLoopbackTCPAddress(listen.Address) &&
			len(cfg.Clients.AllowedCIDRs) == 0 && !listen.InsecureAllowWideOpen {
			errs = append(errs, "admin.listen.address is non-loopback plaintext TCP with no clients.allowed_cidrs: admin endpoints would accept unauthenticated requests from any source IP; configure admin.listen.tls (mutual TLS) or clients.allowed_cidrs, or acknowledge with admin.listen.insecure_allow_wide_open: true")
		}

		if cfg.Listen.Address != "" && cfg.Listen.Socket == "" && cfg.Listen.Address == listen.Address {
			errs = append(errs, fmt.Sprintf("admin.listen.address must differ from listen.address, got %q", listen.Address))
		}
	}

	return errs
}

func validateTCPListenerSecurity(cfg *Config) []string {
	var errs []string

	if cfg.Listen.TLS.Enabled() && !cfg.Listen.TLS.Complete() {
		errs = append(errs, requiresError("listen.tls", "cert_file, key_file, and client_ca_file together"))
		return errs
	}

	if cfg.Listen.TLS.Complete() {
		if _, err := BuildMutualTLSServerConfig(cfg.Listen.TLS); err != nil {
			errs = append(errs, err.Error())
		}
	}

	errs = append(errs, plainTCPListenerErrors("TCP listener", "listen", cfg.Listen)...)

	return errs
}

// validateKeylessTrustEntries validates the common structure shared between
// policy_bundle and container_create.image_trust: a list of signing keys
// (each requiring a non-empty PEM field) and a list of keyless identities
// (each requiring a non-empty issuer and a valid subject_pattern regexp).
// prefix is the dot-separated config path of the parent block (e.g.
// "policy_bundle" or "request_body.container_create.image_trust") and
// appears verbatim in every returned error string.
func validateKeylessTrustEntries(prefix string, keys []signingKeyEntry, keyless []keylessEntry) []string {
	var errs []string

	for i, k := range keys {
		if strings.TrimSpace(k.PEM) == "" {
			errs = append(errs,
				fmt.Sprintf("%s.allowed_signing_keys[%d].pem is required", prefix, i),
			)
		}
	}

	for i, kl := range keyless {
		if strings.TrimSpace(kl.Issuer) == "" {
			errs = append(errs,
				fmt.Sprintf("%s.allowed_keyless[%d].issuer is required", prefix, i),
			)
		}
		if strings.TrimSpace(kl.SubjectPattern) == "" {
			errs = append(errs,
				fmt.Sprintf("%s.allowed_keyless[%d].subject_pattern is required", prefix, i),
			)
		} else if _, err := regexp.Compile(kl.SubjectPattern); err != nil {
			errs = append(errs,
				fmt.Sprintf("%s.allowed_keyless[%d].subject_pattern: %v", prefix, i, err),
			)
		}
	}

	return errs
}

// signingKeyEntry is the minimal shape shared by PolicyBundleSigningKey and
// SigningKeyConfig. It exists solely so validateKeylessTrustEntries can
// operate on both without duplicating logic.
type signingKeyEntry struct{ PEM string }

// keylessEntry is the minimal shape shared by PolicyBundleKeyless and
// KeylessConfig.
type keylessEntry struct{ Issuer, SubjectPattern string }

// validatePolicyBundle validates the policy_bundle sub-block. The verifier
// itself enforces deeper structural checks (PEM parsing, regex compilation,
// etc.) at startup; here we only catch the cases the operator can fix from
// the config file alone.
func validatePolicyBundle(cfg *Config) []string {
	pb := cfg.PolicyBundle
	if !pb.Enabled {
		return nil
	}

	var errs []string

	if strings.TrimSpace(pb.SignaturePath) == "" {
		errs = append(errs, requiredFieldError("policy_bundle.signature_path"))
	}

	if len(pb.AllowedSigningKeys) == 0 && len(pb.AllowedKeyless) == 0 {
		errs = append(errs,
			"policy_bundle: enabled=true requires at least one allowed_signing_keys or allowed_keyless entry",
		)
	}

	keys := make([]signingKeyEntry, len(pb.AllowedSigningKeys))
	for i, k := range pb.AllowedSigningKeys {
		keys[i] = signingKeyEntry(k)
	}
	kls := make([]keylessEntry, len(pb.AllowedKeyless))
	for i, kl := range pb.AllowedKeyless {
		kls[i] = keylessEntry(kl)
	}
	errs = append(errs, validateKeylessTrustEntries("policy_bundle", keys, kls)...)

	if pb.VerifyTimeout != "" {
		d, err := time.ParseDuration(pb.VerifyTimeout)
		if err != nil || d <= 0 {
			errs = append(errs,
				fmt.Sprintf("policy_bundle.verify_timeout must be a positive duration, got %q", pb.VerifyTimeout),
			)
		}
	}

	return errs
}

// validateRequestBody runs the request-body inspection schema check plus the
// full client-routing / ownership cross-field validation. The work is split
// into focused helpers below so each section's preconditions are visible at
// the call site rather than buried 100+ lines deep in one function.
func validateRequestBody(cfg *Config) []string {
	var errs []string
	errs = append(errs, validateRequestBodyConfig("request_body", cfg.RequestBody)...)
	errs = append(errs, validateNetworkEndpointConfig(cfg)...)
	errs = append(errs, validateBuildkitAckMutualExclusion(cfg)...)
	errs = append(errs, validateClientsConfig(cfg)...)
	if cfg.Ownership.Owner != "" && cfg.Ownership.LabelKey == "" {
		errs = append(errs, requiredWhenError("ownership.label_key", "ownership.owner is set"))
	}
	return errs
}

// validateNetworkEndpointConfig rejects
// request_body.network.allow_endpoint_config: true combined with an
// explicitly configured request_body.network.endpoint_config block (#186):
// allow_endpoint_config already admits every EndpointSettings field
// unchanged, so a simultaneous granular block is ambiguous — which one an
// operator actually intends to govern the request is not something sockguard
// should guess at silently. Detected via cfg.explicitNetworkEndpointConfig
// (a provenance-only Viper pass; see explicitNetworkEndpointConfigFile/Bytes
// in load.go) rather than comparing cfg.RequestBody.Network.EndpointConfig
// against its Go zero value, because EndpointConfigRequestBodyConfig.AllowAliases
// defaults to true (config.Defaults()), so the merged struct is never the
// zero value even when the operator never wrote the block at all.
func validateNetworkEndpointConfig(cfg *Config) []string {
	if cfg.RequestBody.Network.AllowEndpointConfig && cfg.explicitNetworkEndpointConfig {
		return []string{
			"request_body.network.allow_endpoint_config and request_body.network.endpoint_config are mutually exclusive: allow_endpoint_config: true already admits every EndpointSettings field, so remove the endpoint_config block or set allow_endpoint_config: false and use the granular fields instead",
		}
	}
	return nil
}

// validateBuildkitAckMutualExclusion rejects
// insecure_accept_opaque_buildkit_tunnels: true combined with a configured
// request_body.buildkit block (issue #185 phase 1) — either top-level or on
// any client profile. Mediation supersedes the opaque-tunnel acknowledgment
// per the #185 sign-off ("the wholesale ack and the mediator never stack");
// requiring the operator to pick one avoids the ambiguous state of a
// profile declaring real BuildKit policy while the global ack quietly
// admits the same endpoints with zero inspection. This mirrors #186's
// mutual-exclusion pattern for network.allow_endpoint_config vs
// network.endpoint_config, adapted to Policy.Configured's plain zero-value
// check (see buildkitproxy.Policy.Configured's doc comment for why no
// Viper-provenance tracking is needed here).
func validateBuildkitAckMutualExclusion(cfg *Config) []string {
	if !cfg.InsecureAcceptOpaqueBuildkitTunnels {
		return nil
	}
	var errs []string
	if cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Configured() {
		errs = append(errs, "insecure_accept_opaque_buildkit_tunnels and request_body.buildkit are mutually exclusive: mediation supersedes the opaque-tunnel acknowledgment, so set insecure_accept_opaque_buildkit_tunnels: false and configure request_body.buildkit instead, or remove the request_body.buildkit block and keep the acknowledgment")
	}
	for _, profile := range cfg.Clients.Profiles {
		if !profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build).Configured() {
			continue
		}
		errs = append(errs, fmt.Sprintf("client profile %q configures request_body.buildkit, but the top-level insecure_accept_opaque_buildkit_tunnels=true acknowledgment (a global setting, not per-profile) would otherwise admit the same opaque tunnel with zero inspection for this profile too: set insecure_accept_opaque_buildkit_tunnels: false", profile.Name))
	}
	return errs
}

// Admission-mutation config bounds (#151). These are deliberately generous
// (a legitimate config needs far fewer than 64 rules or 256 total injected
// labels) but bound the strict-decoded mutations subtree against pathological
// configs before it ever reaches the compiled filter.mutationEngine.
const (
	maxMutationRules           = 64
	maxMutationLabelsPerRule   = 32
	maxMutationLabelsTotal     = 256
	maxMutationLabelKeyBytes   = 128
	maxMutationLabelValueBytes = 4096
	maxMutationImageFieldBytes = 4096
)

var mutationRuleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var validMutationSurfaces = map[string]struct{}{
	"container_create": {},
	"service_create":   {},
	"service_update":   {},
}

// mutationImageOverlapEntry is one valid remap_image rule's overlap-check
// shape, collected while validating each rule and checked pairwise by
// validateMutationImageOverlaps once every rule has been walked.
type mutationImageOverlapEntry struct {
	prefix   string
	surfaces []string
	match    string
	from     string
}

// mutationLabelClaim is one valid inject_labels rule's (surface, key) claim,
// collected the same way and checked by validateMutationLabelOverlaps.
type mutationLabelClaim struct {
	prefix  string
	surface string
	key     string
}

// validateMutationsConfig validates the mutations.rules[] block (#151):
// bounds, per-rule id/mode/surfaces, exactly-one-of inject_labels/
// remap_image, label and image-reference shape, cross-rule overlap
// rejection, and the owner-label-key reservation.
func validateMutationsConfig(cfg *Config) []string {
	var errs []string
	rules := cfg.Mutations.Rules

	if len(rules) > maxMutationRules {
		errs = append(errs, fmt.Sprintf("mutations.rules must contain at most %d entries, got %d", maxMutationRules, len(rules)))
	}

	ids := make(map[string]struct{}, len(rules))
	totalLabels := 0
	var imageEntries []mutationImageOverlapEntry
	var labelClaims []mutationLabelClaim

	for i, rule := range rules {
		prefix := fmt.Sprintf("mutations.rules[%d]", i)

		if !mutationRuleIDPattern.MatchString(rule.ID) {
			errs = append(errs, fmt.Sprintf("%s.id must match %s, got %q", prefix, mutationRuleIDPattern.String(), rule.ID))
		} else if _, dup := ids[rule.ID]; dup {
			errs = append(errs, uniqueValueError(prefix+".id", rule.ID))
		} else {
			ids[rule.ID] = struct{}{}
		}

		if _, ok := ParseRolloutMode(rule.Mode); !ok {
			errs = append(errs, fmt.Sprintf("%s.mode must be one of enforce|warn|audit, got %q", prefix, rule.Mode))
		}

		errs = append(errs, validateMutationSurfaces(prefix, rule.Surfaces)...)

		switch {
		case rule.InjectLabels != nil && rule.RemapImage != nil:
			errs = append(errs, fmt.Sprintf("%s: exactly one of inject_labels or remap_image is required, got both", prefix))
		case rule.InjectLabels == nil && rule.RemapImage == nil:
			errs = append(errs, fmt.Sprintf("%s: exactly one of inject_labels or remap_image is required, got neither", prefix))
		case rule.InjectLabels != nil:
			labelErrs, claims := validateMutationInjectLabels(prefix, rule, cfg)
			errs = append(errs, labelErrs...)
			totalLabels += len(rule.InjectLabels.Labels)
			labelClaims = append(labelClaims, claims...)
		case rule.RemapImage != nil:
			imageErrs, entry := validateMutationRemapImage(prefix, rule)
			errs = append(errs, imageErrs...)
			if entry != nil {
				imageEntries = append(imageEntries, *entry)
			}
		}
	}

	if totalLabels > maxMutationLabelsTotal {
		errs = append(errs, fmt.Sprintf("mutations.rules: total inject_labels.labels entries across all rules must not exceed %d, got %d", maxMutationLabelsTotal, totalLabels))
	}

	errs = append(errs, validateMutationLabelOverlaps(labelClaims)...)
	errs = append(errs, validateMutationImageOverlaps(imageEntries)...)

	return errs
}

func validateMutationSurfaces(prefix string, surfaces []string) []string {
	var errs []string
	if len(surfaces) == 0 {
		errs = append(errs, containsAtLeastOneError(prefix+".surfaces", "surface"))
	}
	seen := make(map[string]struct{}, len(surfaces))
	for _, surface := range surfaces {
		if _, ok := validMutationSurfaces[surface]; !ok {
			errs = append(errs, enumValueError(prefix+".surfaces", surface, "container_create", "service_create", "service_update"))
			continue
		}
		if _, dup := seen[surface]; dup {
			errs = append(errs, fmt.Sprintf("%s.surfaces must not contain duplicate %q", prefix, surface))
			continue
		}
		seen[surface] = struct{}{}
	}
	return errs
}

// validateMutationInjectLabels validates one rule's inject_labels block and
// returns the (surface, key) claims validateMutationLabelOverlaps checks
// across every rule once the full list is known — only valid, non-empty keys
// are returned as claims, so a malformed key never produces a spurious
// overlap error on top of its own shape error.
func validateMutationInjectLabels(prefix string, rule MutationRuleConfig, cfg *Config) ([]string, []mutationLabelClaim) {
	var errs []string
	var claims []mutationLabelClaim

	for _, surface := range rule.Surfaces {
		if surface == "service_update" {
			errs = append(errs, fmt.Sprintf("%s.inject_labels is not valid on surface %q: service_update has no label field to mutate", prefix, surface))
		}
	}

	labels := rule.InjectLabels.Labels
	if len(labels) == 0 {
		errs = append(errs, containsAtLeastOneError(prefix+".inject_labels.labels", "label"))
	}
	if len(labels) > maxMutationLabelsPerRule {
		errs = append(errs, fmt.Sprintf("%s.inject_labels.labels must contain at most %d entries, got %d", prefix, maxMutationLabelsPerRule, len(labels)))
	}

	reservedLabelKey := ""
	if cfg.Ownership.Owner != "" {
		reservedLabelKey = cfg.Ownership.LabelKey
	}

	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		value := labels[key]
		valid := true
		if strings.TrimSpace(key) == "" {
			errs = append(errs, fmt.Sprintf("%s.inject_labels.labels keys must be non-empty", prefix))
			valid = false
		}
		if len(key) > maxMutationLabelKeyBytes {
			errs = append(errs, fmt.Sprintf("%s.inject_labels.labels key %q exceeds %d bytes", prefix, key, maxMutationLabelKeyBytes))
			valid = false
		}
		if len(value) > maxMutationLabelValueBytes {
			errs = append(errs, fmt.Sprintf("%s.inject_labels.labels[%q] value exceeds %d bytes", prefix, key, maxMutationLabelValueBytes))
			valid = false
		}
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Sprintf("%s.inject_labels.labels[%q] value must be non-empty", prefix, key))
			valid = false
		}
		if containsControlOrNUL(key) || containsControlOrNUL(value) {
			errs = append(errs, fmt.Sprintf("%s.inject_labels.labels[%q] must not contain control characters or NUL", prefix, key))
			valid = false
		}
		if reservedLabelKey != "" && key == reservedLabelKey {
			errs = append(errs, fmt.Sprintf("%s.inject_labels.labels must not set reserved owner label key %q (ownership.owner is configured)", prefix, key))
			valid = false
		}
		if !valid {
			continue
		}
		for _, surface := range rule.Surfaces {
			claims = append(claims, mutationLabelClaim{prefix: prefix, surface: surface, key: key})
		}
	}

	return errs, claims
}

// validateMutationLabelOverlaps rejects two mutation rules that would inject
// the same label key on the same surface: last-rule-wins is the actual
// runtime behavior (see mutation.go's applyInjectLabels), but a bounded
// declarative DSL should not depend on rule declaration order to resolve an
// operator's own conflicting intent — reject it at config time instead.
func validateMutationLabelOverlaps(claims []mutationLabelClaim) []string {
	var errs []string
	seen := make(map[string]string, len(claims))
	for _, claim := range claims {
		id := claim.surface + "\x00" + claim.key
		if firstPrefix, ok := seen[id]; ok {
			errs = append(errs, fmt.Sprintf(
				"%s.inject_labels.labels[%q] overlaps %s on surface %q: two mutation rules must not inject the same label key on the same surface",
				claim.prefix, claim.key, firstPrefix, claim.surface,
			))
			continue
		}
		seen[id] = claim.prefix
	}
	return errs
}

// validateMutationRemapImage validates one rule's remap_image block. When the
// rule is well-formed enough to reason about for overlap purposes, it also
// returns the mutationImageOverlapEntry validateMutationImageOverlaps needs;
// otherwise nil, so a malformed rule's shape error is not compounded by a
// spurious overlap error against it.
func validateMutationRemapImage(prefix string, rule MutationRuleConfig) ([]string, *mutationImageOverlapEntry) {
	var errs []string
	remap := rule.RemapImage
	match := strings.ToLower(strings.TrimSpace(remap.Match))
	switch match {
	case "exact", "prefix":
	default:
		errs = append(errs, enumValueError(prefix+".remap_image.match", remap.Match, "exact", "prefix"))
	}

	fromOK := validateMutationImageField(prefix+".remap_image.from", remap.From, &errs)
	toOK := validateMutationImageField(prefix+".remap_image.to", remap.To, &errs)

	if match == "exact" {
		if fromOK {
			errs = append(errs, validateMutationImageLiteral(prefix+".remap_image.from", remap.From)...)
		}
		if toOK {
			errs = append(errs, validateMutationImageLiteral(prefix+".remap_image.to", remap.To)...)
		}
	}

	if match != "exact" && match != "prefix" || !fromOK {
		return errs, nil
	}
	return errs, &mutationImageOverlapEntry{prefix: prefix, surfaces: rule.Surfaces, match: match, from: remap.From}
}

// validateMutationImageField checks the shared from/to shape rules (required,
// size-bounded, no control/NUL bytes) and reports via *errs, returning
// whether the field was well-formed enough for further checks to consult its
// value.
func validateMutationImageField(field, value string, errs *[]string) bool {
	if strings.TrimSpace(value) == "" {
		*errs = append(*errs, requiredFieldError(field))
		return false
	}
	ok := true
	if len(value) > maxMutationImageFieldBytes {
		*errs = append(*errs, fmt.Sprintf("%s exceeds %d bytes", field, maxMutationImageFieldBytes))
		ok = false
	}
	if containsControlOrNUL(value) {
		*errs = append(*errs, fmt.Sprintf("%s must not contain control characters or NUL", field))
		ok = false
	}
	return ok
}

// validateMutationImageLiteral confirms value parses as a plausible Docker
// image reference, using the same weak-validation grammar
// filter.validateMutationImageReference applies to a computed remap result at
// request time — so a rule that will always fail its own postcondition check
// is rejected at config load instead of denying every matching request.
func validateMutationImageLiteral(field, value string) []string {
	if _, err := name.ParseReference(value, name.WeakValidation); err != nil {
		return []string{fmt.Sprintf("%s must be a valid image reference, got %q: %v", field, value, err)}
	}
	return nil
}

// validateMutationImageOverlaps rejects two remap_image rules sharing a
// surface whose from patterns could both match the same image reference —
// an exact from that starts with a prefix from, or two prefix froms where
// one prefixes the other (including equal) — because which rule's result
// wins would depend on mutations.rules declaration order, an implicit
// dependency this declarative DSL does not want operators to rely on.
func validateMutationImageOverlaps(entries []mutationImageOverlapEntry) []string {
	var errs []string
	for i := range entries {
		for j := i + 1; j < len(entries); j++ {
			a, b := entries[i], entries[j]
			shared := sharedMutationSurfaces(a.surfaces, b.surfaces)
			if len(shared) == 0 || !mutationImageMatchesOverlap(a, b) {
				continue
			}
			slices.Sort(shared)
			errs = append(errs, fmt.Sprintf(
				"%s.remap_image and %s.remap_image overlap on surface(s) %s: a request image could match both rules' from pattern, making the applied result order-dependent",
				a.prefix, b.prefix, strings.Join(shared, ", "),
			))
		}
	}
	return errs
}

func sharedMutationSurfaces(a, b []string) []string {
	bSet := make(map[string]struct{}, len(b))
	for _, surface := range b {
		bSet[surface] = struct{}{}
	}
	var shared []string
	for _, surface := range a {
		if _, ok := bSet[surface]; ok {
			shared = append(shared, surface)
		}
	}
	return shared
}

func mutationImageMatchesOverlap(a, b mutationImageOverlapEntry) bool {
	switch {
	case a.match == "exact" && b.match == "exact":
		return a.from == b.from
	case a.match == "exact" && b.match == "prefix":
		return strings.HasPrefix(a.from, b.from)
	case a.match == "prefix" && b.match == "exact":
		return strings.HasPrefix(b.from, a.from)
	case a.match == "prefix" && b.match == "prefix":
		return strings.HasPrefix(a.from, b.from) || strings.HasPrefix(b.from, a.from)
	default:
		return false
	}
}

// containsControlOrNUL reports whether s contains a C0 control character
// (including NUL) or DEL — used to reject label keys/values and image
// literals that could smuggle control sequences into a log line or a
// downstream shell/terminal that interprets them.
func containsControlOrNUL(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validateClientsConfig validates the entire `clients:` block: the global
// CIDR allowlist, container-label peer attribution, the profile list itself,
// global concurrency cap, default profile, and each profile-assignment kind
// (source-IP, client certificate, unix peer). Profile-name uniqueness is
// gathered once into profilesByName and passed to each assignment validator
// so they can report assignments referencing undefined profiles.
func validateClientsConfig(cfg *Config) []string {
	var errs []string
	errs = append(errs, validateClientsAllowedCIDRs(cfg)...)
	errs = append(errs, validateClientsContainerLabels(cfg)...)
	errs = append(errs, validateClientsListenerExclusions(cfg)...)

	profilesByName := make(map[string]struct{}, len(cfg.Clients.Profiles))
	for i, profile := range cfg.Clients.Profiles {
		errs = append(errs, validateClientProfile(i, profile, profilesByName)...)
	}

	errs = append(errs, validateClientsGlobalConcurrency(cfg)...)
	errs = append(errs, validateClientsDefaultProfile(cfg, profilesByName)...)
	errs = append(errs, validateClientsSourceIPProfiles(cfg, profilesByName)...)
	errs = append(errs, validateClientsCertificateProfiles(cfg, profilesByName)...)
	errs = append(errs, validateClientsUnixPeerProfiles(cfg, profilesByName)...)
	return errs
}

func validateClientsAllowedCIDRs(cfg *Config) []string {
	var errs []string
	for _, rawCIDR := range cfg.Clients.AllowedCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(rawCIDR)); err == nil {
			continue
		}
		errs = append(errs, fmt.Sprintf("clients.allowed_cidrs entries must be valid CIDR prefixes, got %q", rawCIDR))
	}
	return errs
}

func validateClientsContainerLabels(cfg *Config) []string {
	if cfg.Clients.ContainerLabels.Enabled && cfg.Clients.ContainerLabels.LabelPrefix == "" {
		return []string{requiredWhenError("clients.container_labels.label_prefix", "clients.container_labels.enabled is true")}
	}
	return nil
}

// hasEffectiveListener reports whether at least one of cfg.EffectiveListeners
// (#149) — the legacy listen: block synthesized into one entry, or every
// listeners[*] entry — satisfies predicate. Transport-capability checks use
// this instead of reading cfg.Listen directly, so they hold the same "at
// least one compatible listener" shape whether an operator configures the
// legacy listen: block or an explicit listeners: list.
func hasEffectiveListener(cfg *Config, predicate func(ListenerConfig) bool) bool {
	for _, l := range cfg.EffectiveListeners() {
		if predicate(l) {
			return true
		}
	}
	return false
}

func isUnixListener(l ListenerConfig) bool { return l.Socket != "" }
func isTCPListener(l ListenerConfig) bool  { return l.Address != "" }

// validateClientsListenerExclusions checks the listener-kind constraints that
// would otherwise be reported as cryptic per-feature errors. Each rule is the
// same shape: feature X requires (or forbids) a TCP/unix listener among the
// effective set — see hasEffectiveListener.
func validateClientsListenerExclusions(cfg *Config) []string {
	var errs []string
	hasTCP := hasEffectiveListener(cfg, isTCPListener)
	hasUnix := hasEffectiveListener(cfg, isUnixListener)

	if !hasTCP && len(cfg.Clients.AllowedCIDRs) > 0 {
		errs = append(errs, "clients.allowed_cidrs requires a TCP listener; configure a TCP listen/listeners[*] entry or clear clients.allowed_cidrs")
	}
	if !hasTCP && cfg.Clients.ContainerLabels.Enabled {
		errs = append(errs, "clients.container_labels requires a TCP listener; configure a TCP listen/listeners[*] entry or disable clients.container_labels")
	}
	if !hasTCP && len(cfg.Clients.SourceIPProfiles) > 0 {
		errs = append(errs, "clients.source_ip_profiles requires a TCP listener; configure a TCP listen/listeners[*] entry or clear clients.source_ip_profiles")
	}
	if !hasTCP && len(cfg.Clients.ClientCertificateProfiles) > 0 {
		errs = append(errs, "clients.client_certificate_profiles requires a TCP listener; configure a TCP listen/listeners[*] entry or clear clients.client_certificate_profiles")
	}
	if !hasUnix && len(cfg.Clients.UnixPeerProfiles) > 0 {
		errs = append(errs, "clients.unix_peer_profiles requires a unix listener; configure a unix listen/listeners[*] entry or clear clients.unix_peer_profiles")
	}
	return errs
}

func validateClientsGlobalConcurrency(cfg *Config) []string {
	if cfg.Clients.GlobalConcurrency == nil {
		return nil
	}
	if cfg.Clients.GlobalConcurrency.MaxInflight <= 0 {
		return []string{fmt.Sprintf("clients.global_concurrency.max_inflight must be > 0, got %d", cfg.Clients.GlobalConcurrency.MaxInflight)}
	}
	return nil
}

func validateClientsDefaultProfile(cfg *Config, profilesByName map[string]struct{}) []string {
	if cfg.Clients.DefaultProfile == "" {
		return nil
	}
	if _, ok := profilesByName[cfg.Clients.DefaultProfile]; !ok {
		return []string{configuredMatchError("clients.default_profile", "client profile", cfg.Clients.DefaultProfile)}
	}
	return nil
}

func validateClientsSourceIPProfiles(cfg *Config, profilesByName map[string]struct{}) []string {
	var errs []string
	for i, assignment := range cfg.Clients.SourceIPProfiles {
		prefix := fmt.Sprintf("clients.source_ip_profiles[%d]", i)
		if assignment.Profile == "" {
			errs = append(errs, requiredFieldError(prefix+".profile"))
		} else if _, ok := profilesByName[assignment.Profile]; !ok {
			errs = append(errs, configuredMatchError(prefix+".profile", "client profile", assignment.Profile))
		}
		if len(assignment.CIDRs) == 0 {
			errs = append(errs, containsAtLeastOneError(prefix+".cidrs", "CIDR"))
		}
		for _, rawCIDR := range assignment.CIDRs {
			if _, err := netip.ParsePrefix(strings.TrimSpace(rawCIDR)); err == nil {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s.cidrs entries must be valid CIDR prefixes, got %q", prefix, rawCIDR))
		}
	}
	return errs
}

func validateClientsCertificateProfiles(cfg *Config, profilesByName map[string]struct{}) []string {
	var errs []string
	hasMutualTLS := hasEffectiveListener(cfg, func(l ListenerConfig) bool { return l.TLS.Complete() })
	if len(cfg.Clients.ClientCertificateProfiles) > 0 && !hasMutualTLS {
		errs = append(errs, requiresError("clients.client_certificate_profiles", "a listen/listeners[*] entry with mutual TLS configured"))
	}
	for i, assignment := range cfg.Clients.ClientCertificateProfiles {
		prefix := fmt.Sprintf("clients.client_certificate_profiles[%d]", i)
		if assignment.Profile == "" {
			errs = append(errs, requiredFieldError(prefix+".profile"))
		} else if _, ok := profilesByName[assignment.Profile]; !ok {
			errs = append(errs, configuredMatchError(prefix+".profile", "client profile", assignment.Profile))
		}
		errs = append(errs, validateClientCertificateSelectors(prefix, assignment)...)
	}
	return errs
}

// validateClientCertificateSelectors checks the per-selector identity rules
// for one client-certificate profile assignment and verifies that at least
// one selector is configured.
func validateClientCertificateSelectors(prefix string, assignment ClientCertificateProfileAssignmentConfig) []string {
	var errs []string
	selectorCount := 0
	for _, value := range assignment.CommonNames {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, prefix+".common_names entries must be non-empty")
			continue
		}
		selectorCount++
	}
	for _, value := range assignment.DNSNames {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, prefix+".dns_names entries must be non-empty")
			continue
		}
		selectorCount++
	}
	for _, value := range assignment.IPAddresses {
		if _, err := netip.ParseAddr(strings.TrimSpace(value)); err != nil {
			errs = append(errs, fmt.Sprintf("%s.ip_addresses entries must be valid IP addresses, got %q", prefix, value))
			continue
		}
		selectorCount++
	}
	for _, value := range assignment.URISANs {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil || parsed.String() == "" {
			errs = append(errs, fmt.Sprintf("%s.uri_sans entries must be valid URIs, got %q", prefix, value))
			continue
		}
		selectorCount++
	}
	for _, value := range assignment.SPIFFEIDs {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil || parsed.String() == "" || parsed.Scheme != "spiffe" {
			errs = append(errs, fmt.Sprintf("%s.spiffe_ids entries must be valid SPIFFE IDs, got %q", prefix, value))
			continue
		}
		selectorCount++
	}
	for _, value := range assignment.PublicKeySHA256Pins {
		if _, err := pkipin.NormalizeSubjectPublicKeySHA256Pin(value); err != nil {
			errs = append(errs, fmt.Sprintf("%s.public_key_sha256_pins entries must be hex SHA-256 SPKI pins, got %q", prefix, value))
			continue
		}
		selectorCount++
	}
	if selectorCount <= 0 {
		errs = append(errs, containsAtLeastOneError(prefix, "client certificate identity selector"))
	}
	return errs
}

func validateClientsUnixPeerProfiles(cfg *Config, profilesByName map[string]struct{}) []string {
	var errs []string
	for i, assignment := range cfg.Clients.UnixPeerProfiles {
		prefix := fmt.Sprintf("clients.unix_peer_profiles[%d]", i)
		if assignment.Profile == "" {
			errs = append(errs, requiredFieldError(prefix+".profile"))
		} else if _, ok := profilesByName[assignment.Profile]; !ok {
			errs = append(errs, configuredMatchError(prefix+".profile", "client profile", assignment.Profile))
		}
		if len(assignment.UIDs) == 0 && len(assignment.GIDs) == 0 && len(assignment.PIDs) == 0 {
			errs = append(errs, containsAtLeastOneError(prefix, "unix peer credential selector"))
		}

		if len(assignment.PIDs) > 0 && len(assignment.UIDs) == 0 && len(assignment.GIDs) == 0 {
			errs = append(errs, fmt.Sprintf("%s must not select by pid alone: process IDs are recycled by the kernel and are not a stable identity; add a uid and/or gid selector", prefix))
		}
		for _, pid := range assignment.PIDs {
			if pid > 0 {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s.pids entries must be positive process IDs, got %d", prefix, pid))
		}
	}
	return errs
}

func validateClientProfile(index int, profile ClientProfileConfig, profilesByName map[string]struct{}) []string {
	var errs []string

	prefix := fmt.Sprintf("clients.profiles[%d]", index)
	name := strings.TrimSpace(profile.Name)
	switch name {
	case "":
		errs = append(errs, requiredFieldError(prefix+".name"))
	case WildcardProfile:

		errs = append(errs, fmt.Sprintf("%s.name must not be %q (reserved as the listener allowed_profiles wildcard)", prefix, WildcardProfile))
	default:
		if _, exists := profilesByName[name]; exists {
			errs = append(errs, uniqueValueError(prefix+".name", name))
		}
		profilesByName[name] = struct{}{}
	}

	if len(profile.Rules) == 0 {
		errs = append(errs, containsAtLeastOneError(prefix+".rules", "rule"))
	}

	if _, ok := ParseRolloutMode(profile.Mode); !ok {
		errs = append(errs, fmt.Sprintf("%s.mode must be one of enforce|warn|audit, got %q", prefix, profile.Mode))
	}

	errs = append(errs, validateVisibleResourceLabels(prefix+".response.visible_resource_labels", profile.Response.VisibleResourceLabels)...)
	errs = append(errs, validateRequestBodyConfig(prefix+".request_body", profile.RequestBody)...)
	errs = append(errs, validateRuleConfigs(profile.Rules, prefix+".rules")...)
	errs = append(errs, validateLimitsConfig(prefix+".limits", profile.Limits)...)

	return errs
}

func validateLimitsConfig(prefix string, cfg LimitsConfig) []string {
	var errs []string

	if cfg.Priority != "" {
		switch strings.ToLower(strings.TrimSpace(cfg.Priority)) {
		case "low", "normal", "high":

		default:
			errs = append(errs, fmt.Sprintf("%s.priority must be one of low|normal|high, got %q", prefix, cfg.Priority))
		}
	}

	if cfg.Rate != nil {
		ratePfx := prefix + ".rate"
		if cfg.Rate.TokensPerSecond <= 0 {
			errs = append(errs, fmt.Sprintf("%s.tokens_per_second must be > 0, got %v", ratePfx, cfg.Rate.TokensPerSecond))
		}
		effectiveBurst := cfg.Rate.Burst
		switch {
		case cfg.Rate.Burst < 0:
			errs = append(errs, fmt.Sprintf("%s.burst must not be negative, got %v", ratePfx, cfg.Rate.Burst))
		case effectiveBurst == 0:

			effectiveBurst = cfg.Rate.TokensPerSecond
		case effectiveBurst < cfg.Rate.TokensPerSecond:
			errs = append(errs, fmt.Sprintf("%s.burst must be >= tokens_per_second (%v) or 0 (default), got %v",
				ratePfx, cfg.Rate.TokensPerSecond, cfg.Rate.Burst))
		}

		// maxBurstConfig matches the 16-bit integer part of the packed 16.16
		// fixed-point token field in the ratelimit package. Defined here as a
		// local constant to avoid an import cycle; ratelimit.MaxPackedBurst
		// documents the same value but this validator is the enforcement point.
		// burst >= tokens_per_second is already enforced above, so capping burst
		// here implicitly caps tokens_per_second too.
		const maxBurstConfig = 65535.0
		if effectiveBurst > maxBurstConfig {
			errs = append(errs, fmt.Sprintf("%s.burst must not exceed %g (packed token field limit), got %v",
				ratePfx, maxBurstConfig, effectiveBurst))
		}

		errs = append(errs, validateEndpointCosts(ratePfx+".endpoint_costs", cfg.Rate.EndpointCosts, effectiveBurst)...)
	}

	if cfg.Concurrency != nil {
		if cfg.Concurrency.MaxInflight <= 0 {
			errs = append(errs, fmt.Sprintf("%s.concurrency.max_inflight must be > 0, got %d", prefix, cfg.Concurrency.MaxInflight))
		}
	}

	return errs
}

// validateEndpointCosts checks per-entry path/method/cost rules and confirms
// each cost is <= effectiveBurst (a cost greater than burst is permanently
// un-satisfiable, so we fail closed at startup rather than let the limiter
// 429 forever).
func validateEndpointCosts(prefix string, costs []EndpointCostConfig, effectiveBurst float64) []string {
	var errs []string
	for i, ec := range costs {
		entryPfx := fmt.Sprintf("%s[%d]", prefix, i)
		if strings.TrimSpace(ec.Path) == "" {
			errs = append(errs, requiredFieldError(entryPfx+".path"))
		} else {
			regex := "^" + glob.ToRegexString(ec.Path) + "$"
			if _, err := regexp.Compile(regex); err != nil {
				errs = append(errs, fmt.Sprintf("%s.path %q is not a valid glob: %v", entryPfx, ec.Path, err))
			}
		}
		if ec.Cost < 1 {
			errs = append(errs, fmt.Sprintf("%s.cost must be >= 1, got %v", entryPfx, ec.Cost))
		}
		if effectiveBurst > 0 && ec.Cost > effectiveBurst {
			errs = append(errs, fmt.Sprintf("%s.cost (%v) must not exceed effective burst (%v); requests would never succeed",
				entryPfx, ec.Cost, effectiveBurst))
		}
		for j, m := range ec.Methods {
			if strings.TrimSpace(m) == "" {
				errs = append(errs, fmt.Sprintf("%s.methods[%d] must not be empty", entryPfx, j))
			}
		}
	}
	return errs
}

func validateRequestBodyConfig(prefix string, cfg RequestBodyConfig) []string {
	var errs []string
	errs = append(errs, validateContainerCreateConfig(prefix, cfg.ContainerCreate)...)
	errs = append(errs, validateLibpodContainerCreateConfig(prefix, cfg.LibpodContainerCreate)...)
	errs = append(errs, validateExecConfig(prefix, cfg.Exec)...)
	errs = append(errs, validateImagePullConfig(prefix, cfg.ImagePull)...)
	errs = append(errs, validateServiceConfig(prefix, cfg.Service)...)
	errs = append(errs, validateSwarmConfig(prefix, cfg.Swarm)...)
	errs = append(errs, validatePluginConfig(prefix, cfg.Plugin)...)
	errs = append(errs, validateLibpodPodCreateConfig(prefix, cfg.LibpodPodCreate)...)
	errs = append(errs, validateBuildkitConfig(prefix, cfg.Buildkit)...)
	return errs
}

// validateBuildkitConfig validates request_body.buildkit. AllowedRegistries
// (and, since issue #185 phase 3, AllowedCacheRegistries/
// AllowedExporterRegistries) reuse the same bare-registry-host normalization
// as image_pull/service/plugin's allowlists; AllowedRealms/AllowedScopes/
// AllowedIDs (and, since phase 3, AllowedCacheImportTypes/
// AllowedCacheExportTypes/AllowedExporters — opaque type names, not host
// shapes) have no host-shaped structure to normalize, so — like
// container_create.allowed_namespace_sharing_containers — they are only
// checked for being non-empty and free of leading/trailing whitespace
// (whitespace padding is always operator error: it can never match the
// exact string comparison the mediator uses).
func validateBuildkitConfig(prefix string, cfg BuildkitRequestBodyConfig) []string {
	var errs []string
	errs = append(errs, validateRegistryHostEntries(prefix, "buildkit.session.auth.allowed_registries", cfg.Session.Auth.AllowedRegistries)...)
	errs = append(errs, validateBuildkitOpaqueEntries(prefix, "buildkit.session.auth.allowed_realms", cfg.Session.Auth.AllowedRealms)...)
	errs = append(errs, validateBuildkitOpaqueEntries(prefix, "buildkit.session.auth.allowed_scopes", cfg.Session.Auth.AllowedScopes)...)
	errs = append(errs, validateBuildkitOpaqueEntries(prefix, "buildkit.session.secrets.allowed_ids", cfg.Session.Secrets.AllowedIDs)...)
	errs = append(errs, validateBuildkitOpaqueEntries(prefix, "buildkit.session.ssh.allowed_ids", cfg.Session.SSH.AllowedIDs)...)
	errs = append(errs, validateBuildkitOpaqueEntries(prefix, "buildkit.control.solve.allowed_cache_import_types", cfg.Control.Solve.AllowedCacheImportTypes)...)
	errs = append(errs, validateBuildkitOpaqueEntries(prefix, "buildkit.control.solve.allowed_cache_export_types", cfg.Control.Solve.AllowedCacheExportTypes)...)
	errs = append(errs, validateRegistryHostEntries(prefix, "buildkit.control.solve.allowed_cache_registries", cfg.Control.Solve.AllowedCacheRegistries)...)
	errs = append(errs, validateBuildkitOpaqueEntries(prefix, "buildkit.control.solve.allowed_exporters", cfg.Control.Solve.AllowedExporters)...)
	errs = append(errs, validateRegistryHostEntries(prefix, "buildkit.control.solve.allowed_exporter_registries", cfg.Control.Solve.AllowedExporterRegistries)...)

	errs = append(errs, validateBuildkitNonNegative(prefix, "buildkit.session.file_sync.max_files", int64(cfg.Session.FileSync.MaxFiles))...)
	errs = append(errs, validateBuildkitNonNegative(prefix, "buildkit.session.file_sync.max_total_bytes", cfg.Session.FileSync.MaxTotalBytes)...)
	errs = append(errs, validateBuildkitNonNegative(prefix, "buildkit.session.file_sync.max_path_length", int64(cfg.Session.FileSync.MaxPathLength))...)
	errs = append(errs, validateBuildkitNonNegative(prefix, "buildkit.session.file_sync.max_file_bytes", cfg.Session.FileSync.MaxFileBytes)...)
	errs = append(errs, validateBuildkitNonNegative(prefix, "buildkit.session.file_send.max_bytes", cfg.Session.FileSend.MaxBytes)...)
	errs = append(errs, validateBuildkitNonNegative(prefix, "buildkit.session.upload.max_bytes", cfg.Session.Upload.MaxBytes)...)
	return errs
}

// validateBuildkitNonNegative rejects a negative Phase 5 cap-override value.
// Zero is always valid (it means "inherit buildkitproxy.Limits' hardcoded
// default" — see BuildkitFileSyncRequestBodyConfig's doc comment), so this
// intentionally does not use the strictly-positive ">0" convention
// validateClientsGlobalConcurrency/validateAdminConfig use for fields with no
// such zero-means-default sentinel.
func validateBuildkitNonNegative(prefix, field string, value int64) []string {
	if value < 0 {
		return []string{fmt.Sprintf("%s.%s must be >= 0, got %d", prefix, field, value)}
	}
	return nil
}

// validateBuildkitOpaqueEntries flags any entry that is empty or carries
// leading/trailing whitespace. entries is the dotted field name suffix used
// in the error message (e.g. "buildkit.session.secrets.allowed_ids").
func validateBuildkitOpaqueEntries(prefix, entries string, values []string) []string {
	var errs []string
	for _, v := range values {
		if v != "" && v == strings.TrimSpace(v) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.%s entries must be non-empty values with no leading/trailing whitespace, got %q", prefix, entries, v))
	}
	return errs
}

// validateLibpodPodCreateConfig validates request_body.libpod_pod_create.
// libpod_volume/libpod_network/libpod_secret reuse
// Volume/Network/SecretRequestBodyConfig verbatim, which today have no
// free-text fields requiring their own validator (see
// validateRequestBodyConfig's Docker-compat counterparts), so there is
// nothing analogous to add for them here.
func validateLibpodPodCreateConfig(prefix string, cfg LibpodPodCreateRequestBodyConfig) []string {
	return validateRegistryHostEntries(prefix, "libpod_pod_create.allowed_infra_image_registries", cfg.AllowedInfraImageRegistries)
}

// validateHostPathEntries flags any entries that don't normalize to absolute
// host paths via normalizeAllowedBindMount. Shared by bind-mount and device
// allowlists across container_create / service / plugin.
func validateHostPathEntries(prefix, entries string, paths []string) []string {
	var errs []string
	for _, rawPath := range paths {
		if _, ok := normalizeAllowedBindMount(rawPath); ok {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.%s entries must be absolute host paths, got %q", prefix, entries, rawPath))
	}
	return errs
}

// validateRegistryHostEntries flags any entries that don't normalize to a
// bare registry host via normalizeAllowedRegistryHost.
func validateRegistryHostEntries(prefix, entries string, registries []string) []string {
	var errs []string
	for _, registry := range registries {
		if _, ok := normalizeAllowedRegistryHost(registry); ok {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.%s entries must be bare registry hosts, got %q", prefix, entries, registry))
	}
	return errs
}

func validateContainerCreateConfig(prefix string, cfg ContainerCreateRequestBodyConfig) []string {
	var errs []string
	errs = append(errs, validateHostPathEntries(prefix, "container_create.allowed_bind_mounts", cfg.AllowedBindMounts)...)
	errs = append(errs, validateHostPathEntries(prefix, "container_create.allowed_devices", cfg.AllowedDevices)...)
	for i, entry := range cfg.AllowedDeviceRequests {
		if strings.TrimSpace(entry.Driver) == "" {
			errs = append(errs, fmt.Sprintf("%s.container_create.allowed_device_requests[%d].driver is required", prefix, i))
		}
		for j, capSet := range entry.AllowedCapabilities {
			if len(capSet) == 0 {
				errs = append(errs, fmt.Sprintf("%s.container_create.allowed_device_requests[%d].allowed_capabilities[%d] must be a non-empty capability set", prefix, i, j))
			}
		}
		if entry.MaxCount != nil && *entry.MaxCount < -1 {
			errs = append(errs, fmt.Sprintf("%s.container_create.allowed_device_requests[%d].max_count must be -1 or a non-negative integer, got %d", prefix, i, *entry.MaxCount))
		}
	}
	for _, entry := range cfg.AllowedNamespaceSharingContainers {
		if entry != "" && entry == strings.TrimSpace(entry) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.container_create.allowed_namespace_sharing_containers entries must be non-empty container ID or name values, got %q", prefix, entry))
	}
	errs = append(errs, validateImageTrustConfig(prefix+".container_create.image_trust", cfg.ImageTrust)...)
	return errs
}

// validateLibpodContainerCreateConfig mirrors validateContainerCreateConfig's
// pattern for the libpod_container_create block: absolute-path checks on the
// bind-mount/device allowlists and image-trust config. Namespace-sharing
// target entries follow the same non-empty/trimmed check as the Docker
// equivalent's allowed_namespace_sharing_containers.
func validateLibpodContainerCreateConfig(prefix string, cfg LibpodContainerCreateRequestBodyConfig) []string {
	var errs []string
	errs = append(errs, validateHostPathEntries(prefix, "libpod_container_create.allowed_bind_mounts", cfg.AllowedBindMounts)...)
	errs = append(errs, validateHostPathEntries(prefix, "libpod_container_create.allowed_devices", cfg.AllowedDevices)...)
	for _, entry := range cfg.AllowedNamespaceSharingContainers {
		if entry != "" && entry == strings.TrimSpace(entry) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.libpod_container_create.allowed_namespace_sharing_containers entries must be non-empty container ID or name values, got %q", prefix, entry))
	}
	errs = append(errs, validateImageTrustConfig(prefix+".libpod_container_create.image_trust", cfg.ImageTrust)...)
	return errs
}

func validateExecConfig(prefix string, cfg ExecRequestBodyConfig) []string {
	var errs []string
	for i, command := range cfg.AllowedCommands {
		if validExecCommand(command) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.exec.allowed_commands entries must contain at least one non-empty argv token, got entry %d", prefix, i+1))
	}
	for _, name := range cfg.AllowedEnvVars {
		if validExecEnvVarName(name) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.exec.allowed_env_vars entries must be a bare variable name (no '=', no whitespace), got %q", prefix, name))
	}
	for _, name := range cfg.DeniedEnvVars {
		if validExecEnvVarName(name) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.exec.denied_env_vars entries must be a bare variable name (no '=', no whitespace), got %q", prefix, name))
	}
	for i, entry := range cfg.AllowedEnvValues {
		if validExecEnvValue(entry) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.exec.allowed_env_values entry %d must be an exact NAME=VALUE string with an unpadded variable name", prefix, i+1))
	}
	return errs
}

func validateImagePullConfig(prefix string, cfg ImagePullRequestBodyConfig) []string {
	return validateRegistryHostEntries(prefix, "image_pull.allowed_registries", cfg.AllowedRegistries)
}

func validateServiceConfig(prefix string, cfg ServiceRequestBodyConfig) []string {
	var errs []string
	errs = append(errs, validateHostPathEntries(prefix, "service.allowed_bind_mounts", cfg.AllowedBindMounts)...)
	errs = append(errs, validateRegistryHostEntries(prefix, "service.allowed_registries", cfg.AllowedRegistries)...)
	return errs
}

func validateSwarmConfig(prefix string, cfg SwarmRequestBodyConfig) []string {
	var errs []string
	for _, remoteAddr := range cfg.AllowedJoinRemoteAddrs {
		if validRemoteAddress(remoteAddr) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.swarm.allowed_join_remote_addrs entries must be bare host[:port] values, got %q", prefix, remoteAddr))
	}
	return errs
}

func validatePluginConfig(prefix string, cfg PluginRequestBodyConfig) []string {
	var errs []string
	errs = append(errs, validateRegistryHostEntries(prefix, "plugin.allowed_registries", cfg.AllowedRegistries)...)
	errs = append(errs, validateHostPathEntries(prefix, "plugin.allowed_bind_mounts", cfg.AllowedBindMounts)...)
	errs = append(errs, validateHostPathEntries(prefix, "plugin.allowed_devices", cfg.AllowedDevices)...)
	for _, capability := range cfg.AllowedCapabilities {
		if validPluginCapability(capability) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.plugin.allowed_capabilities entries must be non-empty capability names, got %q", prefix, capability))
	}
	for _, rawPrefix := range cfg.AllowedSetEnvPrefixes {
		if validPluginSetEnvPrefix(rawPrefix) {
			continue
		}
		errs = append(errs, fmt.Sprintf("%s.plugin.allowed_set_env_prefixes entries must be non-empty env assignment prefixes, got %q", prefix, rawPrefix))
	}
	return errs
}

func validateRuleConfigs(rules []RuleConfig, prefix string) []string {
	var errs []string
	for i, r := range rules {
		rulePrefix := fmt.Sprintf("%s[%d]", prefix, i)
		if r.Match.Method == "" {
			errs = append(errs, rulePrefix+".match.method is required")
		}
		if r.Match.Path == "" {
			errs = append(errs, rulePrefix+".match.path is required")
		} else if strings.Contains(r.Match.Path, "%") {
			errs = append(errs, literalPercentRuleError(rulePrefix, r.Match.Path))
		}
		switch r.Action {
		case "allow", "deny":
		default:
			errs = append(errs, fmt.Sprintf("%s %s", rulePrefix, enumValueError("action", r.Action, "allow", "deny")))
		}
	}
	return errs
}

func requiredFieldError(field string) string {
	return field + " is required"
}

func requiredWhenError(field, condition string) string {
	return fmt.Sprintf("%s is required when %s", field, condition)
}

func requiresError(field, requirement string) string {
	return fmt.Sprintf("%s requires %s", field, requirement)
}

func containsAtLeastOneError(field, singular string) string {
	return fmt.Sprintf("%s must contain at least one %s", field, singular)
}

func configuredMatchError(field, kind, got string) string {
	return fmt.Sprintf("%s must match a configured %s, got %q", field, kind, got)
}

func uniqueValueError(field, got string) string {
	return fmt.Sprintf("%s must be unique, got duplicate %q", field, got)
}

func enumValueError(field, got string, allowed ...string) string {
	return fmt.Sprintf("%s must be %s, got %q", field, formatAllowedValues(allowed...), got)
}

func formatAllowedValues(values ...string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	case 2:
		return values[0] + " or " + values[1]
	default:
		return strings.Join(values[:len(values)-1], ", ") + ", or " + values[len(values)-1]
	}
}

func normalizeAllowedBindMount(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	cleaned := path.Clean(value)
	return cleaned, true
}

func validExecCommand(command []string) bool {
	if len(command) == 0 {
		return false
	}
	for _, token := range command {
		if strings.TrimSpace(token) == "" {
			return false
		}
	}
	return true
}

// validExecEnvVarName reports whether value is a bare environment variable
// name suitable for allowed_env_vars/denied_env_vars: non-empty, no "=" (a
// "=" strongly suggests the operator pasted a KEY=VALUE
// pair rather than a bare name — these fields are name-only), and no
// embedded whitespace. No POSIX identifier-shape enforcement is applied —
// Docker itself doesn't require one, and the schema's other string-list
// fields stay similarly lenient.
func validExecEnvVarName(value string) bool {
	return value != "" && !strings.Contains(value, "=") && !strings.ContainsAny(value, " \t\r\n")
}

func validExecEnvValue(value string) bool {
	name, _, ok := strings.Cut(value, "=")
	return ok && validExecEnvVarName(name)
}

func normalizeAllowedRegistryHost(value string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" || strings.Contains(trimmed, "://") || strings.Contains(trimmed, "/") {
		return "", false
	}
	switch trimmed {
	case "index.docker.io":
		return "docker.io", true
	default:
		return trimmed, true
	}
}

func validRemoteAddress(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.Contains(trimmed, "://") || strings.Contains(trimmed, "/") {
		return false
	}
	return !strings.ContainsAny(trimmed, " \t\r\n")
}

func validPluginSetEnvPrefix(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && strings.Contains(trimmed, "=") && !strings.ContainsAny(trimmed, " \t\r\n")
}

func validPluginCapability(value string) bool {
	return strings.TrimSpace(value) != ""
}

func validateImageTrustConfig(prefix string, cfg ImageTrustConfig) []string {
	switch cfg.Mode {
	case "", "off":

		return nil
	case "warn", "enforce":

	default:
		return []string{enumValueError(prefix+".mode", cfg.Mode, "off", "warn", "enforce")}
	}

	var errs []string

	if len(cfg.AllowedSigningKeys) == 0 && len(cfg.AllowedKeyless) == 0 {
		errs = append(errs,
			prefix+": at least one allowed_signing_keys or allowed_keyless entry is required when mode is not off",
		)
	}

	keys := make([]signingKeyEntry, len(cfg.AllowedSigningKeys))
	for i, k := range cfg.AllowedSigningKeys {
		keys[i] = signingKeyEntry(k)
	}
	kls := make([]keylessEntry, len(cfg.AllowedKeyless))
	for i, kl := range cfg.AllowedKeyless {
		kls[i] = keylessEntry(kl)
	}
	errs = append(errs, validateKeylessTrustEntries(prefix, keys, kls)...)

	if cfg.VerifyTimeout != "" {
		d, err := time.ParseDuration(cfg.VerifyTimeout)
		if err != nil || d <= 0 {
			errs = append(errs,
				fmt.Sprintf("%s.verify_timeout must be a positive duration, got %q", prefix, cfg.VerifyTimeout),
			)
		}
	}

	return errs
}

// validateLogOutputField validates a log output value under the given config
// field path. It wraps validateLogOutput so callers can pass a field-specific
// prefix (e.g. "log.audit.output") and receive errors that reference that
// path directly, without post-hoc string replacement.
func validateLogOutputField(fieldPath, output string) error {
	if err := validateLogOutput(output); err != nil {
		return fmt.Errorf("%s: %w", fieldPath, err)
	}
	return nil
}

func validateVisibleResourceLabels(prefix string, values []string) []string {
	var errs []string
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			errs = append(errs, fmt.Sprintf("%s entries must be non-empty", prefix))
			continue
		}
		if strings.Contains(value, ",") {
			errs = append(errs, fmt.Sprintf("%s entries must not contain commas, got %q", prefix, raw))
			continue
		}
		key, selected, hasValue := strings.Cut(value, "=")
		if strings.TrimSpace(key) == "" {
			errs = append(errs, fmt.Sprintf("%s entries must include a label key, got %q", prefix, raw))
			continue
		}
		if hasValue && strings.TrimSpace(selected) == "" {
			errs = append(errs, fmt.Sprintf("%s entries with '=' must include a non-empty value, got %q", prefix, raw))
		}
	}
	return errs
}
