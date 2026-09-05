package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/glob"
	"github.com/codeswhat/sockguard/app/internal/pkipin"
	"github.com/codeswhat/sockguard/app/internal/upstream"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
	"github.com/google/go-containerregistry/pkg/name"
)

// ValidationError holds multiple validation errors.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation failed:\n  - %s", strings.Join(e.Errors, "\n  - "))
}

// validateMode selects whether validation may dereference the filesystem
// paths a config names.
type validateMode uint8

const (
	// validateFull is startup and CLI validation: TLS material named by
	// listen.tls is loaded so a missing, unreadable, or malformed
	// cert/key/CA fails fast instead of at the first client connection.
	validateFull validateMode = iota
	// validateStructural is validation of a candidate config supplied by a
	// remote caller. It performs every check validateFull does EXCEPT
	// reading files. See ValidateStructural for why that distinction is a
	// security boundary and not an optimization.
	validateStructural
)

// Validate checks a Config for correctness, returning a ValidationError
// if any problems are found. It loads the TLS material the config names, so
// it must only be used on a config the operator supplied (startup, the CLI).
// For a candidate config that arrived over the network, use
// ValidateStructural.
func Validate(cfg *Config) error {
	return validateWithMode(cfg, validateFull)
}

// ValidateStructural is Validate with every filesystem dereference disabled.
//
// The admin API's POST /validate accepts candidate YAML from a caller and
// returns the validation errors verbatim. Under Validate, a listen.tls block
// whose cert_file, key_file, and client_ca_file are all set makes the
// validator call tls.LoadX509KeyPair and os.ReadFile on those paths and wrap
// the resulting *os.PathError into the response. A caller who cannot read the
// host filesystem can therefore point the candidate at any absolute path and
// learn from the error whether it exists, whether the process can read it,
// and whether it parses as PEM — a filesystem probing oracle built out of a
// validation endpoint.
//
// Scrubbing the error text is not sufficient: "loaded" versus "did not load"
// is itself the answer the probe is after. The dereference has to not happen.
// So the structural mode still compiles the client-certificate identity
// constraints (pure, and the check most likely to catch a real operator
// mistake) and still requires cert_file/key_file/client_ca_file to be set
// together, but never opens them.
func ValidateStructural(cfg *Config) error {
	return validateWithMode(cfg, validateStructural)
}

func validateWithMode(cfg *Config, mode validateMode) error {
	errs := validateBasic(cfg, mode)
	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

func validateBasic(cfg *Config, mode validateMode) []string {
	var errs []string
	errs = append(errs, validateListeners(cfg, mode)...)
	errs = append(errs, validateServer(cfg)...)
	errs = append(errs, validateUpstream(cfg)...)
	errs = append(errs, validateLogging(cfg)...)
	errs = append(errs, validateResponse(cfg)...)
	errs = append(errs, validateHealthMetrics(cfg)...)
	if cfg.Admin.Enabled {
		errs = append(errs, validateAdmin(cfg, mode)...)
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
func validateListeners(cfg *Config, mode validateMode) []string {
	var errs []string
	if len(cfg.Listeners) > 0 {
		if cfg.explicitLegacyListen {
			errs = append(errs, "listen and listeners are mutually exclusive; migrate the listen: block into a single-entry listeners: list")
		}
		errs = append(errs, validateExplicitListeners(cfg, mode)...)
		errs = append(errs, validateExplicitListenersBindUniqueness(cfg)...)
		return errs
	}
	return validateLegacyListen(cfg, mode)
}

func validateLegacyListen(cfg *Config, mode validateMode) []string {
	var errs []string
	if cfg.Listen.Socket == "" && cfg.Listen.Address == "" {
		errs = append(errs, "at least one listener is required (listen.socket or listen.address)")
	}
	if cfg.Listen.Socket != "" {
		errs = append(errs, validateSocketOwnership("listen", cfg.Listen)...)
	}
	if cfg.Listen.Socket == "" && cfg.Listen.Address != "" {
		errs = append(errs, validateTCPListenerSecurity(cfg, mode)...)
	}
	return errs
}

// validateExplicitListeners validates each entry of the explicit
// listeners: list: name shape/uniqueness/reservation, the listeners cap,
// exactly-one-of-socket-or-address (stricter than the legacy implicit
// socket-wins fallback — new entries reject ambiguity outright), per-entry
// TLS/plaintext-ack/ownership security, and the allowed_profiles scope.
func validateExplicitListeners(cfg *Config, mode validateMode) []string {
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
			errs = append(errs, validateListenerTCPSecurity(label, l.ListenConfig, mode)...)
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
		// default owner-only mode; no ownership fields required.
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
func validateListenerTCPSecurity(prefix string, listen ListenConfig, mode validateMode) []string {
	var errs []string

	if listen.TLS.Enabled() && !listen.TLS.Complete() {
		errs = append(errs, requiresError(prefix+".tls", "cert_file, key_file, and client_ca_file together"))
		return errs
	}

	if listen.TLS.Complete() {
		if err := checkMutualTLSForField(prefix+".tls", listen.TLS, mode); err != nil {
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

// validateServer validates server.shutdown_grace. Unlike
// upstream.hijack_inactivity_timeout, 0 is a valid value here — it means
// "close immediately, don't wait" — so every value, including an explicit
// empty string, goes through ParseDuration and only a parse failure or a
// negative duration is rejected.
func validateServer(cfg *Config) []string {
	if d, err := time.ParseDuration(cfg.Server.ShutdownGrace); err != nil || d < 0 {
		return []string{fmt.Sprintf("server.shutdown_grace must be a non-negative duration, got %q", cfg.Server.ShutdownGrace)}
	}
	return nil
}

func validateUpstream(cfg *Config) []string {
	var errs []string
	// Either the legacy single socket or at least one endpoint must be set.
	// endpoints takes precedence; socket is the fallback when endpoints is empty.
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
	// Unlike RequestTimeout, hijack_inactivity_timeout has no "off"/legacy-empty
	// disable spelling (see its config.go doc comment), so every value —
	// including an explicit empty string — goes through ParseDuration and 0 is
	// rejected the same as a negative duration.
	if hijackTimeout, err := time.ParseDuration(cfg.Upstream.HijackInactivityTimeout); err != nil || hijackTimeout <= 0 {
		errs = append(errs, fmt.Sprintf("upstream.hijack_inactivity_timeout must be a positive duration, got %q", cfg.Upstream.HijackInactivityTimeout))
	}
	if _, ok := upstreamflavor.Configured(cfg.Upstream.Flavor); !ok {
		errs = append(errs, fmt.Sprintf(
			"upstream.flavor must be %q, %q or %q, got %q",
			upstreamflavor.Auto, upstreamflavor.Docker, upstreamflavor.Podman, cfg.Upstream.Flavor,
		))
	}
	if d := cfg.Upstream.Failover.HealthInterval; d != "" {
		// Zero is ambiguous: durationOrZero maps it to the resolver default (5s),
		// not "disabled", which surprises an operator who writes "0s" meaning off.
		// Reject it and steer them to a negative value (disable) or omission
		// (default). Negative parses fine and is intentionally allowed.
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
	errs = append(errs, validateVisibleResourceLabels("response.visible_resource_labels", cfg.Response.VisibleResourceLabels, ownerReservedLabelKey(cfg))...)
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

func validateAdmin(cfg *Config, mode validateMode) []string {
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
	errs = append(errs, validateAdminListener(cfg, mode)...)
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
		} else if !strings.HasPrefix(r.Match.Path, "/") {
			errs = append(errs, rootlessRuleError(fmt.Sprintf("rule %d", i+1), r.Match.Path))
		} else if strings.Contains(r.Match.Path, "%") && !validEscapedLibpodImageScpRule(r.Match) {
			errs = append(errs, literalPercentRuleError(fmt.Sprintf("rule %d", i+1), r.Match.Path))
		} else if filter.HasVersionPrefix(r.Match.Path) {
			errs = append(errs, versionPrefixRuleError(fmt.Sprintf("rule %d", i+1), r.Match.Path))
		}
		switch r.Action {
		case "allow", "deny":
		default:
			errs = append(errs, fmt.Sprintf("rule %d: %s", i+1, enumValueError("action", r.Action, "allow", "deny")))
		}
	}
	return errs
}

// validEscapedLibpodImageScpRule recognizes the one route family whose exact
// policy view legitimately contains percent escapes. Podman's gorilla/mux
// router uses EscapedPath for POST /libpod/images/scp/{name:.*}; dual-view
// evaluation then requires the decoded and encoded route spellings to allow.
// Keep this exception narrower than the earlier push/tag/untag routes: a
// multi-method rule, glob, or raw action suffix can otherwise match a
// double-encoded request that Podman routes somewhere other than image SCP.
func validEscapedLibpodImageScpRule(match MatchConfig) bool {
	if !strings.EqualFold(strings.TrimSpace(match.Method), "POST") || strings.Contains(match.Method, ",") {
		return false
	}
	const prefix = "/libpod/images/scp/"
	rest, ok := strings.CutPrefix(match.Path, prefix)
	if !ok || rest == "" || strings.Contains(match.Path, "*") {
		return false
	}
	for _, action := range []string{"push", "tag", "untag"} {
		if rest == action || strings.HasSuffix(rest, "/"+action) {
			return false
		}
	}
	_, err := url.PathUnescape(match.Path)
	return err == nil
}

// versionPrefixRuleError reports a rule path pattern that itself begins with
// a Docker/Podman API version prefix (e.g. "/v1.45/..." or
// "/v5.8.1-dev/..."). NormalizePath strips exactly that prefix from the
// request path before rule matching runs, using the same predicate
// (filter.HasVersionPrefix, built on filter's stripVersionPrefix) this check
// calls — so a pattern that still carries the prefix can never match real
// traffic and is silently dead rather than doing what its author intended.
// Failing closed at validation time beats the startup warning this replaces:
// a rule an operator believed was denying (or allowing) versioned traffic
// that in fact never fires is a security-relevant gap, not a style nit.
func versionPrefixRuleError(label, pattern string) string {
	return fmt.Sprintf(
		"%s: match.path %q begins with an API version prefix; sockguard strips version prefixes before matching, so this pattern never matches real traffic — write the pattern without the /vN... prefix",
		label, pattern,
	)
}

// rootlessRuleError reports a rule path pattern that does not begin with "/".
// Every path rule matching ever sees is rooted: NormalizePath and
// NormalizePodmanRoutePath both preserve the leading slash of an HTTP
// request-target, and the anchored regex a pattern compiles to
// ("^containers/[^/]*$" for "containers/*", "^[^/]*$" for "*") cannot match a
// path that starts with one. So a rootless pattern describes nothing the proxy
// will ever be asked about.
//
// It used to match anyway on the segment-glob fast path, which stripped a
// leading slash from both the pattern and the request path and so read
// "containers/*" as "/containers/*" — a silent widening on an allow rule and,
// once the walker was corrected, a silent narrowing on a deny. Rejecting the
// shape is what keeps that correction from quietly reversing an operator's
// intent: the same fail-closed reasoning as versionPrefixRuleError and
// literalPercentRuleError, which also refuse a pattern that can only ever be
// dead. Write the pattern with its leading "/" ("/containers/*"), and use
// "/**" rather than "**" for a catch-all.
func rootlessRuleError(label, pattern string) string {
	return fmt.Sprintf(
		"%s: match.path %q must start with '/'; sockguard matches rules against the rooted request path, so a pattern without a leading slash never matches real traffic — write it as %q",
		label, pattern, "/"+pattern,
	)
}

// literalPercentRuleError reports a rule path pattern that contains a literal
// '%' outside Podman's encoded image-SCP route. Other policy paths are decoded
// exactly once by the HTTP layer, so a '%XX' in their pattern only ever matches
// a doubly-encoded request, never normal traffic. The rule the author meant is
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
func validateAdminListener(cfg *Config, mode validateMode) []string {
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
			if err := checkMutualTLSForField("admin.listen.tls", listen.TLS, mode); err != nil {
				errs = append(errs, err.Error())
			}
		}

		errs = append(errs, plainTCPListenerErrors("TCP admin listener", "admin.listen", listen.ListenConfig)...)

		// A non-loopback plaintext admin listener with no client CIDR
		// allowlist is wide open: the admin endpoints accept candidate YAML
		// and expose policy metadata with no authentication and no IP
		// backstop. Unlike the main listener (whose unauthenticated opt-in
		// still routes through the policy chain), CIDRs are the admin
		// surface's only admission control, so this is an error rather than
		// the startup warning it used to be — acknowledged only by the
		// explicit insecure_allow_wide_open flag.
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

func validateTCPListenerSecurity(cfg *Config, mode validateMode) []string {
	var errs []string

	if cfg.Listen.TLS.Enabled() && !cfg.Listen.TLS.Complete() {
		errs = append(errs, requiresError("listen.tls", "cert_file, key_file, and client_ca_file together"))
		return errs
	}

	if cfg.Listen.TLS.Complete() {
		if err := checkMutualTLSForField("listen.tls", cfg.Listen.TLS, mode); err != nil {
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

// validateNetworkEndpointConfig rejects allow_endpoint_config: true combined
// with an explicitly configured endpoint_config block (#186):
// allow_endpoint_config already admits every EndpointSettings field
// unchanged, so a simultaneous granular block is ambiguous — which one an
// operator actually intends to govern the request is not something sockguard
// should guess at silently. Detected via the cfg.explicit*EndpointConfig
// provenance flags (a provenance-only Viper pass; see
// explicitEndpointConfigFile/Bytes in load.go) rather than comparing the
// merged EndpointConfig against its Go zero value, because
// EndpointConfigRequestBodyConfig.AllowAliases defaults to true
// (config.Defaults()), so the merged struct is never the zero value even
// when the operator never wrote the block at all.
//
// Both groups that carry the block are checked. request_body.libpod_network
// was originally exempt on the belief that libpod had no network-connect
// endpoint to gate; it does (POST /libpod/networks/{name}/connect), so an
// operator writing both keys there used to get silence where the Docker
// spelling gave them an error — a config that quietly means something other
// than what it says.
func validateNetworkEndpointConfig(cfg *Config) []string {
	var errs []string
	if cfg.RequestBody.Network.AllowEndpointConfig && cfg.explicitNetworkEndpointConfig {
		errs = append(errs, endpointConfigMutualExclusionError("request_body", "network"))
	}
	if cfg.RequestBody.LibpodNetwork.AllowEndpointConfig && cfg.explicitLibpodNetworkEndpointConfig {
		errs = append(errs, endpointConfigMutualExclusionError("request_body", "libpod_network"))
	}
	for i, profile := range cfg.Clients.Profiles {
		prefix := fmt.Sprintf("clients.profiles[%d].request_body", i)
		if profile.RequestBody.Network.AllowEndpointConfig && profile.explicitNetworkEndpointConfig {
			errs = append(errs, endpointConfigMutualExclusionError(prefix, "network"))
		}
		if profile.RequestBody.LibpodNetwork.AllowEndpointConfig && profile.explicitLibpodNetworkEndpointConfig {
			errs = append(errs, endpointConfigMutualExclusionError(prefix, "libpod_network"))
		}
	}
	return errs
}

// endpointConfigMutualExclusionError renders the #186 mutual-exclusion
// message for one request_body group. One template, so the two groups cannot
// drift into differently-worded advice for the identical mistake.
func endpointConfigMutualExclusionError(prefix, group string) string {
	return fmt.Sprintf("%s.%s.allow_endpoint_config and %s.%s.endpoint_config are mutually exclusive: allow_endpoint_config: true already admits every EndpointSettings field, so remove the endpoint_config block or set allow_endpoint_config: false and use the granular fields instead", prefix, group, prefix, group)
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

// buildkitMediationConfigured reports whether request_body.buildkit is
// configured in ANY scope — top level or any client profile — which is
// exactly the condition validateBuildkitAckMutualExclusion above turns into a
// refusal once insecure_accept_opaque_buildkit_tunnels is set too. It exists
// so ApplyCompat (compat.go) can ask that question in one call rather than
// re-deriving the scope list, which would drift the moment a third scope
// appears; a scope added to the loop above belongs here as well.
func buildkitMediationConfigured(cfg *Config) bool {
	if cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Configured() {
		return true
	}
	for _, profile := range cfg.Clients.Profiles {
		if profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build).Configured() {
			return true
		}
	}
	return false
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

	// cfg.Ownership.LabelKey is required-when validated separately
	// (validateRequestBody); read it as-is here rather than re-deriving the
	// Defaults() fallback, so this check is exact even if that other
	// validation error is also present in the same run.
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

	// Exact-match from/to must additionally parse as plausible image
	// references — an exact match replaces the whole reference, so an
	// unparseable literal can never legitimately match or produce a valid
	// result. A prefix match's from/to are deliberately allowed to be a bare
	// registry-host or path prefix (e.g. "internal.example.com/"), which does
	// not itself parse as a complete reference, so this check does not apply
	// there.
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
		errs = append(errs, validateClientProfile(i, profile, profilesByName, ownerReservedLabelKey(cfg))...)
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
		// A PID alone is not a stable identity: the kernel recycles process IDs,
		// so a process that inherits a previously-trusted PID would silently
		// acquire its profile. PIDs may only narrow a UID/GID match, never select
		// a profile on their own — require at least one uid or gid alongside them.
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

func validateClientProfile(index int, profile ClientProfileConfig, profilesByName map[string]struct{}, reservedLabelKey string) []string {
	var errs []string

	prefix := fmt.Sprintf("clients.profiles[%d]", index)
	name := strings.TrimSpace(profile.Name)
	switch name {
	case "":
		errs = append(errs, requiredFieldError(prefix+".name"))
	case WildcardProfile:
		// "*" is reserved by listeners[*].allowed_profiles as the
		// "admit every profile" wildcard (#149) and cannot double as a
		// concrete profile name.
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

	errs = append(errs, validateVisibleResourceLabels(prefix+".response.visible_resource_labels", profile.Response.VisibleResourceLabels, reservedLabelKey)...)
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
			// ok
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
			// Default: burst equals tokens_per_second.
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

	// Phase 5 (issue #185) cap overrides: zero means "use buildkitproxy.
	// Limits' hardcoded default" (see BuildkitFileSyncRequestBodyConfig's
	// doc comment), so zero is valid — only negative is operator error.
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
		} else if !strings.HasPrefix(r.Match.Path, "/") {
			errs = append(errs, rootlessRuleError(rulePrefix, r.Match.Path))
		} else if strings.Contains(r.Match.Path, "%") && !validEscapedLibpodImageScpRule(r.Match) {
			errs = append(errs, literalPercentRuleError(rulePrefix, r.Match.Path))
		} else if filter.HasVersionPrefix(r.Match.Path) {
			errs = append(errs, versionPrefixRuleError(rulePrefix, r.Match.Path))
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
		// nothing to validate when feature is disabled
		return nil
	case "warn", "enforce":
		// valid
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

// ownerReservedLabelKey returns the label key ownership stamps and filters on,
// or "" when owner scoping is off. Read as-is rather than re-deriving the
// Defaults() fallback, matching validateMutationInjectLabels: an empty
// LabelKey alongside a configured owner is its own error, reported separately.
func ownerReservedLabelKey(cfg *Config) string {
	if cfg.Ownership.Owner == "" {
		return ""
	}
	return cfg.Ownership.LabelKey
}

// validateVisibleResourceLabels checks one visible_resource_labels list.
//
// reservedLabelKey is the ownership label key (empty when owner scoping is
// off). A visibility selector may not claim it. Both layers write the same
// `label` filter key upstream and the values are ANDed, so selecting on the
// owner key either restates what ownership already enforces or asks for a
// label to hold two values at once. Docker's Swarm control-plane lists resolve
// that second case by folding `label` into a map[string]string over a
// randomly-ordered Args.Get (daemon/cluster/filters.go), so one of the two
// values wins nondeterministically and the visibility scope can silently
// disappear. Keeping each layer's keys disjoint removes the case.
func validateVisibleResourceLabels(prefix string, values []string, reservedLabelKey string) []string {
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
		key = strings.TrimSpace(key)
		if key == "" {
			errs = append(errs, fmt.Sprintf("%s entries must include a label key, got %q", prefix, raw))
			continue
		}
		if reservedLabelKey != "" && key == reservedLabelKey {
			errs = append(errs, fmt.Sprintf("%s entries must not select on the reserved owner label key %q (ownership.owner is configured; that key is proxy-enforced)", prefix, key))
			continue
		}
		if hasValue && strings.TrimSpace(selected) == "" {
			errs = append(errs, fmt.Sprintf("%s entries with '=' must include a non-empty value, got %q", prefix, raw))
		}
	}
	return errs
}
