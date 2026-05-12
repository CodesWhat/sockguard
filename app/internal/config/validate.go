package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/pkipin"
)

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

	// At least one listener
	if cfg.Listen.Socket == "" && cfg.Listen.Address == "" {
		errs = append(errs, "at least one listener is required (listen.socket or listen.address)")
	}

	if cfg.Listen.Socket != "" {
		errs = append(errs, validateUnixSocketListenerSecurity(cfg)...)
	}

	if cfg.Listen.Socket == "" && cfg.Listen.Address != "" {
		errs = append(errs, validateTCPListenerSecurity(cfg)...)
	}

	// Non-empty upstream
	if cfg.Upstream.Socket == "" {
		errs = append(errs, "upstream.socket is required")
	}

	// Valid log level
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
		// OK
	default:
		errs = append(errs, enumValueError("log.level", cfg.Log.Level, "debug", "info", "warn", "error"))
	}

	// Valid log format
	switch cfg.Log.Format {
	case "json", "text":
		// OK
	default:
		errs = append(errs, enumValueError("log.format", cfg.Log.Format, "json", "text"))
	}

	// Log output must resolve to stderr, stdout, or a local file path.
	if err := validateLogOutput(cfg.Log.Output); err != nil {
		errs = append(errs, err.Error())
	}
	if cfg.Log.Audit.Enabled {
		switch cfg.Log.Audit.Format {
		case "json":
			// OK
		default:
			errs = append(errs, fmt.Sprintf("log.audit.format must be json, got %q", cfg.Log.Audit.Format))
		}
		if err := validateLogOutput(cfg.Log.Audit.Output); err != nil {
			errs = append(errs, strings.Replace(err.Error(), "log output", "log.audit.output", 1))
		}
	}

	switch cfg.Response.DenyVerbosity {
	case "minimal", "verbose":
		// OK
	default:
		errs = append(errs, enumValueError("response.deny_verbosity", cfg.Response.DenyVerbosity, "minimal", "verbose"))
	}
	errs = append(errs, validateVisibleResourceLabels("response.visible_resource_labels", cfg.Response.VisibleResourceLabels)...)

	// Health path starts with /
	if cfg.Health.Enabled && !strings.HasPrefix(cfg.Health.Path, "/") {
		errs = append(errs, fmt.Sprintf("health.path must start with /, got %q", cfg.Health.Path))
	}
	if cfg.Health.Watchdog.Enabled {
		interval, err := time.ParseDuration(cfg.Health.Watchdog.Interval)
		if err != nil || interval <= 0 {
			errs = append(errs, fmt.Sprintf("health.watchdog.interval must be a positive duration, got %q", cfg.Health.Watchdog.Interval))
		}
	}
	if cfg.Metrics.Enabled && !strings.HasPrefix(cfg.Metrics.Path, "/") {
		errs = append(errs, fmt.Sprintf("metrics.path must start with /, got %q", cfg.Metrics.Path))
	}
	if cfg.Health.Enabled && cfg.Metrics.Enabled && cfg.Health.Path == cfg.Metrics.Path {
		errs = append(errs, fmt.Sprintf("metrics.path must not equal health.path when both endpoints are enabled, got %q", cfg.Metrics.Path))
	}

	errs = append(errs, validateRequestBody(cfg)...)

	// At least one rule
	if len(cfg.Rules) == 0 {
		errs = append(errs, containsAtLeastOneError("rules", "rule"))
	}

	// Validate each rule
	for i, r := range cfg.Rules {
		if r.Match.Method == "" {
			errs = append(errs, fmt.Sprintf("rule %d: match.method is required", i+1))
		}
		if r.Match.Path == "" {
			errs = append(errs, fmt.Sprintf("rule %d: match.path is required", i+1))
		}
		switch r.Action {
		case "allow", "deny":
			// OK
		default:
			errs = append(errs, fmt.Sprintf("rule %d: %s", i+1, enumValueError("action", r.Action, "allow", "deny")))
		}
	}

	return errs
}

func validateUnixSocketListenerSecurity(cfg *Config) []string {
	if strings.TrimSpace(cfg.Listen.SocketMode) == HardenedListenSocketMode {
		return nil
	}

	return []string{
		fmt.Sprintf("listen.socket_mode must be %q because unix listeners are created with owner-only permissions", HardenedListenSocketMode),
	}
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

	if IsNonLoopbackTCPAddress(cfg.Listen.Address) && !cfg.Listen.InsecureAllowPlainTCP && !cfg.Listen.TLS.Complete() {
		errs = append(errs,
			fmt.Sprintf("non-loopback TCP listener %q requires listen.tls mTLS config or listen.insecure_allow_plain_tcp=true", cfg.Listen.Address),
		)
	}

	return errs
}

func validateRequestBody(cfg *Config) []string {
	var errs []string

	errs = append(errs, validateRequestBodyConfig("request_body", cfg.RequestBody)...)

	for _, rawCIDR := range cfg.Clients.AllowedCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(rawCIDR)); err == nil {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("clients.allowed_cidrs entries must be valid CIDR prefixes, got %q", rawCIDR),
		)
	}

	if cfg.Clients.ContainerLabels.Enabled && cfg.Clients.ContainerLabels.LabelPrefix == "" {
		errs = append(errs, requiredWhenError("clients.container_labels.label_prefix", "clients.container_labels.enabled is true"))
	}

	if cfg.Listen.Socket != "" && len(cfg.Clients.AllowedCIDRs) > 0 {
		errs = append(errs, "clients.allowed_cidrs requires a TCP listener; remove listen.socket or clear clients.allowed_cidrs")
	}

	if cfg.Listen.Socket != "" && cfg.Clients.ContainerLabels.Enabled {
		errs = append(errs, "clients.container_labels requires a TCP listener; remove listen.socket or disable clients.container_labels")
	}

	profilesByName := make(map[string]struct{}, len(cfg.Clients.Profiles))
	for i, profile := range cfg.Clients.Profiles {
		errs = append(errs, validateClientProfile(i, profile, profilesByName)...)
	}

	if cfg.Clients.DefaultProfile != "" {
		if _, ok := profilesByName[cfg.Clients.DefaultProfile]; !ok {
			errs = append(errs, configuredMatchError("clients.default_profile", "client profile", cfg.Clients.DefaultProfile))
		}
	}

	if cfg.Listen.Socket != "" && len(cfg.Clients.SourceIPProfiles) > 0 {
		errs = append(errs, "clients.source_ip_profiles requires a TCP listener; remove listen.socket or clear clients.source_ip_profiles")
	}
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

	if len(cfg.Clients.ClientCertificateProfiles) > 0 && !cfg.Listen.TLS.Complete() {
		errs = append(errs, requiresError("clients.client_certificate_profiles", "listen.tls mutual TLS configuration"))
	}
	if cfg.Listen.Socket != "" && len(cfg.Clients.ClientCertificateProfiles) > 0 {
		errs = append(errs, "clients.client_certificate_profiles requires a TCP listener; remove listen.socket or clear clients.client_certificate_profiles")
	}
	for i, assignment := range cfg.Clients.ClientCertificateProfiles {
		prefix := fmt.Sprintf("clients.client_certificate_profiles[%d]", i)
		if assignment.Profile == "" {
			errs = append(errs, requiredFieldError(prefix+".profile"))
		} else if _, ok := profilesByName[assignment.Profile]; !ok {
			errs = append(errs, configuredMatchError(prefix+".profile", "client profile", assignment.Profile))
		}
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
		if selectorCount == 0 {
			errs = append(errs, containsAtLeastOneError(prefix, "client certificate identity selector"))
		}
	}

	if cfg.Listen.Socket == "" && len(cfg.Clients.UnixPeerProfiles) > 0 {
		errs = append(errs, "clients.unix_peer_profiles requires a unix listener; set listen.socket or clear clients.unix_peer_profiles")
	}
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
		for _, pid := range assignment.PIDs {
			if pid > 0 {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s.pids entries must be positive process IDs, got %d", prefix, pid))
		}
	}

	if cfg.Ownership.Owner != "" && cfg.Ownership.LabelKey == "" {
		errs = append(errs, requiredWhenError("ownership.label_key", "ownership.owner is set"))
	}

	return errs
}

func validateClientProfile(index int, profile ClientProfileConfig, profilesByName map[string]struct{}) []string {
	var errs []string

	prefix := fmt.Sprintf("clients.profiles[%d]", index)
	name := strings.TrimSpace(profile.Name)
	if name == "" {
		errs = append(errs, requiredFieldError(prefix+".name"))
	} else {
		if _, exists := profilesByName[name]; exists {
			errs = append(errs, uniqueValueError(prefix+".name", name))
		}
		profilesByName[name] = struct{}{}
	}

	if len(profile.Rules) == 0 {
		errs = append(errs, containsAtLeastOneError(prefix+".rules", "rule"))
	}

	errs = append(errs, validateVisibleResourceLabels(prefix+".response.visible_resource_labels", profile.Response.VisibleResourceLabels)...)
	errs = append(errs, validateRequestBodyConfig(prefix+".request_body", profile.RequestBody)...)
	errs = append(errs, validateRuleConfigs(profile.Rules, prefix+".rules")...)
	errs = append(errs, validateLimitsConfig(prefix+".limits", profile.Limits)...)

	return errs
}

func validateLimitsConfig(prefix string, cfg LimitsConfig) []string {
	var errs []string

	if cfg.Rate != nil {
		ratePfx := prefix + ".rate"
		if cfg.Rate.TokensPerSecond <= 0 {
			errs = append(errs, fmt.Sprintf("%s.tokens_per_second must be > 0, got %v", ratePfx, cfg.Rate.TokensPerSecond))
		}
		effectiveBurst := cfg.Rate.Burst
		if effectiveBurst == 0 {
			// Default: burst equals tokens_per_second.
			effectiveBurst = cfg.Rate.TokensPerSecond
		}
		if effectiveBurst < cfg.Rate.TokensPerSecond {
			errs = append(errs, fmt.Sprintf("%s.burst must be >= tokens_per_second (%v) or 0 (default), got %v",
				ratePfx, cfg.Rate.TokensPerSecond, cfg.Rate.Burst))
		}
		if cfg.Rate.Burst < 0 {
			errs = append(errs, fmt.Sprintf("%s.burst must not be negative, got %v", ratePfx, cfg.Rate.Burst))
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
			regex := "^" + filter.GlobToRegexString(ec.Path) + "$"
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

	for _, rawPath := range cfg.ContainerCreate.AllowedBindMounts {
		if _, ok := normalizeAllowedBindMount(rawPath); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf(
				"%s.container_create.allowed_bind_mounts entries must be absolute host paths, got %q",
				prefix,
				rawPath,
			),
		)
	}

	for _, rawPath := range cfg.ContainerCreate.AllowedDevices {
		if _, ok := normalizeAllowedBindMount(rawPath); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf(
				"%s.container_create.allowed_devices entries must be absolute host paths, got %q",
				prefix,
				rawPath,
			),
		)
	}

	for i, entry := range cfg.ContainerCreate.AllowedDeviceRequests {
		if strings.TrimSpace(entry.Driver) == "" {
			errs = append(errs,
				fmt.Sprintf("%s.container_create.allowed_device_requests[%d].driver is required", prefix, i),
			)
		}
		for j, capSet := range entry.AllowedCapabilities {
			if len(capSet) == 0 {
				errs = append(errs,
					fmt.Sprintf("%s.container_create.allowed_device_requests[%d].allowed_capabilities[%d] must be a non-empty capability set", prefix, i, j),
				)
			}
		}
		if entry.MaxCount != nil && *entry.MaxCount < -1 {
			errs = append(errs,
				fmt.Sprintf("%s.container_create.allowed_device_requests[%d].max_count must be -1 or a non-negative integer, got %d", prefix, i, *entry.MaxCount),
			)
		}
	}

	errs = append(errs, validateImageTrustConfig(prefix+".container_create.image_trust", cfg.ContainerCreate.ImageTrust)...)

	for i, command := range cfg.Exec.AllowedCommands {
		if validExecCommand(command) {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("%s.exec.allowed_commands entries must contain at least one non-empty argv token, got entry %d", prefix, i+1),
		)
	}

	for _, registry := range cfg.ImagePull.AllowedRegistries {
		if _, ok := normalizeAllowedRegistryHost(registry); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("%s.image_pull.allowed_registries entries must be bare registry hosts, got %q", prefix, registry),
		)
	}

	for _, rawPath := range cfg.Service.AllowedBindMounts {
		if _, ok := normalizeAllowedBindMount(rawPath); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf(
				"%s.service.allowed_bind_mounts entries must be absolute host paths, got %q",
				prefix,
				rawPath,
			),
		)
	}

	for _, registry := range cfg.Service.AllowedRegistries {
		if _, ok := normalizeAllowedRegistryHost(registry); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("%s.service.allowed_registries entries must be bare registry hosts, got %q", prefix, registry),
		)
	}

	for _, remoteAddr := range cfg.Swarm.AllowedJoinRemoteAddrs {
		if validRemoteAddress(remoteAddr) {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("%s.swarm.allowed_join_remote_addrs entries must be bare host[:port] values, got %q", prefix, remoteAddr),
		)
	}

	for _, registry := range cfg.Plugin.AllowedRegistries {
		if _, ok := normalizeAllowedRegistryHost(registry); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("%s.plugin.allowed_registries entries must be bare registry hosts, got %q", prefix, registry),
		)
	}

	for _, rawPath := range cfg.Plugin.AllowedBindMounts {
		if _, ok := normalizeAllowedBindMount(rawPath); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf(
				"%s.plugin.allowed_bind_mounts entries must be absolute host paths, got %q",
				prefix,
				rawPath,
			),
		)
	}

	for _, rawPath := range cfg.Plugin.AllowedDevices {
		if _, ok := normalizeAllowedBindMount(rawPath); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf(
				"%s.plugin.allowed_devices entries must be absolute host paths, got %q",
				prefix,
				rawPath,
			),
		)
	}

	for _, capability := range cfg.Plugin.AllowedCapabilities {
		if validPluginCapability(capability) {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("%s.plugin.allowed_capabilities entries must be non-empty capability names, got %q", prefix, capability),
		)
	}

	for _, rawPrefix := range cfg.Plugin.AllowedSetEnvPrefixes {
		if validPluginSetEnvPrefix(rawPrefix) {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf("%s.plugin.allowed_set_env_prefixes entries must be non-empty env assignment prefixes, got %q", prefix, rawPrefix),
		)
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

	for i, k := range cfg.AllowedSigningKeys {
		if strings.TrimSpace(k.PEM) == "" {
			errs = append(errs,
				fmt.Sprintf("%s.allowed_signing_keys[%d].pem is required", prefix, i),
			)
		}
	}

	for i, kl := range cfg.AllowedKeyless {
		if strings.TrimSpace(kl.Issuer) == "" {
			errs = append(errs,
				fmt.Sprintf("%s.allowed_keyless[%d].issuer is required", prefix, i),
			)
		}
		if strings.TrimSpace(kl.SubjectPattern) == "" {
			errs = append(errs,
				fmt.Sprintf("%s.allowed_keyless[%d].subject_pattern is required", prefix, i),
			)
		}
	}

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
