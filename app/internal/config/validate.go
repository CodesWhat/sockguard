package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"strings"
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
			addr, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s.ip_addresses entries must be valid IP addresses, got %q", prefix, value))
				continue
			}
			selectorCount++
			if !addr.IsValid() {
				errs = append(errs, fmt.Sprintf("%s.ip_addresses entries must be valid IP addresses, got %q", prefix, value))
			}
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
