package config

import (
	"fmt"
	"net/netip"
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
		errs = append(errs, "at least one listener required (listen.socket or listen.address)")
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
		errs = append(errs, fmt.Sprintf("invalid log level %q (must be debug, info, warn, or error)", cfg.Log.Level))
	}

	// Valid log format
	switch cfg.Log.Format {
	case "json", "text":
		// OK
	default:
		errs = append(errs, fmt.Sprintf("invalid log format %q (must be json or text)", cfg.Log.Format))
	}

	// Log output must resolve to stderr, stdout, or a local file path.
	if err := validateLogOutput(cfg.Log.Output); err != nil {
		errs = append(errs, err.Error())
	}

	switch cfg.Response.DenyVerbosity {
	case "minimal", "verbose":
		// OK
	default:
		errs = append(errs, fmt.Sprintf("invalid deny response verbosity %q (must be minimal or verbose)", cfg.Response.DenyVerbosity))
	}

	// Health path starts with /
	if cfg.Health.Enabled && !strings.HasPrefix(cfg.Health.Path, "/") {
		errs = append(errs, fmt.Sprintf("health path must start with /, got %q", cfg.Health.Path))
	}

	errs = append(errs, validateRequestBody(cfg)...)

	// At least one rule
	if len(cfg.Rules) == 0 {
		errs = append(errs, "at least one rule is required")
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
			errs = append(errs, fmt.Sprintf("rule %d: invalid action %q (must be allow or deny)", i+1, r.Action))
		}
	}

	return errs
}

func validateTCPListenerSecurity(cfg *Config) []string {
	var errs []string

	if cfg.Listen.TLS.Enabled() && !cfg.Listen.TLS.Complete() {
		errs = append(errs, "listen.tls requires cert_file, key_file, and client_ca_file together")
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

	for _, rawPath := range cfg.RequestBody.ContainerCreate.AllowedBindMounts {
		if _, ok := normalizeAllowedBindMount(rawPath); ok {
			continue
		}
		errs = append(
			errs,
			fmt.Sprintf(
				"request_body.container_create.allowed_bind_mounts entries must be absolute host paths, got %q",
				rawPath,
			),
		)
	}

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
		errs = append(errs, "clients.container_labels.label_prefix is required when clients.container_labels.enabled is true")
	}

	if cfg.Listen.Socket != "" && len(cfg.Clients.AllowedCIDRs) > 0 {
		errs = append(errs, "clients.allowed_cidrs requires a TCP listener; remove listen.socket or clear clients.allowed_cidrs")
	}

	if cfg.Listen.Socket != "" && cfg.Clients.ContainerLabels.Enabled {
		errs = append(errs, "clients.container_labels requires a TCP listener; remove listen.socket or disable clients.container_labels")
	}

	if cfg.Ownership.Owner != "" && cfg.Ownership.LabelKey == "" {
		errs = append(errs, "ownership.label_key is required when ownership.owner is set")
	}

	return errs
}

func normalizeAllowedBindMount(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	cleaned := path.Clean(value)
	return cleaned, true
}
