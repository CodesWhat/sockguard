package config

import (
	"fmt"
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
