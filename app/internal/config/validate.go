package config

import (
	"fmt"
	"strings"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

var compileRulesFn = CompileRules
var compileFilterRule = filter.CompileRule

// ValidationError holds multiple validation errors.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation failed:\n  - %s", strings.Join(e.Errors, "\n  - "))
}

// Validate checks a Config for correctness, returning a ValidationError
// if any problems are found. On success it returns the compiled filter rules
// that the server should enforce.
func Validate(cfg *Config) ([]*filter.CompiledRule, error) {
	errs := validateBasic(cfg)
	if len(errs) > 0 {
		return nil, &ValidationError{Errors: errs}
	}

	compiled, err := compileRulesFn(cfg.Rules)
	if err != nil {
		return nil, &ValidationError{Errors: []string{err.Error()}}
	}

	return compiled, nil
}

func validateBasic(cfg *Config) []string {
	var errs []string

	// At least one listener
	if cfg.Listen.Socket == "" && cfg.Listen.Address == "" {
		errs = append(errs, "at least one listener required (listen.socket or listen.address)")
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
	if err := logging.ValidateOutput(cfg.Log.Output); err != nil {
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

// CompileRules converts RuleConfig entries into compiled filter rules.
func CompileRules(rules []RuleConfig) ([]*filter.CompiledRule, error) {
	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i, r := range rules {
		methods := splitMethods(r.Match.Method)
		cr, err := compileFilterRule(filter.Rule{
			Methods: methods,
			Pattern: r.Match.Path,
			Action:  filter.Action(r.Action),
			Reason:  r.Reason,
			Index:   i,
		})
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled, nil
}

func splitMethods(value string) []string {
	methods := strings.Split(value, ",")
	for i := range methods {
		methods[i] = strings.TrimSpace(methods[i])
	}
	return methods
}
