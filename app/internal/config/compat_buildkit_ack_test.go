package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// buildkitMediationScopes are the two places request_body.buildkit can be
// configured. validateBuildkitAckMutualExclusion rejects the deprecated ack
// against BOTH of them, so ApplyCompat has to skip its auto-ack for both too
// — a skip that only covered the top level would still hand a
// profile-mediating operator the same startup refusal naming a key they
// never wrote.
var buildkitMediationScopes = []struct {
	name  string
	apply func(cfg *Config)
}{
	{
		name: "top level",
		apply: func(cfg *Config) {
			cfg.RequestBody.Buildkit.Control.Solve.Allow = true
		},
	},
	{
		name: "client profile",
		apply: func(cfg *Config) {
			cfg.Clients.Profiles = []ClientProfileConfig{
				{
					Name:  "builders",
					Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
					RequestBody: RequestBodyConfig{
						Buildkit: BuildkitRequestBodyConfig{
							Control: BuildkitControlRequestBodyConfig{Solve: BuildkitSolveRequestBodyConfig{Allow: true}},
						},
					},
				},
			}
		},
	},
}

// TestCompatAutoAckWouldCollideWithBuildkitMediation is the reproduction half
// of the pair: it pins that the value ApplyCompat used to set unconditionally
// is exactly the value Validate refuses once request_body.buildkit is
// configured. Without this, TestCompatDoesNotAckBuildkitTunnelWhenMediationConfigured
// below could keep passing for the wrong reason (say, because the
// mutual-exclusion check was relaxed rather than because compat stopped
// setting the flag), and the operator-facing refusal it exists to prevent
// would be back with nothing failing.
func TestCompatAutoAckWouldCollideWithBuildkitMediation(t *testing.T) {
	for _, scope := range buildkitMediationScopes {
		t.Run(scope.name, func(t *testing.T) {
			cfg := Defaults()
			scope.apply(&cfg)

			if err := Validate(&cfg); err != nil {
				t.Fatalf("Validate() error = %v, want nil before the ack is set", err)
			}

			// Exactly what ApplyCompat did for GRPC=1 / SESSION=1.
			cfg.InsecureAcceptOpaqueBuildkitTunnels = true

			err := Validate(&cfg)
			if err == nil {
				t.Fatal("Validate() = nil with both the ack and request_body.buildkit set; the mutual-exclusion gate this fix routes around is gone")
			}
			if !strings.Contains(err.Error(), "insecure_accept_opaque_buildkit_tunnels") || !strings.Contains(err.Error(), "request_body.buildkit") {
				t.Fatalf("expected the mutual-exclusion message naming both settings, got: %v", err)
			}
		})
	}
}

// TestCompatDoesNotAckBuildkitTunnelWhenMediationConfigured is the fix half.
//
// GRPC=1 / SESSION=1 still auto-set insecure_accept_opaque_buildkit_tunnels
// on a config with no BuildKit mediation policy (the drop-in migration
// promise — TestCompatGrpcEnvAutoAcksBuildkitTunnel). Once
// request_body.buildkit IS configured, auto-setting it turns an operator who
// already migrated into a startup refusal naming a key they never wrote,
// because ApplyCompat runs before validation. Compat must leave the flag
// alone there and let the compat /grpc and /session rules be admitted by
// mediation instead.
func TestCompatDoesNotAckBuildkitTunnelWhenMediationConfigured(t *testing.T) {
	for _, envKey := range []string{"GRPC", "SESSION"} {
		for _, scope := range buildkitMediationScopes {
			t.Run(envKey+"/"+scope.name, func(t *testing.T) {
				cfg := Defaults()
				scope.apply(&cfg)
				t.Setenv(envKey, "1")

				var logBuf bytes.Buffer
				logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

				if !ApplyCompat(&cfg, logger) {
					t.Fatalf("expected compat to activate for %s=1", envKey)
				}

				if cfg.InsecureAcceptOpaqueBuildkitTunnels {
					t.Fatalf("%s=1 auto-set InsecureAcceptOpaqueBuildkitTunnels with request_body.buildkit configured (%s); the two are mutually exclusive and validation would refuse to start", envKey, scope.name)
				}
				// Config-level validation is only the half this package owns:
				// the top-level rule-admission check lives in cmd, and for the
				// profile scope it still refuses (correctly — a profile policy
				// cannot mediate top-level rules). See
				// TestValidateRefusesProfileOnlyBuildkitMediationWithCompatGrpc
				// and TestValidateAcceptsCompatGrpcAlongsideBuildkitMediation
				// in internal/cmd for the end-to-end verdicts.
				if err := Validate(&cfg); err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				if strings.Contains(logBuf.String(), "set insecure_accept_opaque_buildkit_tunnels: true explicitly going forward") {
					t.Fatalf("expected no nudge toward the deprecated ack under mediation, got logs: %s", logBuf.String())
				}
				if !strings.Contains(logBuf.String(), "request_body.buildkit is configured") {
					t.Fatalf("expected a log record explaining why the ack was left unset, got logs: %s", logBuf.String())
				}
			})
		}
	}
}

// TestCompatDoesNotClearAnExplicitAckUnderMediation guards the one thing the
// skip must NOT do: an operator who wrote insecure_accept_opaque_buildkit_tunnels
// themselves AND a request_body.buildkit block still has a genuinely
// contradictory config, and the refusal names a key they really did write.
// Silently clearing it here would resolve the contradiction in the
// operator's favor without telling them.
func TestCompatDoesNotClearAnExplicitAckUnderMediation(t *testing.T) {
	cfg := Defaults()
	cfg.InsecureAcceptOpaqueBuildkitTunnels = true
	cfg.RequestBody.Buildkit.Control.Solve.Allow = true
	t.Setenv("GRPC", "1")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if !ApplyCompat(&cfg, logger) {
		t.Fatal("expected compat to activate")
	}

	if !cfg.InsecureAcceptOpaqueBuildkitTunnels {
		t.Fatal("ApplyCompat cleared an explicitly configured InsecureAcceptOpaqueBuildkitTunnels")
	}
	// The skip log runs on this path too, so it must not describe the flag as
	// unset when the operator set it: the value it reports has to be the real
	// one.
	if strings.Contains(logBuf.String(), "unset") {
		t.Fatalf("skip log claims the acknowledgment is unset while the operator set it: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "insecure_accept_opaque_buildkit_tunnels=true") {
		t.Fatalf("skip log does not report the acknowledgment's actual value: %s", logBuf.String())
	}
	if err := Validate(&cfg); err == nil {
		t.Fatal("Validate() = nil for an explicitly set ack alongside request_body.buildkit, want the mutual-exclusion refusal")
	}
}

// TestCompatGeneratedRulesProvenance pins the signal cmd/rules.go reads to
// decide whether a refused rule came from a Tecnativa env var. Env presence
// is NOT that signal: compat only generates rules while the ruleset still
// matches the defaults, so a config with its own rules leaves the flag false
// even with GRPC=1 set, and its refusal keeps the hand-written wording.
func TestCompatGeneratedRulesProvenance(t *testing.T) {
	t.Run("false before ApplyCompat", func(t *testing.T) {
		cfg := Defaults()
		if cfg.HasCompatGeneratedRules() {
			t.Fatal("HasCompatGeneratedRules() = true on a freshly defaulted config")
		}
	})

	t.Run("true once compat generates the ruleset", func(t *testing.T) {
		cfg := Defaults()
		t.Setenv("GRPC", "1")

		if !ApplyCompat(&cfg, discardLogger) {
			t.Fatal("expected compat to activate")
		}
		if !cfg.HasCompatGeneratedRules() {
			t.Fatal("HasCompatGeneratedRules() = false after ApplyCompat replaced the ruleset")
		}
	})

	t.Run("false when compat declines on a custom ruleset", func(t *testing.T) {
		cfg := Defaults()
		cfg.Rules = []RuleConfig{
			{Match: MatchConfig{Method: "POST", Path: "/grpc"}, Action: "allow"},
			{Match: MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}
		t.Setenv("GRPC", "1")

		if ApplyCompat(&cfg, discardLogger) {
			t.Fatal("expected compat to decline against a custom ruleset")
		}
		if cfg.HasCompatGeneratedRules() {
			t.Fatal("HasCompatGeneratedRules() = true for rules the operator wrote")
		}
	})
}
