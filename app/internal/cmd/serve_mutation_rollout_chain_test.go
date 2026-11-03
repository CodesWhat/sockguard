package cmd

import (
	"io"
	"log/slog"
	"net/http"
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/testhelp"
)

// TestServeChainMutationRolloutAmbiguousBody sends a body the admission
// mutation engine refuses as request_body_ambiguous through the production
// chain under a profile in each rollout mode.
//
// Warn and audit forward a request the policy would deny. With an
// enforce-mode rule configured, the engine can't mutate a body it can't read
// unambiguously, so forwarding it would send the client's bytes with the
// required rewrite silently skipped: the one body shape that dodges the engine
// would also dodge the label an operator required. That refusal holds in
// every mode. A surface with only a warn-mode rule has no required rewrite to
// skip, so there the rollout modes forward the body untouched and log what
// enforce would have refused.
func TestServeChainMutationRolloutAmbiguousBody(t *testing.T) {
	const (
		injected  = "com.example.team"
		ambiguous = "request_body_ambiguous"
		body      = "{\"Image\":\"alpine\",\"Labels\":{\"İstanbul\":\"1\"}}"
	)
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	for _, ruleMode := range []string{"enforce", "warn"} {
		for _, mode := range []string{"enforce", "warn", "audit"} {
			t.Run("rule "+ruleMode+"/profile "+mode, func(t *testing.T) {
				daemon := &keyRolloutChainDaemon{}
				collector := &testhelp.CollectingHandler{}
				logger := testhelp.NewTeeLogger(slog.NewTextHandler(io.Discard, nil), collector)
				addr := newEngineChainWithLogger(t, "mut-rollout", daemon, logger, func(cfg *config.Config) {
					cfg.Log.AccessLog = true
					cfg.Rules = rules
					cfg.Mutations.Rules = []config.MutationRuleConfig{{
						ID:           "team-label",
						Mode:         ruleMode,
						Surfaces:     []string{"container_create"},
						InjectLabels: &config.InjectLabelsMutationConfig{Labels: map[string]string{injected: "platform"}},
					}}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "rollout", Mode: mode, Rules: rules}}
					cfg.Clients.DefaultProfile = "rollout"
				})

				status, answer := sendNamespaceChainRequest(t, "http://"+addr+"/v1.45/containers/create", body)
				record := keyRolloutChainRecord(t, collector)

				forwardsUntouched := ruleMode == "warn" && mode != "enforce"
				if !forwardsUntouched {
					if status != http.StatusBadRequest || len(daemon.received()) != 0 {
						t.Errorf("status %d, daemon %q, want 400 and nothing forwarded; body: %s", status, daemon.received(), answer)
					}
					if record.Message != "request_denied" || record.Attrs["reason_code"] != ambiguous {
						t.Errorf("access log = %s with reason_code %v, want request_denied with %s", record.Message, record.Attrs["reason_code"], ambiguous)
					}
					return
				}
				if status != http.StatusCreated {
					t.Errorf("status = %d, want %d; body: %s", status, http.StatusCreated, answer)
				}
				if got := daemon.received(); !slices.Equal(got, []string{body}) {
					t.Errorf("daemon received %q, want the client's bytes %q", got, body)
				}
				if record.Message != "request_would_deny" || record.Attrs["reason_code"] != ambiguous || record.Attrs["rollout_mode"] != mode {
					t.Errorf("access log = %s with reason_code %v, rollout_mode %v, want request_would_deny with %s, %s",
						record.Message, record.Attrs["reason_code"], record.Attrs["rollout_mode"], ambiguous, mode)
				}
			})
		}
	}
}
