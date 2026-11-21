package cmd

import (
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// catalogAckCase drives one allow rule through validateAndCompileRules with
// and without the acknowledgment that guards the catalog entry it reaches.
type catalogAckCase struct {
	name       string
	method     string
	path       string
	wantEntry  string
	blindWrite bool // true: insecure_allow_body_blind_writes guards it; false: read exfiltration
}

func catalogAckConfig(tc catalogAckCase, ack bool) config.Config {
	cfg := config.Defaults()
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: tc.method, Path: tc.path}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.Rules = rules
	if ack {
		if tc.blindWrite {
			cfg.InsecureAllowBodyBlindWrites = true
		} else {
			cfg.InsecureAllowReadExfiltration = true
		}
	}
	return cfg
}

func runCatalogAckCases(t *testing.T, cases []catalogAckCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := catalogAckConfig(tc, false)
			_, err := validateAndCompileRules(&cfg)
			if err == nil {
				t.Fatalf("expected %s %s without acknowledgment to fail validation", tc.method, tc.path)
			}
			if !strings.Contains(err.Error(), tc.wantEntry) {
				t.Fatalf("expected %q in error, got: %v", tc.wantEntry, err)
			}
			wantFlag := "insecure_allow_read_exfiltration"
			if tc.blindWrite {
				wantFlag = "insecure_allow_body_blind_writes"
			}
			if !strings.Contains(err.Error(), wantFlag) {
				t.Fatalf("expected %s hint in error, got: %v", wantFlag, err)
			}

			cfg = catalogAckConfig(tc, true)
			if _, err := validateAndCompileRules(&cfg); err != nil {
				t.Fatalf("acknowledged config rejected: %v", err)
			}
		})
	}
}

func TestDockerCheckpointRoutesRequireAcknowledgment(t *testing.T) {
	runCatalogAckCases(t, []catalogAckCase{
		{name: "ALLOW_DELETE shape reaches checkpoint delete", method: http.MethodDelete, path: "/containers/**", wantEntry: "DELETE /containers/sockguard-test/checkpoints/sockguard-test", blindWrite: true},
		{name: "exact checkpoint delete", method: http.MethodDelete, path: "/containers/*/checkpoints/*", wantEntry: "DELETE /containers/sockguard-test/checkpoints/sockguard-test", blindWrite: true},
		{name: "wildcard checkpoint create", method: http.MethodPost, path: "/containers/*/checkpoints", wantEntry: "POST /containers/sockguard-test/checkpoints", blindWrite: true},
		{name: "checkpoint list is an exfil surface", method: http.MethodGet, path: "/containers/*/checkpoints", wantEntry: "GET /containers/sockguard-test/checkpoints"},
		{name: "broad container GET reaches checkpoint list", method: http.MethodGet, path: "/containers/**", wantEntry: "GET /containers/sockguard-test/checkpoints"},
	})
}

func TestDockerCheckpointRoutesStayDeniedByDefault(t *testing.T) {
	cfg := config.Defaults()
	if _, err := validateAndCompileRules(&cfg); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}
