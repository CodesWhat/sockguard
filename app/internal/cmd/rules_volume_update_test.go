package cmd

import (
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// TestBodySensitiveWriteCatalogTreatsVolumeUpdateAsInspected pins the
// config-validation half of the cluster-volume update gap:
// PUT /volumes/{name} must be in the body-sensitive write catalog, and it must
// be recognized as covered by request_body.volume so allowing it neither slips
// through unlisted nor spuriously demands insecure_allow_body_blind_writes.
func TestBodySensitiveWriteCatalogTreatsVolumeUpdateAsInspected(t *testing.T) {
	endpoint := findBodySensitiveWriteEndpoint(t, http.MethodPut, "/volumes/sockguard-test")

	// The route moby registers is PUT /volumes/{name:.*}, so the catalog
	// identifier has to be the slash-bearing shape or a rule constrained
	// below one literal segment would be missed.
	if endpoint.identifierShape != catalogIdentifierPath {
		t.Fatalf("identifierShape = %v, want catalogIdentifierPath", endpoint.identifierShape)
	}

	// An empty RequestBodyConfig is the fail-closed default posture: the
	// protection this reports has to hold with nothing configured.
	if !bodyInspectionConfiguredForEndpoint(config.RequestBodyConfig{}, endpoint) {
		t.Fatal("PUT /volumes/{name} is not recognized as covered by request_body.volume inspection")
	}
}

// TestValidateAndCompileRulesAllowsVolumeUpdateWithRequestBodyInspection is
// the positive half: a rule opening the cluster-volume update validates clean
// under the default config, exactly as POST /volumes/create does, because the
// endpoint is inspected rather than blind.
func TestValidateAndCompileRulesAllowsVolumeUpdateWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPut, Path: "/volumes/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}
