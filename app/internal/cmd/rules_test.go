package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
)

func useRuleDeps(t *testing.T) {
	t.Helper()

	originalValidateConfig := validateConfig
	originalCompileFilterRule := compileFilterRule

	t.Cleanup(func() {
		validateConfig = originalValidateConfig
		compileFilterRule = originalCompileFilterRule
	})
}

func TestValidateAndCompileRulesReturnsCompiledRules(t *testing.T) {
	cfg := config.Defaults()

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsContainerCreateWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsBodySensitiveWriteRulesWithExplicitOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.InsecureAllowBodyBlindWrites = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsRawReadExfiltrationWithExplicitOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.InsecureAllowReadExfiltration = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/images/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/*/push"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/*/push"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsExecWithConfiguredBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/exec"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.RequestBody.Exec.AllowedCommands = [][]string{{"/usr/local/bin/pre-update"}}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsImagePullWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/create"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsBuildWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/build"}, Action: "allow"},
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

func TestBodySensitiveWriteCatalogTreatsLibpodBuildAsInspected(t *testing.T) {
	var endpoint bodySensitiveWriteEndpoint
	found := false
	for _, candidate := range bodySensitiveWriteEndpoints {
		if candidate.method == http.MethodPost && candidate.path == "/libpod/build" {
			endpoint = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatal("POST /libpod/build is missing from the body-sensitive write catalog")
	}
	if !bodyInspectionConfiguredForEndpoint(config.RequestBodyConfig{}, endpoint) {
		t.Fatal("POST /libpod/build is not recognized as covered by request_body.build inspection")
	}
}

// TestBodySensitiveWriteCatalogTreatsLibpodImagePullAsInspected pins the
// config-validation half of the libpod image-pull gap: POST
// /libpod/images/pull must be in the body-sensitive write catalog, and it must
// be recognized as covered by request_body.image_pull so allowing it does not
// spuriously demand insecure_allow_body_blind_writes.
func TestBodySensitiveWriteCatalogTreatsLibpodImagePullAsInspected(t *testing.T) {
	var endpoint bodySensitiveWriteEndpoint
	found := false
	for _, candidate := range bodySensitiveWriteEndpoints {
		if candidate.method == http.MethodPost && candidate.path == "/libpod/images/pull" {
			endpoint = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatal("POST /libpod/images/pull is missing from the body-sensitive write catalog")
	}
	if !bodyInspectionConfiguredForEndpoint(config.RequestBodyConfig{}, endpoint) {
		t.Fatal("POST /libpod/images/pull is not recognized as covered by request_body.image_pull inspection")
	}
}

// TestBodySensitiveWriteCatalogTreatsLibpodNetworkAttachAsInspected pins the
// config-validation half of the libpod network connect/disconnect gap: both
// paths must be in the body-sensitive write catalog, and both must be
// recognized as covered by request_body.libpod_network so allowing them does
// not spuriously demand insecure_allow_body_blind_writes.
func TestBodySensitiveWriteCatalogTreatsLibpodNetworkAttachAsInspected(t *testing.T) {
	for _, path := range []string{"/libpod/networks/sockguard-test/connect", "/libpod/networks/sockguard-test/disconnect", "/libpod/networks/sockguard-test/update"} {
		t.Run(path, func(t *testing.T) {
			var endpoint bodySensitiveWriteEndpoint
			found := false
			for _, candidate := range bodySensitiveWriteEndpoints {
				if candidate.method == http.MethodPost && candidate.path == path {
					endpoint = candidate
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("POST %s is missing from the body-sensitive write catalog", path)
			}
			if !bodyInspectionConfiguredForEndpoint(config.RequestBodyConfig{}, endpoint) {
				t.Fatalf("POST %s is not recognized as covered by request_body.libpod_network inspection", path)
			}
		})
	}
}

func TestValidateAndCompileRulesAllowsLibpodNetworkAttachWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/networks/*/connect"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/networks/*/disconnect"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/networks/*/update"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsLibpodImagePullWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/pull"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsServiceWritesWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.RequestBody.Service.AllowOfficial = true

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsSwarmInitWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/init"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsVolumeSecretAndConfigWritesWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/volumes/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/secrets/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/configs/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.RequestBody.Secret.AllowTemplateDrivers = true
	cfg.RequestBody.Config.AllowTemplateDrivers = true

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsNetworkWritesWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/networks/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/networks/*/connect"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/networks/*/disconnect"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsContainerUpdateArchiveAndImageLoadWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPut, Path: "/containers/*/archive"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/load"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.RequestBody.ContainerArchive.AllowedPaths = []string{"/tmp/uploads"}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsSwarmJoinAndUpdateWithConfiguredInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/join"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.RequestBody.Swarm.AllowedJoinRemoteAddrs = []string{"manager.internal:2377"}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesAllowsSwarmUnlockAndNodeUpdateWithRequestBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/unlock"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/nodes/*/update"}, Action: "allow"},
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

func TestValidateAndCompileRulesAllowsPluginWritesWithConfiguredInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/pull"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/*/upgrade"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/*/set"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.RequestBody.Plugin.AllowedRegistries = []string{"plugins.example.com"}
	cfg.RequestBody.Plugin.AllowedBindMounts = []string{"/var/lib/plugins"}
	cfg.RequestBody.Plugin.AllowedDevices = []string{"/dev/fuse"}
	cfg.RequestBody.Plugin.AllowedCapabilities = []string{"CAP_SYS_ADMIN"}
	cfg.RequestBody.Plugin.AllowedSetEnvPrefixes = []string{"DEBUG=", "LOG_LEVEL="}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesRejectsSwarmJoinWithoutConfiguredRemoteAllowlist(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/join"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected swarm join blind-write validation to fail")
	}
	if !strings.Contains(err.Error(), "POST /swarm/join") {
		t.Fatalf("expected swarm join endpoint in error, got: %v", err)
	}
}

func TestValidateAndCompileRulesRejectsPluginSetWithoutAllowedEnvPrefixes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/*/set"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected plugin set blind-write validation to fail")
	}
	if !strings.Contains(err.Error(), "POST /plugins/sockguard-test/set") {
		t.Fatalf("expected plugin set endpoint in error, got: %v", err)
	}
}

func TestBodyInspectionConfiguredForEndpointRejectsUnknownEndpoint(t *testing.T) {
	requestBody := config.RequestBodyConfig{
		Exec: config.ExecRequestBodyConfig{
			AllowedCommands: [][]string{{"/bin/true"}},
		},
		Swarm: config.SwarmRequestBodyConfig{
			AllowedJoinRemoteAddrs: []string{"manager.internal:2377"},
		},
		Plugin: config.PluginRequestBodyConfig{
			AllowedSetEnvPrefixes: []string{"DEBUG="},
		},
	}
	endpoint := bodySensitiveWriteEndpoint{
		method: http.MethodPost,
		path:   "/future/body-sensitive",
	}

	if bodyInspectionConfiguredForEndpoint(requestBody, endpoint) {
		t.Fatal("expected unknown endpoint to be treated as not body-inspected")
	}
}

func TestValidateAndCompileRulesRejectsOnlyExecAndPluginSetWhenTheirRequiredPolicyIsMissing(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/exec"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/networks/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/load"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/unlock"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/*/set"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected missing required policy validation to fail")
	}
	if !strings.Contains(err.Error(), "POST /containers/sockguard-test/exec") {
		t.Fatalf("expected exec endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "POST /plugins/sockguard-test/set") {
		t.Fatalf("expected plugin set endpoint in error, got: %v", err)
	}
	for _, endpoint := range []string{"POST /networks/create", "POST /images/load", "POST /swarm/unlock"} {
		if strings.Contains(err.Error(), endpoint) {
			t.Fatalf("did not expect inspected endpoint %s in error, got: %v", endpoint, err)
		}
	}
}

func TestValidateAndCompileRulesRejectsRawReadExfiltrationRulesWithoutExplicitOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/services/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/tasks/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/attach"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/images/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/*/push"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected raw read exfiltration validation to fail")
	}
	for _, endpoint := range []string{
		"GET /containers/sockguard-test/archive",
		"GET /containers/sockguard-test/export",
		"GET /containers/sockguard-test/logs",
		"GET /containers/sockguard-test/attach/ws",
		"GET /services/sockguard-test/logs",
		"GET /tasks/sockguard-test/logs",
		"POST /containers/sockguard-test/attach",
		"GET /images/get",
		"GET /images/sockguard-test/get",
		"POST /images/sockguard-test/push",
		"POST /plugins/sockguard-test/push",
	} {
		if !strings.Contains(err.Error(), endpoint) {
			t.Fatalf("expected %s in error, got: %v", endpoint, err)
		}
	}
	if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
		t.Fatalf("expected explicit read exfiltration opt-in hint, got: %v", err)
	}
}

func TestValidateAndCompileRulesRejectsContainerArchiveRuleWithoutReadExfiltrationOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/archive"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected container archive read exfiltration validation to fail")
	}
	if !strings.Contains(err.Error(), "GET /containers/sockguard-test/archive") {
		t.Fatalf("expected guarded container archive endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
		t.Fatalf("expected explicit read exfiltration opt-in hint, got: %v", err)
	}
}

func TestValidateAndCompileRulesRejectsRegistryPushWithoutExfiltrationOptIn(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		endpoint string
		ackBlind bool
	}{
		{
			name:     "image push",
			path:     "/images/*/push",
			endpoint: "POST /images/sockguard-test/push",
		},
		{
			name:     "plugin push",
			path:     "/plugins/*/push",
			endpoint: "POST /plugins/sockguard-test/push",
		},
		{
			name:     "libpod manifest registry push",
			path:     "/libpod/manifests/*/registry/*",
			endpoint: "POST /libpod/manifests/sockguard-test/registry/sockguard-test",
		},
		{
			name:     "libpod manifest push (backward-compat)",
			path:     "/libpod/manifests/*/push",
			endpoint: "POST /libpod/manifests/sockguard-test/push",
			// The normalized rule also reaches v4's body-bearing generic
			// manifest-create route for a manifest literally named "*/push".
			// Acknowledge that independent risk so this case can isolate the
			// v3 registry-push response gate it is asserting.
			ackBlind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.InsecureAllowBodyBlindWrites = tt.ackBlind
			cfg.Rules = []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: tt.path}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			}

			_, err := validateAndCompileRules(&cfg)
			if err == nil {
				t.Fatal("expected registry push exfiltration validation to fail")
			}
			if !strings.Contains(err.Error(), tt.endpoint) {
				t.Fatalf("expected guarded endpoint %s in error, got: %v", tt.endpoint, err)
			}
			if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
				t.Fatalf("expected explicit exfiltration opt-in hint, got: %v", err)
			}
		})
	}
}

func TestValidateAndCompileRulesAllowsNamedClientProfilesWithBodyInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "watchtower",
			RequestBody: config.RequestBodyConfig{
				Exec: config.ExecRequestBodyConfig{
					AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
				},
			},
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/exec"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}

	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("validateAndCompileRules() error = %v", err)
	}
	if len(compiled) != len(cfg.Rules) {
		t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
	}
}

func TestValidateAndCompileRulesRejectsNamedClientProfileBlindWrites(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "watchtower",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/exec"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected named client profile blind-write validation to fail")
	}
	if !strings.Contains(err.Error(), "watchtower") {
		t.Fatalf("expected profile name in error, got: %v", err)
	}
}

func TestValidateAndCompileRulesRejectsNamedClientProfileReadExfiltration(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "backup-agent",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/services/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/tasks/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/attach"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/images/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/*/push"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/*/push"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected named client profile raw read exfiltration validation to fail")
	}
	if !strings.Contains(err.Error(), "backup-agent") {
		t.Fatalf("expected profile name in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "GET /containers/sockguard-test/archive") {
		t.Fatalf("expected guarded raw read endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "POST /containers/sockguard-test/attach") {
		t.Fatalf("expected guarded attach endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "GET /containers/sockguard-test/attach/ws") {
		t.Fatalf("expected guarded websocket attach endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "GET /services/sockguard-test/logs") {
		t.Fatalf("expected guarded service logs endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "POST /images/sockguard-test/push") {
		t.Fatalf("expected guarded image push endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "POST /plugins/sockguard-test/push") {
		t.Fatalf("expected guarded plugin push endpoint in error, got: %v", err)
	}
}

func TestValidateAndCompileRulesAllowsBuildkitTunnelWithExplicitOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.InsecureAcceptOpaqueBuildkitTunnels = true //nolint:staticcheck // SA1019: exercising the deprecated flag intentionally
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/session"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/grpc"}, Action: "allow"},
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

func TestValidateAndCompileRulesRejectsBuildkitTunnelRulesWithoutExplicitOptIn(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		endpoint string
	}{
		{
			name:     "session",
			path:     "/session",
			endpoint: "POST /session",
		},
		{
			name:     "grpc",
			path:     "/grpc",
			endpoint: "POST /grpc",
		},
		{
			name:     "moby buildkit control method path",
			path:     "/moby.buildkit.v1.Control/*",
			endpoint: "POST /moby.buildkit.v1.Control/Solve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Rules = []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: tt.path}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			}

			_, err := validateAndCompileRules(&cfg)
			if err == nil {
				t.Fatal("expected buildkit tunnel validation to fail")
			}
			if !strings.Contains(err.Error(), tt.endpoint) {
				t.Fatalf("expected guarded endpoint %s in error, got: %v", tt.endpoint, err)
			}
			if !strings.Contains(err.Error(), "insecure_accept_opaque_buildkit_tunnels=true") {
				t.Fatalf("expected explicit buildkit tunnel opt-in hint, got: %v", err)
			}
		})
	}
}

func TestValidateAndCompileRulesRejectsNamedClientProfileBuildkitTunnel(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{
			Name: "buildx-remote",
			Rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodPost, Path: "/session"}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			},
		},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected named client profile buildkit tunnel validation to fail")
	}
	if !strings.Contains(err.Error(), "buildx-remote") {
		t.Fatalf("expected profile name in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "POST /session") {
		t.Fatalf("expected guarded session endpoint in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "top-level insecure_accept_opaque_buildkit_tunnels=true") {
		t.Fatalf("expected profile-scoped top-level opt-in hint, got: %v", err)
	}
}

func TestValidateAndCompileRulesRejectsBroadContainerWriteRulesWithoutExplicitOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/containers/**"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected broad container write validation to fail")
	}
	if !strings.Contains(err.Error(), "POST /containers/sockguard-test/exec") {
		t.Fatalf("expected exec endpoint in error, got: %v", err)
	}
	if strings.Contains(err.Error(), "POST /containers/create") {
		t.Fatalf("did not expect create endpoint in error once request body inspection exists, got: %v", err)
	}
}

func TestCompileConfiguredRulesCommaSeparatedMethods(t *testing.T) {
	compiled, err := compileConfiguredRules([]config.RuleConfig{{
		Match:  config.MatchConfig{Method: "POST,PUT,DELETE", Path: "/**"},
		Action: "deny",
	}})
	if err != nil {
		t.Fatalf("compileConfiguredRules() error = %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled %d rules, want 1", len(compiled))
	}
	req := httptest.NewRequest(http.MethodDelete, "/containers/test", nil)
	action, _, _ := filter.Evaluate(compiled, req)
	if action != filter.ActionDeny {
		t.Fatalf("action = %v, want %v", action, filter.ActionDeny)
	}
}

func TestCompileConfiguredRulesHonorsFirstMatchWinsForOverlappingAllowAndDenyRules(t *testing.T) {
	cases := []struct {
		name    string
		rules   []config.RuleConfig
		want    filter.Action
		wantIdx int
	}{
		{
			name: "allow before deny",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/json"}, Action: "deny"},
			},
			want:    filter.ActionAllow,
			wantIdx: 0,
		},
		{
			name: "deny before allow",
			rules: []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/json"}, Action: "deny"},
				{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/**"}, Action: "allow"},
			},
			want:    filter.ActionDeny,
			wantIdx: 0,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := compileConfiguredRules(tt.rules)
			if err != nil {
				t.Fatalf("compileConfiguredRules() error = %v", err)
			}

			action, index, _ := filter.Evaluate(compiled, req)
			if action != tt.want {
				t.Fatalf("action = %v, want %v", action, tt.want)
			}
			if index != tt.wantIdx {
				t.Fatalf("index = %d, want %d", index, tt.wantIdx)
			}
		})
	}
}

func TestSplitMethodsHandlesEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty string", in: "", want: []string{}},
		{name: "whitespace only", in: "  \t  ", want: []string{}},
		{name: "trailing comma", in: "GET,", want: []string{"GET"}},
		{name: "adjacent whitespace", in: "GET, PUT", want: []string{"GET", "PUT"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := splitMethods(tt.in)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("splitMethods(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestCompileConfiguredRulesWrapsRuleError(t *testing.T) {
	useRuleDeps(t)

	compileFilterRule = func(filter.Rule) (*filter.CompiledRule, error) {
		return nil, errors.New("boom")
	}

	_, err := compileConfiguredRules([]config.RuleConfig{{
		Match:  config.MatchConfig{Method: http.MethodGet, Path: "/_ping"},
		Action: "allow",
	}})
	if err == nil {
		t.Fatal("expected compileConfiguredRules() to fail")
	}
	if !strings.Contains(err.Error(), "rule 1: boom") {
		t.Fatalf("expected wrapped rule error, got: %v", err)
	}
}

func TestValidateAndCompileRulesReturnsConfigValidationError(t *testing.T) {
	useRuleDeps(t)

	validateConfig = func(*config.Config) error {
		return errors.New("boom")
	}

	cfg := config.Defaults()
	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected validateAndCompileRules() to fail")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected config validation error, got: %v", err)
	}
}

func TestValidateAndCompileRulesReturnsCompileError(t *testing.T) {
	useRuleDeps(t)

	validateConfig = func(*config.Config) error {
		return nil
	}
	compileFilterRule = func(filter.Rule) (*filter.CompiledRule, error) {
		return nil, errors.New("boom")
	}

	cfg := config.Defaults()
	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected validateAndCompileRules() to fail")
	}
	if !strings.Contains(err.Error(), "rule 1: boom") {
		t.Fatalf("expected wrapped compile error, got: %v", err)
	}
}

// TestPresetConfigsPassBuildChain verifies that every shipped preset YAML passes
// the full validateAndCompileRules (BuildChain) check — not just config.Validate.
// This catches missing insecure_allow_* flags that cause the server to refuse
// startup even when config.Load + config.Validate both succeed.
func TestPresetConfigsPassBuildChain(t *testing.T) {
	presetsDir := filepath.Join("..", "..", "configs")

	entries, err := os.ReadDir(presetsDir)
	if err != nil {
		t.Fatalf("failed to read presets directory %s: %v", presetsDir, err)
	}

	var yamlFiles []string
	for _, e := range entries {
		if !e.IsDir() && (filepath.Ext(e.Name()) == ".yaml" || filepath.Ext(e.Name()) == ".yml") {
			yamlFiles = append(yamlFiles, e.Name())
		}
	}
	if len(yamlFiles) == 0 {
		t.Fatal("no preset YAML configs found — expected at least one")
	}

	for _, name := range yamlFiles {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(presetsDir, name)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load(%s) error: %v", name, err)
			}
			if _, err := validateAndCompileRules(cfg); err != nil {
				t.Fatalf("validateAndCompileRules(%s) error: %v", name, err)
			}
		})
	}
}

// TestPresetConfigsDenyAttestationStatementsByDefault is an attestation
// conformance test: it loops over every shipped preset in app/configs (not a
// fixed list) and asserts each one denies GET /images/{name}/attestations
// with ?statement=true unless the preset explicitly documents opting in via
// response.allow_attestation_statements: true. Attestation statements can
// carry SBOM/provenance content — including build-environment details —
// generated by a different, potentially less-trusted pipeline than the
// image itself, so silently permitting them is treated as a config
// regression. Because this walks the configs directory rather than naming
// files, any future preset automatically inherits the check.
func TestPresetConfigsDenyAttestationStatementsByDefault(t *testing.T) {
	presetsDir := filepath.Join("..", "..", "configs")

	entries, err := os.ReadDir(presetsDir)
	if err != nil {
		t.Fatalf("failed to read presets directory %s: %v", presetsDir, err)
	}

	var yamlFiles []string
	for _, e := range entries {
		if !e.IsDir() && (filepath.Ext(e.Name()) == ".yaml" || filepath.Ext(e.Name()) == ".yml") {
			yamlFiles = append(yamlFiles, e.Name())
		}
	}
	if len(yamlFiles) == 0 {
		t.Fatal("no preset YAML configs found — expected at least one")
	}

	for _, name := range yamlFiles {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(presetsDir, name)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load(%s) error: %v", name, err)
			}

			if cfg.Response.AllowAttestationStatements {
				t.Skipf("%s explicitly opts in to response.allow_attestation_statements: true", name)
			}

			rf := responsefilter.New(serveResponseFilterOptions(cfg))

			req, err := http.NewRequest(http.MethodGet, "http://sockguard.test/v1.55/images/alpine/attestations?statement=true", nil)
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			body := `{"manifests":[]}`
			resp := &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
				Body:          io.NopCloser(strings.NewReader(body)),
				ContentLength: int64(len(body)),
				Request:       req,
			}

			if err := rf.ModifyResponse(resp); !errors.Is(err, responsefilter.ErrResponseRejected) {
				t.Fatalf("%s: ModifyResponse() error = %v, want ErrResponseRejected", name, err)
			}
		})
	}
}

// --- #148: libpod pod-create/exec/volume/network/secret gate tables ---

func TestValidateAndCompileRulesLibpodGates(t *testing.T) {
	tests := []struct {
		name string
		// configure mutates a fresh config.Defaults() to set up the case's
		// rules and any request-body/insecure-flag opt-ins.
		configure func(cfg *config.Config)
		wantErr   bool
		// wantErrContains lists substrings that must all appear in the
		// returned error: guarded endpoints plus, where relevant, the
		// opt-in hint.
		wantErrContains []string
	}{
		{
			name: "allows libpod pod create with request body inspection",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/pods/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
		{
			name: "allows libpod exec with configured body inspection",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/exec"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/exec/*/start"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				// #148 design decision C3: request_body.exec is shared
				// between the Docker-compat and libpod exec paths — no
				// separate libpod_exec config.
				cfg.RequestBody.Exec.AllowedCommands = [][]string{{"/usr/local/bin/pre-update"}}
			},
		},
		{
			name: "allows libpod volume, network, and secret writes with request body inspection",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/volumes/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/networks/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/secrets/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
		{
			name: "rejects libpod exec without configured allowlist",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/exec"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr:         true,
			wantErrContains: []string{"POST /libpod/containers/sockguard-test/exec"},
		},
		{
			// Pins #148 design decision C2: play/kube (and its kube/play
			// alias), kube/apply, and manifest writes have NO request-body
			// inspector at all — full YAML/PodSpec modeling is deferred
			// past v1.6 — so admitting any of them requires
			// insecure_allow_body_blind_writes exactly like any other
			// uninspected body-sensitive write, never a free pass.
			name: "rejects libpod play/kube and manifest writes without explicit opt-in",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/play/kube"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/kube/play"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/kube/apply"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/manifests/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/manifests/*"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPut, Path: "/libpod/manifests/*"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr: true,
			wantErrContains: []string{
				"POST /libpod/play/kube",
				"POST /libpod/kube/play",
				"POST /libpod/kube/apply",
				"POST /libpod/manifests/create",
				"POST /libpod/manifests/sockguard-test",
				"PUT /libpod/manifests/sockguard-test",
				"insecure_allow_body_blind_writes=true",
			},
		},
		{
			name: "allows libpod play/kube with explicit blind-write opt-in",
			configure: func(cfg *config.Config) {
				cfg.InsecureAllowBodyBlindWrites = true
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/play/kube"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
		{
			// Pins the libpod read/export surface added to
			// sensitiveExfilEndpoints: container archive/export/logs/attach,
			// image export/get/push, and GET /libpod/generate/kube (a read
			// despite the "generate" name — see the inline comment on
			// sensitiveExfilEndpoints for the source-verified deviation
			// from the design doc's literal placement).
			name: "rejects libpod read exfil rules without explicit opt-in",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/containers/**"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/attach"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/images/**"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/*/push"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/generate/**"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr: true,
			wantErrContains: []string{
				"GET /libpod/containers/sockguard-test/archive",
				"GET /libpod/containers/sockguard-test/export",
				"GET /libpod/containers/sockguard-test/logs",
				"POST /libpod/containers/sockguard-test/attach",
				"GET /libpod/images/export",
				"GET /libpod/images/sockguard-test/get",
				"POST /libpod/images/sockguard-test/push",
				"GET /libpod/generate/kube",
			},
		},
		{
			name: "allows libpod read exfil with explicit opt-in",
			configure: func(cfg *config.Config) {
				cfg.InsecureAllowReadExfiltration = true
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/containers/**"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/attach"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/images/**"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/*/push"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/generate/**"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			tt.configure(&cfg)

			compiled, err := validateAndCompileRules(&cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validateAndCompileRules() to fail")
				}
				for _, want := range tt.wantErrContains {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("expected %q in error, got: %v", want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("validateAndCompileRules() error = %v", err)
			}
			if len(compiled) != len(cfg.Rules) {
				t.Fatalf("compiled %d rules, want %d", len(compiled), len(cfg.Rules))
			}
		})
	}
}

func TestValidateAndCompileRulesLibpodImageLoadAndImportRequireBlindWriteAck(t *testing.T) {
	for _, endpoint := range []string{"/libpod/images/load", "/libpod/images/import"} {
		t.Run(endpoint, func(t *testing.T) {
			for _, tt := range []struct {
				name         string
				acknowledged bool
				wantErr      bool
			}{
				{name: "without acknowledgment", wantErr: true},
				{name: "with acknowledgment", acknowledged: true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					cfg := config.Defaults()
					cfg.InsecureAllowBodyBlindWrites = tt.acknowledged
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: http.MethodPost, Path: endpoint}, Action: "allow"},
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}

					compiled, err := validateAndCompileRules(&cfg)
					if tt.wantErr {
						if err == nil {
							t.Fatal("expected validateAndCompileRules() to reject an unacknowledged body-blind image write")
						}
						for _, want := range []string{"insecure_allow_body_blind_writes=true", "POST " + endpoint} {
							if !strings.Contains(err.Error(), want) {
								t.Fatalf("expected %q in error, got: %v", want, err)
							}
						}
						return
					}

					if err != nil {
						t.Fatalf("validateAndCompileRules() error = %v", err)
					}
					for _, requestPath := range []string{endpoint, "/v5.0.0" + endpoint} {
						req := httptest.NewRequest(http.MethodPost, requestPath, nil)
						action, _, _ := filter.Evaluate(compiled, req)
						if action != filter.ActionAllow {
							t.Errorf("POST %s action = %q, want %q", requestPath, action, filter.ActionAllow)
						}
					}
				})
			}
		})
	}
}

func TestBodyInspectionConfiguredForEndpointLibpodCases(t *testing.T) {
	tests := []struct {
		name        string
		requestBody config.RequestBodyConfig
		endpoint    bodySensitiveWriteEndpoint
		want        bool
	}{
		{
			name:        "libpod exec create without allowlist is not configured",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/containers/sockguard-test/exec"},
			want:        false,
		},
		{
			name: "libpod exec create with allowlist is configured",
			requestBody: config.RequestBodyConfig{
				Exec: config.ExecRequestBodyConfig{AllowedCommands: [][]string{{"/bin/true"}}},
			},
			endpoint: bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/containers/sockguard-test/exec"},
			want:     true,
		},
		{
			name: "libpod exec start shares the same exec config as libpod exec create",
			requestBody: config.RequestBodyConfig{
				Exec: config.ExecRequestBodyConfig{AllowedCommands: [][]string{{"/bin/true"}}},
			},
			endpoint: bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/exec/sockguard-test/start"},
			want:     true,
		},
		{
			name:        "libpod pod create always has a real inspector",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/pods/create"},
			want:        true,
		},
		{
			name:        "libpod volume create always has a real inspector",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/volumes/create"},
			want:        true,
		},
		{
			name:        "libpod network create always has a real inspector",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/networks/create"},
			want:        true,
		},
		{
			name:        "libpod secret create always has a real inspector",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/secrets/create"},
			want:        true,
		},
		{
			name:        "play/kube has no inspector regardless of config",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/play/kube"},
			want:        false,
		},
		{
			name:        "kube/play alias has no inspector regardless of config",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/kube/play"},
			want:        false,
		},
		{
			name:        "kube/apply has no inspector regardless of config",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/kube/apply"},
			want:        false,
		},
		{
			name:        "manifest create has no inspector regardless of config",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPost, path: "/libpod/manifests/create"},
			want:        false,
		},
		{
			name:        "manifest update has no inspector regardless of config",
			requestBody: config.RequestBodyConfig{},
			endpoint:    bodySensitiveWriteEndpoint{method: http.MethodPut, path: "/libpod/manifests/sockguard-test"},
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bodyInspectionConfiguredForEndpoint(tt.requestBody, tt.endpoint)
			if got != tt.want {
				t.Fatalf("bodyInspectionConfiguredForEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

// libpodCatalogEntry finds one endpoint in bodySensitiveWriteEndpoints,
// failing the test when it is absent. Every libpod container-write case below
// starts by proving its path is in the catalog at all: an endpoint missing
// from the catalog is scored as "not a body-sensitive write" rather than as
// "uninspected", which is exactly how PUT /libpod/containers/{name}/archive
// and POST /libpod/containers/{name}/update went unnoticed.
func libpodCatalogEntry(t *testing.T, method, path string) bodySensitiveWriteEndpoint {
	t.Helper()

	for _, candidate := range bodySensitiveWriteEndpoints {
		if candidate.method == method && candidate.path == path {
			return candidate
		}
	}
	t.Fatalf("%s %s is missing from the body-sensitive write catalog", method, path)
	return bodySensitiveWriteEndpoint{}
}

// TestBodySensitiveWriteCatalogCoversLibpodContainerWrites pins the
// config-validation half of the libpod container-write gap. Archive and update
// must be recognized as inspected so allowing them does not spuriously demand
// insecure_allow_body_blind_writes; restore must NOT be, because its body is
// an opaque CRIU checkpoint archive no inspector reads.
func TestBodySensitiveWriteCatalogCoversLibpodContainerWrites(t *testing.T) {
	tests := []struct {
		method        string
		path          string
		wantInspected bool
	}{
		{http.MethodPut, "/libpod/containers/sockguard-test/archive", true},
		{http.MethodPost, "/libpod/containers/sockguard-test/update", true},
		{http.MethodPost, "/libpod/containers/sockguard-test/restore", false},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			endpoint := libpodCatalogEntry(t, tt.method, tt.path)
			if got := bodyInspectionConfiguredForEndpoint(config.RequestBodyConfig{}, endpoint); got != tt.wantInspected {
				t.Fatalf("bodyInspectionConfiguredForEndpoint(%s %s) = %v, want %v", tt.method, tt.path, got, tt.wantInspected)
			}
		})
	}
}

// TestValidateAndCompileRulesLibpodContainerWriteGates pins what an operator
// actually experiences at startup for each of the five libpod container-write
// endpoints: archive and update pass on their built-in inspectors, restore
// demands the blind-write acknowledgment because nothing reads its body, and
// checkpoint and mount demand the read-exfiltration acknowledgment because
// their risk is entirely in the response.
func TestValidateAndCompileRulesLibpodContainerWriteGates(t *testing.T) {
	tests := []struct {
		name            string
		configure       func(cfg *config.Config)
		wantErr         bool
		wantErrContains []string
	}{
		{
			name: "allows libpod container archive on the shared container_archive inspector",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPut, Path: "/libpod/containers/*/archive"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
		{
			name: "allows libpod container update on the shared container_update inspector",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/update"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
		{
			name: "allows an exact libpod container update on the shared container_update inspector",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/real-id/update"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
		{
			name: "rejects an exact libpod container restore without the blind-write acknowledgment",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/real-id/restore"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr:         true,
			wantErrContains: []string{"insecure_allow_body_blind_writes=true", "POST /libpod/containers/real-id/restore"},
		},
		{
			name: "allows an exact libpod container restore once the blind-write acknowledgment is set",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/real-id/restore"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg.InsecureAllowBodyBlindWrites = true
			},
		},
		{
			name: "rejects libpod container restore without the blind-write acknowledgment",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/restore"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr:         true,
			wantErrContains: []string{"insecure_allow_body_blind_writes=true", "POST /libpod/containers/sockguard-test/restore"},
		},
		{
			name: "allows libpod container restore once the blind-write acknowledgment is set",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/restore"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg.InsecureAllowBodyBlindWrites = true
			},
		},
		{
			name: "rejects libpod container checkpoint without the read-exfiltration acknowledgment",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/checkpoint"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr:         true,
			wantErrContains: []string{"insecure_allow_read_exfiltration", "POST /libpod/containers/sockguard-test/checkpoint"},
		},
		{
			name: "rejects libpod container mount without the read-exfiltration acknowledgment",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/mount"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr:         true,
			wantErrContains: []string{"insecure_allow_read_exfiltration", "POST /libpod/containers/sockguard-test/mount"},
		},
		{
			name: "allows libpod checkpoint and mount once the read-exfiltration acknowledgment is set",
			configure: func(cfg *config.Config) {
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/checkpoint"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/mount"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg.InsecureAllowReadExfiltration = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			tt.configure(&cfg)

			_, err := validateAndCompileRules(&cfg)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("validateAndCompileRules() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("validateAndCompileRules() = nil, want an error")
			}
			for _, want := range tt.wantErrContains {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want it to mention %q", err.Error(), want)
				}
			}
		})
	}
}

func TestValidateAndCompileRulesRequiresReadExfiltrationAckForLibpodShowMounted(t *testing.T) {
	for _, scope := range []string{"default policy", "named client profile"} {
		for _, rulePath := range []string{
			"/libpod/containers/showmounted",
			"*/containers/showmounted",
		} {
			t.Run(scope+" "+rulePath, func(t *testing.T) {
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodGet, Path: rulePath}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "storage-reader", Rules: rules}}
				} else {
					cfg.Rules = rules
				}

				_, err := validateAndCompileRules(&cfg)
				if err == nil {
					t.Fatal("validateAndCompileRules() = nil, want read-exfiltration acknowledgment error")
				}
				for _, want := range []string{"insecure_allow_read_exfiltration", "GET /libpod/containers/showmounted"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %q, want it to mention %q", err.Error(), want)
					}
				}
				if scope == "named client profile" && !strings.Contains(err.Error(), "storage-reader") {
					t.Fatalf("error = %q, want it to mention the client profile", err.Error())
				}

				cfg.InsecureAllowReadExfiltration = true
				if _, err := validateAndCompileRules(&cfg); err != nil {
					t.Fatalf("validateAndCompileRules() with acknowledgment error = %v", err)
				}
			})
		}
	}
}

func TestValidateAndCompileRulesRejectsExactLibpodContainerReadExfiltration(t *testing.T) {
	for _, scope := range []string{"default policy", "named client profile"} {
		for _, operation := range []string{"checkpoint", "mount"} {
			t.Run(scope+" "+operation, func(t *testing.T) {
				path := "/libpod/containers/real-id/" + operation
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: path}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "backup-agent",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				_, err := validateAndCompileRules(&cfg)
				if err == nil {
					t.Fatal("validateAndCompileRules() = nil, want an error")
				}
				for _, want := range []string{"insecure_allow_read_exfiltration", "POST " + path} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %q, want it to mention %q", err.Error(), want)
					}
				}
				if scope == "named client profile" && !strings.Contains(err.Error(), "backup-agent") {
					t.Fatalf("error = %q, want it to mention the client profile", err.Error())
				}
			})
		}
	}
}

func TestValidateAndCompileRulesEvaluatesOrderedLibpodReadExfiltrationRules(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		rules     func(operation string) []config.RuleConfig
		wantErr   bool
	}{
		{
			name:      "broader allow still exposes another identifier after exact sentinel deny",
			operation: "checkpoint",
			rules: func(operation string) []config.RuleConfig {
				return []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/sockguard-test/" + operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/" + operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr: true,
		},
		{
			name:      "broader allow still exposes another identifier after exact sentinel deny",
			operation: "mount",
			rules: func(operation string) []config.RuleConfig {
				return []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/sockguard-test/" + operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/" + operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
			wantErr: true,
		},
		{
			name:      "earlier wildcard deny shadows later exact allow",
			operation: "checkpoint",
			rules: func(operation string) []config.RuleConfig {
				return []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/" + operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/real-id/" + operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
		{
			name:      "earlier wildcard deny shadows later exact allow",
			operation: "mount",
			rules: func(operation string) []config.RuleConfig {
				return []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/" + operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/real-id/" + operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			},
		},
	}

	for _, scope := range []string{"default policy", "named client profile"} {
		for _, tt := range tests {
			t.Run(scope+" "+tt.operation+" "+tt.name, func(t *testing.T) {
				rules := tt.rules(tt.operation)
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "backup-agent",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				_, err := validateAndCompileRules(&cfg)
				if !tt.wantErr {
					if err != nil {
						t.Fatalf("validateAndCompileRules() error = %v, want nil", err)
					}
					return
				}
				if err == nil {
					t.Fatal("validateAndCompileRules() = nil, want an error")
				}
				if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration") {
					t.Fatalf("error = %q, want the read-exfiltration acknowledgment", err.Error())
				}
				if scope == "named client profile" && !strings.Contains(err.Error(), "backup-agent") {
					t.Fatalf("error = %q, want it to mention the client profile", err.Error())
				}
			})
		}
	}
}

func TestValidateAndCompileRulesRejectsSelectiveWildcardCatalogShadows(t *testing.T) {
	tests := []struct {
		operation string
		ack       string
	}{
		{operation: "checkpoint", ack: "insecure_allow_read_exfiltration"},
		{operation: "mount", ack: "insecure_allow_read_exfiltration"},
		{operation: "restore", ack: "insecure_allow_body_blind_writes"},
	}

	for _, scope := range []string{"default policy", "named client profile"} {
		for _, tt := range tests {
			t.Run(scope+" "+tt.operation, func(t *testing.T) {
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/sockguard-*/" + tt.operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/" + tt.operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "backup-agent",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				_, err := validateAndCompileRules(&cfg)
				if err == nil {
					t.Fatal("validateAndCompileRules() = nil, want an acknowledgment error for the reachable real-id route")
				}
				if !strings.Contains(err.Error(), tt.ack) {
					t.Fatalf("error = %q, want it to mention %q", err.Error(), tt.ack)
				}
				if scope == "named client profile" && !strings.Contains(err.Error(), "backup-agent") {
					t.Fatalf("error = %q, want it to mention the client profile", err.Error())
				}
			})
		}
	}
}

func TestValidateAndCompileRulesRejectsNoLeadingSlashCatalogGlobs(t *testing.T) {
	tests := []struct {
		operation string
		ack       string
	}{
		{operation: "checkpoint", ack: "insecure_allow_read_exfiltration"},
		{operation: "mount", ack: "insecure_allow_read_exfiltration"},
		{operation: "restore", ack: "insecure_allow_body_blind_writes"},
	}

	for _, scope := range []string{"default policy", "named client profile"} {
		for _, tt := range tests {
			t.Run(scope+" "+tt.operation, func(t *testing.T) {
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/sockguard-test/" + tt.operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "*/containers/*/" + tt.operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "backup-agent",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				_, err := validateAndCompileRules(&cfg)
				if err == nil {
					t.Fatal("validateAndCompileRules() = nil, want an acknowledgment error for the reachable real-id route")
				}
				if !strings.Contains(err.Error(), tt.ack) {
					t.Fatalf("error = %q, want it to mention %q", err.Error(), tt.ack)
				}
				wantWitness := "POST /libpod/containers/a/" + tt.operation
				if !strings.Contains(err.Error(), wantWitness) {
					t.Fatalf("error = %q, want it to identify reachable route %q", err.Error(), wantWitness)
				}
				if scope == "named client profile" && !strings.Contains(err.Error(), "backup-agent") {
					t.Fatalf("error = %q, want it to mention the client profile", err.Error())
				}
			})
		}
	}
}

func TestValidateAndCompileRulesRejectsRelativeSingleStarCatalogGlobs(t *testing.T) {
	tests := []struct {
		operation string
		ack       string
	}{
		{operation: "checkpoint", ack: "insecure_allow_read_exfiltration"},
		{operation: "restore", ack: "insecure_allow_body_blind_writes"},
	}

	for _, scope := range []string{"default policy", "named client profile"} {
		for _, tt := range tests {
			t.Run(scope+" "+tt.operation, func(t *testing.T) {
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/sockguard-test/" + tt.operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "libpod/containers/*/" + tt.operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "backup-agent",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				_, err := validateAndCompileRules(&cfg)
				if err == nil {
					t.Fatal("validateAndCompileRules() = nil, want an acknowledgment error for the reachable real-id route")
				}
				for _, want := range []string{tt.ack, "POST /libpod/containers/a/" + tt.operation} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %q, want it to mention %q", err.Error(), want)
					}
				}
				if scope == "named client profile" && !strings.Contains(err.Error(), "backup-agent") {
					t.Fatalf("error = %q, want it to mention the client profile", err.Error())
				}

				if tt.operation == "restore" {
					cfg.InsecureAllowBodyBlindWrites = true
				} else {
					cfg.InsecureAllowReadExfiltration = true
				}
				if _, err := validateAndCompileRules(&cfg); err != nil {
					t.Fatalf("validateAndCompileRules() with acknowledgment error = %v", err)
				}

				compiled, err := compileConfiguredRules(rules)
				if err != nil {
					t.Fatalf("compileConfiguredRules() error = %v", err)
				}
				for _, request := range []struct {
					path string
					want filter.Action
				}{
					{path: "/libpod/containers/sockguard-test/" + tt.operation, want: filter.ActionDeny},
					{path: "/libpod/containers/real-id/" + tt.operation, want: filter.ActionAllow},
				} {
					req := httptest.NewRequest(http.MethodPost, request.path, nil)
					action, _, _ := filter.Evaluate(compiled, req)
					if action != request.want {
						t.Errorf("POST %s action = %q, want %q", request.path, action, request.want)
					}
				}
			})
		}
	}
}

func TestValidateAndCompileRulesAllowsFullyShadowedCatalogRoutes(t *testing.T) {
	for _, scope := range []string{"default policy", "named client profile"} {
		for _, operation := range []string{"checkpoint", "mount", "restore"} {
			t.Run(scope+" "+operation, func(t *testing.T) {
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/" + operation}, Action: "deny"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/" + operation}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "backup-agent",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				if _, err := validateAndCompileRules(&cfg); err != nil {
					t.Fatalf("validateAndCompileRules() error = %v, want nil for a fully shadowed allow", err)
				}
			})
		}
	}
}

func TestValidateAndCompileRulesRejectsSlashBearingCatalogRoutes(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		denyPattern  string
		allowPattern string
		wantAck      string
		wantWitness  string
		ackBlind     bool
	}{
		{
			name:         "docker image export",
			method:       http.MethodGet,
			denyPattern:  "/images/*/get",
			allowPattern: "/images/*/*/get",
			wantAck:      "insecure_allow_read_exfiltration",
			wantWitness:  "GET /images/a/a/get",
		},
		{
			name:         "docker image push",
			method:       http.MethodPost,
			denyPattern:  "/images/*/push",
			allowPattern: "/images/*/*/push",
			wantAck:      "insecure_allow_read_exfiltration",
			wantWitness:  "POST /images/a/a/push",
		},
		{
			name:         "libpod image export",
			method:       http.MethodGet,
			denyPattern:  "/libpod/images/*/get",
			allowPattern: "/libpod/images/*/*/get",
			wantAck:      "insecure_allow_read_exfiltration",
			wantWitness:  "GET /libpod/images/a/a/get",
		},
		{
			name:         "libpod image push",
			method:       http.MethodPost,
			denyPattern:  "/libpod/images/*/push",
			allowPattern: "/libpod/images/*/*/push",
			wantAck:      "insecure_allow_read_exfiltration",
			wantWitness:  "POST /libpod/images/a/a/push",
		},
		{
			name:         "plugin push",
			method:       http.MethodPost,
			denyPattern:  "/plugins/*/push",
			allowPattern: "/plugins/*/*/push",
			wantAck:      "insecure_allow_read_exfiltration",
			wantWitness:  "POST /plugins/a/a/push",
		},
		{
			name:         "plugin set",
			method:       http.MethodPost,
			denyPattern:  "/plugins/*/set",
			allowPattern: "/plugins/*/*/set",
			wantAck:      "insecure_allow_body_blind_writes",
			wantWitness:  "POST /plugins/a/a/set",
		},
		{
			name:         "libpod manifest create",
			method:       http.MethodPost,
			denyPattern:  "/libpod/manifests/*",
			allowPattern: "/libpod/manifests/a/a",
			wantAck:      "insecure_allow_body_blind_writes",
			wantWitness:  "POST /libpod/manifests/a/a",
		},
		{
			name:         "libpod manifest modify",
			method:       http.MethodPut,
			denyPattern:  "/libpod/manifests/*",
			allowPattern: "/libpod/manifests/a/a",
			wantAck:      "insecure_allow_body_blind_writes",
			wantWitness:  "PUT /libpod/manifests/a/a",
		},
		{
			name:         "libpod manifest registry push",
			method:       http.MethodPost,
			denyPattern:  "/libpod/manifests/*/registry/*",
			allowPattern: "/libpod/manifests/*/registry/*/*",
			wantAck:      "insecure_allow_read_exfiltration",
			wantWitness:  "POST /libpod/manifests/a/registry/a/a",
			ackBlind:     true,
		},
	}

	for _, scope := range []string{"default policy", "named client profile"} {
		for _, tt := range tests {
			t.Run(scope+" "+tt.name, func(t *testing.T) {
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: tt.method, Path: tt.denyPattern}, Action: "deny"},
					{Match: config.MatchConfig{Method: tt.method, Path: tt.allowPattern}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				cfg.InsecureAllowBodyBlindWrites = tt.ackBlind
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "slash-bearing",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				_, err := validateAndCompileRules(&cfg)
				if err == nil {
					t.Fatalf("validateAndCompileRules() = nil, want %s error for reachable slash-bearing route", tt.wantAck)
				}
				for _, want := range []string{tt.wantAck, tt.wantWitness} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %q, want it to mention %q", err.Error(), want)
					}
				}
				if scope == "named client profile" && !strings.Contains(err.Error(), "slash-bearing") {
					t.Fatalf("error = %q, want it to mention the client profile", err.Error())
				}
			})
		}
	}
}

func TestValidateAndCompileRulesAllowsFullyShadowedSlashBearingCatalogRoutes(t *testing.T) {
	for _, scope := range []string{"default policy", "named client profile"} {
		for _, endpoint := range []struct {
			method       string
			allowPattern string
		}{
			{method: http.MethodGet, allowPattern: "/libpod/images/*/*/get"},
			{method: http.MethodPost, allowPattern: "/libpod/images/*/*/push"},
		} {
			t.Run(scope+" "+endpoint.method, func(t *testing.T) {
				rules := []config.RuleConfig{
					{Match: config.MatchConfig{Method: endpoint.method, Path: "/libpod/images/**"}, Action: "deny"},
					{Match: config.MatchConfig{Method: endpoint.method, Path: endpoint.allowPattern}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				cfg := config.Defaults()
				if scope == "named client profile" {
					cfg.Rules = []config.RuleConfig{
						{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
					}
					cfg.Clients.Profiles = []config.ClientProfileConfig{{
						Name:  "fully-shadowed",
						Rules: rules,
					}}
				} else {
					cfg.Rules = rules
				}

				if _, err := validateAndCompileRules(&cfg); err != nil {
					t.Fatalf("validateAndCompileRules() error = %v, want nil for a fully shadowed slash-bearing allow", err)
				}
			})
		}
	}
}

func TestFirstAllowedCatalogPathInstructionBudgetFailsClosed(t *testing.T) {
	rules := make([]config.RuleConfig, 0, 129)
	for i := 0; i < 128; i++ {
		rules = append(rules, config.RuleConfig{
			Match: config.MatchConfig{
				Method: http.MethodPost,
				Path:   fmt.Sprintf("/unrelated/%03d/%s", i, strings.Repeat("x", 32)),
			},
			Action: "deny",
		})
	}
	rules = append(rules, config.RuleConfig{
		Match:  config.MatchConfig{Method: http.MethodPost, Path: "/libpod/manifests/**"},
		Action: "allow",
	})

	witness, result := firstAllowedCatalogPath(http.MethodPost, "/libpod/manifests/sockguard-test", catalogIdentifierPath, nil, rules)
	if result != catalogReachabilityIndeterminate {
		t.Fatalf("firstAllowedCatalogPath() result = %v, want indeterminate after instruction-budget exhaustion", result)
	}
	if witness != "/libpod/manifests/sockguard-test" {
		t.Fatalf("firstAllowedCatalogPath() witness = %q, want stable fail-closed catalog path", witness)
	}
}
