package cmd

import (
	"errors"
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
		"GET /containers/sockguard-test/top",
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

func TestValidateAndCompileRulesRejectsContainerTopWithoutReadExfiltrationOptIn(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "targeted rule", path: "/containers/*/top"},
		{name: "broad container rule", path: "/containers/**"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Rules = []config.RuleConfig{
				{Match: config.MatchConfig{Method: http.MethodGet, Path: tt.path}, Action: "allow"},
				{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
			}

			_, err := validateAndCompileRules(&cfg)
			if err == nil {
				t.Fatal("expected container top read exfiltration validation to fail")
			}
			if !strings.Contains(err.Error(), "GET /containers/sockguard-test/top") {
				t.Fatalf("expected guarded container top endpoint in error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration: true") {
				t.Fatalf("expected explicit read exfiltration opt-in hint, got: %v", err)
			}
			if !strings.Contains(err.Error(), "process arguments") {
				t.Fatalf("expected container top risk in error, got: %v", err)
			}
		})
	}
}

func TestValidateAndCompileRulesRejectsLibpodContainerTopWithoutReadExfiltrationOptIn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/containers/*/top"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	_, err := validateAndCompileRules(&cfg)
	if err == nil {
		t.Fatal("expected libpod container top read exfiltration validation to fail")
	}
	if !strings.Contains(err.Error(), "GET /libpod/containers/sockguard-test/top") {
		t.Fatalf("expected guarded libpod container top endpoint in error, got: %v", err)
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

func TestComposeExampleConfigsPassBuildChain(t *testing.T) {
	examples, err := filepath.Glob(filepath.Join("..", "..", "..", "examples", "compose", "*", "sockguard*.yaml"))
	if err != nil {
		t.Fatalf("glob compose examples: %v", err)
	}
	if len(examples) == 0 {
		t.Fatal("no compose example configs found")
	}

	for _, path := range examples {
		path := path
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load(%s) error: %v", path, err)
			}
			if _, err := validateAndCompileRules(cfg); err != nil {
				t.Fatalf("validateAndCompileRules(%s) error: %v", path, err)
			}
		})
	}
}

func TestContainerTopAffectedConfigsChooseLeastPrivilege(t *testing.T) {
	tests := []struct {
		path             string
		wantTopRule      bool
		wantReadExfilAck bool
	}{
		{path: filepath.Join("..", "..", "configs", "cis-docker-benchmark.yaml")},
		{path: filepath.Join("..", "..", "configs", "drydock-with-build.yaml")},
		{path: filepath.Join("..", "..", "configs", "drydock-with-compose.yaml")},
		{path: filepath.Join("..", "..", "configs", "drydock-with-mediated-build.yaml")},
		{path: filepath.Join("..", "..", "configs", "drydock-with-selfupdate.yaml")},
		{path: filepath.Join("..", "..", "configs", "drydock.yaml")},
		{path: filepath.Join("..", "..", "configs", "multi-listener.yaml")},
		{
			path:             filepath.Join("..", "..", "configs", "podman-readonly.yaml"),
			wantTopRule:      true,
			wantReadExfilAck: true,
		},
		{path: filepath.Join("..", "..", "..", "examples", "compose", "cis-docker-benchmark", "sockguard.yaml")},
		{path: filepath.Join("..", "..", "..", "examples", "compose", "drydock", "sockguard.yaml")},
		{path: filepath.Join("..", "..", "..", "examples", "compose", "multi-host", "sockguard.yaml")},
	}

	for _, tt := range tests {
		t.Run(filepath.Base(filepath.Dir(tt.path))+"/"+filepath.Base(tt.path), func(t *testing.T) {
			cfg, err := config.Load(tt.path)
			if err != nil {
				t.Fatalf("Load(%s) error: %v", tt.path, err)
			}

			gotTopRule := configAllowsContainerTop(cfg)
			if gotTopRule != tt.wantTopRule {
				t.Errorf("Docker-compatible container top allow rule = %v, want %v", gotTopRule, tt.wantTopRule)
			}
			if cfg.InsecureAllowReadExfiltration != tt.wantReadExfilAck {
				t.Errorf("insecure_allow_read_exfiltration = %v, want %v", cfg.InsecureAllowReadExfiltration, tt.wantReadExfilAck)
			}
		})
	}
}

func configAllowsContainerTop(cfg *config.Config) bool {
	if rulesAllowContainerTop(cfg.Rules) {
		return true
	}
	for _, profile := range cfg.Clients.Profiles {
		if rulesAllowContainerTop(profile.Rules) {
			return true
		}
	}
	return false
}

func rulesAllowContainerTop(rules []config.RuleConfig) bool {
	for _, rule := range rules {
		if rule.Action == "allow" && rule.Match.Path == "/containers/*/top" && slices.Contains(splitMethods(rule.Match.Method), http.MethodGet) {
			return true
		}
	}
	return false
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
