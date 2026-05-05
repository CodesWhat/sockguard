package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
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
	} {
		if !strings.Contains(err.Error(), endpoint) {
			t.Fatalf("expected %s in error, got: %v", endpoint, err)
		}
	}
	if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration=true") {
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
	if !strings.Contains(err.Error(), "insecure_allow_read_exfiltration=true") {
		t.Fatalf("expected explicit read exfiltration opt-in hint, got: %v", err)
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
