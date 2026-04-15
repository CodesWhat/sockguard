package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

var (
	validateConfig    = config.Validate
	compileFilterRule = filter.CompileRule
)

type bodySensitiveWriteEndpoint struct {
	method string
	path   string
}

type readSensitiveExfilEndpoint struct {
	method string
	path   string
}

var bodySensitiveWriteEndpoints = []bodySensitiveWriteEndpoint{
	{method: http.MethodPost, path: "/containers/sockguard-test/exec"},
	{method: http.MethodPost, path: "/exec/sockguard-test/start"},
	{method: http.MethodPost, path: "/containers/sockguard-test/update"},
	{method: http.MethodPut, path: "/containers/sockguard-test/archive"},
	{method: http.MethodPost, path: "/images/create"},
	{method: http.MethodPost, path: "/images/load"},
	{method: http.MethodPost, path: "/build"},
	{method: http.MethodPost, path: "/volumes/create"},
	{method: http.MethodPost, path: "/networks/create"},
	{method: http.MethodPost, path: "/networks/sockguard-test/connect"},
	{method: http.MethodPost, path: "/networks/sockguard-test/disconnect"},
	{method: http.MethodPost, path: "/secrets/create"},
	{method: http.MethodPost, path: "/configs/create"},
	{method: http.MethodPost, path: "/services/create"},
	{method: http.MethodPost, path: "/services/sockguard-test/update"},
	{method: http.MethodPost, path: "/swarm/init"},
	{method: http.MethodPost, path: "/swarm/join"},
	{method: http.MethodPost, path: "/swarm/update"},
	{method: http.MethodPost, path: "/swarm/unlock"},
	{method: http.MethodPost, path: "/nodes/sockguard-test/update"},
	{method: http.MethodPost, path: "/plugins/pull"},
	{method: http.MethodPost, path: "/plugins/sockguard-test/upgrade"},
	{method: http.MethodPost, path: "/plugins/sockguard-test/set"},
	{method: http.MethodPost, path: "/plugins/create"},
}

var readSensitiveExfilEndpoints = []readSensitiveExfilEndpoint{
	{method: http.MethodGet, path: "/containers/sockguard-test/archive"},
	{method: http.MethodGet, path: "/containers/sockguard-test/export"},
	// Validation only sees method+path, not query strings, so treat the
	// path-level logs surface conservatively rather than trying to special-case
	// follow=1 or other streaming toggles here.
	{method: http.MethodGet, path: "/containers/sockguard-test/logs"},
	{method: http.MethodGet, path: "/containers/sockguard-test/attach/ws"},
	{method: http.MethodGet, path: "/services/sockguard-test/logs"},
	{method: http.MethodGet, path: "/tasks/sockguard-test/logs"},
	{method: http.MethodPost, path: "/containers/sockguard-test/attach"},
	{method: http.MethodGet, path: "/images/get"},
	{method: http.MethodGet, path: "/images/sockguard-test/get"},
}

func validateAndCompileRules(cfg *config.Config) ([]*filter.CompiledRule, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	compiled, err := compileConfiguredRules(cfg.Rules)
	if err != nil {
		return nil, err
	}

	if err := validateBodyBlindWriteRules(cfg, compiled); err != nil {
		return nil, err
	}
	if err := validateReadExfiltrationRules(cfg, compiled); err != nil {
		return nil, err
	}
	if _, err := compileClientProfiles(cfg); err != nil {
		return nil, err
	}

	return compiled, nil
}

func compileConfiguredRules(rules []config.RuleConfig) ([]*filter.CompiledRule, error) {
	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i, rule := range rules {
		spec := filter.Rule{
			Methods: splitMethods(rule.Match.Method),
			Pattern: rule.Match.Path,
			Action:  filter.Action(rule.Action),
			Reason:  rule.Reason,
			Index:   i,
		}

		compiledRule, err := compileFilterRule(spec)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		compiled = append(compiled, compiledRule)
	}
	return compiled, nil
}

func splitMethods(methods string) []string {
	parts := strings.Split(methods, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func validateBodyBlindWriteRules(cfg *config.Config, compiled []*filter.CompiledRule) error {
	return validateBodyBlindWriteRulesForPolicy("", cfg.InsecureAllowBodyBlindWrites, cfg.RequestBody, compiled)
}

func validateReadExfiltrationRules(cfg *config.Config, compiled []*filter.CompiledRule) error {
	return validateReadExfiltrationRulesForPolicy("", cfg.InsecureAllowReadExfiltration, compiled)
}

func validateBodyBlindWriteRulesForPolicy(scope string, insecure bool, requestBody config.RequestBodyConfig, compiled []*filter.CompiledRule) error {
	if insecure {
		return nil
	}

	exposed := allowedBodySensitiveWriteEndpoints(requestBody, compiled)
	if len(exposed) == 0 {
		return nil
	}

	if scope == "" {
		return fmt.Errorf(
			"rules allow body-sensitive write endpoints without request body inspection; set insecure_allow_body_blind_writes=true to acknowledge this risk: %s",
			strings.Join(exposed, ", "),
		)
	}

	return fmt.Errorf(
		"client profile %q allows body-sensitive write endpoints without request body inspection; set insecure_allow_body_blind_writes=true to acknowledge this risk: %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

func validateReadExfiltrationRulesForPolicy(scope string, insecure bool, compiled []*filter.CompiledRule) error {
	if insecure {
		return nil
	}

	exposed := allowedReadSensitiveExfilEndpoints(compiled)
	if len(exposed) == 0 {
		return nil
	}

	if scope == "" {
		return fmt.Errorf(
			"rules allow raw archive/export or log/attach streaming endpoints; set insecure_allow_read_exfiltration=true to acknowledge this risk: %s",
			strings.Join(exposed, ", "),
		)
	}

	return fmt.Errorf(
		"client profile %q allows raw archive/export or log/attach streaming endpoints; set insecure_allow_read_exfiltration=true to acknowledge this risk: %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

func allowedBodySensitiveWriteEndpoints(requestBody config.RequestBodyConfig, compiled []*filter.CompiledRule) []string {
	allowed := make([]string, 0, len(bodySensitiveWriteEndpoints))
	for _, endpoint := range bodySensitiveWriteEndpoints {
		if bodyInspectionConfiguredForEndpoint(requestBody, endpoint) {
			continue
		}
		req := &http.Request{Method: endpoint.method, URL: &url.URL{Path: endpoint.path}}
		action, _, _ := filter.Evaluate(compiled, req)
		if action != filter.ActionAllow {
			continue
		}
		allowed = append(allowed, endpoint.method+" "+endpoint.path)
	}
	return allowed
}

func allowedReadSensitiveExfilEndpoints(compiled []*filter.CompiledRule) []string {
	allowed := make([]string, 0, len(readSensitiveExfilEndpoints))
	for _, endpoint := range readSensitiveExfilEndpoints {
		req := &http.Request{Method: endpoint.method, URL: &url.URL{Path: endpoint.path}}
		action, _, _ := filter.Evaluate(compiled, req)
		if action != filter.ActionAllow {
			continue
		}
		allowed = append(allowed, endpoint.method+" "+endpoint.path)
	}
	return allowed
}

func bodyInspectionConfiguredForEndpoint(requestBody config.RequestBodyConfig, endpoint bodySensitiveWriteEndpoint) bool {
	switch endpoint.path {
	case "/containers/sockguard-test/exec", "/exec/sockguard-test/start":
		return len(requestBody.Exec.AllowedCommands) > 0
	case "/images/create", "/build":
		return true
	case "/volumes/create", "/secrets/create", "/configs/create", "/services/create", "/services/sockguard-test/update", "/swarm/init", "/plugins/pull", "/plugins/sockguard-test/upgrade":
		return true
	case "/swarm/join":
		return len(requestBody.Swarm.AllowedJoinRemoteAddrs) > 0
	case "/swarm/update":
		return true
	case "/plugins/sockguard-test/set":
		return len(requestBody.Plugin.AllowedSetEnvPrefixes) > 0
	case "/plugins/create":
		return true
	default:
		return false
	}
}

func compileClientProfiles(cfg *config.Config) (map[string]filter.Policy, error) {
	profiles := make(map[string]filter.Policy, len(cfg.Clients.Profiles))
	for _, profile := range cfg.Clients.Profiles {
		compiledRules, err := compileConfiguredRules(profile.Rules)
		if err != nil {
			return nil, fmt.Errorf("client profile %q: %w", profile.Name, err)
		}
		if err := validateBodyBlindWriteRulesForPolicy(profile.Name, cfg.InsecureAllowBodyBlindWrites, profile.RequestBody, compiledRules); err != nil {
			return nil, err
		}
		if err := validateReadExfiltrationRulesForPolicy(profile.Name, cfg.InsecureAllowReadExfiltration, compiledRules); err != nil {
			return nil, err
		}
		profiles[profile.Name] = filter.Policy{
			Rules: compiledRules,
			ContainerCreate: filter.ContainerCreateOptions{
				AllowPrivileged:   profile.RequestBody.ContainerCreate.AllowPrivileged,
				AllowHostNetwork:  profile.RequestBody.ContainerCreate.AllowHostNetwork,
				AllowedBindMounts: profile.RequestBody.ContainerCreate.AllowedBindMounts,
			},
			Exec: filter.ExecOptions{
				AllowPrivileged: profile.RequestBody.Exec.AllowPrivileged,
				AllowRootUser:   profile.RequestBody.Exec.AllowRootUser,
				AllowedCommands: profile.RequestBody.Exec.AllowedCommands,
			},
			ImagePull: filter.ImagePullOptions{
				AllowImports:       profile.RequestBody.ImagePull.AllowImports,
				AllowAllRegistries: profile.RequestBody.ImagePull.AllowAllRegistries,
				AllowOfficial:      profile.RequestBody.ImagePull.AllowOfficial,
				AllowedRegistries:  profile.RequestBody.ImagePull.AllowedRegistries,
			},
			Build: filter.BuildOptions{
				AllowRemoteContext:   profile.RequestBody.Build.AllowRemoteContext,
				AllowHostNetwork:     profile.RequestBody.Build.AllowHostNetwork,
				AllowRunInstructions: profile.RequestBody.Build.AllowRunInstructions,
			},
			Volume: filter.VolumeOptions{
				AllowCustomDrivers: profile.RequestBody.Volume.AllowCustomDrivers,
				AllowDriverOpts:    profile.RequestBody.Volume.AllowDriverOpts,
			},
			Secret: filter.SecretOptions{
				AllowCustomDrivers:   profile.RequestBody.Secret.AllowCustomDrivers,
				AllowTemplateDrivers: profile.RequestBody.Secret.AllowTemplateDrivers,
			},
			Config: filter.ConfigOptions{
				AllowCustomDrivers:   profile.RequestBody.Config.AllowCustomDrivers,
				AllowTemplateDrivers: profile.RequestBody.Config.AllowTemplateDrivers,
			},
			Service: filter.ServiceOptions{
				AllowHostNetwork:   profile.RequestBody.Service.AllowHostNetwork,
				AllowedBindMounts:  profile.RequestBody.Service.AllowedBindMounts,
				AllowAllRegistries: profile.RequestBody.Service.AllowAllRegistries,
				AllowOfficial:      profile.RequestBody.Service.AllowOfficial,
				AllowedRegistries:  profile.RequestBody.Service.AllowedRegistries,
			},
			Swarm: filter.SwarmOptions{
				AllowForceNewCluster:          profile.RequestBody.Swarm.AllowForceNewCluster,
				AllowExternalCA:               profile.RequestBody.Swarm.AllowExternalCA,
				AllowedJoinRemoteAddrs:        profile.RequestBody.Swarm.AllowedJoinRemoteAddrs,
				AllowTokenRotation:            profile.RequestBody.Swarm.AllowTokenRotation,
				AllowManagerUnlockKeyRotation: profile.RequestBody.Swarm.AllowManagerUnlockKeyRotation,
				AllowAutoLockManagers:         profile.RequestBody.Swarm.AllowAutoLockManagers,
				AllowSigningCAUpdate:          profile.RequestBody.Swarm.AllowSigningCAUpdate,
			},
			Plugin: filter.PluginOptions{
				AllowHostNetwork:      profile.RequestBody.Plugin.AllowHostNetwork,
				AllowIPCHost:          profile.RequestBody.Plugin.AllowIPCHost,
				AllowPIDHost:          profile.RequestBody.Plugin.AllowPIDHost,
				AllowAllDevices:       profile.RequestBody.Plugin.AllowAllDevices,
				AllowedBindMounts:     profile.RequestBody.Plugin.AllowedBindMounts,
				AllowedDevices:        profile.RequestBody.Plugin.AllowedDevices,
				AllowAllCapabilities:  profile.RequestBody.Plugin.AllowAllCapabilities,
				AllowedCapabilities:   profile.RequestBody.Plugin.AllowedCapabilities,
				AllowAllRegistries:    profile.RequestBody.Plugin.AllowAllRegistries,
				AllowOfficial:         profile.RequestBody.Plugin.AllowOfficial,
				AllowedRegistries:     profile.RequestBody.Plugin.AllowedRegistries,
				AllowedSetEnvPrefixes: profile.RequestBody.Plugin.AllowedSetEnvPrefixes,
			},
		}
	}
	return profiles, nil
}
