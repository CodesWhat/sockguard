package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

var (
	validateConfig    = config.Validate
	compileFilterRule = filter.CompileRule
)

type bodySensitiveWriteEndpoint struct {
	method string
	path   string
}

type sensitiveExfilEndpoint struct {
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
	{method: http.MethodPost, path: "/libpod/build"},
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
	// libpod native surface (#148 PR2). POST /libpod/containers/create always
	// runs through an inspector with fail-closed defaults exactly like its
	// Docker-compat counterpart /containers/create (deliberately NOT listed
	// here — see bodyInspectionConfiguredForEndpoint's cases below), but is
	// included in this catalog per the design doc's "Agreed core" item 4 so
	// an operator auditing acknowledged sensitive endpoints sees it listed
	// alongside the rest of the libpod write surface as it grows.
	{method: http.MethodPost, path: "/libpod/containers/create"},
	// libpod-native writes (#148). Pod-create, exec, and volume/network/
	// secret create have real inspectors (see bodyInspectionConfiguredForEndpoint)
	// wired through request_body.libpod_pod_create / the shared
	// request_body.exec / request_body.libpod_volume|network|secret.
	{method: http.MethodPost, path: "/libpod/pods/create"},
	{method: http.MethodPost, path: "/libpod/containers/sockguard-test/exec"},
	{method: http.MethodPost, path: "/libpod/exec/sockguard-test/start"},
	{method: http.MethodPost, path: "/libpod/volumes/create"},
	{method: http.MethodPost, path: "/libpod/networks/create"},
	{method: http.MethodPost, path: "/libpod/secrets/create"},
	// play/kube, its "kube/play" alias (Podman registers both spellings on
	// the identical libpod.PlayKube/KubePlay handlers), kube/apply, and
	// manifest-list writes have NO request-body inspector at all (#148
	// design doc decision C2: full YAML/PodSpec modeling is deferred past
	// v1.6) — a single POST /libpod/play/kube can provision an arbitrary
	// number of privileged containers from a Kubernetes-shaped manifest sockguard
	// never parses. These deliberately have no case in
	// bodyInspectionConfiguredForEndpoint below (falling through to its
	// `default: return false`), so any allow rule admitting them requires
	// insecure_allow_body_blind_writes — see that flag's docs for the
	// N-privileged-containers blast-radius warning specific to play/kube.
	{method: http.MethodPost, path: "/libpod/play/kube"},
	{method: http.MethodPost, path: "/libpod/kube/play"},
	{method: http.MethodPost, path: "/libpod/kube/apply"},
	{method: http.MethodPost, path: "/libpod/manifests/create"},
	{method: http.MethodPost, path: "/libpod/manifests/sockguard-test"},
	{method: http.MethodPut, path: "/libpod/manifests/sockguard-test"},
}

type buildkitTunnelEndpoint struct {
	method string
	path   string
}

// buildkitTunnelEndpoints probes the opaque, unversioned BuildKit
// session/gRPC transport: POST /session (frontend/session bridge) and
// POST /grpc (the moby.buildkit.v1.Control gRPC service tunneled over an
// HTTP/1.1 hijack), still used by current Buildx (0.36.0) despite Engine API
// 1.53 deprecating both. Neither carries a request body sockguard can bound
// or inspect once opened, so admitting either requires the dedicated
// insecure_accept_opaque_buildkit_tunnels acknowledgment rather than the
// bounded-exec insecure_allow_body_blind_writes escape hatch. A literal
// "/moby.buildkit.v1.Control/*"-shaped rule is probed too: sockguard's
// net/http server has no h2c support today (see the h2c-preface guard
// integration test), so a native-gRPC path can't reach an operator-authored
// rule yet, but a rule that would admit one is still a live gap for the day
// it does.
var buildkitTunnelEndpoints = []buildkitTunnelEndpoint{
	{method: http.MethodPost, path: "/session"},
	{method: http.MethodPost, path: "/grpc"},
	{method: http.MethodPost, path: "/moby.buildkit.v1.Control/Solve"},
}

var sensitiveExfilEndpoints = []sensitiveExfilEndpoint{
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
	// Registry pushes are writes at the Docker API layer, but they read local
	// artifact content and transmit it to a caller-selected registry. Treat
	// them as exfiltration surfaces alongside archive/export downloads.
	{method: http.MethodPost, path: "/images/sockguard-test/push"},
	{method: http.MethodPost, path: "/plugins/sockguard-test/push"},
	// libpod read/export surface (#148). Confirmed against Podman v5.8.1's
	// own route table (pkg/api/server/register_archive.go,
	// register_containers.go, register_images.go) rather than assumed from
	// naming symmetry with the compat entries above — libpod has no
	// /attach/ws variant (Docker-only dual attach mechanism) and no
	// plugin API at all (plugins are a Moby-only concept), so neither has a
	// libpod counterpart here. GET /libpod/generate/kube is also included:
	// despite the "generate" name suggesting a write, Podman registers it as
	// a GET (libpod.GenerateKube) that dumps existing pod/container
	// definitions to YAML — a read/export surface that can leak env vars and
	// other resource data — so it belongs here, not in
	// bodySensitiveWriteEndpoints above where the #148 design doc's initial
	// pass listed it.
	{method: http.MethodGet, path: "/libpod/containers/sockguard-test/archive"},
	{method: http.MethodGet, path: "/libpod/containers/sockguard-test/export"},
	{method: http.MethodGet, path: "/libpod/containers/sockguard-test/logs"},
	{method: http.MethodPost, path: "/libpod/containers/sockguard-test/attach"},
	{method: http.MethodGet, path: "/libpod/images/export"},
	{method: http.MethodGet, path: "/libpod/images/sockguard-test/get"},
	{method: http.MethodPost, path: "/libpod/images/sockguard-test/push"},
	{method: http.MethodGet, path: "/libpod/generate/kube"},
	// Manifest-list push routes read local manifest content and transmit it
	// to a caller-selected registry — a write at the Docker API layer but an
	// exfiltration surface just like the image/plugin push entries above.
	// POST .../registry/{destination} is the current (Podman v4.0.0+) route;
	// POST .../push is kept for backward compat (deprecated since v4.0.0 but
	// still routable). Both are registered in Podman v5.8.1's
	// pkg/api/server/register_manifest.go.
	{method: http.MethodPost, path: "/libpod/manifests/sockguard-test/registry/sockguard-test"},
	{method: http.MethodPost, path: "/libpod/manifests/sockguard-test/push"},
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
	if err := validateBuildkitTunnelRules(cfg, compiled); err != nil {
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

func validateBuildkitTunnelRules(cfg *config.Config, compiled []*filter.CompiledRule) error {
	//nolint:staticcheck // SA1019: deprecated flag still needs validating for as long as it stays functional
	return validateBuildkitTunnelRulesForPolicy("", cfg.InsecureAcceptOpaqueBuildkitTunnels, cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Configured(), compiled)
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
		"client profile %q allows body-sensitive write endpoints without request body inspection; set the top-level insecure_allow_body_blind_writes=true to acknowledge this risk (it is a global setting, not per-profile): %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

func validateReadExfiltrationRulesForPolicy(scope string, insecure bool, compiled []*filter.CompiledRule) error {
	if insecure {
		return nil
	}

	exposed := allowedSensitiveExfilEndpoints(compiled)
	if len(exposed) == 0 {
		return nil
	}

	if scope == "" {
		return fmt.Errorf(
			"rules allow raw archive/export, log/attach streaming, or registry push endpoints "+
				"(these can exfiltrate container files, images, plugins, environment variables, and secrets); "+
				"either tighten the allow rules to omit these paths or set "+
				"insecure_allow_read_exfiltration: true to acknowledge the risk. "+
				"Exposed endpoints: %s",
			strings.Join(exposed, ", "),
		)
	}

	return fmt.Errorf(
		"client profile %q allows raw archive/export, log/attach streaming, or registry push endpoints "+
			"(these can exfiltrate container files, images, plugins, environment variables, and secrets); "+
			"either tighten the profile's allow rules to omit these paths or set the "+
			"top-level insecure_allow_read_exfiltration: true to acknowledge the risk "+
			"(it is a global setting, not per-profile). "+
			"Exposed endpoints: %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

// validateBuildkitTunnelRulesForPolicy admits a rule allowing the opaque
// BuildKit tunnel endpoints when EITHER the wholesale
// insecure_accept_opaque_buildkit_tunnels acknowledgment is set OR
// buildkitConfigured is true — i.e. request_body.buildkit
// (config.BuildkitRequestBodyConfig, translated via
// buildkitproxy.Policy.Configured) is configured for this scope. The two
// are mutually exclusive by construction (see
// validateBuildkitAckMutualExclusion in the config package), so in practice
// exactly one of these two conditions can ever be true for a given scope —
// this function does not need to (and does not) re-check that invariant.
//
// IMPORTANT — this function governs STARTUP admission only, i.e. whether
// sockguard refuses to boot at all. What actually happens to a /session or
// /grpc request at request time depends on which of the two conditions above
// admitted the rule, enforced by the filter inspector + mediator pair
// (filter.buildkitPolicy.inspect in buildkit.go, and cmd/serve.go's
// withBuildkitMediator): when request_body.buildkit IS configured for the
// resolved policy, withBuildkitMediator hands POST /session and POST /grpc to
// internal/buildkitproxy.Mediator, which terminates the h2c tunnel and
// enforces buildkitproxy.Classify + Policy.Allowed per gRPC method — the
// literal /moby.buildkit.v1.Control/<Method> probe path stays hard-denied by
// the filter inspector regardless of PolicyConfig.Buildkit.TunnelConfigured
// (see buildkit.go's inspect doc comment for why: it carries no upgrade for
// any mediator to terminate). When request_body.buildkit is NOT configured —
// the insecure_accept_opaque_buildkit_tunnels path — withBuildkitMediator is
// a no-op and the request falls through to the plain ReverseProxy exactly as
// it did pre-#185; that flag's meaning and denial message below are
// unchanged.
func validateBuildkitTunnelRulesForPolicy(scope string, insecure, buildkitConfigured bool, compiled []*filter.CompiledRule) error {
	if insecure || buildkitConfigured {
		return nil
	}

	exposed := allowedBuildkitTunnelEndpoints(compiled)
	if len(exposed) == 0 {
		return nil
	}

	if scope == "" {
		return fmt.Errorf(
			"rules allow the opaque BuildKit session/gRPC tunnel (POST /session, POST /grpc, or a moby.buildkit.v1.Control method path) — "+
				"these streams carry secrets, SSH agent forwarding, and file sync that sockguard cannot inspect or bound once opened; "+
				"set insecure_accept_opaque_buildkit_tunnels=true to acknowledge this risk, or configure request_body.buildkit (issue #185) "+
				"to admit them under sockguard's BuildKit gRPC mediation policy instead: %s",
			strings.Join(exposed, ", "),
		)
	}

	return fmt.Errorf(
		"client profile %q allows the opaque BuildKit session/gRPC tunnel (POST /session, POST /grpc, or a moby.buildkit.v1.Control method path); "+
			"set the top-level insecure_accept_opaque_buildkit_tunnels=true to acknowledge this risk (it is a global setting, not per-profile), "+
			"or configure this profile's request_body.buildkit (issue #185) to admit them under sockguard's BuildKit gRPC mediation policy instead: %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

func allowedBuildkitTunnelEndpoints(compiled []*filter.CompiledRule) []string {
	allowed := make([]string, 0, len(buildkitTunnelEndpoints))
	for _, endpoint := range buildkitTunnelEndpoints {
		req := &http.Request{Method: endpoint.method, URL: &url.URL{Path: endpoint.path}}
		action, _, _ := filter.Evaluate(compiled, req)
		if action != filter.ActionAllow {
			continue
		}
		allowed = append(allowed, endpoint.method+" "+endpoint.path)
	}
	return allowed
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

func allowedSensitiveExfilEndpoints(compiled []*filter.CompiledRule) []string {
	allowed := make([]string, 0, len(sensitiveExfilEndpoints))
	for _, endpoint := range sensitiveExfilEndpoints {
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
	case "/containers/sockguard-test/exec", "/exec/sockguard-test/start",
		"/libpod/containers/sockguard-test/exec", "/libpod/exec/sockguard-test/start":
		// Shared request_body.exec config covers both the Docker-compat and
		// libpod exec paths (#148 design doc decision C3) — same field,
		// same condition.
		return len(requestBody.Exec.AllowedCommands) > 0
	case "/containers/sockguard-test/update", "/containers/sockguard-test/archive", "/images/create", "/images/load", "/build", "/libpod/build":
		return true
	case "/volumes/create", "/networks/create", "/networks/sockguard-test/connect", "/networks/sockguard-test/disconnect", "/secrets/create", "/configs/create", "/services/create", "/services/sockguard-test/update", "/swarm/init", "/plugins/pull", "/plugins/sockguard-test/upgrade":
		return true
	case "/swarm/join":
		return len(requestBody.Swarm.AllowedJoinRemoteAddrs) > 0
	case "/swarm/update", "/swarm/unlock", "/nodes/sockguard-test/update":
		return true
	case "/plugins/sockguard-test/set":
		return len(requestBody.Plugin.AllowedSetEnvPrefixes) > 0
	case "/plugins/create":
		return true
	case "/libpod/containers/create":
		return true
	case "/libpod/pods/create", "/libpod/volumes/create", "/libpod/networks/create", "/libpod/secrets/create":
		// libpod_pod_create/libpod_volume/libpod_network/libpod_secret gates
		// are all plain booleans/allowlists with real fail-closed defaults —
		// none of them read insecure_allow_body_blind_writes the way exec
		// does — so, like the Docker-compat entries above, the built-in
		// inspector always provides real protection independent of whether
		// the operator has customized it. #148.
		return true
	// /libpod/play/kube, /libpod/kube/play, /libpod/kube/apply, and
	// /libpod/manifests/* deliberately have NO case here: they have no
	// request-body inspector at all (#148 design doc decision C2), so they
	// fall through to `default: false` below and always require
	// insecure_allow_body_blind_writes to admit.
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
		//nolint:staticcheck // SA1019: deprecated flag still needs validating for as long as it stays functional
		if err := validateBuildkitTunnelRulesForPolicy(profile.Name, cfg.InsecureAcceptOpaqueBuildkitTunnels, profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build).Configured(), compiledRules); err != nil {
			return nil, err
		}
		profiles[profile.Name] = filter.Policy{
			Rules:        compiledRules,
			PolicyConfig: profile.RequestBody.ToFilterOptions(),
		}
	}
	return profiles, nil
}
