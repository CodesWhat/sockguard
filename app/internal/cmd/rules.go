package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

var (
	validateConfig = config.Validate
	// validateConfigStructural is the filesystem-free validator used for a
	// candidate config that arrived over the admin API. See
	// config.ValidateStructural.
	validateConfigStructural = config.ValidateStructural
	compileFilterRule        = filter.CompileRule
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
	// Podman's native image pull, the libpod counterpart of
	// POST /images/create. It runs through the SAME request_body.image_pull
	// registry allowlist (filter.imagePullPolicy.inspectLibpod), so it is
	// recognized as inspected below rather than requiring the blind-write
	// acknowledgment — it is listed here so an operator auditing the
	// body-sensitive write surface sees it alongside the rest of it.
	{method: http.MethodPost, path: "/libpod/images/pull"},
	// Podman's native image load and import. Both run through the SAME
	// config an operator already sets for the Docker-compat spellings —
	// request_body.image_load for the archive, request_body.image_pull's
	// allow_imports for the import — so both are recognized as inspected
	// below rather than requiring the blind-write acknowledgment.
	{method: http.MethodPost, path: "/libpod/images/load"},
	{method: http.MethodPost, path: "/libpod/images/import"},
	// The two libpod "local API" routes have no Docker analog and, unlike
	// every other entry in this catalog, take their input from a path on the
	// DAEMON HOST rather than from the request: /libpod/local/build's
	// required `localcontextdir` and /libpod/local/images/load's required
	// `path` are absolute server-side paths that Podman v5.8.1 validates
	// only as absolute-and-exists (internal/localapi's
	// ValidatePathForLocalAPI — no sandbox root). Nothing crosses the socket
	// for sockguard to read, so they deliberately have no case in
	// bodyInspectionConfiguredForEndpoint and always require
	// insecure_allow_body_blind_writes, which is also exactly what the
	// runtime inspectors demand (filter.buildPolicy.inspectLibpodBuildControls
	// and filter.imageLoadPolicy.inspect).
	{method: http.MethodPost, path: "/libpod/local/build"},
	{method: http.MethodPost, path: "/libpod/local/images/load"},
	// Image SCP creates a local image from an archive fetched over SSH from
	// a host the CALLER names, so it is an uninspectable image-ingest path
	// that bypasses request_body.image_pull's registry allowlist entirely
	// (Podman v5.8.1 pkg/domain/utils/scp.go: an unknown connection name
	// falls back to a literal "ssh://"+name rather than being rejected). It
	// is also an egress channel, so it appears in sensitiveExfilEndpoints
	// too — admitting it takes both acknowledgments, one per direction.
	{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test"},
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
	// Podman's image-name matcher accepts slashes. This second representative
	// catches constrained rules under the literal "scp" name prefix that route
	// to image push before the later /images/scp/{name:.*} handler.
	{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test/push"},
	// Image SCP transfers a local image to another HOST over SSH, with the
	// destination named by the caller in the `destination` query parameter
	// (Podman v5.8.1 pkg/api/server/register_images.go routes
	// POST /libpod/images/scp/{name:.*} to libpod.ImageScp, which parses
	// source from the path and destination from the query and hands both to
	// domainUtils.ExecuteTransfer). It is the push entries' problem without
	// their one mitigation: there is no registry to allowlist, and an
	// unrecognized connection name is turned into "ssh://"+name instead of
	// being refused, so the destination is an arbitrary SSH endpoint.
	{method: http.MethodPost, path: "/libpod/images/scp/sockguard-test"},
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

// validateAndCompileRules validates and compiles an operator-supplied config.
// It uses the full validator, which loads the TLS material the config names.
func validateAndCompileRules(cfg *config.Config) ([]*filter.CompiledRule, error) {
	return validateAndCompileRulesWith(cfg, validateConfig)
}

// validateAndCompileRulesStructural is validateAndCompileRules for a candidate
// config supplied by a remote caller. Every check that does not touch the
// filesystem still runs; the TLS material named by listen.tls is never opened,
// so the admin API's POST /validate cannot be used to probe host paths. See
// config.ValidateStructural.
func validateAndCompileRulesStructural(cfg *config.Config) ([]*filter.CompiledRule, error) {
	return validateAndCompileRulesWith(cfg, validateConfigStructural)
}

func validateAndCompileRulesWith(cfg *config.Config, validate func(*config.Config) error) ([]*filter.CompiledRule, error) {
	if err := validate(cfg); err != nil {
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
	return validateBodyBlindWriteRulesForPolicy("", cfg.InsecureAllowBodyBlindWrites, cfg.RequestBody, compiled, cfg.Rules)
}

func validateReadExfiltrationRules(cfg *config.Config, compiled []*filter.CompiledRule) error {
	return validateReadExfiltrationRulesForPolicy("", cfg.InsecureAllowReadExfiltration, compiled, cfg.Rules)
}

func validateBuildkitTunnelRules(cfg *config.Config, compiled []*filter.CompiledRule) error {
	//nolint:staticcheck // SA1019: deprecated flag still needs validating for as long as it stays functional
	return validateBuildkitTunnelRulesForPolicy("", cfg.InsecureAcceptOpaqueBuildkitTunnels, cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Configured(), compiled)
}

func validateBodyBlindWriteRulesForPolicy(scope string, insecure bool, requestBody config.RequestBodyConfig, compiled []*filter.CompiledRule, configuredRules []config.RuleConfig) error {
	if insecure {
		return nil
	}

	exposed := allowedBodySensitiveWriteEndpoints(requestBody, compiled, configuredRules)
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

func validateReadExfiltrationRulesForPolicy(scope string, insecure bool, compiled []*filter.CompiledRule, configuredRules []config.RuleConfig) error {
	if insecure {
		return nil
	}

	exposed := allowedSensitiveExfilEndpoints(compiled, configuredRules)
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

func allowedBodySensitiveWriteEndpoints(requestBody config.RequestBodyConfig, compiled []*filter.CompiledRule, configuredRules []config.RuleConfig) []string {
	endpoints := appendExactLibpodImageScpBodyEndpoints(bodySensitiveWriteEndpoints, configuredRules)
	allowed := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
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
	if path, ok := configuredLibpodImageScpAllow(configuredRules); ok && !slices.Contains(allowed, http.MethodPost+" "+path) {
		allowed = append(allowed, http.MethodPost+" "+path)
	}
	return allowed
}

func allowedSensitiveExfilEndpoints(compiled []*filter.CompiledRule, configuredRules []config.RuleConfig) []string {
	endpoints := appendExactLibpodImageScpExfilEndpoints(sensitiveExfilEndpoints, configuredRules)
	allowed := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		req := &http.Request{Method: endpoint.method, URL: &url.URL{Path: endpoint.path}}
		action, _, _ := filter.Evaluate(compiled, req)
		if action != filter.ActionAllow {
			continue
		}
		allowed = append(allowed, endpoint.method+" "+endpoint.path)
	}
	if path, ok := configuredLibpodImageScpAllow(configuredRules); ok && !slices.Contains(allowed, http.MethodPost+" "+path) {
		allowed = append(allowed, http.MethodPost+" "+path)
	}
	if path, ok := configuredLibpodSlashBearingImagePushAllow(configuredRules); ok && !slices.Contains(allowed, http.MethodPost+" "+path) {
		allowed = append(allowed, http.MethodPost+" "+path)
	}
	return allowed
}

// configuredLibpodImageScpAllow audits the source rules instead of relying on
// one representative request. A deny for that representative must not hide a
// later wildcard allow that still opens every other caller-selected image
// name. Exact paths retain their own spelling in the validation error; broad
// patterns report the route family they expose.
func configuredLibpodImageScpAllow(rules []config.RuleConfig) (string, bool) {
	const prefix = "/libpod/images/scp/"
	for index, rule := range rules {
		if rule.Action != "allow" || !methodListIncludes(rule.Match.Method, http.MethodPost) {
			continue
		}
		pattern := strings.TrimSpace(rule.Match.Path)
		if !strings.Contains(pattern, "*") {
			// Exact paths are already added as probes and evaluated against the
			// complete first-match rule set by the caller.
			continue
		}
		if libpodImagePathIsHandledBeforeScp(pattern) {
			continue
		}
		if globCanMatchNonemptyPathBelow(pattern, prefix) && !libpodImageScpAllowDefinitelyShadowed(pattern, rules[:index]) {
			return prefix + "*", true
		}
	}
	return "", false
}

func libpodImagePathIsHandledBeforeScp(path string) bool {
	for _, suffix := range []string{"/push", "/tag", "/untag"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

type reachabilityGlobKind uint8

const (
	reachabilityGlobLiteral reachabilityGlobKind = iota
	reachabilityGlobSegmentStar
	reachabilityGlobAnyStar
	reachabilityGlobOptionalDeep
)

type reachabilityGlobPart struct {
	kind    reachabilityGlobKind
	literal rune
}

type reachabilityGlobState struct {
	part int
	deep bool
}

// globCanMatchNonemptyPathBelow decides whether a path glob intersects the
// dynamic route family prefix+<nonempty name>. It models the repository's
// complete glob dialect as a small epsilon-NFA, so startup validation does not
// depend on any finite set of representative image names.
func globCanMatchNonemptyPathBelow(pattern, prefix string) bool {
	return globHasMatchOutsideCovers(pattern, prefix, nil)
}

func parseReachabilityGlob(pattern string) []reachabilityGlobPart {
	runes := []rune(pattern)
	parts := make([]reachabilityGlobPart, 0, len(runes))
	for index := 0; index < len(runes); {
		switch {
		case index+2 < len(runes) && runes[index] == '/' && runes[index+1] == '*' && runes[index+2] == '*':
			parts = append(parts, reachabilityGlobPart{kind: reachabilityGlobOptionalDeep})
			index += 3
		case index+1 < len(runes) && runes[index] == '*' && runes[index+1] == '*':
			parts = append(parts, reachabilityGlobPart{kind: reachabilityGlobAnyStar})
			index += 2
		case runes[index] == '*':
			parts = append(parts, reachabilityGlobPart{kind: reachabilityGlobSegmentStar})
			index++
		default:
			parts = append(parts, reachabilityGlobPart{kind: reachabilityGlobLiteral, literal: runes[index]})
			index++
		}
	}
	return parts
}

func reachabilityGlobClosure(parts []reachabilityGlobPart, states map[reachabilityGlobState]struct{}) map[reachabilityGlobState]struct{} {
	queue := make([]reachabilityGlobState, 0, len(states))
	for state := range states {
		queue = append(queue, state)
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		if state.deep {
			next := reachabilityGlobState{part: state.part + 1}
			if _, ok := states[next]; !ok {
				states[next] = struct{}{}
				queue = append(queue, next)
			}
			continue
		}
		if state.part >= len(parts) {
			continue
		}
		switch parts[state.part].kind {
		case reachabilityGlobSegmentStar, reachabilityGlobAnyStar, reachabilityGlobOptionalDeep:
			next := reachabilityGlobState{part: state.part + 1}
			if _, ok := states[next]; !ok {
				states[next] = struct{}{}
				queue = append(queue, next)
			}
		}
	}
	return states
}

func reachabilityGlobStep(parts []reachabilityGlobPart, states map[reachabilityGlobState]struct{}, value rune) map[reachabilityGlobState]struct{} {
	next := make(map[reachabilityGlobState]struct{})
	for state := range reachabilityGlobClosure(parts, states) {
		if state.deep {
			next[state] = struct{}{}
			continue
		}
		if state.part >= len(parts) {
			continue
		}
		part := parts[state.part]
		switch part.kind {
		case reachabilityGlobLiteral:
			if value == part.literal {
				next[reachabilityGlobState{part: state.part + 1}] = struct{}{}
			}
		case reachabilityGlobSegmentStar:
			if value != '/' {
				next[state] = struct{}{}
			}
		case reachabilityGlobAnyStar:
			next[state] = struct{}{}
		case reachabilityGlobOptionalDeep:
			if value == '/' {
				next[reachabilityGlobState{part: state.part, deep: true}] = struct{}{}
			}
		}
	}
	return reachabilityGlobClosure(parts, next)
}

func libpodImageScpAllowDefinitelyShadowed(pattern string, earlier []config.RuleConfig) bool {
	return globAllowDefinitelyShadowed(pattern, "/libpod/images/scp/", earlier)
}

func configuredLibpodSlashBearingImagePushAllow(rules []config.RuleConfig) (string, bool) {
	const prefix = "/libpod/images/"
	for index, rule := range rules {
		if rule.Action != "allow" || !methodListIncludes(rule.Match.Method, http.MethodPost) {
			continue
		}
		pattern := strings.TrimSpace(rule.Match.Path)
		if !strings.Contains(pattern, "*") || !strings.HasSuffix(pattern, "/push") {
			continue
		}
		if globCanMatchNonemptyPathBelow(pattern, prefix) && !globAllowDefinitelyShadowed(pattern, prefix, rules[:index]) {
			return prefix + "*/push", true
		}
	}
	return "", false
}

func globAllowDefinitelyShadowed(pattern, prefix string, earlier []config.RuleConfig) bool {
	covers := make([]string, 0, len(earlier))
	for _, rule := range earlier {
		if !methodListIncludes(rule.Match.Method, http.MethodPost) {
			continue
		}
		covers = append(covers, strings.TrimSpace(rule.Match.Path))
	}
	return !globHasMatchOutsideCovers(pattern, prefix, covers)
}

type reachabilityGlobLanguageState struct {
	candidate map[reachabilityGlobState]struct{}
	covers    []map[reachabilityGlobState]struct{}
}

// globHasMatchOutsideCovers decides exact language reachability for a rule at
// its ordered position: it finds a nonempty suffix below prefix accepted by
// pattern and by none of the earlier method-compatible cover patterns.
func globHasMatchOutsideCovers(pattern, prefix string, covers []string) bool {
	candidateParts := parseReachabilityGlob(pattern)
	coverParts := make([][]reachabilityGlobPart, len(covers))
	state := reachabilityGlobLanguageState{
		candidate: reachabilityGlobClosure(candidateParts, map[reachabilityGlobState]struct{}{{}: {}}),
		covers:    make([]map[reachabilityGlobState]struct{}, len(covers)),
	}
	for index, cover := range covers {
		coverParts[index] = parseReachabilityGlob(cover)
		state.covers[index] = reachabilityGlobClosure(coverParts[index], map[reachabilityGlobState]struct{}{{}: {}})
	}
	for _, value := range prefix {
		state.candidate = reachabilityGlobStep(candidateParts, state.candidate, value)
		for index := range state.covers {
			state.covers[index] = reachabilityGlobStep(coverParts[index], state.covers[index], value)
		}
		if len(state.candidate) == 0 {
			return false
		}
	}

	alphabet := reachabilityGlobAlphabet(candidateParts, coverParts)
	queue := []reachabilityGlobLanguageState{state}
	seen := map[string]struct{}{reachabilityGlobLanguageStateKey(state): {}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, value := range alphabet {
			next := reachabilityGlobLanguageState{
				candidate: reachabilityGlobStep(candidateParts, current.candidate, value),
				covers:    make([]map[reachabilityGlobState]struct{}, len(current.covers)),
			}
			if len(next.candidate) == 0 {
				continue
			}
			covered := false
			for index := range current.covers {
				next.covers[index] = reachabilityGlobStep(coverParts[index], current.covers[index], value)
				covered = covered || reachabilityGlobAccepts(coverParts[index], next.covers[index])
			}
			if reachabilityGlobAccepts(candidateParts, next.candidate) && !covered {
				return true
			}
			key := reachabilityGlobLanguageStateKey(next)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				queue = append(queue, next)
			}
		}
	}
	return false
}

func reachabilityGlobAlphabet(candidate []reachabilityGlobPart, covers [][]reachabilityGlobPart) []rune {
	literals := make(map[rune]struct{})
	add := func(parts []reachabilityGlobPart) {
		for _, part := range parts {
			if part.kind == reachabilityGlobLiteral {
				literals[part.literal] = struct{}{}
			}
		}
	}
	add(candidate)
	for _, parts := range covers {
		add(parts)
	}
	alphabet := make([]rune, 0, len(literals)+2)
	alphabet = append(alphabet, '/')
	for literal := range literals {
		if literal != '/' {
			alphabet = append(alphabet, literal)
		}
	}
	other := rune('a')
	for other == '/' {
		other++
	}
	for {
		if _, exists := literals[other]; !exists {
			break
		}
		other++
	}
	alphabet = append(alphabet, other)
	return alphabet
}

func reachabilityGlobAccepts(parts []reachabilityGlobPart, states map[reachabilityGlobState]struct{}) bool {
	_, ok := states[reachabilityGlobState{part: len(parts)}]
	return ok
}

func reachabilityGlobLanguageStateKey(state reachabilityGlobLanguageState) string {
	var builder strings.Builder
	builder.WriteString(reachabilityGlobStatesKey(state.candidate))
	for _, cover := range state.covers {
		builder.WriteByte('|')
		builder.WriteString(reachabilityGlobStatesKey(cover))
	}
	return builder.String()
}

func reachabilityGlobStatesKey(states map[reachabilityGlobState]struct{}) string {
	values := make([]int, 0, len(states))
	for state := range states {
		value := state.part * 2
		if state.deep {
			value++
		}
		values = append(values, value)
	}
	slices.Sort(values)
	return fmt.Sprint(values)
}

func methodListIncludes(methods, want string) bool {
	for _, method := range splitMethods(methods) {
		if method == "*" || strings.EqualFold(method, want) {
			return true
		}
	}
	return false
}

func appendExactLibpodImageScpBodyEndpoints(base []bodySensitiveWriteEndpoint, rules []config.RuleConfig) []bodySensitiveWriteEndpoint {
	paths := exactLibpodImageScpPaths(rules)
	endpoints := make([]bodySensitiveWriteEndpoint, 0, len(base)+len(paths))
	endpoints = append(endpoints, base...)
	for _, path := range paths {
		endpoints = append(endpoints, bodySensitiveWriteEndpoint{method: http.MethodPost, path: path})
	}
	return endpoints
}

func appendExactLibpodImageScpExfilEndpoints(base []sensitiveExfilEndpoint, rules []config.RuleConfig) []sensitiveExfilEndpoint {
	paths := append(exactLibpodImageScpPaths(rules), exactLibpodImagePushPaths(rules)...)
	endpoints := make([]sensitiveExfilEndpoint, 0, len(base)+len(paths))
	endpoints = append(endpoints, base...)
	for _, path := range paths {
		endpoints = append(endpoints, sensitiveExfilEndpoint{method: http.MethodPost, path: path})
	}
	return endpoints
}

func exactLibpodImagePushPaths(rules []config.RuleConfig) []string {
	const prefix = "/libpod/images/"
	const suffix = "/push"
	paths := make([]string, 0)
	for _, rule := range rules {
		path := strings.TrimSpace(rule.Match.Path)
		if strings.Contains(path, "*") || !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) || len(path) <= len(prefix)+len(suffix) || slices.Contains(paths, path) {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

// The static catalog probes one representative dynamic path, which catches
// wildcard rules but cannot catch an allow rule naming a different SCP image
// exactly. Add every literal SCP path from the source rules as another probe.
// Patterns containing * remain covered by the representative catalog entry.
func exactLibpodImageScpPaths(rules []config.RuleConfig) []string {
	const prefix = "/libpod/images/scp/"
	const representative = prefix + "sockguard-test"
	paths := make([]string, 0)
	for _, rule := range rules {
		path := strings.TrimSpace(rule.Match.Path)
		if path == representative || strings.Contains(path, "*") || !strings.HasPrefix(path, prefix) || len(path) == len(prefix) || libpodImagePathIsHandledBeforeScp(path) || slices.Contains(paths, path) {
			continue
		}
		paths = append(paths, path)
	}
	return paths
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
	case "/libpod/pods/create", "/libpod/volumes/create", "/libpod/networks/create", "/libpod/secrets/create", "/libpod/images/pull", "/libpod/images/load", "/libpod/images/import":
		// libpod_pod_create/libpod_volume/libpod_network/libpod_secret gates
		// are all plain booleans/allowlists with real fail-closed defaults —
		// none of them read insecure_allow_body_blind_writes the way exec
		// does — so, like the Docker-compat entries above, the built-in
		// inspector always provides real protection independent of whether
		// the operator has customized it. #148. POST /libpod/images/pull
		// joins them on the same terms: it reuses request_body.image_pull,
		// whose allow_official-only default already denies a pull from any
		// non-Docker-Hub-official registry, exactly as it does for the
		// Docker-compat /images/create entry above. So do
		// POST /libpod/images/load, which carries the same archive body the
		// /images/load entry above is inspected on and is read by the same
		// imageLoadPolicy, and POST /libpod/images/import, which is gated by
		// request_body.image_pull.allow_imports — false by default, and the
		// same flag that already gates the Docker-compat fromSrc import.
		return true
	// /libpod/play/kube, /libpod/kube/play, /libpod/kube/apply,
	// /libpod/manifests/*, /libpod/local/build, /libpod/local/images/load,
	// and /libpod/images/scp/* deliberately have NO case here: they have no
	// request-body inspector at all (#148 design doc decision C2 for the
	// kube/manifest set; for the rest, the input is a daemon-host path or an
	// SSH destination that never crosses the socket), so they fall through
	// to `default: false` below and always require
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
		if err := validateBodyBlindWriteRulesForPolicy(profile.Name, cfg.InsecureAllowBodyBlindWrites, profile.RequestBody, compiledRules, profile.Rules); err != nil {
			return nil, err
		}
		if err := validateReadExfiltrationRulesForPolicy(profile.Name, cfg.InsecureAllowReadExfiltration, compiledRules, profile.Rules); err != nil {
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
