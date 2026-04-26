package filter

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

// DenialResponse is the JSON body returned when a request is denied.
type DenialResponse struct {
	Message string `json:"message"`
	Method  string `json:"method,omitempty"`
	Path    string `json:"path,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// DenyResponseVerbosity controls how much detail filter denial responses include.
type DenyResponseVerbosity string

const (
	// DenyResponseVerbosityVerbose includes request details in the denial response body.
	DenyResponseVerbosityVerbose DenyResponseVerbosity = "verbose"
	// DenyResponseVerbosityMinimal returns only a generic denial message.
	DenyResponseVerbosityMinimal DenyResponseVerbosity = "minimal"
)

const (
	reasonCodeMatchedAllowRule              = "matched_allow_rule"
	reasonCodeMatchedDenyRule               = "matched_deny_rule"
	reasonCodeNoMatchingAllowRule           = "no_matching_allow_rule"
	reasonCodeClientPolicyProfileUnresolved = "client_policy_profile_unresolved"
	reasonCodeRequestBodyPolicyDenied       = "request_body_policy_denied"
	reasonCodeRequestBodyTooLarge           = "request_body_too_large"
	reasonCodeRequestBodyInspectionFailed   = "request_body_inspection_failed"
)

// PolicyConfig configures deny-response behavior plus request-body inspection
// policies shared by the default middleware policy and named client profiles.
type PolicyConfig struct {
	// DenyResponseVerbosity controls how much detail denied requests include in
	// the JSON response body.
	DenyResponseVerbosity DenyResponseVerbosity
	// ContainerCreate configures request-body policy checks for
	// POST /containers/create.
	ContainerCreate ContainerCreateOptions
	// Exec configures request-body policy checks for exec create/start.
	Exec ExecOptions
	// ImagePull configures request/query inspection for POST /images/create.
	ImagePull ImagePullOptions
	// Build configures request-body/query inspection for POST /build.
	Build BuildOptions
	// Volume configures request-body inspection for POST /volumes/create.
	Volume VolumeOptions
	// Secret configures request-body inspection for POST /secrets/create.
	Secret SecretOptions
	// Config configures request-body inspection for POST /configs/create.
	Config ConfigOptions
	// Service configures request-body inspection for service create/update.
	Service ServiceOptions
	// Swarm configures request-body inspection for swarm init.
	Swarm SwarmOptions
	// Plugin configures request-body inspection for plugin write endpoints.
	Plugin PluginOptions
}

// Options configures filter middleware behavior.
type Options struct {
	PolicyConfig
	// Profiles defines named per-client policy overrides selected at request time.
	Profiles map[string]Policy
	// ResolveProfile returns the named policy to apply for the request.
	ResolveProfile func(*http.Request) (string, bool)
}

// Policy defines a named request policy profile that can override the global
// rules and request-body inspection options for a single request.
type Policy struct {
	Rules []*CompiledRule
	PolicyConfig
}

// ParseDenyResponseVerbosity normalizes a configured deny verbosity value.
// Empty or unknown values default to DenyResponseVerbosityMinimal so the proxy
// never leaks the raw request path on an unknown or missing config — verbose
// is an explicit opt-in for rule authoring and dev work only.
func ParseDenyResponseVerbosity(value string) DenyResponseVerbosity {
	switch DenyResponseVerbosity(value) {
	case DenyResponseVerbosityMinimal:
		return DenyResponseVerbosityMinimal
	case DenyResponseVerbosityVerbose:
		return DenyResponseVerbosityVerbose
	default:
		return DenyResponseVerbosityMinimal
	}
}

func (c PolicyConfig) normalized() PolicyConfig {
	c.DenyResponseVerbosity = ParseDenyResponseVerbosity(string(c.DenyResponseVerbosity))
	return c
}

func (o Options) normalized() Options {
	o.PolicyConfig = o.PolicyConfig.normalized()
	return o
}

type runtimePolicy struct {
	rules                 []*CompiledRule
	denyResponseVerbosity DenyResponseVerbosity
	inspectPolicies       []requestInspectPolicy
}

type inspectSeverity int

const (
	inspectSeverityMedium inspectSeverity = iota
	inspectSeverityHigh
	inspectSeverityCritical
)

type requestInspectPolicy struct {
	matches           func(*http.Request, string) bool
	severity          inspectSeverity
	inspect           func(*slog.Logger, *http.Request, string) (string, error)
	errorLogMessage   string
	denyReasonOnError string
}

// Middleware is the stable convenience API for callers that want filter middleware
// with default options. Use MiddlewareWithOptions only when overriding deny
// response behavior.
//
// Denied requests get a JSON response: most policy denials are 403, while
// request-body size rejections return 413. Allowed requests pass through to
// next. Decision metadata is written to the access log RequestMeta when present.
func Middleware(rules []*CompiledRule, logger *slog.Logger) func(http.Handler) http.Handler {
	return MiddlewareWithOptions(rules, logger, Options{})
}

// MiddlewareWithOptions returns HTTP middleware that evaluates each request
// against compiled rules and allows deny response detail to be configured.
func MiddlewareWithOptions(rules []*CompiledRule, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	opts = opts.normalized()
	defaultPolicy := compileRuntimePolicy(rules, opts.PolicyConfig)
	profilePolicies := make(map[string]runtimePolicy, len(opts.Profiles))
	for name, profile := range opts.Profiles {
		profilePolicies[name] = compileRuntimePolicy(profile.Rules, profile.PolicyConfig)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			activePolicy := defaultPolicy
			if opts.ResolveProfile != nil {
				if profileName, ok := opts.ResolveProfile(r); ok {
					if meta := logging.MetaForRequest(w, r); meta != nil && profileName != "" {
						meta.Profile = profileName
					}
					profile, found := profilePolicies[profileName]
					if !found {
						denyWithReasonCode(w, r, logger, reasonCodeClientPolicyProfileUnresolved, "client policy profile could not be resolved", activePolicy.denyResponseVerbosity)
						return
					}
					activePolicy = profile
				}
			}

			normPath := NormalizePath(r.URL.Path)
			action, ruleIndex, reason := evaluateNormalized(activePolicy.rules, r.Method, normPath)
			denyStatus := http.StatusForbidden
			reasonCode := ruleDecisionReasonCode(action, reason)

			// Write decision to shared RequestMeta (created by access log middleware).
			if m := logging.MetaForRequest(w, r); m != nil {
				m.Decision = string(action)
				m.Rule = ruleIndex
				m.ReasonCode = reasonCode
				m.Reason = reason
				m.NormPath = normPath
			}

			if action == ActionAllow {
				denyReason, denyReasonCode, status := activePolicy.inspectAllowedRequest(logger, r, normPath)
				if denyReason != "" {
					action = ActionDeny
					reasonCode = denyReasonCode
					reason = denyReason
					if status != 0 {
						denyStatus = status
					}
					if m := logging.MetaForRequest(w, r); m != nil {
						m.Decision = string(action)
						m.ReasonCode = reasonCode
						m.Reason = reason
					}
				}
			}

			if action == ActionDeny {
				if err := httpjson.Write(w, denyStatus, denyResponse(r, reason, activePolicy.denyResponseVerbosity)); err != nil {
					logger.ErrorContext(r.Context(), "failed to encode denial response", "error", err, "method", r.Method, "path", r.URL.Path)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func compileRuntimePolicy(rules []*CompiledRule, cfg PolicyConfig) runtimePolicy {
	cfg = cfg.normalized()
	containerCreate := newContainerCreatePolicy(cfg.ContainerCreate)
	exec := newExecPolicy(cfg.Exec)
	imagePull := newImagePullPolicy(cfg.ImagePull)
	build := newBuildPolicy(cfg.Build)
	volume := newVolumePolicy(cfg.Volume)
	secret := newSecretPolicy(cfg.Secret)
	configPolicy := newConfigPolicy(cfg.Config)
	service := newServicePolicy(cfg.Service)
	swarm := newSwarmPolicy(cfg.Swarm)
	plugin := newPluginPolicy(cfg.Plugin)

	return runtimePolicy{
		rules:                 rules,
		denyResponseVerbosity: cfg.DenyResponseVerbosity,
		inspectPolicies: []requestInspectPolicy{
			{
				matches:           matchesContainerCreateInspection,
				severity:          inspectSeverityCritical,
				inspect:           containerCreate.inspect,
				errorLogMessage:   "failed to inspect container create request body",
				denyReasonOnError: "unable to inspect container create request body",
			},
			{
				matches:           matchesExecInspection,
				severity:          inspectSeverityHigh,
				inspect:           exec.inspect,
				errorLogMessage:   "failed to inspect exec request body",
				denyReasonOnError: "unable to inspect exec request body",
			},
			{
				matches:  matchesImagePullInspection,
				severity: inspectSeverityHigh,
				inspect: func(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
					return imagePull.inspect(r, normalizedPath)
				},
				errorLogMessage:   "failed to inspect image pull request",
				denyReasonOnError: "unable to inspect image pull request",
			},
			{
				matches:  matchesBuildInspection,
				severity: inspectSeverityCritical,
				inspect: func(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
					return build.inspect(r, normalizedPath)
				},
				errorLogMessage:   "failed to inspect build request",
				denyReasonOnError: "unable to inspect build request",
			},
			{
				matches:  matchesVolumeInspection,
				severity: inspectSeverityMedium,
				inspect: func(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
					return volume.inspect(logger, r, normalizedPath)
				},
				errorLogMessage:   "failed to inspect volume create request body",
				denyReasonOnError: "unable to inspect volume create request body",
			},
			{
				matches:           matchesSecretInspection,
				severity:          inspectSeverityMedium,
				inspect:           secret.inspect,
				errorLogMessage:   "failed to inspect secret create request body",
				denyReasonOnError: "unable to inspect secret create request body",
			},
			{
				matches:           matchesConfigInspection,
				severity:          inspectSeverityMedium,
				inspect:           configPolicy.inspect,
				errorLogMessage:   "failed to inspect config create request body",
				denyReasonOnError: "unable to inspect config create request body",
			},
			{
				matches:           matchesServiceInspection,
				severity:          inspectSeverityCritical,
				inspect:           service.inspect,
				errorLogMessage:   "failed to inspect service request body",
				denyReasonOnError: "unable to inspect service request body",
			},
			{
				matches:           matchesSwarmInspection,
				severity:          inspectSeverityCritical,
				inspect:           swarm.inspect,
				errorLogMessage:   "failed to inspect swarm init request body",
				denyReasonOnError: "unable to inspect swarm init request body",
			},
			{
				matches:           matchesPluginInspection,
				severity:          inspectSeverityCritical,
				inspect:           plugin.inspect,
				errorLogMessage:   "failed to inspect plugin request body",
				denyReasonOnError: "unable to inspect plugin request body",
			},
		},
	}
}

func matchesContainerCreateInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && normalizedPath == "/containers/create"
}

func matchesExecInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && (isExecCreatePath(normalizedPath) || isExecStartPath(normalizedPath))
}

func matchesImagePullInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && normalizedPath == "/images/create"
}

func matchesBuildInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && normalizedPath == "/build"
}

func matchesVolumeInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && normalizedPath == "/volumes/create"
}

func matchesSecretInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && normalizedPath == "/secrets/create"
}

func matchesConfigInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && normalizedPath == "/configs/create"
}

func matchesServiceInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost && isServiceWritePath(normalizedPath)
}

func matchesSwarmInspection(r *http.Request, normalizedPath string) bool {
	if r == nil || r.Method != http.MethodPost {
		return false
	}
	switch normalizedPath {
	case "/swarm/init", "/swarm/join", "/swarm/update":
		return true
	default:
		return false
	}
}

func matchesPluginInspection(r *http.Request, normalizedPath string) bool {
	return r != nil && r.Method == http.MethodPost &&
		(normalizedPath == "/plugins/pull" || normalizedPath == "/plugins/create" || isPluginUpgradePath(normalizedPath) || isPluginSetPath(normalizedPath))
}

func (p runtimePolicy) inspectAllowedRequest(logger *slog.Logger, r *http.Request, normalizedPath string) (string, string, int) {
	bestSeverity := inspectSeverity(-1)
	var matchingPolicyBuf [11]requestInspectPolicy
	matchingPolicies := matchingPolicyBuf[:0]
	for _, policy := range p.inspectPolicies {
		if policy.matches != nil && !policy.matches(r, normalizedPath) {
			continue
		}
		if policy.severity > bestSeverity {
			bestSeverity = policy.severity
			matchingPolicies = matchingPolicies[:0]
		}
		if policy.severity == bestSeverity {
			matchingPolicies = append(matchingPolicies, policy)
		}
	}

	for _, policy := range matchingPolicies {
		denyReason, err := policy.inspect(logger, r, normalizedPath)
		if err != nil {
			if rejection, ok := requestRejectionFromError(err); ok {
				return rejection.reason, requestRejectionReasonCode(rejection.status), rejection.status
			}
			logger.ErrorContext(r.Context(), policy.errorLogMessage, "error", err, "method", r.Method, "path", r.URL.Path)
			return policy.denyReasonOnError, reasonCodeRequestBodyInspectionFailed, http.StatusForbidden
		}
		if denyReason != "" {
			return denyReason, reasonCodeRequestBodyPolicyDenied, http.StatusForbidden
		}
	}
	return "", "", 0
}

func denyWithReasonCode(w http.ResponseWriter, r *http.Request, logger *slog.Logger, reasonCode, reason string, verbosity DenyResponseVerbosity) {
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.Decision = string(ActionDeny)
		meta.ReasonCode = reasonCode
		meta.Reason = reason
		if meta.NormPath == "" {
			meta.NormPath = NormalizePath(r.URL.Path)
		}
	}
	if err := httpjson.Write(w, http.StatusForbidden, denyResponse(r, reason, verbosity)); err != nil {
		logger.ErrorContext(r.Context(), "failed to encode denial response", "error", err, "method", r.Method, "path", r.URL.Path)
	}
}

func ruleDecisionReasonCode(action Action, reason string) string {
	switch action {
	case ActionAllow:
		return reasonCodeMatchedAllowRule
	case ActionDeny:
		if reason == "no matching allow rule" {
			return reasonCodeNoMatchingAllowRule
		}
		return reasonCodeMatchedDenyRule
	default:
		return ""
	}
}

func requestRejectionReasonCode(status int) string {
	if status == http.StatusRequestEntityTooLarge {
		return reasonCodeRequestBodyTooLarge
	}
	return reasonCodeRequestBodyPolicyDenied
}

func denyResponse(r *http.Request, reason string, verbosity DenyResponseVerbosity) DenialResponse {
	resp := DenialResponse{
		Message: "request denied by sockguard policy",
	}
	if verbosity == DenyResponseVerbosityMinimal {
		return resp
	}

	resp.Method = r.Method
	resp.Path = redactDeniedPath(r.URL.Path)
	resp.Reason = reason
	return resp
}

func redactDeniedPath(requestPath string) string {
	if requestPath == "" {
		return ""
	}

	cleanedPath := canonicalizePath(requestPath)
	normalizedPath := stripVersionPrefix(cleanedPath)

	var versionPrefix string
	if normalizedPath != cleanedPath && strings.HasSuffix(cleanedPath, normalizedPath) {
		versionPrefix = strings.TrimSuffix(cleanedPath, normalizedPath)
	}

	switch {
	case strings.HasPrefix(normalizedPath, "/secrets/"):
		return versionPrefix + "/secrets/<redacted>"
	case normalizedPath == "/swarm/unlockkey":
		return versionPrefix + "/swarm/<redacted>"
	default:
		return requestPath
	}
}
