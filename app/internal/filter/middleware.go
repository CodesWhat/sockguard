package filter

import (
	"fmt"
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
	// ContainerUpdate configures request-body inspection for
	// POST /containers/*/update.
	ContainerUpdate ContainerUpdateOptions
	// ContainerArchive configures request-body inspection for
	// PUT /containers/*/archive.
	ContainerArchive ContainerArchiveOptions
	// ImageLoad configures request-body inspection for POST /images/load.
	ImageLoad ImageLoadOptions
	// Volume configures request-body inspection for POST /volumes/create.
	Volume VolumeOptions
	// Network configures request-body inspection for network writes.
	Network NetworkOptions
	// Secret configures request-body inspection for POST /secrets/create.
	Secret SecretOptions
	// Config configures request-body inspection for POST /configs/create.
	Config ConfigOptions
	// Service configures request-body inspection for service create/update.
	Service ServiceOptions
	// Swarm configures request-body inspection for swarm writes.
	Swarm SwarmOptions
	// Node configures request-body inspection for node update.
	Node NodeOptions
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
	rules                    []*CompiledRule
	denyResponseVerbosity    DenyResponseVerbosity
	inspectPoliciesByMethod  map[string][]requestInspectPolicy
}

type inspectSeverity int

const (
	inspectSeverityMedium inspectSeverity = iota
	inspectSeverityHigh
	inspectSeverityCritical
)

// Compile-time assertion: the bucket walk in inspectAllowedRequest descends
// from len(buckets)-1 to 0, so index order must match ascending severity.
// If the iota block is reordered (e.g. a new severityLow inserted before
// Medium), this assignment fails to compile because the array size becomes 0.
var _ [1]struct{} = [inspectSeverityCritical - inspectSeverityHigh]struct{}{}
var _ [1]struct{} = [inspectSeverityHigh - inspectSeverityMedium]struct{}{}

type requestInspectPolicy struct {
	method            string
	matches           func(string) bool
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

			var normPath string
			if m := logging.MetaForRequest(w, r); m != nil && m.NormPath != "" {
				normPath = m.NormPath
			} else {
				normPath = NormalizePath(r.URL.Path)
			}
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
				meta := logging.MetaForRequest(w, r)
				if meta.AllowsPassThrough() {
					meta.Decision = logging.DecisionWouldDeny
					next.ServeHTTP(w, r)
					return
				}
				if err := httpjson.Write(w, denyStatus, denyResponse(r, reason, activePolicy.denyResponseVerbosity)); err != nil {
					logger.ErrorContext(r.Context(), "failed to encode denial response", "error", err, "method", r.Method, "path", r.URL.Path)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// adaptNoLogger wraps an inspect func that has no logger parameter into the
// standard (*slog.Logger, *http.Request, string) → (string, error) signature.
func adaptNoLogger(fn func(*http.Request, string) (string, error)) func(*slog.Logger, *http.Request, string) (string, error) {
	return func(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
		return fn(r, normalizedPath)
	}
}

func compileRuntimePolicy(rules []*CompiledRule, cfg PolicyConfig) runtimePolicy {
	cfg = cfg.normalized()
	all := []requestInspectPolicy{
		{http.MethodPost, matchesContainerCreateInspection, inspectSeverityCritical, newContainerCreatePolicy(cfg.ContainerCreate).inspect, "failed to inspect container create request body", "unable to inspect container create request body"},
		{http.MethodPost, matchesExecInspection, inspectSeverityHigh, newExecPolicy(cfg.Exec).inspect, "failed to inspect exec request body", "unable to inspect exec request body"},
		{http.MethodPost, matchesImagePullInspection, inspectSeverityHigh, adaptNoLogger(newImagePullPolicy(cfg.ImagePull).inspect), "failed to inspect image pull request", "unable to inspect image pull request"},
		{http.MethodPost, matchesBuildInspection, inspectSeverityCritical, adaptNoLogger(newBuildPolicy(cfg.Build).inspect), "failed to inspect build request", "unable to inspect build request"},
		{http.MethodPost, matchesContainerUpdateInspection, inspectSeverityHigh, newContainerUpdatePolicy(cfg.ContainerUpdate).inspect, "failed to inspect container update request body", "unable to inspect container update request body"},
		{http.MethodPut, matchesContainerArchiveInspection, inspectSeverityHigh, newContainerArchivePolicy(cfg.ContainerArchive).inspect, "failed to inspect container archive request body", "unable to inspect container archive request body"},
		{http.MethodPost, matchesImageLoadInspection, inspectSeverityHigh, newImageLoadPolicy(cfg.ImageLoad).inspect, "failed to inspect image load request body", "unable to inspect image load request body"},
		{http.MethodPost, matchesVolumeInspection, inspectSeverityMedium, newVolumePolicy(cfg.Volume).inspect, "failed to inspect volume create request body", "unable to inspect volume create request body"},
		{http.MethodPost, matchesNetworkInspection, inspectSeverityHigh, newNetworkPolicy(cfg.Network).inspect, "failed to inspect network request body", "unable to inspect network request body"},
		{http.MethodPost, matchesSecretInspection, inspectSeverityMedium, newSecretPolicy(cfg.Secret).inspect, "failed to inspect secret create request body", "unable to inspect secret create request body"},
		{http.MethodPost, matchesConfigInspection, inspectSeverityMedium, newConfigPolicy(cfg.Config).inspect, "failed to inspect config create request body", "unable to inspect config create request body"},
		{http.MethodPost, matchesServiceInspection, inspectSeverityCritical, newServicePolicy(cfg.Service).inspect, "failed to inspect service request body", "unable to inspect service request body"},
		{http.MethodPost, matchesSwarmInspection, inspectSeverityCritical, newSwarmPolicy(cfg.Swarm).inspect, "failed to inspect swarm request body", "unable to inspect swarm request body"},
		{http.MethodPost, matchesNodeInspection, inspectSeverityHigh, newNodePolicy(cfg.Node).inspect, "failed to inspect node update request body", "unable to inspect node update request body"},
		{http.MethodPost, matchesPluginInspection, inspectSeverityCritical, newPluginPolicy(cfg.Plugin).inspect, "failed to inspect plugin request body", "unable to inspect plugin request body"},
	}
	byMethod := make(map[string][]requestInspectPolicy, 2)
	for _, p := range all {
		byMethod[p.method] = append(byMethod[p.method], p)
	}
	// Fail loud if any (method, severity) group would overflow the fixed
	// inspectBuckets array at request time. The bucket walk silently drops
	// overflow entries, which would disable enforcement for the dropped
	// inspectors — a future contributor adding a 17th POST/critical policy
	// must bump inspectBucketCapacity rather than let that happen quietly.
	for method, ps := range byMethod {
		var sevCounts [3]int
		for _, p := range ps {
			sevCounts[int(p.severity)]++
		}
		for sev, n := range sevCounts {
			if n > inspectBucketCapacity {
				panic(fmt.Sprintf("filter: inspectBuckets capacity %d exceeded for method %s severity %d: %d policies", inspectBucketCapacity, method, sev, n))
			}
		}
	}
	return runtimePolicy{
		rules:                   rules,
		denyResponseVerbosity:   cfg.DenyResponseVerbosity,
		inspectPoliciesByMethod: byMethod,
	}
}

func matchesContainerCreateInspection(normalizedPath string) bool {
	return normalizedPath == "/containers/create"
}

func matchesExecInspection(normalizedPath string) bool {
	return isExecCreatePath(normalizedPath) || isExecStartPath(normalizedPath)
}

func matchesImagePullInspection(normalizedPath string) bool {
	return normalizedPath == "/images/create"
}

func matchesBuildInspection(normalizedPath string) bool {
	return normalizedPath == "/build"
}

func matchesContainerUpdateInspection(normalizedPath string) bool {
	return isContainerUpdatePath(normalizedPath)
}

func matchesContainerArchiveInspection(normalizedPath string) bool {
	return isContainerArchivePath(normalizedPath)
}

func matchesImageLoadInspection(normalizedPath string) bool {
	return normalizedPath == "/images/load"
}

func matchesVolumeInspection(normalizedPath string) bool {
	return normalizedPath == "/volumes/create"
}

func matchesNetworkInspection(normalizedPath string) bool {
	return isNetworkWritePath(normalizedPath)
}

func matchesSecretInspection(normalizedPath string) bool {
	return normalizedPath == "/secrets/create"
}

func matchesConfigInspection(normalizedPath string) bool {
	return normalizedPath == "/configs/create"
}

func matchesServiceInspection(normalizedPath string) bool {
	return isServiceWritePath(normalizedPath)
}

func matchesSwarmInspection(normalizedPath string) bool {
	switch normalizedPath {
	case "/swarm/init", "/swarm/join", "/swarm/update", "/swarm/unlock":
		return true
	default:
		return false
	}
}

func matchesNodeInspection(normalizedPath string) bool {
	return isNodeUpdatePath(normalizedPath)
}

func matchesPluginInspection(normalizedPath string) bool {
	return normalizedPath == "/plugins/pull" || normalizedPath == "/plugins/create" || isPluginUpgradePath(normalizedPath) || isPluginSetPath(normalizedPath)
}

// inspectBucketCapacity bounds how many policies of a single severity may
// match the same method in inspectAllowedRequest. Sized to comfortably hold
// the current static policy list with headroom; if a future contributor adds
// inspectors past this cap, compileRuntimePolicy panics at startup so the
// overflow is loud rather than silent.
const inspectBucketCapacity = 16

// inspectBuckets holds matched policies grouped by severity for zero-alloc
// single-pass triage in inspectAllowedRequest. The array is stack-allocated
// because [3][16] fits on the frame and the slice backing p.inspectPolicies
// caps out at ~15 entries.
type inspectBuckets [3][inspectBucketCapacity]*requestInspectPolicy

func (p runtimePolicy) inspectAllowedRequest(logger *slog.Logger, r *http.Request, normalizedPath string) (string, string, int) {
	var buckets inspectBuckets
	var counts [3]int

	for i := range p.inspectPoliciesByMethod[r.Method] {
		policy := &p.inspectPoliciesByMethod[r.Method][i]
		if policy.matches != nil && !policy.matches(normalizedPath) {
			continue
		}
		sev := int(policy.severity)
		if counts[sev] < len(buckets[sev]) {
			buckets[sev][counts[sev]] = policy
			counts[sev]++
		}
	}

	// Walk severity buckets from highest to lowest; run inspect on the first
	// non-empty bucket only.
	for sev := len(buckets) - 1; sev >= 0; sev-- {
		if counts[sev] == 0 {
			continue
		}
		for _, policy := range buckets[sev][:counts[sev]] {
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
		if reason == ReasonNoMatchingAllowRule {
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
