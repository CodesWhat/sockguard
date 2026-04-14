package filter

import (
	"log/slog"
	"net/http"
	"path"
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

// Options configures filter middleware behavior.
type Options struct {
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
	// Profiles defines named per-client policy overrides selected at request time.
	Profiles map[string]Policy
	// ResolveProfile returns the named policy to apply for the request.
	ResolveProfile func(*http.Request) (string, bool)
}

// Policy defines a named request policy profile that can override the global
// rules and request-body inspection options for a single request.
type Policy struct {
	Rules                 []*CompiledRule
	DenyResponseVerbosity DenyResponseVerbosity
	ContainerCreate       ContainerCreateOptions
	Exec                  ExecOptions
	ImagePull             ImagePullOptions
	Build                 BuildOptions
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

func (o Options) normalized() Options {
	o.DenyResponseVerbosity = ParseDenyResponseVerbosity(string(o.DenyResponseVerbosity))
	return o
}

type runtimePolicy struct {
	rules                 []*CompiledRule
	denyResponseVerbosity DenyResponseVerbosity
	containerCreatePolicy containerCreatePolicy
	execPolicy            execPolicy
	imagePullPolicy       imagePullPolicy
	buildPolicy           buildPolicy
}

// Middleware is the stable convenience API for callers that want filter middleware
// with default options. Use MiddlewareWithOptions only when overriding deny
// response behavior.
//
// Denied requests get a 403 JSON response. Allowed requests pass through to next.
// Decision metadata is written to the access log RequestMeta when present.
func Middleware(rules []*CompiledRule, logger *slog.Logger) func(http.Handler) http.Handler {
	return MiddlewareWithOptions(rules, logger, Options{})
}

// MiddlewareWithOptions returns HTTP middleware that evaluates each request
// against compiled rules and allows deny response detail to be configured.
func MiddlewareWithOptions(rules []*CompiledRule, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	opts = opts.normalized()
	defaultPolicy := compileRuntimePolicy(rules, opts)
	profilePolicies := make(map[string]runtimePolicy, len(opts.Profiles))
	for name, profile := range opts.Profiles {
		profilePolicies[name] = compileRuntimePolicy(profile.Rules, Options{
			DenyResponseVerbosity: profile.DenyResponseVerbosity,
			ContainerCreate:       profile.ContainerCreate,
			Exec:                  profile.Exec,
			ImagePull:             profile.ImagePull,
			Build:                 profile.Build,
		})
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
						denyWithReason(w, r, logger, "client policy profile could not be resolved", activePolicy.denyResponseVerbosity)
						return
					}
					activePolicy = profile
				}
			}

			normPath := NormalizePath(r.URL.Path)
			action, ruleIndex, reason := evaluateNormalized(activePolicy.rules, r.Method, normPath)

			// Write decision to shared RequestMeta (created by access log middleware).
			if m := logging.MetaForRequest(w, r); m != nil {
				m.Decision = string(action)
				m.Rule = ruleIndex
				m.Reason = reason
				m.NormPath = normPath
			}

			if action == ActionAllow {
				denyReason, err := activePolicy.containerCreatePolicy.inspect(r, normPath)
				if err != nil {
					logger.ErrorContext(r.Context(), "failed to inspect container create request body", "error", err, "method", r.Method, "path", r.URL.Path)
					denyReason = "unable to inspect container create request body"
				}
				if denyReason == "" {
					denyReason, err = activePolicy.execPolicy.inspect(r, normPath)
					if err != nil {
						logger.ErrorContext(r.Context(), "failed to inspect exec request body", "error", err, "method", r.Method, "path", r.URL.Path)
						denyReason = "unable to inspect exec request body"
					}
				}
				if denyReason == "" {
					denyReason, err = activePolicy.imagePullPolicy.inspect(r, normPath)
					if err != nil {
						logger.ErrorContext(r.Context(), "failed to inspect image pull request", "error", err, "method", r.Method, "path", r.URL.Path)
						denyReason = "unable to inspect image pull request"
					}
				}
				if denyReason == "" {
					denyReason, err = activePolicy.buildPolicy.inspect(r, normPath)
					if err != nil {
						logger.ErrorContext(r.Context(), "failed to inspect build request", "error", err, "method", r.Method, "path", r.URL.Path)
						denyReason = "unable to inspect build request"
					}
				}
				if denyReason != "" {
					action = ActionDeny
					reason = denyReason
					if m := logging.MetaForRequest(w, r); m != nil {
						m.Decision = string(action)
						m.Reason = reason
					}
				}
			}

			if action == ActionDeny {
				if err := httpjson.Write(w, http.StatusForbidden, denyResponse(r, reason, activePolicy.denyResponseVerbosity)); err != nil {
					logger.ErrorContext(r.Context(), "failed to encode denial response", "error", err, "method", r.Method, "path", r.URL.Path)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func compileRuntimePolicy(rules []*CompiledRule, opts Options) runtimePolicy {
	opts = opts.normalized()
	return runtimePolicy{
		rules:                 rules,
		denyResponseVerbosity: opts.DenyResponseVerbosity,
		containerCreatePolicy: newContainerCreatePolicy(opts.ContainerCreate),
		execPolicy:            newExecPolicy(opts.Exec),
		imagePullPolicy:       newImagePullPolicy(opts.ImagePull),
		buildPolicy:           newBuildPolicy(opts.Build),
	}
}

func denyWithReason(w http.ResponseWriter, r *http.Request, logger *slog.Logger, reason string, verbosity DenyResponseVerbosity) {
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.Decision = string(ActionDeny)
		meta.Reason = reason
		if meta.NormPath == "" {
			meta.NormPath = NormalizePath(r.URL.Path)
		}
	}
	if err := httpjson.Write(w, http.StatusForbidden, denyResponse(r, reason, verbosity)); err != nil {
		logger.ErrorContext(r.Context(), "failed to encode denial response", "error", err, "method", r.Method, "path", r.URL.Path)
	}
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

	cleanedPath := path.Clean(requestPath)
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
