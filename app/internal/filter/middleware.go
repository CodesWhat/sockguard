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
	containerCreatePolicy := newContainerCreatePolicy(opts.ContainerCreate)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			normPath := NormalizePath(r.URL.Path)
			action, ruleIndex, reason := evaluateNormalized(rules, r.Method, normPath)

			// Write decision to shared RequestMeta (created by access log middleware).
			if m := logging.MetaForRequest(w, r); m != nil {
				m.Decision = string(action)
				m.Rule = ruleIndex
				m.Reason = reason
				m.NormPath = normPath
			}

			if action == ActionAllow {
				denyReason, err := containerCreatePolicy.inspect(r, normPath)
				if err != nil {
					logger.ErrorContext(r.Context(), "failed to inspect container create request body", "error", err, "method", r.Method, "path", r.URL.Path)
					denyReason = "unable to inspect container create request body"
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
				if err := httpjson.Write(w, http.StatusForbidden, denyResponse(r, reason, opts)); err != nil {
					logger.ErrorContext(r.Context(), "failed to encode denial response", "error", err, "method", r.Method, "path", r.URL.Path)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func denyResponse(r *http.Request, reason string, opts Options) DenialResponse {
	resp := DenialResponse{
		Message: "request denied by sockguard policy",
	}
	if opts.DenyResponseVerbosity == DenyResponseVerbosityMinimal {
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
