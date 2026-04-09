package filter

import (
	"log/slog"
	"net/http"

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

type DenyResponseVerbosity string

const (
	DenyResponseVerbosityVerbose DenyResponseVerbosity = "verbose"
	DenyResponseVerbosityMinimal DenyResponseVerbosity = "minimal"
)

// Options configures filter middleware behavior.
type Options struct {
	DenyResponseVerbosity DenyResponseVerbosity
}

func (o Options) normalized() Options {
	if o.DenyResponseVerbosity == "" {
		o.DenyResponseVerbosity = DenyResponseVerbosityVerbose
	}
	return o
}

// Middleware returns HTTP middleware that evaluates each request against compiled rules.
// Denied requests get a 403 JSON response. Allowed requests pass through to next.
// Decision metadata is written to the RequestMeta in context for the access logger.
func Middleware(rules []*CompiledRule, logger *slog.Logger) func(http.Handler) http.Handler {
	return MiddlewareWithOptions(rules, logger, Options{})
}

// MiddlewareWithOptions returns HTTP middleware that evaluates each request
// against compiled rules and allows deny response detail to be configured.
func MiddlewareWithOptions(rules []*CompiledRule, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	opts = opts.normalized()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			normPath := NormalizePath(r.URL.Path)
			action, ruleIndex, reason := evaluateNormalized(rules, r.Method, normPath)

			// Write decision to shared RequestMeta (created by access log middleware)
			if m := logging.Meta(r.Context()); m != nil {
				m.Decision = string(action)
				m.Rule = ruleIndex
				m.Reason = reason
				m.NormPath = normPath
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
	resp.Path = r.URL.Path
	resp.Reason = reason
	return resp
}
