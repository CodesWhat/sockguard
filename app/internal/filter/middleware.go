package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/internal/logging"
)

// DenialResponse is the JSON body returned when a request is denied.
type DenialResponse struct {
	Message string `json:"message"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Reason  string `json:"reason,omitempty"`
}

// Middleware returns HTTP middleware that evaluates each request against compiled rules.
// Denied requests get a 403 JSON response. Allowed requests pass through to next.
// Decision metadata is written to the RequestMeta in context for the access logger.
func Middleware(rules []*CompiledRule, logger *slog.Logger) func(http.Handler) http.Handler {
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
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				if err := json.NewEncoder(w).Encode(DenialResponse{
					Message: "request denied by sockguard policy",
					Method:  r.Method,
					Path:    r.URL.Path,
					Reason:  reason,
				}); err != nil {
					logger.ErrorContext(r.Context(), "failed to encode denial response", "error", err, "method", r.Method, "path", r.URL.Path)
					// Fallback: attempt plaintext response since JSON encoding failed
					fmt.Fprintf(w, "request denied by sockguard policy: %s %s", r.Method, r.URL.Path)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
