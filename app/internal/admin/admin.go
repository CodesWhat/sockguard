// Package admin implements sockguard's in-band admin HTTP endpoints.
//
// At v0.8.0 the admin surface is a single endpoint:
//
//	POST <path>   parse + validate + compile a candidate YAML config and
//	              return a structured JSON report; running policy is
//	              unaffected.
//
// The endpoint is opt-in (admin.enabled=false by default) and rides the main
// listener, so it inherits the listener's CIDR allowlist, mTLS posture, and
// the per-profile rate-limit / concurrency gates configured under
// clients.profiles[*].limits. Wire-up in internal/cmd/serve.go places this
// interceptor between the rate-limit middleware and the filter middleware so
// admin requests are rate-limited like every other caller but never reach the
// Docker-API rule evaluator.
package admin

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

// ValidateResponse is the JSON body returned by the validate endpoint.
//
// On success: OK=true, Rules is the number of top-level compiled rules,
// Profiles is the number of compiled client profiles, CompatActive is true
// when Tecnativa-compat env aliases injected rules. Errors is nil.
//
// On validation failure: OK=false and Errors carries the human-readable
// validator output split per-issue. Rules / Profiles are zero.
type ValidateResponse struct {
	OK           bool     `json:"ok"`
	Errors       []string `json:"errors,omitempty"`
	Rules        int      `json:"rules,omitempty"`
	Profiles     int      `json:"profiles,omitempty"`
	CompatActive bool     `json:"compat_active,omitempty"`
}

// Validator is the callback wired up by internal/cmd that knows how to parse
// YAML bytes, run config.Validate + rule compilation, and report the result.
// Keeping the validator pluggable avoids an import cycle on internal/cmd while
// still letting this package own the HTTP surface.
type Validator func(yaml []byte) ValidateResponse

// Options configures Interceptor.
//
// Path must start with "/". MaxBodyBytes caps the request body to prevent
// abusive callers from forcing sockguard to parse arbitrarily large YAML.
// Validate is required.
type Options struct {
	Path         string
	MaxBodyBytes int64
	Validate     Validator
	Logger       *slog.Logger
}

// NewValidateInterceptor returns a middleware that short-circuits POST <path>
// to the configured validator. All other requests pass through to next.
//
// Method gating: anything other than POST on <path> returns 405 with
// Allow: POST. The body is hard-capped at MaxBodyBytes via
// http.MaxBytesReader; oversize bodies return 413. YAML parse / validation
// failures return 422 with a structured ValidateResponse.
func NewValidateInterceptor(opts Options) func(http.Handler) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 524288
	}
	if opts.Validate == nil {
		// A nil validator is a programmer error; fail closed at construction
		// time would be ideal, but the existing layer plumbing returns a
		// middleware unconditionally — so degrade safely to a 503 instead.
		return serviceUnavailableMiddleware("admin validator not configured", opts.Logger)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != opts.Path {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodPost {
				logging.SetDeniedWithCode(w, r, "admin_method_not_allowed", "POST required", nil)
				w.Header().Set("Allow", http.MethodPost)
				_ = httpjson.Write(w, http.StatusMethodNotAllowed, httpjson.ErrorResponse{Message: "method not allowed"})
				return
			}
			handlePOST(w, r, opts)
		})
	}
}

func handlePOST(w http.ResponseWriter, r *http.Request, opts Options) {
	// MaxBytesReader returns http.MaxBytesError on overflow, which we surface as 413.
	limited := http.MaxBytesReader(w, r.Body, opts.MaxBodyBytes)
	defer func() { _ = limited.Close() }()

	body, err := io.ReadAll(limited)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			logging.SetDeniedWithCode(w, r, "admin_body_too_large", "request body exceeds admin.max_body_bytes", nil)
			_ = httpjson.Write(w, http.StatusRequestEntityTooLarge, httpjson.ErrorResponse{
				Message: "request body exceeds admin.max_body_bytes",
			})
			return
		}
		opts.Logger.WarnContext(r.Context(), "admin validate: failed to read body", "error", err)
		_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{
			Message: "failed to read request body",
		})
		return
	}

	result := opts.Validate(body)
	status := http.StatusOK
	if !result.OK {
		status = http.StatusUnprocessableEntity
		logging.SetDeniedWithCode(w, r, "admin_validation_failed", "candidate config failed validation", nil)
	}
	if encErr := httpjson.Write(w, status, result); encErr != nil {
		opts.Logger.WarnContext(r.Context(), "admin validate: failed to encode response", "error", encErr)
	}
}

func serviceUnavailableMiddleware(reason string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.ErrorContext(r.Context(), "admin endpoint misconfigured", "reason", reason)
			_ = httpjson.Write(w, http.StatusServiceUnavailable, httpjson.ErrorResponse{Message: reason})
		})
	}
}
