package admin

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

type PolicyDiffResponse struct {
	OK              bool                  `json:"ok"`
	BaseVersion     int64                 `json:"base_version,omitempty"`
	Changed         bool                  `json:"changed"`
	Changes         []config.PolicyChange `json:"changes"`
	UnknownKeys     int                   `json:"unknown_keys,omitempty"`
	Validation      string                `json:"validation,omitempty"`
	RestartRequired bool                  `json:"restart_required"`
	Error           string                `json:"error,omitempty"`
}

type PolicyDiffOptions struct {
	Path            string
	MaxRequestBytes int64
	Source          func() *PolicySnapshot
	Compare         func([]byte, *PolicySnapshot) PolicyDiffResponse
	Logger          *slog.Logger
}

// NewPolicyDiffInterceptor compares a bounded body against one generation.
func NewPolicyDiffInterceptor(opts PolicyDiffOptions) func(http.Handler) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = 524288
	}
	if opts.Source == nil || opts.Compare == nil {
		return serviceUnavailableMiddleware(opts.Path, "admin policy comparison not configured", opts.Logger)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !matchesAdminPath(r.URL.Path, opts.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				logging.SetDeniedWithCode(w, r, "admin_method_not_allowed", "POST required", nil)
				_ = httpjson.Write(w, http.StatusMethodNotAllowed, httpjson.ErrorResponse{Message: "method not allowed"})
				return
			}
			snapshot := opts.Source()
			if snapshot == nil || snapshot.Config == nil {
				_ = httpjson.Write(w, http.StatusServiceUnavailable, httpjson.ErrorResponse{Message: "active policy unavailable"})
				return
			}
			body := http.MaxBytesReader(w, r.Body, opts.MaxRequestBytes)
			defer func() { _ = body.Close() }()
			data, err := io.ReadAll(body)
			if err != nil {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					_ = httpjson.Write(w, http.StatusRequestEntityTooLarge, httpjson.ErrorResponse{Message: "request body exceeds admin.max_request_bytes"})
				} else {
					_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: "failed to read request body"})
				}
				return
			}
			result := opts.Compare(data, snapshot)
			status := http.StatusOK
			if !result.OK {
				status = http.StatusUnprocessableEntity
				logging.SetDeniedWithCode(w, r, "admin_validation_failed", "candidate config failed validation", nil)
			}
			if err := httpjson.Write(w, status, result); err != nil {
				opts.Logger.WarnContext(r.Context(), "admin policy diff: failed to encode response")
			}
		})
	}
}
