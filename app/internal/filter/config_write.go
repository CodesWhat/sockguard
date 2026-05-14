package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxConfigWriteBodyBytes = 1 << 20 // 1 MiB

// ConfigOptions configures request-body policy checks for POST /configs/create.
type ConfigOptions struct {
	AllowCustomDrivers   bool
	AllowTemplateDrivers bool
}

type configPolicy struct {
	allowCustomDrivers   bool
	allowTemplateDrivers bool
}

type configRequest struct {
	Driver         string `json:"Driver"`
	TemplateDriver string `json:"TemplateDriver"`
	Templating     struct {
		Name string `json:"Name"`
	} `json:"Templating"`
}

func newConfigPolicy(opts ConfigOptions) configPolicy {
	return configPolicy{
		allowCustomDrivers:   opts.AllowCustomDrivers,
		allowTemplateDrivers: opts.AllowTemplateDrivers,
	}
}

func (p configPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/configs/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxConfigWriteBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("config create denied: request body exceeds %d byte limit", maxConfigWriteBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req configRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "config create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "config create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !p.allowCustomDrivers {
		return fmt.Sprintf("config create denied: driver %q is not allowed", driver), nil
	}

	templateDriver := strings.TrimSpace(req.TemplateDriver)
	if templateDriver == "" {
		templateDriver = strings.TrimSpace(req.Templating.Name)
	}
	if templateDriver != "" && !p.allowTemplateDrivers {
		return fmt.Sprintf("config create denied: template driver %q is not allowed", templateDriver), nil
	}

	return "", nil
}
