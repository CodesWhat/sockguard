package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const maxConfigWriteBodyBytes = 1 << 20 // 1 MiB

// ConfigWriteOptions configures request-body policy checks for POST /configs/create.
type ConfigWriteOptions struct {
	AllowCustomDrivers   bool
	AllowTemplateDrivers bool
}

type configWritePolicy struct {
	allowCustomDrivers   bool
	allowTemplateDrivers bool
}

type configWriteRequest struct {
	Driver         string `json:"Driver"`
	TemplateDriver string `json:"TemplateDriver"`
	Templating     struct {
		Name string `json:"Name"`
	} `json:"Templating"`
}

func newConfigWritePolicy(opts ConfigWriteOptions) configWritePolicy {
	return configWritePolicy{
		allowCustomDrivers:   opts.AllowCustomDrivers,
		allowTemplateDrivers: opts.AllowTemplateDrivers,
	}
}

func (p configWritePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/configs/create" || r.Body == nil {
		return "", nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigWriteBodyBytes+1))
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxConfigWriteBodyBytes {
		return fmt.Sprintf("config create denied: request body exceeds %d byte limit", maxConfigWriteBodyBytes), nil
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	if len(body) == 0 {
		return "", nil
	}

	var req configWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "config create request body is not valid JSON; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
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
