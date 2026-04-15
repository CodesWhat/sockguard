package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxSecretBodyBytes = 1 << 20 // 1 MiB

// SecretOptions configures request-body policy checks for POST /secrets/create.
type SecretOptions struct {
	AllowCustomDrivers   bool
	AllowTemplateDrivers bool
}

type secretPolicy struct {
	allowCustomDrivers   bool
	allowTemplateDrivers bool
}

type secretCreateRequest struct {
	Driver         string `json:"Driver"`
	TemplateDriver string `json:"TemplateDriver"`
	Templating     struct {
		Name string `json:"Name"`
	} `json:"Templating"`
}

func newSecretPolicy(opts SecretOptions) secretPolicy {
	return secretPolicy{
		allowCustomDrivers:   opts.AllowCustomDrivers,
		allowTemplateDrivers: opts.AllowTemplateDrivers,
	}
}

func (p secretPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/secrets/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxSecretBodyBytes)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxSecretBodyBytes {
		return fmt.Sprintf("secret create denied: request body exceeds %d byte limit", maxSecretBodyBytes), nil
	}

	if len(body) == 0 {
		return "", nil
	}

	var req secretCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "secret create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !p.allowCustomDrivers {
		return fmt.Sprintf("secret create denied: driver %q is not allowed", driver), nil
	}

	templateDriver := strings.TrimSpace(req.TemplateDriver)
	if templateDriver == "" {
		templateDriver = strings.TrimSpace(req.Templating.Name)
	}
	if templateDriver != "" && !p.allowTemplateDrivers {
		return fmt.Sprintf("secret create denied: template driver %q is not allowed", templateDriver), nil
	}

	return "", nil
}
