package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const driverCreateMaxBodyBytes = 1 << 20 // 1 MiB

// ConfigOptions configures request-body policy checks for POST /configs/create.
type ConfigOptions struct {
	AllowCustomDrivers   bool
	AllowTemplateDrivers bool
}

// SecretOptions configures request-body policy checks for POST /secrets/create.
type SecretOptions struct {
	AllowCustomDrivers   bool
	AllowTemplateDrivers bool
}

func newConfigPolicy(opts ConfigOptions) driverCreatePolicy {
	return driverCreatePolicy{
		kind:                 "config",
		path:                 "/configs/create",
		maxBodyBytes:         driverCreateMaxBodyBytes,
		allowCustomDrivers:   opts.AllowCustomDrivers,
		allowTemplateDrivers: opts.AllowTemplateDrivers,
	}
}

func newSecretPolicy(opts SecretOptions) driverCreatePolicy {
	return driverCreatePolicy{
		kind:                 "secret",
		path:                 "/secrets/create",
		maxBodyBytes:         driverCreateMaxBodyBytes,
		allowCustomDrivers:   opts.AllowCustomDrivers,
		allowTemplateDrivers: opts.AllowTemplateDrivers,
	}
}

// driverCreatePolicy backs POST /configs/create and POST /secrets/create.
// Both endpoints share the same JSON shape and the same driver / template
// driver allow-list semantics — only the kind label, target path, and size
// cap differ. Keeping one inspect implementation prevents the two policies
// from drifting apart.
type driverCreatePolicy struct {
	kind                 string
	path                 string
	maxBodyBytes         int64
	allowCustomDrivers   bool
	allowTemplateDrivers bool
}

type driverCreateRequest struct {
	Driver         string `json:"Driver"`
	TemplateDriver string `json:"TemplateDriver"`
	Templating     struct {
		Name string `json:"Name"`
	} `json:"Templating"`
}

func (p driverCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != p.path || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, p.maxBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s create denied: request body exceeds %d byte limit", p.kind, p.maxBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req driverCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), fmt.Sprintf("%s create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", p.kind), "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return fmt.Sprintf("%s create denied: request body could not be inspected", p.kind), nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !p.allowCustomDrivers {
		return fmt.Sprintf("%s create denied: driver %q is not allowed", p.kind, driver), nil
	}

	templateDriver := strings.TrimSpace(req.TemplateDriver)
	if templateDriver == "" {
		templateDriver = strings.TrimSpace(req.Templating.Name)
	}
	if templateDriver != "" && !p.allowTemplateDrivers {
		return fmt.Sprintf("%s create denied: template driver %q is not allowed", p.kind, templateDriver), nil
	}

	return "", nil
}
