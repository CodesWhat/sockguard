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

// driverCreateRequest reads Driver as the object both engines decode, Name
// and Options (moby 28.5.1 api/types/swarm SecretSpec.Driver, a *Driver;
// Podman 5.8.6 pkg/domain/entities SecretCreateRequest.Driver, a
// SecretDriverSpec). dockerd hands Options to the secrets plugin Name picks,
// and Podman's compat handler passes on Name only. Any option is refused
// without allow_custom_drivers either way, the rule the libpod route applies
// to driveropts. A driver name is always custom here, `file` included,
// because dockerd resolves every name as a plugin and the Docker CLI omits
// Driver for the built-in store, which on Podman picks the file default.
type driverCreateRequest struct {
	Driver struct {
		Name    string            `json:"Name"`
		Options map[string]string `json:"Options"`
	} `json:"Driver"`
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
		logRequestError(logger, r, slog.LevelDebug, fmt.Sprintf("%s create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", p.kind), err)
		return fmt.Sprintf("%s create denied: request body could not be inspected", p.kind), nil
	}

	if driver := strings.TrimSpace(req.Driver.Name); driver != "" && !p.allowCustomDrivers {
		return fmt.Sprintf("%s create denied: driver %q is not allowed", p.kind, driver), nil
	}
	if len(req.Driver.Options) > 0 && !p.allowCustomDrivers {
		return fmt.Sprintf("%s create denied: driver options are not allowed", p.kind), nil
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
