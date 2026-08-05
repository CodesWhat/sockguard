package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// libpodSecretPolicy backs POST /libpod/secrets/create. Unlike Docker's
// /secrets/create (driver/template driver read from a JSON body,
// driver_create.go), libpod's secret-create driver/driveropts/labels are URL
// QUERY parameters (pkg/bindings/secrets.CreateOptions.ToParams, pinned to
// Podman v5.8.1 — confirmed directly against upstream source per the design
// doc's C4 requirement); the request BODY is the raw secret payload bytes
// handed straight to the secret driver, not a JSON envelope. This inspector
// therefore never reads r.Body: doing so would needlessly buffer arbitrary
// (and possibly large/binary) secret material into memory for a field that
// was never there to inspect. There is no libpod analog of Docker's
// Templating/TemplateDriver secret field — Podman secrets have no template
// driver concept — so SecretOptions.AllowTemplateDrivers is a no-op here,
// documented in configuration.mdx's libpod_secret section.
type libpodSecretPolicy struct {
	allowCustomDrivers bool
}

func newLibpodSecretPolicy(opts SecretOptions) libpodSecretPolicy {
	return libpodSecretPolicy{allowCustomDrivers: opts.AllowCustomDrivers}
}

func (p libpodSecretPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"secrets/create" {
		return "", nil
	}

	if driver := strings.TrimSpace(r.URL.Query().Get("driver")); driver != "" && !p.allowCustomDrivers {
		return fmt.Sprintf("libpod secret create denied: driver %q is not allowed", driver), nil
	}

	return "", nil
}
