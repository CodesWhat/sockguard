package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/queryparam"
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

// inspect applies allow_custom_drivers to the `driver` query parameter.
// libpod.CreateSecret decodes it with gorilla/schema, which matches the key in
// any letter case and keeps the last value, so `?Driver=shell` and
// `?driver=&driver=shell` both store the secret with the shell driver while
// the first value of the exact key reads as no driver at all. The parameter is
// read through queryparam, which refuses both shapes. Read from Podman 5.8.6
// (pkg/api/handlers/libpod/secrets.go).
func (p libpodSecretPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"secrets/create" {
		return "", nil
	}
	if p.allowCustomDrivers {
		return "", nil
	}

	driver, _, ok := queryparam.Scalar(logging.RequestQuery(r), "driver")
	if !ok {
		return ambiguousQueryReason("libpod secret create", "driver"), nil
	}
	if driver = strings.TrimSpace(driver); driver != "" {
		return fmt.Sprintf("libpod secret create denied: driver %q is not allowed", driver), nil
	}

	return "", nil
}
