package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/queryparam"
)

// libpodDefaultSecretDriver is the secret driver containers.conf names by
// default (go.podman.io/common v0.67.1 pkg/config/default.go,
// defaultSecretConfig). podman-remote sends it as `driver` on every create,
// because the CLI's --driver flag defaults to the containers.conf value.
const libpodDefaultSecretDriver = "file"

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

// inspect applies allow_custom_drivers to the `driver` and `driveropts`
// query parameters. Read from Podman 5.8.6 (pkg/api/handlers/libpod/secrets.go
// and pkg/domain/infra/abi/secrets.go) and go.podman.io/common v0.67.1
// (pkg/secrets/secrets.go).
//
// An empty driver and `file` both pass: abi.SecretCreate fills an empty one
// with the containers.conf default, which is `file`. Any other name is a
// custom driver.
//
// `driveropts` is a JSON object handed to whichever driver ends up storing
// the secret, the default included. The file driver's `path` option is the
// directory on the daemon host the secret data is written to, created if it
// doesn't exist, and with a shell driver configured as the default the
// options are the commands it runs. Choosing either is the same step as
// choosing a driver, so any option needs allow_custom_drivers too. An empty
// value, `{}` and `null` carry no option and leave the daemon's configured
// ones in place.
//
// libpod.CreateSecret decodes both parameters with gorilla/schema, which
// matches the key in any letter case and keeps the last value, so
// `?Driver=shell` and `?driver=&driver=shell` both store the secret with the
// shell driver while the first value of the exact key reads as no driver at
// all. Both parameters are read through queryparam, which refuses both shapes.
func (p libpodSecretPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"secrets/create" {
		return "", nil
	}
	if p.allowCustomDrivers {
		return "", nil
	}

	query := logging.RequestQuery(r)
	driver, _, ok := queryparam.Scalar(query, "driver")
	if !ok {
		return ambiguousQueryReason("libpod secret create", "driver"), nil
	}
	if driver = strings.TrimSpace(driver); driver != "" && driver != libpodDefaultSecretDriver {
		return fmt.Sprintf("libpod secret create denied: driver %q is not allowed", driver), nil
	}

	driverOpts, _, ok := queryparam.Scalar(query, "driveropts")
	if !ok {
		return ambiguousQueryReason("libpod secret create", "driveropts"), nil
	}
	if strings.TrimSpace(driverOpts) == "" {
		return "", nil
	}
	// Podman's convertStringMap keeps every key that decodes even when
	// another value has the wrong type, so the options are counted as raw
	// values: one key of any type is an option.
	var options map[string]json.RawMessage
	if err := json.Unmarshal([]byte(driverOpts), &options); err != nil {
		return "libpod secret create denied: driver options could not be inspected", nil
	}
	if len(options) > 0 {
		return "libpod secret create denied: driver options are not allowed", nil
	}

	return "", nil
}
