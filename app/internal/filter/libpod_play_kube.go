package filter

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// LibpodPlayKubeOptions configures query checks for POST /libpod/play/kube and
// its /libpod/kube/play alias.
//
// The YAML body is opaque to sockguard, which is why the route also sits in
// the blind-write catalog. Only the two query parameters that pick the log
// driver for every container the YAML creates are inspected here, so this
// block never counts as body inspection for that catalog.
type LibpodPlayKubeOptions struct {
	// AllowedLogDrivers allowlists the logDriver query parameter, and
	// AllowedLogEndpointOptions lists the destination options the logOptions
	// parameter may carry. Default empty: off. An absent logDriver selects
	// the daemon default and is always allowed. See logDriverPolicy.
	AllowedLogDrivers         []string
	AllowedLogEndpointOptions []string
}

type libpodPlayKubePolicy struct {
	logDrivers logDriverPolicy
}

func newLibpodPlayKubePolicy(opts LibpodPlayKubeOptions) libpodPlayKubePolicy {
	return libpodPlayKubePolicy{logDrivers: newLogDriverPolicy(opts.AllowedLogDrivers, opts.AllowedLogEndpointOptions)}
}

func isLibpodPlayKubeCreatePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"play/kube" || normalizedPath == libpodPathPrefix+"kube/play"
}

// inspect applies the log driver allowlist to a kube play's logDriver and
// logOptions query parameters. Podman decodes them with gorilla/schema, which
// matches a key in any letter case and, for the scalar, keeps the last value
// of a repeated key, so every spelling and every value of each is checked
// rather than the first one. logOptions entries are "key=value" strings, the
// same shape a compat create's Config map is rewritten into.
func (p libpodPlayKubePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !p.logDrivers.enabled() || !isLibpodPlayKubeCreatePath(normalizedPath) {
		return "", nil
	}
	const subject = "libpod kube play"
	query, err := logging.ParseRequestQuery(r)
	if err != nil {
		return "", newRequestRejectionError(http.StatusBadRequest, subject+" denied: query parameters could not be parsed")
	}
	drivers, options := libpodPlayKubeLogQuery(query)
	for _, driver := range drivers {
		if reason := p.logDrivers.denyArgsReason(subject, driver, nil); reason != "" {
			return reason, nil
		}
	}
	return p.logDrivers.denyArgsReason(subject, "", options), nil
}

func libpodPlayKubeLogQuery(query url.Values) (drivers, options []string) {
	for key, values := range query {
		switch {
		case strings.EqualFold(key, "logDriver"):
			drivers = append(drivers, values...)
		case strings.EqualFold(key, "logOptions"):
			options = append(options, values...)
		}
	}
	return drivers, options
}
