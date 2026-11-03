package filter

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// logEndpointOptionKeys are the log driver options that name a destination the
// daemon sends every line of a container's output to: a syslog, GELF, Fluentd,
// Loki or Splunk collector, or a custom AWS endpoint. A client that can pick
// one of them can point a container's log at a host it controls, whatever the
// driver's own checks say about the address. Lower case, because the policy
// compares the lowered name (see logOptionName).
//
// "path", the file a Podman upstream writes the log to, is not here: it has
// its own gate, allow_log_path.
var logEndpointOptionKeys = map[string]struct{}{
	"syslog-address":               {},
	"gelf-address":                 {},
	"fluentd-address":              {},
	"loki-url":                     {},
	"loki-proxy-url":               {},
	"splunk-url":                   {},
	"awslogs-endpoint":             {},
	"awslogs-credentials-endpoint": {},
}

// LogEndpointOptionKeys returns the destination option names, sorted, that
// allowed_log_endpoint_options may list.
func LogEndpointOptionKeys() []string {
	keys := make([]string, 0, len(logEndpointOptionKeys))
	for key := range logEndpointOptionKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// logDriverPolicy is the opt-in log driver allowlist shared by the surfaces
// that can set a container's log driver: compat and libpod container create,
// libpod kube play, and swarm service create/update. It is off, and enforces
// nothing, until allowed_log_drivers is non-empty.
//
// An empty driver name selects the daemon's own default and is allowed, the
// way an empty Runtime is under allowed_runtimes: the operator chose that
// default. Its options are still checked.
type logDriverPolicy struct {
	drivers  []string
	endpoint map[string]struct{}
}

func newLogDriverPolicy(drivers, endpointOptions []string) logDriverPolicy {
	p := logDriverPolicy{}
	for _, driver := range drivers {
		driver = strings.TrimSpace(driver)
		if driver == "" || slices.Contains(p.drivers, driver) {
			continue
		}
		p.drivers = append(p.drivers, driver)
	}
	if len(endpointOptions) > 0 {
		p.endpoint = make(map[string]struct{}, len(endpointOptions))
		for _, key := range endpointOptions {
			if name := logOptionName(key); name != "" {
				p.endpoint[name] = struct{}{}
			}
		}
	}
	return p
}

func (p logDriverPolicy) enabled() bool {
	return len(p.drivers) > 0
}

// logOptionName is the name a Podman upstream reads a "--log-opt" argument
// under: the argument up to its first "=", lowered and not trimmed by Podman
// (trimmed here too, which refuses nothing a client has a use for).
func logOptionName(arg string) string {
	name, _, _ := strings.Cut(arg, "=")
	return strings.ToLower(strings.TrimSpace(name))
}

// denyMapReason checks a driver name and its options map, as Docker's
// HostConfig.LogConfig, libpod's log_configuration and swarm's
// TaskTemplate.LogDriver carry them. subject names the surface in a refusal.
func (p logDriverPolicy) denyMapReason(subject, driver string, options map[string]string) string {
	if !p.enabled() {
		return ""
	}
	args := make([]string, 0, len(options))
	for key, value := range options {
		args = append(args, key+"="+value)
	}
	sort.Strings(args)
	return p.denyArgsReason(subject, driver, args)
}

// denyArgsReason checks a driver name and its options as "key=value"
// arguments, which is how a Podman upstream reads a compat create's Config map
// ("--log-opt") and how play/kube's logOptions query parameter arrives.
//
// An argument named "driver" replaces the driver name on a Podman upstream (the
// compat create writes each Config entry out as "--log-opt key=value" and
// FillOutSpecGen switches on the lowered name), so it is checked against the
// allowlist exactly like the driver field. Driver names are compared exactly,
// the way dockerd and Podman look them up.
func (p logDriverPolicy) denyArgsReason(subject, driver string, args []string) string {
	if !p.enabled() {
		return ""
	}
	if driver != "" && !slices.Contains(p.drivers, driver) {
		return fmt.Sprintf("%s denied: log driver %q is not allowed (see allowed_log_drivers)", subject, driver)
	}
	for _, arg := range args {
		name, rest, _ := strings.Cut(arg, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "driver":
			if !slices.Contains(p.drivers, rest) {
				return fmt.Sprintf("%s denied: log driver %q is not allowed (see allowed_log_drivers)", subject, rest)
			}
		default:
			lowered := logOptionName(arg)
			if _, endpoint := logEndpointOptionKeys[lowered]; !endpoint {
				continue
			}
			if _, listed := p.endpoint[lowered]; !listed {
				return fmt.Sprintf("%s denied: log option %q sets a log destination and is not allowed (see allowed_log_endpoint_options)", subject, lowered)
			}
		}
	}
	return ""
}
