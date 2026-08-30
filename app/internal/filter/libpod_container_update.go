package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// libpodContainerUpdateSubject prefixes libpod-family denial reasons, matching
// the convention the other libpod inspectors use.
const libpodContainerUpdateSubject = "libpod container update"

// inspectLibpod applies containerUpdatePolicy — and therefore the single
// request_body.container_update config block — to Podman's native
// POST /libpod/containers/{name}/update. It shares ContainerUpdateOptions with
// inspect rather than forking a second config surface, for the same reason
// request_body.exec, request_body.build and request_body.image_pull are
// shared across both API families: an operator must not be able to lock one
// spelling of an endpoint and silently leave the other open.
//
// It is a separate method rather than a widened path guard on inspect because
// the two endpoints share a name and nothing else. Verified against Podman
// v5.8.1 (pkg/api/handlers/libpod/containers.go UpdateContainer, and
// pkg/api/handlers/types.go UpdateEntities):
//
//   - The body is updateEntitiesWire, which embeds handlers.UpdateEntities,
//     which in turn embeds specs.LinuxResources, define.UpdateHealthCheckConfig
//     and define.UpdateContainerDevicesLimits. Every one of those is an
//     ANONYMOUS field, so encoding/json flattens them: the wire keys are OCI's
//     lowercase `memory`/`cpu`/`pids`/`blockIO`/`devices`, libpod's snake_case
//     `health_*`, and the bare Go names of the device-limit lists. Almost none
//     of them collide with Docker's PascalCase container.UpdateConfig, so
//     running inspect's field lists over this body would have found nothing
//     and allowed everything.
//   - There is no HostConfig/Resources nesting to walk. Podman decodes the
//     request root straight into the struct, so a value under a decoy wrapper
//     is never applied and is deliberately not read here.
//   - The restart policy is NOT in the body. It arrives as the `restartPolicy`
//     and `restartRetries` query parameters, so allowRestartPolicy has to be
//     enforced against the query or it is not enforced at all.
//
// Three field groups have no counterpart in ContainerUpdateOptions and are
// denied outright rather than passed through, because there is no gate that
// honestly governs them and default-deny is the house posture:
// healthcheck commands (an exec primitive on a timer), environment changes,
// and the caller-chosen daemon-host healthcheck log directory. See
// libpodContainerUpdateUngoverned.
//
// AllowPrivileged and AllowCapabilities are inert here, and that is a
// statement about libpod rather than an omission: UpdateEntities carries no
// privileged flag and no capability list, so there is no field for either gate
// to read. Podman's own summary for the route is "changes to resource limits
// and healthchecks" — a container cannot be made privileged through it.
func (p containerUpdatePolicy) inspectLibpod(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isLibpodContainerUpdatePath(normalizedPath) {
		return "", nil
	}

	if !p.allowRestartPolicy {
		if field, ok := libpodContainerUpdateRestartQueryField(r.URL.Query()); ok {
			return fmt.Sprintf("%s denied: restart policy changes are not allowed (%s)", libpodContainerUpdateSubject, field), nil
		}
	}

	if r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxContainerUpdateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s denied: request body exceeds %d byte limit", libpodContainerUpdateSubject, maxContainerUpdateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var root map[string]json.RawMessage
	if err := decodePolicySubsetJSON(body, &root); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod container update request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return libpodContainerUpdateSubject + " denied: request body could not be inspected", nil
	}
	if len(root) == 0 {
		return "", nil
	}

	// Root only: Podman applies nothing outside the request root, so reading
	// deeper would deny on values the daemon never honors.
	objects := []map[string]json.RawMessage{root}

	if reason, ok := libpodContainerUpdateUngovernedDenyReason(objects); ok {
		return fmt.Sprintf("%s denied: %s", libpodContainerUpdateSubject, reason), nil
	}
	if !p.allowBlindWrites && containerUpdateHasAnyField(objects, libpodContainerUpdateBlindWriteFields...) {
		return libpodContainerUpdateSubject + " denied: healthcheck timing and log-retention changes require insecure_allow_body_blind_writes: true", nil
	}
	if !p.allowAllDevices && containerUpdateHasAnyField(objects, libpodContainerUpdateDeviceFields...) {
		return libpodContainerUpdateSubject + " denied: device changes are not allowed", nil
	}
	if !p.allowRestartPolicy && containerUpdateHasAnyField(objects, libpodContainerUpdateLifecycleFields...) {
		return libpodContainerUpdateSubject + " denied: healthcheck failure-action changes are not allowed", nil
	}
	if !p.allowResourceUpdates && containerUpdateHasAnyField(objects, libpodContainerUpdateResourceControlFields...) {
		return libpodContainerUpdateSubject + " denied: resource control changes are not allowed", nil
	}

	return "", nil
}

// libpodContainerUpdateRestartQueryField reports the first query parameter
// carrying a restart-policy change, if any.
//
// Podman decodes this query with gorilla/schema (utils.GetDecoder), which
// matches a struct tag with strings.EqualFold and, for a scalar, takes the
// LAST value when a key repeats. net/url's Values.Get does neither, so
// `?RestartPolicy=always` and `?restartPolicy=no&restartPolicy=always` would
// both slip past a plain Get. Raw keys are matched with the same EqualFold
// semantics and every value is checked.
//
// restartRetries counts as a restart-policy change even though Podman rejects
// it unless restartPolicy is also set to on-failure: it is only ever honored
// as part of one, so admitting it under a policy that denies restart changes
// would be admitting half of a denied operation. An empty value is ignored
// because gorilla/schema fails to parse "" into the handler's uint and Podman
// 400s the request before any update happens.
func libpodContainerUpdateRestartQueryField(query url.Values) (string, bool) {
	for _, name := range []string{"restartpolicy", "restartretries"} {
		for key, values := range query {
			if !strings.EqualFold(key, name) {
				continue
			}
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return name, true
				}
			}
		}
	}
	return "", false
}

// libpodContainerUpdateUngovernedDenyReason returns the reason for the first
// ungoverned field present in objects, scanning libpodContainerUpdateUngoverned
// in declaration order so a body carrying several of them always denies with
// the same message. Field names are matched case-insensitively, the way
// encoding/json resolves a struct field.
func libpodContainerUpdateUngovernedDenyReason(objects []map[string]json.RawMessage) (string, bool) {
	for _, entry := range libpodContainerUpdateUngoverned {
		if containerUpdateHasAnyField(objects, entry.field) {
			return entry.reason, true
		}
	}
	return "", false
}

type libpodContainerUpdateUngovernedField struct {
	field  string
	reason string
}

// libpodContainerUpdateUngoverned are the UpdateEntities keys with no
// counterpart anywhere in ContainerUpdateOptions, mapped to the denial reason
// each gets. They are refused unconditionally rather than passed through:
// admitting them while telling bodyInspectionConfiguredForEndpoint that this
// path is inspected would be worse than the gap this fix closes, because it
// would report protection sockguard is not providing.
//
// health_cmd and health_startup_cmd are the sharp ones. Podman runs a
// healthcheck command inside the container on a timer, so setting one on a
// container the caller may already start and stop is exec by another name —
// and it reaches a caller who was never granted POST /containers/{id}/exec.
// request_body.exec is the config that governs commands run in a container,
// and container_update is not it, so this inspector refuses rather than
// admitting an exec no allowlist ever saw.
//
// Env/UnsetEnv rewrite the container's environment, which is both a secret
// surface and an execution-control surface (PATH, LD_PRELOAD) for every
// process the container starts afterward, including that healthcheck.
//
// health_log_destination names a directory the daemon writes healthcheck logs
// into, on the DAEMON host rather than in the container, chosen by the caller.
//
// Everything else in define.UpdateHealthCheckConfig either rides
// AllowRestartPolicy as a lifecycle change (see
// libpodContainerUpdateLifecycleFields) or requires the global body-blind
// write acknowledgment (see libpodContainerUpdateBlindWriteFields).
var libpodContainerUpdateUngoverned = []libpodContainerUpdateUngovernedField{
	{"health_cmd", "healthcheck command changes are not allowed (a healthcheck command is executed inside the container; grant exec through request_body.exec and the exec endpoints instead)"},
	{"health_startup_cmd", "startup healthcheck command changes are not allowed (a healthcheck command is executed inside the container; grant exec through request_body.exec and the exec endpoints instead)"},
	{"health_log_destination", "healthcheck log destination changes are not allowed (it names a directory on the daemon host)"},
	{"Env", "environment changes are not allowed"},
	{"UnsetEnv", "environment changes are not allowed"},
}

// libpodContainerUpdateBlindWriteFields can make an already-approved
// healthcheck execute at high frequency or retain unbounded daemon logs. None
// has a structured ContainerUpdateOptions policy, so they fail closed unless
// the operator explicitly enables insecure_allow_body_blind_writes. Command,
// environment, and daemon-host log-destination fields remain unconditionally
// denied above even under that acknowledgment.
var libpodContainerUpdateBlindWriteFields = []string{
	"health_interval",
	"health_retries",
	"health_timeout",
	"health_start_period",
	"health_startup_interval",
	"health_startup_timeout",
	"health_startup_success",
	"health_max_log_size",
	"health_max_log_count",
}

// libpodContainerUpdateDeviceFields is specs.LinuxResources.Devices, the OCI
// cgroup device allowlist and the libpod analog of the DeviceCgroupRules entry
// in containerUpdateDeviceFields. Gated by AllowAllDevices, exactly as its
// Docker-compat counterpart is.
var libpodContainerUpdateDeviceFields = []string{
	"devices",
}

// libpodContainerUpdateLifecycleFields are the UpdateEntities keys that
// change what the daemon does to the container on its own initiative:
// health_on_failure selects none/kill/restart/stop, no_healthcheck disables
// the check that would trigger it, and health_startup_retries is described by
// define.UpdateHealthCheckConfig itself as "the maximum number of retries
// before the startup healthcheck will restart the container". All three are
// restart-policy decisions in everything but name, so they ride
// AllowRestartPolicy alongside the restartPolicy query parameter rather than
// getting a gate of their own.
//
// Timing and log-retention fields are kept separate because they use the
// global body-blind-write acknowledgment rather than this lifecycle gate.
var libpodContainerUpdateLifecycleFields = []string{
	"health_on_failure",
	"no_healthcheck",
	"health_startup_retries",
}

// libpodContainerUpdateResourceControlFields are the UpdateEntities keys that
// change resource limits, gated by AllowResourceUpdates exactly as
// containerUpdateResourceControlFields is on the Docker-compat path. The
// grouping follows Docker's: per-device IO throttles are resource control
// there (BlkioDeviceReadBps and friends) and are resource control here.
//
// The first block is specs.LinuxResources, embedded and therefore flattened to
// the request root. The second is define.UpdateContainerDevicesLimits, which
// carries no json tags at all, so its wire keys are the bare Go field names.
// The last is updateEntitiesWire.Rlimits, libpod's Ulimits.
var libpodContainerUpdateResourceControlFields = []string{
	"memory",
	"cpu",
	"pids",
	"blockIO",
	"hugepageLimits",
	"network",
	"rdma",
	"unified",

	"BlkIOWeightDevice",
	"DeviceReadBPs",
	"DeviceWriteBPs",
	"DeviceReadIOPs",
	"DeviceWriteIOPs",

	"r_limits",
}
