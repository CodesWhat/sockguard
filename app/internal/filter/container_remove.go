package filter

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/queryparam"
)

// ContainerRemoveOptions configures query inspection for container removal,
// including slash-bearing names used by Docker's legacy link-removal route.
type ContainerRemoveOptions struct {
	AllowForce         bool
	AllowRemoveVolumes bool
	AllowRemoveLinks   bool
}

type containerRemovePolicy struct {
	allowForce         bool
	allowRemoveVolumes bool
	allowRemoveLinks   bool
}

func newContainerRemovePolicy(opts ContainerRemoveOptions) containerRemovePolicy {
	return containerRemovePolicy{
		allowForce:         opts.AllowForce,
		allowRemoveVolumes: opts.AllowRemoveVolumes,
		allowRemoveLinks:   opts.AllowRemoveLinks,
	}
}

// containerRemoveGate names the request_body.container_remove flag that
// opens a query parameter.
type containerRemoveGate uint8

const (
	containerRemoveGateForce containerRemoveGate = iota
	containerRemoveGateVolumes
	containerRemoveGateLinks
)

// containerRemoveFlag is a query parameter whose true value a closed gate
// refuses.
type containerRemoveFlag struct {
	name   string
	gate   containerRemoveGate
	reason string
}

const (
	containerRemoveForceReason   = "container remove denied: force removal is not allowed"
	containerRemoveVolumesReason = "container remove denied: anonymous volume removal is not allowed"
)

// compatContainerRemoveFlags are the flags of DELETE /containers/{id}. dockerd
// and Podman's compat route both read `force`, `v` and `link`.
var compatContainerRemoveFlags = [...]containerRemoveFlag{
	{name: "force", gate: containerRemoveGateForce, reason: containerRemoveForceReason},
	{name: "v", gate: containerRemoveGateVolumes, reason: containerRemoveVolumesReason},
	{name: "link", gate: containerRemoveGateLinks, reason: "container remove denied: link removal is not allowed"},
}

// libpodContainerRemoveFlags are the flags of DELETE /libpod/containers/{id}.
// Podman 5.8.6 serves it from the compat handler, which on a libpod request
// takes the volumes flag from `volumes` and adds `depend`
// (pkg/api/handlers/compat/containers.go:38-71).
//
//   - `v` is in the route's swagger as "delete volumes" and the handler
//     ignores it, so it is gated as what it is documented to be, for a client
//     that follows the documentation or a release that starts reading it.
//   - `depend` removes every container that depends on the target
//     (pkg/domain/infra/abi/containers.go:469). When the target is a pod's
//     infra container or a kube service container that removes the pod, and
//     pod removal deletes the anonymous volumes of every container in it
//     whatever `volumes` says (libpod/runtime_ctr.go:837,
//     libpod/runtime_pod_common.go:256). Which container a request names can't
//     be told from the request, so `depend` waits for allow_remove_volumes.
//     It never stops a running workload container: the dependents are removed
//     with the request's own `force`. A pod's infra container can be stopped,
//     but only once every workload container in the pod is already stopped.
//
// `timeout` only applies to a forced stop and `ignore` only hides a missing
// container, so neither is read. `link` is decoded and ignored here.
var libpodContainerRemoveFlags = [...]containerRemoveFlag{
	{name: "force", gate: containerRemoveGateForce, reason: containerRemoveForceReason},
	{name: "volumes", gate: containerRemoveGateVolumes, reason: containerRemoveVolumesReason},
	{name: "v", gate: containerRemoveGateVolumes, reason: containerRemoveVolumesReason},
	{name: "depend", gate: containerRemoveGateVolumes, reason: "container remove denied: removing dependent containers can delete anonymous volumes and is not allowed"},
}

func (p containerRemovePolicy) allows(gate containerRemoveGate) bool {
	switch gate {
	case containerRemoveGateForce:
		return p.allowForce
	case containerRemoveGateVolumes:
		return p.allowRemoveVolumes
	case containerRemoveGateLinks:
		return p.allowRemoveLinks
	default:
		return false
	}
}

// inspect applies allow_force, allow_remove_volumes and allow_remove_links to
// the query flags of a container removal, on the Docker-compatible route and
// on Podman's libpod one (see the two flag tables for which flag each gate
// covers on each route).
//
// dockerd reads each with httputils.BoolValue, the first value under the
// exact key (moby 28.5.1 deleteContainers). Podman's compat.RemoveContainer
// decodes them with gorilla/schema, which matches the key in any letter case
// and keeps the last value (Podman 5.8.6, pkg/api/handlers/compat/containers.go),
// so on a Podman upstream `?Force=1` and `?force=0&force=1` force-removed a
// running container that the first value of the exact key said was not
// forced. Each flag is read through queryparam, which refuses both shapes,
// and only while its gate is closed: with the gate open, no value of it
// changes the decision.
//
// The libpod route decodes its bools with gorilla/schema's own converter
// rather than the BoolValue copy the compat route registers. It is true for
// "on" and for what strconv.ParseBool reads as true, and answers anything it
// can't read with 400, so every value it removes with is one
// dockerBoolQueryValue calls true.
func (p containerRemovePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodDelete {
		return "", nil
	}
	var flags []containerRemoveFlag
	switch {
	case isContainerRemovePath(normalizedPath):
		flags = compatContainerRemoveFlags[:]
	case isLibpodContainerRemovePath(normalizedPath):
		flags = libpodContainerRemoveFlags[:]
	default:
		return "", nil
	}

	query, err := logging.ParseRequestQuery(r)
	if err != nil {
		return "", newRequestRejectionError(http.StatusBadRequest, "container remove denied: query parameters could not be parsed")
	}

	for _, flag := range flags {
		if p.allows(flag.gate) {
			continue
		}
		value, _, ok := queryparam.Scalar(query, flag.name)
		if !ok {
			return ambiguousQueryReason("container remove", flag.name), nil
		}
		if dockerBoolQueryValue(value) {
			return flag.reason, nil
		}
	}

	return "", nil
}

func isContainerRemovePath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "/containers/") && len(normalizedPath) > len("/containers/")
}

// dockerBoolQueryValue mirrors Moby's httputils.BoolValue. Docker treats only
// the five normalized values below as false and treats every other value as
// true. Podman's compat routes decode with NewCompatAPIDecoder, which registers
// a converter that copies this same function, so they agree on the spellings:
// no 400 on "no", "none" or "yes", and an empty value sets false.
func dockerBoolQueryValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "no", "false", "none":
		return false
	default:
		return true
	}
}
