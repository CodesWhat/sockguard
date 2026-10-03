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

// inspect applies allow_force, allow_remove_volumes and allow_remove_links to
// the `force`, `v` and `link` query parameters.
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
func (p containerRemovePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodDelete || !isContainerRemovePath(normalizedPath) {
		return "", nil
	}

	query, err := logging.ParseRequestQuery(r)
	if err != nil {
		return "", newRequestRejectionError(http.StatusBadRequest, "container remove denied: query parameters could not be parsed")
	}

	for _, flag := range []struct {
		name    string
		allowed bool
		reason  string
	}{
		{name: "force", allowed: p.allowForce, reason: "container remove denied: force removal is not allowed"},
		{name: "v", allowed: p.allowRemoveVolumes, reason: "container remove denied: anonymous volume removal is not allowed"},
		{name: "link", allowed: p.allowRemoveLinks, reason: "container remove denied: link removal is not allowed"},
	} {
		if flag.allowed {
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
