package filter

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/logging"
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

func (p containerRemovePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodDelete || !isContainerRemovePath(normalizedPath) {
		return "", nil
	}

	query, err := logging.ParseRequestQuery(r)
	if err != nil {
		return "", newRequestRejectionError(http.StatusBadRequest, "container remove denied: query parameters could not be parsed")
	}

	if !p.allowForce && dockerBoolQueryValue(query, "force") {
		return "container remove denied: force removal is not allowed", nil
	}
	if !p.allowRemoveVolumes && dockerBoolQueryValue(query, "v") {
		return "container remove denied: anonymous volume removal is not allowed", nil
	}
	if !p.allowRemoveLinks && dockerBoolQueryValue(query, "link") {
		return "container remove denied: link removal is not allowed", nil
	}

	return "", nil
}

func isContainerRemovePath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "/containers/") && len(normalizedPath) > len("/containers/")
}

// dockerBoolQueryValue mirrors Moby's httputils.BoolValue. Docker treats only
// the five normalized values below as false and treats every other value as
// true. url.Values.Get intentionally selects the first repeated value, the
// same choice net/http's Request.FormValue makes in the daemon handler.
func dockerBoolQueryValue(query url.Values, key string) bool {
	switch strings.ToLower(strings.TrimSpace(query.Get(key))) {
	case "", "0", "no", "false", "none":
		return false
	default:
		return true
	}
}
