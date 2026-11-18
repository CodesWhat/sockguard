package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// maxContainerStartBodyBytes bounds the read that decides whether a start
// request carries a body at all. A real start has none, so the limit is only
// there to keep a hostile body from being buffered.
const maxContainerStartBodyBytes = 4 << 10

// containerStartPolicy refuses a body on POST /containers/{name}/start.
//
// A start request has no body. Docker 24.x, and 25.x with DOCKER_MIN_API_VERSION
// set to 1.23 or lower, still decode one below API 1.24 and treat it as the
// container's HostConfig: ContainerStart replaces the stored HostConfig and
// registers its bind mounts on the stopped container. A client could create a
// harmless container through the create inspector and start it with a
// privileged HostConfig that nothing inspects. Docker 26 and newer reject such
// a body outright, so refusing every non-empty body costs no legitimate
// client anything, whatever API version prefix the path carries and whether the
// body is fixed-length or chunked. It has no opt-out.
type containerStartPolicy struct{}

func newContainerStartPolicy() containerStartPolicy { return containerStartPolicy{} }

// isContainerStartPath matches the Docker-compat start route. Docker registers
// it as /containers/{name:.*}/start, so a name may itself contain slashes
// (legacy link aliases such as a/b), and the name is everything between
// /containers/ and the final /start. normalizedPath must already have gone
// through NormalizePath.
func isContainerStartPath(normalizedPath string) bool {
	name, ok := strings.CutPrefix(normalizedPath, "/containers/")
	if !ok {
		return false
	}
	name, ok = strings.CutSuffix(name, "/start")
	return ok && name != ""
}

func matchesContainerStartInspection(normalizedPath string) bool {
	return isContainerStartPath(normalizedPath)
}

const containerStartBodyDeniedReason = "container start denied: a request body is not allowed (Docker applies a HostConfig sent with start on older API versions)"

func (p containerStartPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isContainerStartPath(normalizedPath) {
		return "", nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return "", nil
	}
	body, err := readBoundedBodyUnchecked(r, maxContainerStartBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return containerStartBodyDeniedReason, nil
		}
		return "", fmt.Errorf("read body: %w", err)
	}
	if len(body) > 0 {
		return containerStartBodyDeniedReason, nil
	}
	return "", nil
}
