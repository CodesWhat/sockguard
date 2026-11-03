package proxy

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// IsStreamingRequest reports whether r is an open-ended stream that holds a
// connection for as long as a client cares to keep it: events, followed logs,
// streaming stats, wait, attach, and exec start (which hijacks). The
// rate-limit middleware exempts these from the concurrency caps and bounds
// them with the separate stream cap instead.
//
// It is deliberately narrower than the upstream-timeout classifier. Build,
// prune, image pull/push/load, export and archive are long but finite, heavy
// operations, and max_inflight is exactly what should bound how many of them
// run at once, so they keep counting. Libpod paths are normalized to their
// Docker form before matching.
func IsStreamingRequest(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return false
	}
	path := requestNormalizedPath(w, r)
	if filter.IsHijackCandidatePath(r.Method, path) {
		return true
	}
	path = strings.TrimPrefix(path, "/libpod")
	switch r.Method {
	case http.MethodGet:
		switch {
		case path == "/events":
			return true
		case matchContainerAction(path, "logs"):
			return dockerBoolValue(r, "follow")
		case matchContainerAction(path, "stats"):
			return dockerBoolValueOrDefault(r, "stream", true)
		case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/attach/ws"):
			return true
		}
	case http.MethodPost:
		return matchContainerAction(path, "wait")
	}
	return false
}
