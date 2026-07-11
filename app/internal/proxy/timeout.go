package proxy

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

// WithRequestTimeout wraps next so that ordinary finite upstream requests are
// bounded by a total per-request deadline. When the deadline fires, the proxy
// transport aborts the upstream connection and the ReverseProxy ErrorHandler
// returns a 504 (reasonCodeUpstreamRequestTimeout). This is the body-phase
// backstop that ResponseHeaderTimeout cannot provide: a daemon that sends
// headers promptly and then hangs the body would otherwise pin the request
// until the client gives up.
//
// A non-positive timeout disables the wrapper entirely — next is returned
// unchanged. Long-lived endpoints (event streams, follow/stream reads, image
// pull/build/push, plugin pull/push/upgrade, container export/get, container
// archive i.e. docker cp, websocket attach, and the blocking container wait)
// are exempt, because a deadline would sever a legitimately long response.
// Hijacked endpoints
// (attach, exec start) never reach this handler: HijackHandler short-circuits
// them earlier in the chain.
func WithRequestTimeout(next http.Handler, timeout time.Duration) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLongLivedUpstreamRequest(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isLongLivedUpstreamRequest reports whether a proxied request is expected to
// have an unbounded or very long response and therefore must not carry the
// per-request upstream deadline. Docker API version prefixes (/v1.XX/) are
// stripped before matching.
func isLongLivedUpstreamRequest(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return false
	}
	path := requestNormalizedPath(w, r)
	switch r.Method {
	case http.MethodGet:
		switch {
		case path == "/events":
			return true
		case matchContainerAction(path, "logs"):
			return dockerBoolValue(r, "follow")
		case matchContainerAction(path, "stats"):
			// Stats streams by default; only an explicitly false stream makes it
			// one-shot — mirror the daemon's BoolValueOrDefault(stream, true).
			return dockerBoolValueOrDefault(r, "stream", true)
		case matchContainerAction(path, "export"):
			return true
		case matchContainerAction(path, "archive"):
			// GET /containers/{id}/archive is docker cp FROM the container; a
			// large filesystem tarball can legitimately take longer than the
			// deadline to stream.
			return true
		case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/get"):
			return true
		case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/attach/ws"):
			return true
		}
	case http.MethodPut:
		// PUT /containers/{id}/archive is docker cp INTO the container;
		// exempt for the same large-transfer reason as the GET form.
		return matchContainerAction(path, "archive")
	case http.MethodPost:
		switch {
		case path == "/build" || path == "/images/create" || path == "/images/load":
			return true
		case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/push"):
			return true
		case path == "/plugins/pull":
			// Plugin pull streams registry download progress like image create.
			return true
		case strings.HasPrefix(path, "/plugins/") &&
			(strings.HasSuffix(path, "/push") || strings.HasSuffix(path, "/upgrade")):
			// Plugin push/upgrade stream a registry transfer like image push/pull.
			return true
		case matchContainerAction(path, "wait"):
			// /containers/{id}/wait blocks until the container exits.
			return true
		}
	}
	return false
}

// matchContainerAction reports whether path is exactly /containers/{id}/{action}.
func matchContainerAction(path, action string) bool {
	rest, ok := strings.CutPrefix(path, "/containers/")
	if !ok {
		return false
	}
	id, act, ok := strings.Cut(rest, "/")
	if !ok || id == "" {
		return false
	}
	return act == action
}

// dockerBoolValue mirrors the daemon's api/server/httputils.BoolValue: a query
// value is false only when empty or one of "0"/"no"/"false"/"none"
// (case-insensitive), and true otherwise. Matching dockerd's own parsing keeps
// the long-lived-request classification consistent with how the daemon will
// actually treat ?follow=/?stream= — e.g. follow=yes streams at the daemon, so
// it must be exempt from the request deadline here too, not just follow=1.
func dockerBoolValue(r *http.Request, key string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "", "0", "no", "false", "none":
		return false
	default:
		return true
	}
}

// dockerBoolValueOrDefault mirrors httputils.BoolValueOrDefault: an absent key
// returns def; a present key (including an empty value) is parsed by
// dockerBoolValue. Used for ?stream=, which the daemon defaults to true.
func dockerBoolValueOrDefault(r *http.Request, key string, def bool) bool {
	if _, ok := r.URL.Query()[key]; !ok {
		return def
	}
	return dockerBoolValue(r, key)
}

func requestNormalizedPath(w http.ResponseWriter, r *http.Request) string {
	if meta := logging.MetaForRequest(w, r); meta != nil && meta.NormPath != "" {
		return meta.NormPath
	}
	return filter.NormalizePath(r.URL.Path)
}
