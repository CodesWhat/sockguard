package proxy

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// WithRequestTimeout wraps next so that ordinary finite upstream requests are
// bounded by a total per-request deadline. When the deadline fires, the proxy
// transport aborts the upstream connection. This is the body-phase backstop
// that ResponseHeaderTimeout cannot provide: a daemon that sends headers
// promptly and then hangs the body would otherwise pin the request until the
// client gives up.
//
// What the client sees depends on whether response headers were already
// committed, and only the first case is a 504:
//
//   - Deadline fires BEFORE response headers arrive: the error surfaces from
//     RoundTrip, the ReverseProxy ErrorHandler runs, and the client gets a 504
//     (reasonCodeUpstreamRequestTimeout).
//   - Deadline fires AFTER response headers are committed: Go's ReverseProxy
//     does not route a copyResponse read error to ErrorHandler, and HTTP does
//     not allow replacing a sent status anyway. The client keeps the committed
//     status and sees a truncated body. The request is still aborted, which is
//     the point, but there is no 504 and cannot be one.
//
// The second case is the one this wrapper exists for, which makes it easy to
// describe backwards; both this comment and the docs did until 2026-08-29.
// TestWithRequestTimeout_BodyPhaseTruncatesRatherThanReturning504 pins it.
//
// A non-positive timeout disables the wrapper entirely — next is returned
// unchanged. Long-lived endpoints (event streams, follow/stream reads
// including service and task logs, streaming native Podman container/pod top,
// image pull/create/export/build/push, plugin create/pull/push/upgrade,
// container export/get, container archive i.e. docker cp, websocket attach,
// the BuildKit tunnel endpoints POST /session and POST /grpc, and the blocking
// container wait) are exempt, because a deadline would sever a legitimately
// long response.
// Hijacked endpoints
// (attach, exec start) never reach this handler: HijackHandler short-circuits
// them earlier in the chain.
func WithRequestTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return WithRequestTimeoutForFlavor(next, timeout, false)
}

// WithRequestTimeoutForFlavor is WithRequestTimeout with an explicit upstream
// engine classification. podmanUpstream must be true only when the upstream
// has been resolved as Podman; Docker-compatible top can stream on Podman but
// is always finite on Docker.
func WithRequestTimeoutForFlavor(next http.Handler, timeout time.Duration, podmanUpstream bool) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLongLivedUpstreamRequestForFlavor(w, r, podmanUpstream) {
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
	return isLongLivedUpstreamRequestForFlavor(w, r, false)
}

func isLongLivedUpstreamRequestForFlavor(w http.ResponseWriter, r *http.Request, podmanUpstream bool) bool {
	if r == nil {
		return false
	}
	path := requestNormalizedPath(w, r)
	nativeLibpod := false
	if nativePath, ok := strings.CutPrefix(path, "/libpod"); ok {
		path = nativePath
		nativeLibpod = true
	}
	switch r.Method {
	case http.MethodGet:
		switch {
		case path == "/events":
			return true
		case nativeLibpod && (matchContainerAction(path, "top") || matchPodAction(path, "top")):
			return podmanBoolValue(r, "stream")
		case podmanUpstream && matchContainerAction(path, "top"):
			return podmanCompatBoolValue(r, "stream")
		case matchContainerAction(path, "logs"):
			return dockerBoolValue(r, "follow")
		case matchResourceAction(path, "services", "logs"):
			// GET /services/{id}/logs?follow=1 tails a swarm service's
			// aggregated log stream the same way container logs do.
			return dockerBoolValue(r, "follow")
		case matchResourceAction(path, "tasks", "logs"):
			// GET /tasks/{id}/logs?follow=1 tails a single swarm task's log
			// stream.
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
		case path == "/images/export":
			// GET /images/export streams a tarball of multiple images (Podman's
			// libpod multi-image export) like the single-image /images/{name}/get
			// case above.
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
		case path == "/build" || path == "/images/create" || path == "/images/pull" || path == "/images/load" || path == "/plugins/create":
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
		case filter.IsBuildkitTunnelPath(path):
			// POST /session and POST /grpc are BuildKit's long-lived tunnel.
			// When request_body.buildkit is configured the mediator claims
			// them upstream of this handler and they never arrive here, but
			// with it unset withBuildkitMediator falls through to next — and
			// next is this deadline. The Tecnativa compat layer reaches that
			// state with no YAML at all: GRPC=1 or SESSION=1 auto-sets
			// insecure_accept_opaque_buildkit_tunnels, so a plain drop-in
			// migration would lose every build at the 60s default.
			// Sharing filter's predicate keeps the two definitions from
			// drifting the way the container-only log match already did.
			return true
		}
	}
	return false
}

// matchContainerAction reports whether path is exactly /containers/{id}/{action}.
func matchContainerAction(path, action string) bool {
	return matchResourceAction(path, "containers", action)
}

// matchResourceAction reports whether path is exactly /{resource}/{id}/{action},
// e.g. matchResourceAction(path, "services", "logs") for
// /services/{id}/logs.
func matchResourceAction(path, resource, action string) bool {
	rest, ok := strings.CutPrefix(path, "/"+resource+"/")
	if !ok {
		return false
	}
	id, act, ok := strings.Cut(rest, "/")
	if !ok || id == "" {
		return false
	}
	return act == action
}

// matchPodAction reports whether path is exactly /pods/{id}/{action}.
func matchPodAction(path, action string) bool {
	rest, ok := strings.CutPrefix(path, "/pods/")
	if !ok {
		return false
	}
	id, act, ok := strings.Cut(rest, "/")
	if !ok || id == "" {
		return false
	}
	return act == action
}

// podmanBoolValue mirrors the gorilla/schema bool conversion used by Podman's
// libpod handlers. Query keys are case-insensitive and the last repeated value
// within each identically-cased key group wins. gorilla/schema visits distinct
// case-folded groups in map order, so any truthy group is treated as streaming
// to avoid applying a deadline to a response Podman may stream. strconv.ParseBool
// spellings and the exact lowercase value "on" are accepted; omitted, invalid,
// and false-only groups remain finite.
func podmanBoolValue(r *http.Request, key string) bool {
	for queryKey, values := range r.URL.Query() {
		if !strings.EqualFold(queryKey, key) || len(values) == 0 {
			continue
		}
		value := values[len(values)-1]
		if value == "on" {
			return true
		}
		parsed, err := strconv.ParseBool(value)
		if err == nil && parsed {
			return true
		}
	}
	return false
}

func podmanCompatBoolValue(r *http.Request, key string) bool {
	// Podman's compatibility decoder uses the Docker falsy set, but retains
	// gorilla/schema's case-insensitive field lookup and per-key last value.
	for queryKey, values := range r.URL.Query() {
		if !strings.EqualFold(queryKey, key) || len(values) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(values[len(values)-1])) {
		case "", "0", "no", "false", "none":
			continue
		default:
			return true
		}
	}
	return false
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
