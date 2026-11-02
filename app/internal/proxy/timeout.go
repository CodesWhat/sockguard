package proxy

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/filter"
	"github.com/codeswhat/sockguard/v2/app/internal/logging"
	"github.com/codeswhat/sockguard/v2/app/internal/upstream"
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
// container wait and the prune endpoints) are exempt, because a deadline
// would sever a legitimately long response. Container and pod stop/restart
// skip the response-header deadline but get a request deadline of
// max(timeout, grace+30s), grace being the clamped (at most 1h) ?t= value
// (default 10s). GET /system/df skips only the response-header deadline.
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
		mode, grace := upstreamExemptionForFlavor(w, r, podmanUpstream)
		if mode == exemptFull {
			next.ServeHTTP(w, r)
			return
		}
		deadline := timeout
		if mode == exemptGraceBound {
			deadline = graceBoundDeadline(timeout, grace)
		}
		ctx, cancel := context.WithTimeout(r.Context(), deadline)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WithUpstreamDeadlines applies both upstream time bounds to next: the total
// per-request deadline (WithRequestTimeoutForFlavor) and the response-header
// deadline. Requests with any exemption skip the header deadline; the header
// deadline lives on the transport, so those requests are marked with
// upstream.MarkLongLived for the resolver to route over its
// header-deadline-free transport. The mark is set even when the request
// timeout is disabled, because the header deadline is a separate setting.
// The total deadline is skipped only for fully exempt requests; stop/restart
// get a deadline derived from their grace period and /system/df keeps the
// configured request timeout.
func WithUpstreamDeadlines(next http.Handler, requestTimeout time.Duration, podmanUpstream bool) http.Handler {
	bounded := WithRequestTimeoutForFlavor(next, requestTimeout, podmanUpstream)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode, _ := upstreamExemptionForFlavor(w, r, podmanUpstream); mode != exemptNone {
			r = r.WithContext(upstream.MarkLongLived(r.Context()))
		}
		bounded.ServeHTTP(w, r)
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
	mode, _ := upstreamExemptionForFlavor(w, r, podmanUpstream)
	return mode == exemptFull
}

// upstreamExemption says which upstream deadlines a request skips.
type upstreamExemption int

const (
	// exemptNone: both the response-header and request deadlines apply.
	exemptNone upstreamExemption = iota
	// exemptHeaderOnly: skips the response-header deadline; the configured
	// request timeout still applies (GET /system/df).
	exemptHeaderOnly
	// exemptGraceBound: skips the response-header deadline; the request
	// deadline is derived from the stop grace period (stop/restart).
	exemptGraceBound
	// exemptFull: skips both deadlines.
	exemptFull
)

const (
	// defaultStopGrace is Docker's and Podman's default stop timeout.
	defaultStopGrace = 10 * time.Second
	// maxStopGrace caps a client-supplied grace period.
	maxStopGrace = time.Hour
	// stopGraceSlack covers the kill and teardown after the grace expires.
	stopGraceSlack = 30 * time.Second
)

// graceBoundDeadline returns max(configured, grace+slack).
func graceBoundDeadline(configured, grace time.Duration) time.Duration {
	if d := grace + stopGraceSlack; d > configured {
		return d
	}
	return configured
}

// stopGraceFromQuery parses the stop grace period from the request's t (Docker
// and libpod pod) and timeout (libpod container) query params. Absent or
// unparseable values use the 10s default; negative (wait forever in Docker) and
// oversized values clamp to maxStopGrace. When both keys parse, the larger wins.
func stopGraceFromQuery(r *http.Request) time.Duration {
	var best time.Duration
	found := false
	for queryKey, values := range logging.RequestQuery(r) {
		if len(values) == 0 || (!strings.EqualFold(queryKey, "t") && !strings.EqualFold(queryKey, "timeout")) {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(values[len(values)-1]), 10, 64)
		if err != nil {
			if !errors.Is(err, strconv.ErrRange) {
				continue
			}
			// Out of int64 range: treat like any oversized value.
			n = -1
		}
		var d time.Duration
		switch {
		case n < 0 || n > int64(maxStopGrace/time.Second):
			d = maxStopGrace
		default:
			d = time.Duration(n) * time.Second
		}
		if !found || d > best {
			best, found = d, true
		}
	}
	if !found {
		return defaultStopGrace
	}
	return best
}

// upstreamExemptionForFlavor classifies r. For exemptGraceBound it also
// returns the clamped stop grace period.
func upstreamExemptionForFlavor(w http.ResponseWriter, r *http.Request, podmanUpstream bool) (upstreamExemption, time.Duration) {
	if r != nil && r.Method == http.MethodPost {
		path := requestNormalizedPath(w, r)
		path = strings.TrimPrefix(path, "/libpod")
		if matchContainerAction(path, "stop") || matchContainerAction(path, "restart") ||
			matchPodAction(path, "stop") || matchPodAction(path, "restart") {
			return exemptGraceBound, stopGraceFromQuery(r)
		}
	}
	if r != nil && r.Method == http.MethodGet {
		path := requestNormalizedPath(w, r)
		path = strings.TrimPrefix(path, "/libpod")
		if path == "/system/df" {
			return exemptHeaderOnly, 0
		}
	}
	if longLivedClassification(w, r, podmanUpstream) {
		return exemptFull, 0
	}
	return exemptNone, 0
}

func longLivedClassification(w http.ResponseWriter, r *http.Request, podmanUpstream bool) bool {
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
		case isPrunePath(path):
			// Prune walks and deletes arbitrarily many objects before it
			// replies.
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

// isPrunePath reports whether path is one of the Docker or libpod prune
// endpoints (libpod prefix already stripped).
func isPrunePath(path string) bool {
	switch path {
	case "/containers/prune", "/images/prune", "/volumes/prune", "/networks/prune",
		"/build/prune", "/pods/prune", "/system/prune":
		return true
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
	for queryKey, values := range logging.RequestQuery(r) {
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
	for queryKey, values := range logging.RequestQuery(r) {
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
	switch strings.ToLower(strings.TrimSpace(logging.RequestQuery(r).Get(key))) {
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
	if _, ok := logging.RequestQuery(r)[key]; !ok {
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
