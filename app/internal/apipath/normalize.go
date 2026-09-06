package apipath

import (
	"path"
	"strings"
)

// NormalizePath canonicalizes a request path into the form policy rules are
// matched against: it resolves "." and ".." segments and collapses redundant
// slashes (path.Clean), then strips a leading Docker or Podman API version
// prefix.
//
// It deliberately does NOT percent-decode. The path it receives is r.URL.Path,
// which net/http's request parser has already decoded exactly once — the same
// single decode the Docker daemon's request parser applies. Decoding again
// would let sockguard resolve an escape the daemon leaves literal: a
// double-encoded "%252e", for instance, would become a "." segment that
// path.Clean collapses for sockguard while the daemon still routes it as a
// real path segment, so the two would disagree on which endpoint the request
// targets. internal/filter's evaluateRequestPolicy handles Podman's
// UseEncodedPath exception for the image-SCP route before policy matching.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	return StripVersionPrefix(CanonicalizePath(p))
}

// CanonicalizePath resolves "." / ".." segments and collapses redundant
// slashes via path.Clean, fronted by the allocation-free pathNeedsClean fast
// path. It does not percent-decode — see NormalizePath for why.
func CanonicalizePath(p string) string {
	if pathNeedsClean(p) {
		p = path.Clean(p)
	}
	return p
}

// pathNeedsClean is a zero-allocation fast path in front of path.Clean so
// the overwhelmingly common case — paths that are already clean, like
// `/containers/json` or `/v1.45/_ping` — skips Clean's string allocation
// entirely. `BenchmarkNormalizePath/bare` and `/clean` report 0 B/op when
// this guard returns false; calling path.Clean unconditionally made that
// ~200ns and added two heap allocations per request. We only return true
// when the path actually has a trailing slash, a doubled slash, or a `.`
// or `..` segment — exactly the cases Clean would change.
func pathNeedsClean(p string) bool {
	if p == "/" {
		return false
	}
	if len(p) > 1 && p[len(p)-1] == '/' {
		return true
	}

	absolutePath := strings.HasPrefix(p, "/")
	hasNormalSegment := false
	segmentStart := 0
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}

		needsClean, normalSegment := pathSegmentNeedsClean(p, segmentStart, i, absolutePath, hasNormalSegment, true)
		if needsClean {
			return true
		}
		hasNormalSegment = hasNormalSegment || normalSegment
		segmentStart = i + 1
	}

	needsClean, _ := pathSegmentNeedsClean(p, segmentStart, len(p), absolutePath, hasNormalSegment, false)
	return needsClean
}

func pathSegmentNeedsClean(p string, start, end int, absolutePath, hasNormalSegment, hasMoreSegments bool) (needsClean bool, normalSegment bool) {
	if end == start {
		return start != 0, false
	}

	segmentLen := end - start
	if segmentLen == 1 && p[start] == '.' {
		// WHY: A lone relative "." is already clean because path.Clean(".") == ".".
		// Only dotted segments that would collapse with surrounding path context
		// should take the allocation-heavy Clean path.
		if start == 0 && !absolutePath && !hasMoreSegments {
			return false, false
		}
		return true, false
	}
	if segmentLen == 2 && p[start] == '.' && p[start+1] == '.' {
		return absolutePath || hasNormalSegment, false
	}

	return false, true
}

// StripVersionPrefix removes a leading API version prefix, returning the
// path from the first slash after the version. Uses a hand-rolled byte loop
// so the common case (no prefix) avoids regexp overhead and allocation
// entirely.
//
// Docker's own router only accepts /vN or /vN.N (a single optional minor
// component, digits and a dot only). Podman's libpod bindings send the
// daemon's full three-part semver, e.g. /v5.0.0/libpod/containers/json
// (#148), and its API server registers versioned routes with the regex
// `[0-9][0-9A-Za-z.-]*` (see moby/moby vendor of containers/podman's
// pkg/api/server VersionedPath), which also admits prerelease/build
// suffixes like /v5.8.1-dev/ and /v5.8.1-rc1/. sockguard mirrors that exact
// character class — first char after "v" a digit, then any run of
// [0-9A-Za-z.-] — so its policy view of a path stays byte-identical to
// Podman's own routing view. A wider or narrower class would leave some
// versioned libpod paths unstripped, falling through to a catch-all rule
// with rule matching, body inspection, ownership, visibility and redaction
// all skipped.
func StripVersionPrefix(p string) string {
	// Minimum version prefix is /vN/ (4 chars). Docker and Podman both use
	// lowercase 'v' only.
	if len(p) < 4 || p[0] != '/' || p[1] != 'v' {
		return p
	}
	i := 2
	// First character after "v" must be a digit.
	if p[i] < '0' || p[i] > '9' {
		return p
	}
	i++
	// Consume the rest of Podman's VersionedPath class: [0-9A-Za-z.-]*.
	for i < len(p) {
		c := p[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' {
			i++
			continue
		}
		break
	}
	// Must end with /
	if i >= len(p) || p[i] != '/' {
		return p
	}
	return p[i:]
}

// HasVersionPrefix reports whether p begins with a daemon API version prefix
// (e.g. "/v1.45/") that NormalizePath strips before rule matching. A rule
// pattern carrying such a prefix can never match real traffic — the request
// path is normalized first — so it is almost always an authoring mistake worth
// flagging.
func HasVersionPrefix(p string) bool {
	return StripVersionPrefix(p) != p
}

// NormalizePodmanRoutePath keeps the trailing slash that gorilla/mux includes
// in route matching while applying the same API-version and clean-path rules
// used for policy paths. A trailing slash is security-significant for Podman's
// anchored push/tag/untag routes: .../push/ misses the earlier action route and
// falls through to the later image-SCP catch-all.
//
// internal/filter's rule evaluator and the ownership middleware both have to
// compute the same route view, so it is exported rather than kept private to
// either. NormalizePath is not a substitute: path.Clean strips the trailing
// slash, so a caller using it reads POST /libpod/images/scp/victim/push/ as a
// push of an image named "scp/victim" while the daemon routes it as an SCP of
// "victim/push/".
//
// This is the only path shape rule matching ever sees with a trailing slash,
// and every matcher kind treats that slash as a real, empty final segment.
// See internal/filter's matchGlobSegments for why the segment walker has to
// agree with the regex there rather than absorb the slash.
func NormalizePodmanRoutePath(p string) string {
	hasTrailingSlash := len(p) > 1 && strings.HasSuffix(p, "/")
	normalized := NormalizePath(p)
	if hasTrailingSlash && normalized != "/" && !strings.HasSuffix(normalized, "/") {
		normalized += "/"
	}
	return normalized
}
