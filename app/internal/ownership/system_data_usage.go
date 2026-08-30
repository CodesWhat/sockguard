package ownership

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
)

const (
	reasonCodeOwnerResponseTooLarge        = "owner_response_too_large"
	reasonCodeOwnerResponseFilterFail      = "owner_response_filter_failed"
	reasonCodeOwnerLibpodDataUsageUnscoped = "owner_libpod_data_usage_unscopeable"
	reasonCodeOwnerLibpodShowMounted       = "owner_libpod_showmounted_unscopeable"
)

// serveOwnershipAllowed forwards a request the ownership policy did not deny.
//
// Almost everything goes straight to next. Host-wide inventory endpoints are
// the exception: they enumerate resources across the daemon and accept no
// `filters` query parameter, so addOwnerLabelFilter — the
// mechanism that isolates /containers/json, /volumes and /images/json — has
// nothing to attach to. Owner isolation for them has to happen on the response
// when the response carries labels, or fail closed when it does not.
//
// GET /system/df returns Docker-shaped summaries that carry Labels, so it is
// filtered item by item. GET /libpod/system/df returns Podman's own report
// shape, whose entries carry no labels at all, so there is nothing to filter
// on and it is refused instead — see
// responsefilter.LibpodSystemDataUsageDenyReason for the shape and the
// reasoning. GET /libpod/containers/showmounted returns only container IDs and
// daemon-host mount paths, so it is likewise refused.
func serveOwnershipAllowed(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, normPath string, opts Options) {
	if r.Method == http.MethodGet {
		switch normPath {
		case responsefilter.SystemDataUsagePath:
			filterSystemDataUsageResponse(logger, next, w, r, opts)
			return
		case responsefilter.LibpodSystemDataUsagePath:
			denyLibpodSystemDataUsage(w, r)
			return
		case responsefilter.LibpodShowMountedPath:
			denyLibpodShowMounted(w, r)
			return
		}
	}
	next.ServeHTTP(w, r)
}

func denyLibpodShowMounted(w http.ResponseWriter, r *http.Request) {
	reason := responsefilter.LibpodShowMountedDenyReason
	logging.SetDeniedWithCode(w, r, reasonCodeOwnerLibpodShowMounted, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}

// denyLibpodSystemDataUsage refuses GET /libpod/system/df with a 403 and never
// contacts the upstream, so no byte of the host inventory is buffered, let
// alone relayed.
//
// It deliberately does not honor RequestMeta.AllowsPassThrough the way the
// request-side owner verdict does. Everything else in this file — the
// oversized-body 502, the filter-failure 502, the item filtering itself —
// is likewise unconditional: response-side isolation is not a policy verdict
// the operator is staging, it is the layer that decides what leaves the
// proxy, and a warn-mode deployment forwarding a full host inventory is the
// exact disclosure this closes.
func denyLibpodSystemDataUsage(w http.ResponseWriter, r *http.Request) {
	reason := responsefilter.LibpodSystemDataUsageDenyReason
	logging.SetDeniedWithCode(w, r, reasonCodeOwnerLibpodDataUsageUnscoped, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}

// filterSystemDataUsageResponse buffers the upstream /system/df response,
// drops every item that does not carry this proxy's owner label, and converts
// an oversized or undecodable body into a fail-closed 502 — the same shape the
// visibility middleware's response filter uses for /containers/json.
func filterSystemDataUsageResponse(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, opts Options) {
	interceptingW := newOwnerFilterWriter(w)
	next.ServeHTTP(interceptingW, r)

	if interceptingW.overflow {
		logger.ErrorContext(r.Context(), "owner response filter: upstream response exceeds size limit",
			"limit_bytes", filter.MaxResponseBodyBytes, "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
		logging.SetDeniedWithCode(w, r, reasonCodeOwnerResponseTooLarge, "upstream response too large to filter", nil)
		responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
		_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "upstream response too large to filter"})
		return
	}

	dropped, err := interceptingW.flushOwned(opts)
	if fresh := responsefilter.FirstSightSystemDataUsageSections(dropped); len(fresh) > 0 {
		logger.WarnContext(r.Context(), "owner system data usage filter dropped unclassifiable response sections",
			"sections", logging.SafeString(strings.Join(fresh, ",")),
			"note", "this build cannot classify these sections by owner, so they are hidden rather than forwarded",
			"path", logging.SafeString(r.URL.Path))
	}
	if err != nil {
		logger.ErrorContext(r.Context(), "owner system data usage filter failed", "error", logging.SafeString(err.Error()))
		if !interceptingW.headerWritten {
			logging.SetDeniedWithCode(w, r, reasonCodeOwnerResponseFilterFail, "owner response filter failed", nil)
			responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
			_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "owner response filter failed"})
		}
	}
}

// ownerFilterWriter buffers a response so the ownership middleware can rewrite
// the body before it reaches the client.
//
// It is the counterpart of visibility's patternFilterWriter and behaves
// identically on the paths that matter (bounded buffer, overflow flag instead
// of a write error, deferred WriteHeader). It is a separate type rather than a
// shared one because the two middlewares are independent layers: they nest at
// runtime — visibility wraps ownership, so a response passes through the owner
// filter first and the visibility filter second — and each needs its own
// buffer. Unlike patternFilterWriter it is not pooled: /system/df is a
// low-frequency reporting endpoint, not a hot path.
type ownerFilterWriter struct {
	underlying    http.ResponseWriter
	statusCode    int
	body          bytes.Buffer
	headerWritten bool
	// overflow is set once the buffered body would exceed
	// filter.MaxResponseBodyBytes. Further bytes are discarded so the buffer
	// stays bounded and the caller turns the flag into a 502.
	overflow bool
}

func newOwnerFilterWriter(w http.ResponseWriter) *ownerFilterWriter {
	return &ownerFilterWriter{underlying: w, statusCode: http.StatusOK}
}

func (o *ownerFilterWriter) Header() http.Header  { return o.underlying.Header() }
func (o *ownerFilterWriter) WriteHeader(code int) { o.statusCode = code }

// Write buffers the upstream body until it reaches filter.MaxResponseBodyBytes.
// Past that cap it discards further bytes but still reports them as written, so
// httputil.ReverseProxy completes its copy normally — returning an error here
// would make ReverseProxy panic with http.ErrAbortHandler and skip the clean
// 502 path.
func (o *ownerFilterWriter) Write(b []byte) (int, error) {
	if !o.overflow {
		if int64(o.body.Len())+int64(len(b)) > filter.MaxResponseBodyBytes {
			o.overflow = true
		} else {
			return o.body.Write(b)
		}
	}
	return len(b), nil
}

// flushOwned writes the owner-filtered body to the underlying ResponseWriter.
//
// It returns the names of any top-level response sections this build could not
// classify and therefore removed, so the caller can log them once. See
// responsefilter.FilterSystemDataUsage.
func (o *ownerFilterWriter) flushOwned(opts Options) ([]string, error) {
	// RFC 9110 §15.4.5 / §15.3.5: 204 and 304 must carry an empty body; any
	// bytes written for them downgrade the response to 502.
	if o.statusCode == http.StatusNoContent || o.statusCode == http.StatusNotModified {
		o.underlying.WriteHeader(o.statusCode)
		o.headerWritten = true
		return nil, nil
	}
	// Only a 2xx carries a data-usage payload; forward anything else verbatim.
	if o.statusCode < http.StatusOK || o.statusCode >= http.StatusMultipleChoices {
		o.underlying.WriteHeader(o.statusCode)
		o.headerWritten = true
		_, err := o.underlying.Write(o.body.Bytes())
		return nil, err
	}

	filtered, dropped, err := responsefilter.FilterSystemDataUsage(o.body.Bytes(), func(section responsefilter.SystemDataUsageSection, item json.RawMessage) (bool, error) {
		return systemDataUsageItemOwned(section, item, opts)
	})
	if err != nil {
		return nil, err
	}

	o.underlying.Header().Set("Content-Length", strconv.Itoa(len(filtered)))
	o.underlying.WriteHeader(o.statusCode)
	o.headerWritten = true
	_, err = o.underlying.Write(filtered)
	return dropped, err
}

// systemDataUsageItemOwned reports whether a /system/df item carries this
// proxy's owner label.
//
// The rule is deliberately the same one addOwnerLabelFilter pushes upstream for
// the equivalent list endpoints: an exact `<label_key>=<owner>` match on the
// item's own Labels map. In particular AllowUnownedImages is NOT honored here,
// because it is not honored on GET /images/json either — addOwnerLabelFilter
// replaces the label filter unconditionally, so an unlabeled image is already
// absent from that listing. Matching it keeps the two views consistent, and it
// is the fail-closed direction.
func systemDataUsageItemOwned(section responsefilter.SystemDataUsageSection, raw json.RawMessage, opts Options) (bool, error) {
	kind, ok := systemDataUsageSectionKind(section)
	if !ok {
		// Unreachable today: FilterSystemDataUsage only ever calls this with
		// the sections in its own shape table, and removes every other
		// top-level key outright. Kept fail-closed so that adding a section
		// there before adding it here hides the items rather than forwarding
		// them.
		return false, nil
	}
	var item struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return false, fmt.Errorf("decode %s %s item: %w", responsefilter.SystemDataUsagePath, kind, err)
	}
	if len(item.Labels) == 0 {
		return false, nil
	}
	return item.Labels[opts.LabelKey] == opts.Owner, nil
}

func systemDataUsageSectionKind(section responsefilter.SystemDataUsageSection) (string, bool) {
	switch section {
	case responsefilter.SystemDataUsageContainers:
		return "container", true
	case responsefilter.SystemDataUsageImages:
		return "image", true
	case responsefilter.SystemDataUsageVolumes:
		return "volume", true
	default:
		return "", false
	}
}
