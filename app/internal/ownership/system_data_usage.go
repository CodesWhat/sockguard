package ownership

import (
	"bytes"
	"encoding/json"
	"errors"
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
	reasonCodeOwnerNotModified             = "owner_not_modified_unfilterable"
)

// ownerNotModifiedRefusalMessage is the client-facing reason for the 304
// refusal, worded like the visibility middleware's so the two layers read the
// same in an audit sink; only the reason code says which one refused.
const ownerNotModifiedRefusalMessage = "upstream returned 304 Not Modified for an owner-filtered read"

// errNotModifiedUnfilterable marks the 304 refusal so
// filterSystemDataUsageResponse can give it its own reason code rather than
// the generic filter-failure one. See flushOwned.
var errNotModifiedUnfilterable = errors.New(ownerNotModifiedRefusalMessage)

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
// filtered item by item. HEAD on the same route has no body to filter but
// still carries the daemon's Content-Length and ETag for the whole host
// inventory, so it is answered with those removed rather than forwarded — see
// forwardHeadWithoutUpstreamRepresentation. GET /libpod/system/df returns Podman's own report
// shape, whose entries carry no labels at all, so there is nothing to filter
// on and it is refused instead — see
// responsefilter.LibpodSystemDataUsageDenyReason for the shape and the
// reasoning. The refusals also cover HEAD: nothing here has a body-filtering
// step for HEAD to legitimately need, so gating on GET alone would forward it
// straight to the daemon — exactly the unscoped host-inventory disclosure this
// function exists to prevent.
//
// Five more libpod reads have that same no-labels, no-`filters` shape and are
// refused before ordinary ownership evaluation: showmounted, container stats,
// pod stats and the two manifest reads. They cannot wait until this
// allowed-response path because two of their collection words also classify as
// container names, and rollout handling for a foreign container verdict can
// pass through directly.
func serveOwnershipAllowed(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, normPath string, opts Options) {
	if normPath == responsefilter.SystemDataUsagePath {
		switch r.Method {
		case http.MethodGet:
			filterSystemDataUsageResponse(logger, next, w, r, opts)
			return
		case http.MethodHead:
			forwardHeadWithoutUpstreamRepresentation(logger, next, w, r)
			return
		}
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && normPath == responsefilter.LibpodSystemDataUsagePath {
		denyLibpodSystemDataUsage(w, r)
		return
	}
	next.ServeHTTP(w, r)
}

// denyUnscopeableLibpodRead refuses one of filter.LibpodUnscopeableReads() with
// a 403 before any resource inspect or proxied request, so the host inventory,
// the daemon host's mount paths and the cross-owner ID sets in those bodies
// are never read, let alone relayed. Like denyLibpodSystemDataUsage it is
// unconditional: a warn-mode deployment forwarding the body is the exact
// disclosure this closes.
//
// The reason code is assembled from the entry's stem rather than switched on,
// so an endpoint added to that table cannot land here without one.
func denyUnscopeableLibpodRead(w http.ResponseWriter, r *http.Request, read filter.LibpodUnscopeableRead) {
	logging.SetDeniedWithCode(w, r, "owner_libpod_"+read.ReasonCodeStem+"_unscopeable", read.Reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: read.Reason})
}

// denyUnscopeableLibpodWrite refuses one of filter.LibpodUnscopeableWrites()
// with a 403 before the daemon is contacted, so the host-wide change it would
// make never happens.
//
// It is the write-side twin of denyUnscopeableLibpodRead, down to assembling
// the reason code from the entry's stem, and it is unconditional for a
// sharper version of the same reason: the read refusals exist so a body is
// never disclosed, and this one exists so another owner's resources are never
// destroyed. Neither is a verdict warn mode can usefully stage.
func denyUnscopeableLibpodWrite(w http.ResponseWriter, r *http.Request, write filter.LibpodUnscopeableWrite) {
	logging.SetDeniedWithCode(w, r, "owner_libpod_"+write.ReasonCodeStem+"_unscopeable", write.Reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: write.Reason})
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

// forwardHeadWithoutUpstreamRepresentation forwards HEAD /system/df with the
// daemon's representation metadata removed.
//
// It is the owner-isolation twin of the visibility middleware's function of
// the same name, and it is here for the same reason on the same route: a HEAD
// comes back as headers only, so there is no body to classify by owner, while
// the daemon's Content-Length and ETag still describe the whole host
// inventory. The length is a count of every container, image and volume on the
// host, including every other owner's, which is the disclosure
// filterSystemDataUsageResponse exists to prevent for the GET.
//
// The two layers nest — visibility wraps ownership — so a deployment running
// both had this closed by the visibility layer alone. Owner isolation without
// a visibility policy did not, which is why it is fixed at both.
//
// A recorded 304 is refused rather than answered, the same way flushOwned
// refuses one on the GET path: the daemon is confirming a previously fetched
// inventory is still current, and this proxy cannot vouch for what owner
// isolation that inventory was fetched under. Conditional request headers are
// stripped before they reach the daemon (see
// responsefilter.StripConditionalRequestHeaders), so a real daemon cannot
// produce this status on this path; the check stays unconditional anyway
// because the fail-closed claim in docs/content/docs/security.mdx does not
// carve out a method.
func forwardHeadWithoutUpstreamRepresentation(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request) {
	interceptingW := newOwnerFilterWriter(w)
	next.ServeHTTP(interceptingW, r)
	if interceptingW.statusCode == http.StatusNotModified {
		logger.ErrorContext(r.Context(), ownerNotModifiedRefusalMessage,
			"method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
		logging.SetDeniedWithCode(w, r, reasonCodeOwnerNotModified, ownerNotModifiedRefusalMessage, nil)
		responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
		_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: ownerNotModifiedRefusalMessage})
		return
	}
	// Anything buffered is dropped rather than relayed. A daemon sends no body
	// on a HEAD, and one that does is not answering the request that was made.
	responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
	w.WriteHeader(interceptingW.statusCode)
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
			reasonCode, message := reasonCodeOwnerResponseFilterFail, "owner response filter failed"
			// A 304 is not a filter that failed, it is a response shape the
			// filter cannot act on, and the fix is on the upstream rather than
			// in the ownership config. Its own code keeps the two apart in an
			// audit sink.
			if errors.Is(err, errNotModifiedUnfilterable) {
				reasonCode, message = reasonCodeOwnerNotModified, ownerNotModifiedRefusalMessage
			}
			logging.SetDeniedWithCode(w, r, reasonCode, message, nil)
			responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
			_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: message})
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
	// A 304 is refused rather than forwarded, the same way an undecodable
	// /system/df body is. It carries nothing to classify by owner, and
	// confirming the client's cached copy hands back a host inventory that was
	// fetched under whatever isolation was configured at the time. Nothing is
	// written and headerWritten stays false, so the caller substitutes the 502.
	//
	// Requests leave this proxy with their conditional headers stripped (see
	// responsefilter.StripConditionalRequestHeaders), so a daemon has nothing
	// to revalidate against and cannot reach this branch.
	if o.statusCode == http.StatusNotModified {
		return nil, errNotModifiedUnfilterable
	}
	// RFC 9110 §15.4.5: a 204 must carry an empty body; any bytes written for
	// it downgrade the response to 502. Unlike a 304 it is not a revalidation,
	// so it still passes through: there is no stale inventory behind it for
	// the client to fall back on.
	if o.statusCode == http.StatusNoContent {
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

	// The filtered body is not the daemon's, so the daemon's ETag,
	// Content-Encoding, Content-Range and Trailer announcement all describe
	// bytes the client will never see. Clear them the way this file's two 502
	// paths already do, then set the Content-Length that does describe what
	// goes out (the clear removes the upstream's).
	responsefilter.ClearUpstreamRepresentationHeaders(o.underlying.Header())
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
// always sends the owner label upstream, so an unlabeled image is already
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
