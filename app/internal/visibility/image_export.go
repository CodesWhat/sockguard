package visibility

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/imageselector"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

const reasonCodeVisibilityImageExport = "visibility_image_export_unscopeable"

type imageExportRoute uint8

const (
	imageExportRouteNone imageExportRoute = iota
	imageExportRouteDockerBatch
	imageExportRouteDockerSingle
	imageExportRouteLibpodBatch
)

func handleVisibilityImageExportRequest(logger *slog.Logger, next http.Handler, deps visibilityDeps, w http.ResponseWriter, r *http.Request, normPath string, policy *compiledPolicy) bool {
	switch classifyImageExportRoute(r.Method, normPath) {
	case imageExportRouteNone:
		return false
	case imageExportRouteDockerSingle:
		denyUnscopeableDockerImageExport(next, w, r)
		return true
	case imageExportRouteDockerBatch:
		references, err := selectedImageExportReferences(r.URL.RawQuery, "names")
		if err != nil {
			writeInvalidImageExportQuery(w, r, err)
			return true
		}
		if len(references) > 0 {
			denyUnscopeableDockerImageExport(next, w, r)
			return true
		}
		return false
	case imageExportRouteLibpodBatch:
		return handleVisibilityLibpodImageExport(logger, next, deps, w, r, policy)
	default:
		return false
	}
}

// classifyImageExportRoute identifies the three export routes this file gates.
//
// HEAD is classified alongside GET, matching the libpod disk-usage and
// unscopeable-read gates above it in the middleware. Moby and Podman register
// all three routes GET-only today, so a HEAD reaches a 405 rather than an
// exporter, but that is the daemon's routing table rather than a property of
// the request: gating on GET alone would forward the HEAD to the daemon and
// leave the refusal depending on an upstream detail this proxy does not
// control.
func classifyImageExportRoute(method, normPath string) imageExportRoute {
	if method != http.MethodGet && method != http.MethodHead {
		return imageExportRouteNone
	}
	switch normPath {
	case "/images/get":
		return imageExportRouteDockerBatch
	case libpodPrefix + "images/export":
		return imageExportRouteLibpodBatch
	}
	if _, ok := readSubresourceIdentifier(normPath, "/images/", "get"); ok {
		return imageExportRouteDockerSingle
	}
	return imageExportRouteNone
}

func selectedImageExportReferences(rawQuery, key string) ([]string, error) {
	query, err := imageselector.Parse(rawQuery)
	if err != nil {
		return nil, err
	}
	return query.References(key)
}

// handleVisibilityLibpodImageExport preflights every selected reference on
// GET /libpod/images/export before the daemon sees the batch.
//
// A member splits three ways, and only one of the three is a hard failure:
//
//   - A lookup error is not a verdict. Nothing is known about the member, so
//     there is no "would deny" to record and the request fails closed with a
//     502 in every rollout mode. The same goes for a malformed query, which is
//     rejected by the caller before any lookup runs.
//   - A member the policy resolves but hides is a verdict.
//   - A member the policy cannot resolve at all is also a verdict: unlike the
//     single-resource inspect path, where resourceVisibleWithPolicy passes a
//     missing resource through and lets the daemon answer its own 404, a batch
//     member the proxy cannot resolve may still resolve upstream, and the
//     answer is a tar of image content rather than a not-found. Ownership
//     refuses an unresolvable batch member for the same reason.
//
// Both verdicts are deferred to one decision after the loop rather than
// returned on the spot. That keeps them from masking a later member's lookup
// failure, and it makes them honor the rollout mode the way every other
// request-side verdict does: warn and audit record would_deny and forward, so
// an operator staging the policy sees the log entry without the refusal. The
// unconditional refusals in this package (the two event streams, the libpod
// disk-usage and showmounted reads) are response-side controls where
// forwarding IS the disclosure; a preflight verdict on a request is not.
func handleVisibilityLibpodImageExport(logger *slog.Logger, next http.Handler, deps visibilityDeps, w http.ResponseWriter, r *http.Request, policy *compiledPolicy) bool {
	references, err := selectedImageExportReferences(r.URL.RawQuery, "references")
	if err != nil {
		writeInvalidImageExportQuery(w, r, err)
		return true
	}
	hidden := false
	for _, reference := range references {
		visible, found, err := lookupResourceVisibilityWithPolicy(r.Context(), deps, dockerresource.KindImage, reference, policy)
		if err != nil {
			logger.ErrorContext(r.Context(), "visibility policy lookup failed", "error", logging.SafeString(err.Error()), "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
			logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyLookupFailed, "visibility policy lookup failed", nil)
			_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "visibility policy lookup failed"})
			return true
		}
		hidden = hidden || !found || !visible
	}
	if hidden {
		reason := "libpod visibility policy hid resource"
		if meta := logging.MetaForRequest(w, r); meta.AllowsPassThrough() {
			logging.SetWouldDenyWithCode(w, r, reasonCodeVisibilityPolicyHidResource, reason, nil)
			next.ServeHTTP(w, r)
			return true
		}
		logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyHidResource, reason, nil)
		_ = httpjson.Write(w, http.StatusNotFound, httpjson.ErrorResponse{Message: "resource not found"})
		return true
	}
	next.ServeHTTP(w, r)
	return true
}

// denyUnscopeableDockerImageExport refuses a named Docker-compatible export
// before any image lookup or upstream request.
//
// It honors the rollout mode because ownership's refusal of the same two
// routes does: that one is an ordinary verdict returned from
// imageEffectDenial / parseImageBatchOwnershipReferences and passes through
// the shared warn/audit branch in the ownership middleware. The chain runs
// filter, then visibility, then ownership, so a visibility layer that refused
// unconditionally would decide a warn-mode request before ownership could
// record its own would_deny, and the same request would behave differently
// depending on which of the two layers an operator had configured.
func denyUnscopeableDockerImageExport(next http.Handler, w http.ResponseWriter, r *http.Request) {
	reason := "Docker-compatible image export denied: selected platform effects cannot be fully authorized"
	if meta := logging.MetaForRequest(w, r); meta.AllowsPassThrough() {
		logging.SetWouldDenyWithCode(w, r, reasonCodeVisibilityImageExport, reason, nil)
		next.ServeHTTP(w, r)
		return
	}
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityImageExport, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}

func writeInvalidImageExportQuery(w http.ResponseWriter, r *http.Request, err error) {
	reason := fmt.Sprintf("invalid image export query: %v", err)
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityFilterInvalid, reason, nil)
	_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: reason})
}
