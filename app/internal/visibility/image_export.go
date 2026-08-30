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
		denyUnscopeableDockerImageExport(w, r)
		return true
	case imageExportRouteDockerBatch:
		references, err := selectedImageExportReferences(r.URL.RawQuery, "names")
		if err != nil {
			writeInvalidImageExportQuery(w, r, err)
			return true
		}
		if len(references) > 0 {
			denyUnscopeableDockerImageExport(w, r)
			return true
		}
		return false
	case imageExportRouteLibpodBatch:
		return handleVisibilityLibpodImageExport(logger, next, deps, w, r, policy)
	default:
		return false
	}
}

func classifyImageExportRoute(method, normPath string) imageExportRoute {
	if method != http.MethodGet {
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

func handleVisibilityLibpodImageExport(logger *slog.Logger, next http.Handler, deps visibilityDeps, w http.ResponseWriter, r *http.Request, policy *compiledPolicy) bool {
	references, err := selectedImageExportReferences(r.URL.RawQuery, "references")
	if err != nil {
		writeInvalidImageExportQuery(w, r, err)
		return true
	}
	for _, reference := range references {
		visible, found, err := lookupResourceVisibilityWithPolicy(r.Context(), deps, dockerresource.KindImage, reference, policy)
		if err != nil {
			logger.ErrorContext(r.Context(), "visibility policy lookup failed", "error", logging.SafeString(err.Error()), "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
			logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyLookupFailed, "visibility policy lookup failed", nil)
			_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "visibility policy lookup failed"})
			return true
		}
		if !found || !visible {
			logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyHidResource, "libpod visibility policy hid resource", nil)
			_ = httpjson.Write(w, http.StatusNotFound, httpjson.ErrorResponse{Message: "resource not found"})
			return true
		}
	}
	next.ServeHTTP(w, r)
	return true
}

func denyUnscopeableDockerImageExport(w http.ResponseWriter, r *http.Request) {
	reason := "Docker-compatible image export denied: selected platform effects cannot be fully authorized"
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityImageExport, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}

func writeInvalidImageExportQuery(w http.ResponseWriter, r *http.Request, err error) {
	reason := fmt.Sprintf("invalid image export query: %v", err)
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityFilterInvalid, reason, nil)
	_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: reason})
}
