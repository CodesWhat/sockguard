package ownership

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/bodycodec"
	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/responsefilter"
)

const volumeCreateForeignResponseReason = "owner policy denied access to volume"

// mutateVolumeCreateOwnershipBody stamps the owner label into a volume create
// and returns the volume the body names, if any.
//
// A create that names a volume which already exists does not fail on either
// engine: the daemon answers with the stored volume, its Labels, Driver and
// Options included (moby volume/service Create returns the existing volume,
// Podman's compat and native handlers do the same). Stamping the body alone
// therefore lets a tenant read another owner's volume metadata by naming it.
// The name goes to the existing-resource check, which passes a name nothing
// holds and denies one another owner or nobody holds. Docker and Podman both
// decode the body's keys case-insensitively, so every case variant of Name is
// collected.
func mutateVolumeCreateOwnershipBody(r *http.Request, labelKey, owner, labelField string) (*ownershipRequestReferences, error) {
	refs := &ownershipRequestReferences{}
	err := mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := filter.NestedObject(decoded, labelField)
		if err != nil {
			return err
		}
		labels[labelKey] = owner
		for _, name := range filter.FoldedStrings(decoded, "Name") {
			appendEmbeddedOwnershipReference(&refs.existingResources, dockerresource.KindVolume, name, "volume create Name")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return refs, nil
}

// serveVolumeCreateOwned forwards a volume create and checks the volume it
// returns before any byte reaches the client.
//
// The preflight lookup cannot close the window between it and the daemon's
// create: another owner can create the same name in between, and the daemon
// then answers this request with that volume. The returned Labels are the
// authority, so a success whose owner label is not this proxy's is replaced by
// a refusal and the foreign metadata is dropped unread.
func serveVolumeCreateOwned(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, opts Options) {
	interceptingW := newOwnerFilterWriter(w)
	next.ServeHTTP(interceptingW, r)

	if interceptingW.overflow {
		logger.ErrorContext(r.Context(), "owner volume create check: upstream response exceeds size limit",
			"limit_bytes", filter.ResponseBodyLimit(), "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
		logging.SetDeniedWithCode(w, r, reasonCodeOwnerResponseTooLarge, filter.ResponseTooLargeMessage(), nil)
		responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
		_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: filter.ResponseTooLargeMessage()})
		return
	}

	status := interceptingW.statusCode
	if status >= http.StatusOK && status < http.StatusMultipleChoices && status != http.StatusNoContent {
		owned, err := volumeCreateResponseOwned(w.Header(), interceptingW.body.Bytes(), opts)
		if err != nil {
			logger.ErrorContext(r.Context(), "owner volume create check failed", "error", logging.SafeString(err.Error()))
			logging.SetDeniedWithCode(w, r, reasonCodeOwnerResponseFilterFail, "owner response filter failed", nil)
			responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
			_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "owner response filter failed"})
			return
		}
		if !owned {
			if meta := logging.MetaForRequest(w, r); meta.AllowsPassThrough() {
				logging.SetWouldDenyWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, volumeCreateForeignResponseReason, nil)
			} else {
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, volumeCreateForeignResponseReason, nil)
				responsefilter.ClearUpstreamRepresentationHeaders(w.Header())
				_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: volumeCreateForeignResponseReason})
				return
			}
		}
	}

	// Verbatim: the body was only read, so it keeps the daemon's headers and
	// coding.
	w.WriteHeader(status)
	_, _ = w.Write(interceptingW.body.Bytes())
}

// volumeCreateResponseOwned reports whether a created volume's own Labels carry
// this proxy's owner label. Docker's response is volume.Volume and Podman's
// compat and native responses carry the same Labels key.
func volumeCreateResponseOwned(header http.Header, raw []byte, opts Options) (bool, error) {
	body, err := bodycodec.Bytes(header, raw, filter.ResponseBodyLimit())
	if err != nil {
		return false, err
	}
	var volume struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(strings.NewReader(string(body))).Decode(&volume); err != nil {
		return false, fmt.Errorf("decode volume create response: %w", err)
	}
	return volume.Labels[opts.LabelKey] == opts.Owner, nil
}
