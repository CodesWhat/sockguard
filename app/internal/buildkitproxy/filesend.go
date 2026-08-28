// Package buildkitproxy — this file carries Phase 5 (issue #185)'s
// mediation of moby.filesync.v1.FileSend/DiffCopy: buildkitd exporting a
// build's output (a local directory tree, a tarball, an OCI layout, etc)
// back to the client. Per the #185 synthesis, FileSend is admitted only when
// bound to an admitted Control/Solve from the same principal, profile, and
// BuildKit session ID, and gets byte
// caps but — deliberately — no content inspection; see
// rawByteCapValidator's doc comment in streammediation.go for the concrete,
// source-verified reason FileSend cannot safely be decoded as any one
// message shape the way FileSync/Upload can.
package buildkitproxy

import (
	"io"
	"net/http"
)

// forwardFileSendMediated is bridge.go's dispatch target for
// moby.filesync.v1.FileSend/DiffCopy (see streammediation.go's
// isStreamMediatedMethod/forwardStreamMediated).
//
// The SessionRegistry.HasAdmittedSolve check runs BEFORE any stream relay
// begins — a pre-condition on the whole call, not a per-message check — per
// the #185 synthesis's "allow only when bound to an admitted Solve from the
// same correlated BuildKit session" (buildkit_session_mismatch on failure). FileSend's
// BytesMessage.Data carries no ref or other identifying field of its own to
// check with a more specific SessionRegistry.OwnsRef lookup (unlike
// Control/Status, which names the ref it's asking about directly) — "has
// this principal/profile/session scope solved anything at all yet" is the strongest check
// available; see HasAdmittedSolve's own doc comment.
func (b *bridge) forwardFileSendMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	if !b.registry.HasAdmittedSolve(b.session.Key, b.session.ClientUUID) {
		writeGRPCStatus(w, grpcCodePermissionDenied, "FileSend requires an admitted BuildKit solve for this client/profile")
		b.audit(service, method, Deny, "buildkit_session_mismatch")
		b.recordDeniedAndMaybeClose()
		return
	}

	reqCap := &rawByteCapValidator{maxTotalBytes: b.limits.MaxFileSendBytes}
	respCap := &rawByteCapValidator{maxTotalBytes: b.limits.MaxFileSendBytes}

	b.forwardStreamRelay(w, r, service, method, reqCap.validate, func(w http.ResponseWriter, src io.Reader) (*mediationDenial, error) {
		return relayValidatedFrames(w, src, b.limits.MaxMessageBytes, respCap.validate)
	})
}
