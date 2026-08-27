// Package buildkitproxy — this file carries Phase 5 (issue #185)'s
// mediation of moby.upload.v1.Upload/Pull: buildkitd pulling a client-
// streamed stdin/remote-context upload that a Control/Solve's FrontendAttrs
// named via an "http://buildkit-session/<id>" URL. Verified directly against
// moby/buildkit's session/upload/{upload.go,uploadprovider/provider.go} and
// source/http/transport.go source (not just the vendored .proto/.pb.go
// descriptors):
//
//   - session/upload/uploadprovider/provider.go's Uploader.Add generates the
//     id (`identity.NewID()`) and returns exactly
//     "http://buildkit-session/" + id — the literal host "buildkit-session"
//     and URL shape this file's solveUploadKeys looks for in a Solve's
//     FrontendAttrs.
//   - session/upload/upload.go's client-side New() sets the "urlpath" (
//     keyPath, the URL's Path — "/<id>") and "urlhost" (keyHost, "buildkit-
//     session") gRPC metadata keys before calling Upload.Pull — surfaced as
//     HTTP/2 headers on the mediated call this file reads them back from.
//   - provider.go's Pull HANDLER (run on the CLI/session side, i.e. what
//     sockguard's clientLeg ultimately reaches) reads "urlpath", takes
//     path.Base() of it to recover the bare id, looks it up, and DELETES the
//     map entry immediately (before streaming any bytes) — confirming both
//     the exact id-recovery method (path.Base, not a bare prefix trim) this
//     file mirrors, and that upstream's own one-use semantics are consumed
//     at Pull-start, matching SessionRegistry.ConsumeUploadKey's own
//     consume-before-relay timing.
//   - upload.go's client WriteTo reads the pulled content via
//     `u.cc.RecvMsg(&bm)` — a genuinely, unambiguously BytesMessage-typed
//     decode on both sides (no exporter-negotiated dual wire shape the way
//     FileSend has — see rawByteCapValidator's doc comment in
//     streammediation.go for that contrast) — so, unlike FileSend, Upload's
//     BytesMessage frames are safe to decode and unknown-field-check via the
//     same bytesMessageCapValidator FileSync's response direction doesn't
//     use (FileSync needs its own fsutiltypes.Packet-specific handling
//     instead — see filesync.go) but which fits Upload/Pull's genuinely
//     symmetric, unambiguous BytesMessage shape exactly.
package buildkitproxy

import (
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/upload"
)

// uploadSessionHost is the literal URL host moby/buildkit's
// session/upload/uploadprovider.Uploader.Add embeds in every upload URL it
// hands back to a Solve's FrontendAttrs ("http://buildkit-session/<id>") —
// see this file's package doc for the exact upstream source confirming it.
const uploadSessionHost = "buildkit-session"

// solveUploadKeys scans an admitted SolveRequest's FrontendAttrs for
// "context" and "context:<name>" values shaped like an upload-session URL
// (isRemoteContextRef's own isKnownFrontendAttrKey/checkSolveFrontend gate
// in solve.go already allowed these keys through; this is a second,
// independent pass over the SAME already-admitted attrs, looking for a
// value shape neither of those functions specifically recognizes) and
// returns each id for atomic admission alongside the Solve ref. Called from
// bridge.go's forwardControlMediated after message-policy evaluation — see
// this file's package doc for why the id embedded in
// the URL, not the FrontendAttrs key or value string itself, is what later
// binds a specific Upload/Pull call back to this Solve.
//
// A malformed or non-"buildkit-session" URL value is silently skipped, not
// denied: FrontendAttrs' "context"/"context:<name>" values are already
// fully validated by checkSolveFrontend's own allowlist/remote-context gate
// before this ever runs (evaluateSolveRequest only reaches here on an
// admitted Solve), so a value that isn't an upload-session URL is simply a
// normal local or remote context reference this function has nothing to do
// with — not a new denial surface layered on top of an already-decided
// admission.
//
// Candidate ids are deduplicated and sorted so admission is independent of
// Go's randomized map-iteration order.
func solveUploadKeys(req *control.SolveRequest) []string {
	if req == nil {
		return nil
	}
	var ids []string
	seen := make(map[string]struct{})
	for k, v := range req.GetFrontendAttrs() {
		if k != "context" && !isContextAttrKey(k) {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "http" || u.Host != uploadSessionHost {
			continue
		}
		id := path.Base(u.Path)
		if id == "" || id == "." || id == "/" {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// isContextAttrKey reports whether k is a named-additional-build-context
// FrontendAttrs key ("context:<name>") — the same family
// knownFrontendAttrPrefixes' "context:" entry in solve.go recognizes, kept
// as its own tiny helper here rather than exported from solve.go so this
// file's dependency on solve.go's internals stays limited to the one
// string literal both already independently agree on.
func isContextAttrKey(k string) bool {
	return len(k) > len("context:") && k[:len("context:")] == "context:"
}

// forwardUploadMediated is bridge.go's dispatch target for
// moby.upload.v1.Upload/Pull (see streammediation.go's
// isStreamMediatedMethod/forwardStreamMediated). The one-use token check
// runs BEFORE any stream relay begins — a pre-condition on the whole call —
// mirroring provider.go's own upstream behavior of deleting its map entry
// immediately upon a Pull call starting, before any byte is streamed: see
// this file's package doc.
func (b *bridge) forwardUploadMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	if r.Header.Get("urlhost") != uploadSessionHost {
		writeGRPCStatus(w, grpcCodePermissionDenied, "Upload/Pull target is not a recognized BuildKit upload session")
		b.audit(service, method, Deny, "buildkit_upload_token_invalid")
		b.recordDeniedAndMaybeClose()
		return
	}
	id := path.Base(r.Header.Get("urlpath"))
	if id == "" || id == "." || id == "/" || !b.registry.ConsumeUploadKey(b.session.Key, b.session.ClientUUID, id) {
		writeGRPCStatus(w, grpcCodePermissionDenied, "Upload/Pull token is not a currently valid, admitted upload for this client/profile")
		b.audit(service, method, Deny, "buildkit_upload_token_invalid")
		b.recordDeniedAndMaybeClose()
		return
	}

	reqCap := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: b.limits.MaxUploadBytes}
	respCap := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: b.limits.MaxUploadBytes}

	b.forwardStreamRelay(w, r, service, method, reqCap.validate, func(w http.ResponseWriter, src io.Reader) (*mediationDenial, error) {
		return relayValidatedFrames(w, src, b.limits.MaxMessageBytes, respCap.validate)
	})
}
