package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// image_pull_postcheck.go closes the pull half of a forged owner label.
//
// A registry image carries whatever labels its publisher put in its config,
// the owner label among them, and nothing can read them before the pull
// without a registry fetch of our own. A client could pull
// `attacker/app:v2`, labeled owner=victim, under a name no one holds, and the
// image would then pass the victim's ownership checks.
//
// So when the pull has finished upstream, the references it wrote are
// inspected, and one whose image carries another owner's label is untagged and
// reported on the progress stream the client is still reading. A pull's
// response is a stream of JSON lines that ends when the daemon closes it, so
// a final line can still be added after the proxy has copied the daemon's last
// one.

const (
	// imagePullPostCheckTimeout bounds the inspects and untags that follow a
	// pull. They run on a context detached from the client's, so a client that
	// hangs up as the pull ends cannot skip the check.
	imagePullPostCheckTimeout = 30 * time.Second

	imagePullForeignLabelReason  = "it carries another owner's label"
	imagePullUnverifiedReason    = "its owner label could not be verified"
	imagePullRemovalFailedFormat = "owner policy could not remove pulled image %s: it carries another owner's label or could not be verified, and the untag failed"
)

// postPullChecks are the upstream calls the check after a pull makes. Both go
// through the same transport as the proxied request. inspect is not the
// request-memoized one: the pull has just changed what the names point at.
type postPullChecks struct {
	inspect func(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error)
	untag   func(ctx context.Context, reference string, libpod bool) error
}

func refsImageDestinations(refs *ownershipRequestReferences) *imageDestinationReferences {
	if refs == nil {
		return nil
	}
	return refs.imageDestinations
}

// isImagePullDestinations reports whether refs came from a pull, and whether
// from Podman's native route.
func isImagePullDestinations(refs *imageDestinationReferences) (pull, libpod bool) {
	if refs == nil || len(refs.destinations) == 0 {
		return false, false
	}
	switch refs.route {
	case imagePullRoute:
		return true, false
	case libpodImagePullRoute:
		return true, true
	}
	return false, false
}

// pullStreamWriter passes a pull's progress stream through as it arrives and
// remembers the status it carried, so the check afterwards knows whether the
// pull answered at all.
type pullStreamWriter struct {
	http.ResponseWriter
	status int
}

func (p *pullStreamWriter) WriteHeader(code int) {
	if p.status == 0 {
		p.status = code
	}
	p.ResponseWriter.WriteHeader(code)
}

func (p *pullStreamWriter) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	return p.ResponseWriter.Write(b)
}

func (p *pullStreamWriter) Flush() {
	if f, ok := p.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *pullStreamWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// RequestMeta keeps the access-log metadata reachable through this wrapper.
func (p *pullStreamWriter) RequestMeta() *logging.RequestMeta {
	return logging.MetaFromResponseWriter(p.ResponseWriter)
}

// servePullWithOwnerCheck forwards a pull and then checks the references it
// wrote. See the file comment.
//
// Every reference the pull could have written is looked at, and each whose
// image carries an owner label other than the caller's is untagged and named
// in an error line at the end of the stream. A reference nothing holds after
// the pull (the pull failed, or wrote it under the other name of a pair) is
// skipped. An inspect that fails is treated as a foreign label, which is the
// fail-closed side: the name is untagged rather than left for the next owner
// check to find. An image with no owner label, or the caller's own, is left
// alone.
func servePullWithOwnerCheck(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, refs *imageDestinationReferences, libpod bool, opts Options, post *postPullChecks) {
	pw := &pullStreamWriter{ResponseWriter: w}
	next.ServeHTTP(pw, r)
	if pw.status < http.StatusOK || pw.status >= http.StatusMultipleChoices {
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), imagePullPostCheckTimeout)
	defer cancel()

	seen := map[string]struct{}{}
	var lines []string
	for _, dest := range refs.destinations {
		for _, ref := range []string{dest.target, dest.storedTarget} {
			if ref == "" {
				continue
			}
			if _, done := seen[ref]; done {
				continue
			}
			seen[ref] = struct{}{}
			if line := checkPulledReference(ctx, logger, r, ref, libpod, opts, post); line != "" {
				lines = append(lines, line)
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	if encoding := strings.TrimSpace(w.Header().Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		// An intermediary compressed a stream the proxy asked for identity.
		// A plain line appended to it would corrupt the stream, and the
		// untag has already happened.
		logger.WarnContext(ctx, "owner policy could not report a removed pulled image on a compressed stream", "path", logging.SafeString(r.URL.Path))
		return
	}
	for _, line := range lines {
		if _, err := io.WriteString(pw, line+"\n"); err != nil {
			return
		}
	}
	pw.Flush()
}

// checkPulledReference inspects one reference a pull wrote and, when its image
// is another owner's, untags it. It returns the progress line to append, or ""
// when the reference is fine.
func checkPulledReference(ctx context.Context, logger *slog.Logger, r *http.Request, ref string, libpod bool, opts Options, post *postPullChecks) string {
	labels, found, err := post.inspect(ctx, dockerresource.KindImage, ref)
	reason := imagePullForeignLabelReason
	switch {
	case err != nil:
		reason = imagePullUnverifiedReason
	case !found:
		return ""
	default:
		value := labels[opts.LabelKey]
		if value == "" || value == opts.Owner {
			return ""
		}
	}

	if untagErr := post.untag(ctx, ref, libpod); untagErr != nil {
		logger.ErrorContext(ctx, "owner policy could not untag a pulled image",
			"reference", logging.SafeString(ref), "reason", reason, "error", logging.SafeString(untagErr.Error()), "path", logging.SafeString(r.URL.Path))
		return imagePullProgressError(libpod, fmt.Sprintf(imagePullRemovalFailedFormat, ref))
	}
	logger.WarnContext(ctx, "owner policy removed a pulled image",
		"reference", logging.SafeString(ref), "reason", reason, "path", logging.SafeString(r.URL.Path))
	return imagePullProgressError(libpod, fmt.Sprintf("owner policy removed pulled image %s: %s", ref, reason))
}

// imagePullProgressError is one error line in the shape the route's progress
// stream uses. Docker's carries the message twice, as `errorDetail.message`,
// which the Docker CLI and SDKs read, and as the older `error` string. Podman's
// native pull reports through the `error` field of its pull report.
func imagePullProgressError(libpod bool, message string) string {
	var payload any = map[string]string{"error": message}
	if !libpod {
		payload = struct {
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
			Error string `json:"error"`
		}{ErrorDetail: struct {
			Message string `json:"message"`
		}{Message: message}, Error: message}
	}
	line, err := json.Marshal(payload)
	if err != nil {
		return `{"error":"owner policy removed a pulled image"}`
	}
	return string(line)
}

// untagImage removes a reference the proxy's upstream holds. Both engines
// untag when the name is a reference, and drop the image only when it was the
// last name on it. A name that is already gone is a success.
func (u upstreamInspector) untagImage(ctx context.Context, reference string, libpod bool) error {
	prefix := "/images/"
	if libpod {
		prefix = libpodPrefix + "images/"
	}
	target := (&url.URL{Path: prefix + reference}).EscapedPath()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker"+target, nil) // #nosec G704 -- reference is a name this layer already parsed against the image reference grammar.
	if err != nil {
		return fmt.Errorf("build untag request: %w", err)
	}
	resp, err := u.client.Do(req) // #nosec G704 -- the inspector client targets the local container-engine socket, not the URL host.
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	default:
		return fmt.Errorf("untag %q: upstream returned %s", reference, resp.Status)
	}
}
