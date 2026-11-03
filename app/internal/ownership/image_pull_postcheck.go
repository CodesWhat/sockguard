package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
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
//
// A reference the requester already held is not lost to the pull: the image ID
// it pointed at is read before the pull is forwarded, and when the pull moved
// the name onto a foreign image the name goes back to that ID.
//
// Podman's native pull reports the IDs of the images it pulled in its final
// stream object. A short name that registries.conf resolved to a registry the
// computed references do not spell is caught through those IDs. The names on
// such an image are removed when the image did not exist before the pull, which
// a list of the images under the requested reference, taken before the pull,
// tells. A name on an image that was already there is only reported.
//
// A pull by digest has no destination name, and the image it fetches is
// addressable by repository@digest. That reference is inspected after the pull
// and only reported when its image is another owner's. A digest reference pins
// its content, so a client cannot make a victim's reference resolve to other
// bytes, and removing by digest could drop an image other names still hold.

const (
	// imagePullPostCheckTimeout bounds the inspects and untags that follow a
	// pull. They run on a context detached from the client's, so a client that
	// hangs up as the pull ends cannot skip the check.
	imagePullPostCheckTimeout = 30 * time.Second

	imagePullForeignLabelReason  = "it carries another owner's label"
	imagePullUnverifiedReason    = "its owner label could not be verified"
	imagePullRemovalFailedFormat = "owner policy could not remove pulled image %s: it carries another owner's label or could not be verified, and the untag failed"
	imagePullUnnamedFormat       = "owner policy could not remove pulled image %s: it carries another owner's label and is named outside the references this pull was checked under"
	imagePullRestoreFailedFormat = "owner policy removed pulled image %s: %s, but could not restore the image the reference named before"
	imagePullNotVerifiedFormat   = "owner policy could not verify pulled image %s"

	// pullStreamLineLimit bounds one progress line kept for parsing, and
	// maxPulledImageIDs the image IDs a libpod pull report is followed for.
	pullStreamLineLimit = 1 << 20
	maxPulledImageIDs   = 64

	// maxPrePullImages bounds the images the list taken before a libpod pull
	// may hold. A longer list is not trusted as a record of what existed, and
	// the names found by ID after the pull stay report-only.
	maxPrePullImages = 256

	imagePullDigestKeptFormat = "owner policy: pulled image %s carries another owner's label; it was left in place because a digest reference pins its content"
	imagePullMovedFormat      = "owner policy left %s in place: it no longer names the image this pull reported"
)

// pulledImage is what an image inspect gives the check after a pull.
type pulledImage struct {
	id       string
	labels   map[string]string
	repoTags []string
}

// listedImage is one entry of the list taken before a libpod pull.
type listedImage struct {
	id    string
	names []string
}

// postPullChecks are the upstream calls the check after a pull makes. All go
// through the same transport as the proxied request. inspect is not the
// request-memoized one: the pull has just changed what the names point at.
type postPullChecks struct {
	inspect func(ctx context.Context, reference string) (pulledImage, bool, error)
	untag   func(ctx context.Context, reference string, libpod, force bool) error
	retag   func(ctx context.Context, imageID, reference string, libpod bool) error
	// list returns the images whose names match a reference, or an error when
	// the answer is longer than maxPrePullImages or cannot be read.
	list func(ctx context.Context, reference string) ([]listedImage, error)
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
	if refs == nil || (len(refs.destinations) == 0 && len(refs.digests) == 0) {
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
// remembers what it carried: the status, whether any line reported an error,
// and the image IDs a libpod pull report names. The check afterwards needs
// them to know whether the pull answered at all.
type pullStreamWriter struct {
	http.ResponseWriter
	status int

	pending  []byte
	oversize bool
	failed   bool
	unparsed bool
	images   []string
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
	n, err := p.ResponseWriter.Write(b)
	p.scan(b[:n])
	return n, err
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

// scan splits the bytes written into JSON lines and reads each as it
// completes. A line past pullStreamLineLimit is dropped and counts as unparsed.
func (p *pullStreamWriter) scan(b []byte) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			p.keep(b)
			return
		}
		p.keep(b[:i])
		p.endLine()
		b = b[i+1:]
	}
}

func (p *pullStreamWriter) keep(b []byte) {
	if p.oversize {
		return
	}
	if len(p.pending)+len(b) > pullStreamLineLimit {
		p.oversize = true
		p.pending = nil
		return
	}
	p.pending = append(p.pending, b...)
}

func (p *pullStreamWriter) endLine() {
	line := p.pending
	p.pending = nil
	if p.oversize {
		p.oversize = false
		p.unparsed = true
		return
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return
	}
	var report struct {
		Error       string `json:"error"`
		ErrorDetail *struct {
			Message string `json:"message"`
		} `json:"errorDetail"`
		Status string   `json:"status"`
		Images []string `json:"images"`
		ID     string   `json:"id"`
	}
	if err := json.Unmarshal(line, &report); err != nil {
		p.unparsed = true
		return
	}
	if report.Error != "" || report.ErrorDetail != nil || report.Status == "error" {
		p.failed = true
	}
	for _, id := range append(report.Images, report.ID) {
		if id != "" && len(p.images) < maxPulledImageIDs && !slices.Contains(p.images, id) {
			p.images = append(p.images, id)
		}
	}
}

// finish reads a last line the daemon ended without a newline.
func (p *pullStreamWriter) finish() {
	if len(p.pending) > 0 || p.oversize {
		p.endLine()
	}
}

// succeeded reports a pull that answered 2xx and whose stream carried no
// error line and nothing this check could not read.
func (p *pullStreamWriter) succeeded() bool {
	return p.status >= http.StatusOK && p.status < http.StatusMultipleChoices && !p.failed && !p.unparsed
}

// pullCheck is the state of one pull's check.
type pullCheck struct {
	logger *slog.Logger
	r      *http.Request
	libpod bool
	// force sends the untag with force=1. On dockerd that lets removing a
	// reference succeed when a container uses the image, and still removes
	// only that name. On Podman force also removes the containers using the
	// image, so it is sent only on a positive Docker probe, never on Podman,
	// an unresolved or auto flavor, or the native route.
	force  bool
	opts   Options
	post   *postPullChecks
	before map[string]string // reference -> image ID it named before the pull
	// handled holds the names a removal was attempted on.
	handled map[string]struct{}
	lines   []string
	// preIDs are the image IDs the list taken before a libpod pull held, bare
	// of any "sha256:" prefix. preKnown is false when that list could not be
	// taken, and every image is then treated as one that was already there.
	preIDs   map[string]struct{}
	preKnown bool
}

// namesRequestedReference reports whether name is the requested reference
// spelled out by a registry: the same tag, and a repository the requested one
// is a path suffix of. It is how libimage reads the reference filter of its
// list, and what a name registries.conf resolved a short name to looks like.
func namesRequestedReference(refs *imageDestinationReferences, name string) bool {
	nameRepo, nameTag, ok := splitNameTag(name)
	if !ok {
		return false
	}
	for _, dest := range refs.destinations {
		repo, tag, ok := splitNameTag(dest.target)
		if ok && repo != "" && tag == nameTag && (nameRepo == repo || strings.HasSuffix(nameRepo, "/"+repo)) {
			return true
		}
	}
	return false
}

func splitNameTag(ref string) (repo, tag string, ok bool) {
	colon := strings.LastIndex(ref, ":")
	if colon <= strings.LastIndex(ref, "/") {
		return "", "", false
	}
	return ref[:colon], ref[colon+1:], true
}

func bareImageID(id string) string { return strings.TrimPrefix(id, "sha256:") }

func (c *pullCheck) foreign(labels map[string]string) bool {
	value := labels[c.opts.LabelKey]
	return value != "" && value != c.opts.Owner
}

func (c *pullCheck) report(message string) {
	c.lines = append(c.lines, imagePullProgressError(c.libpod, message))
}

// servePullWithOwnerCheck forwards a pull and then checks the references it
// wrote. See the file comment.
//
// Every reference the pull could have written is looked at, and each whose
// image carries an owner label other than the caller's is untagged and named
// in an error line at the end of the stream. A reference the requester held
// before goes back to the image it named. An inspect that fails is treated as
// a foreign label, which is the fail-closed side: the name is untagged rather
// than left for the next owner check to find. An image with no owner label, or
// the caller's own, is left alone.
//
// A destination that none of its names resolves to, after a pull whose stream
// reported no error, is reported as unverified: the pull wrote the image under
// a name this layer did not compute. A pair of names, where the daemon stores
// one of the two, needs only one of them to resolve.
func servePullWithOwnerCheck(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, refs *imageDestinationReferences, libpod bool, opts Options, post *postPullChecks) {
	c := &pullCheck{
		logger:  logger,
		r:       r,
		libpod:  libpod,
		force:   !libpod && opts.UpstreamProbedDocker,
		opts:    opts,
		post:    post,
		before:  map[string]string{},
		handled: map[string]struct{}{},
	}
	var names []string
	for _, dest := range refs.destinations {
		for _, ref := range []string{dest.target, dest.storedTarget} {
			if ref != "" && !slices.Contains(names, ref) {
				names = append(names, ref)
			}
		}
	}

	// What each name points at now, before the pull moves it. The destination
	// check reads labels only, so the ID is read here. A name that cannot be
	// read is treated as not held: the removal that follows then leaves it
	// unnamed rather than guess an image to put back.
	snapshotCtx, snapshotCancel := context.WithTimeout(context.WithoutCancel(r.Context()), imagePullPostCheckTimeout)
	for _, ref := range names {
		if image, found, err := post.inspect(snapshotCtx, ref); err == nil && found && image.id != "" {
			c.before[ref] = image.id
		}
	}
	if libpod && post.list != nil {
		c.snapshotLibpodImages(snapshotCtx, refs)
	}
	snapshotCancel()

	pw := &pullStreamWriter{ResponseWriter: w}
	next.ServeHTTP(pw, r)
	pw.finish()
	if pw.status < http.StatusOK || pw.status >= http.StatusMultipleChoices {
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), imagePullPostCheckTimeout)
	defer cancel()

	found := map[string]bool{}
	for _, ref := range names {
		found[ref] = c.checkReference(ctx, ref)
	}
	for _, ref := range refs.digests {
		c.checkDigest(ctx, ref)
	}
	idChecked := libpod && c.checkReportedImages(ctx, refs, pw.images)
	if pw.succeeded() && !idChecked {
		for _, dest := range refs.destinations {
			if !found[dest.target] && (dest.storedTarget == "" || !found[dest.storedTarget]) {
				logger.WarnContext(ctx, "owner policy could not verify pulled image",
					"reference", logging.SafeString(dest.target), "path", logging.SafeString(r.URL.Path))
				c.report(fmt.Sprintf(imagePullNotVerifiedFormat, dest.target))
			}
		}
	}

	if len(c.lines) == 0 {
		return
	}
	if encoding := strings.TrimSpace(w.Header().Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		// An intermediary compressed a stream the proxy asked for identity.
		// A plain line appended to it would corrupt the stream, and the
		// untag has already happened.
		logger.WarnContext(ctx, "owner policy could not report a removed pulled image on a compressed stream", "path", logging.SafeString(r.URL.Path))
		return
	}
	for _, line := range c.lines {
		if _, err := io.WriteString(pw, line+"\n"); err != nil {
			return
		}
	}
	pw.Flush()
}

// snapshotLibpodImages records the IDs of the images under each destination
// before a libpod pull, and the images the names on them pointed at, so a name
// the pull moves can be put back. One list that fails or runs past the cap
// leaves the snapshot unknown.
func (c *pullCheck) snapshotLibpodImages(ctx context.Context, refs *imageDestinationReferences) {
	ids := map[string]struct{}{}
	for _, dest := range refs.destinations {
		images, err := c.post.list(ctx, dest.target)
		if err != nil || len(images) > maxPrePullImages {
			c.logger.WarnContext(ctx, "owner policy could not list the images present before a pull",
				"reference", logging.SafeString(dest.target), "path", logging.SafeString(c.r.URL.Path))
			return
		}
		for _, image := range images {
			ids[bareImageID(image.id)] = struct{}{}
			for _, name := range image.names {
				if _, held := c.before[name]; !held {
					c.before[name] = image.id
				}
			}
		}
	}
	c.preIDs, c.preKnown = ids, true
}

// checkDigest inspects the reference a pull by digest named. It never removes
// anything: an image that carries another owner's label is reported, and one
// that cannot be read is reported as unverified.
func (c *pullCheck) checkDigest(ctx context.Context, ref string) {
	image, found, err := c.post.inspect(ctx, ref)
	switch {
	case err != nil:
		c.logger.WarnContext(ctx, "owner policy could not verify pulled image",
			"reference", logging.SafeString(ref), "error", logging.SafeString(err.Error()), "path", logging.SafeString(c.r.URL.Path))
		c.report(fmt.Sprintf(imagePullNotVerifiedFormat, ref))
	case !found, !c.foreign(image.labels):
	default:
		c.logger.WarnContext(ctx, "owner policy found a pulled-by-digest image with another owner's label and left it in place",
			"reference", logging.SafeString(ref), "path", logging.SafeString(c.r.URL.Path))
		c.report(fmt.Sprintf(imagePullDigestKeptFormat, ref))
	}
}

// checkReference inspects one reference a pull wrote and, when its image is
// another owner's, removes it. It reports whether the name resolved to an
// image at all.
func (c *pullCheck) checkReference(ctx context.Context, ref string) bool {
	image, found, err := c.post.inspect(ctx, ref)
	reason := imagePullForeignLabelReason
	switch {
	case err != nil:
		reason = imagePullUnverifiedReason
	case !found:
		return false
	case !c.foreign(image.labels):
		return true
	}
	c.remove(ctx, ref, reason)
	return true
}

// remove untags ref and, when the requester held the name before the pull,
// puts it back on the image it named. The untag comes first so the foreign
// image is dropped with its last name instead of left behind unnamed.
func (c *pullCheck) remove(ctx context.Context, ref, reason string) {
	c.handled[ref] = struct{}{}
	if err := c.post.untag(ctx, ref, c.libpod, c.force); err != nil {
		c.logger.ErrorContext(ctx, "owner policy could not untag a pulled image",
			"reference", logging.SafeString(ref), "reason", reason, "error", logging.SafeString(err.Error()), "path", logging.SafeString(c.r.URL.Path))
		c.report(fmt.Sprintf(imagePullRemovalFailedFormat, ref))
		return
	}
	oldID, held := c.before[ref]
	if !held {
		c.logger.WarnContext(ctx, "owner policy removed a pulled image",
			"reference", logging.SafeString(ref), "reason", reason, "path", logging.SafeString(c.r.URL.Path))
		c.report(fmt.Sprintf("owner policy removed pulled image %s: %s", ref, reason))
		return
	}
	if err := c.post.retag(ctx, oldID, ref, c.libpod); err != nil {
		c.logger.ErrorContext(ctx, "owner policy could not restore a reference a pull replaced",
			"reference", logging.SafeString(ref), "image", logging.SafeString(oldID), "error", logging.SafeString(err.Error()), "path", logging.SafeString(c.r.URL.Path))
		c.report(fmt.Sprintf(imagePullRestoreFailedFormat, ref, reason))
		return
	}
	c.logger.WarnContext(ctx, "owner policy removed a pulled image and restored the reference",
		"reference", logging.SafeString(ref), "image", logging.SafeString(oldID), "reason", reason, "path", logging.SafeString(c.r.URL.Path))
	c.report(fmt.Sprintf("owner policy removed pulled image %s: %s; the reference is back on the image it named before", ref, reason))
}

// checkReportedImages inspects the images a libpod pull report names, by ID.
// It catches a short name registries.conf resolved to a name the computed
// references do not spell. On a foreign image, the names it carries that are
// computed destinations (or their localhost/ forms) were written by this pull
// and are removed. Any other name on it is not this pull's to remove, and is
// reported, unless the image did not exist before the pull, when the names on
// it are this pull's and are removed too. It returns whether any reported image
// resolved.
func (c *pullCheck) checkReportedImages(ctx context.Context, refs *imageDestinationReferences, ids []string) bool {
	ours := map[string]struct{}{}
	for _, dest := range refs.destinations {
		for _, ref := range []string{dest.target, dest.storedTarget} {
			if ref == "" {
				continue
			}
			ours[ref] = struct{}{}
			ours["localhost/"+ref] = struct{}{}
		}
	}
	checked := false
	for _, id := range ids {
		image, found, err := c.post.inspect(ctx, id)
		if err != nil {
			checked = true
			c.logger.WarnContext(ctx, "owner policy could not verify pulled image",
				"reference", logging.SafeString(id), "error", logging.SafeString(err.Error()), "path", logging.SafeString(c.r.URL.Path))
			c.report(fmt.Sprintf(imagePullNotVerifiedFormat, id))
			continue
		}
		if !found {
			continue
		}
		checked = true
		if !c.foreign(image.labels) {
			continue
		}
		if len(image.repoTags) == 0 {
			c.logger.ErrorContext(ctx, "owner policy found a pulled image with another owner's label under no name it can untag",
				"image", logging.SafeString(id), "path", logging.SafeString(c.r.URL.Path))
			c.report(fmt.Sprintf(imagePullUnnamedFormat, id))
			continue
		}
		for _, name := range image.repoTags {
			if _, done := c.handled[name]; done {
				continue
			}
			_, written := ours[name]
			_, existed := c.preIDs[bareImageID(image.id)]
			if written {
				c.remove(ctx, name, imagePullForeignLabelReason)
				continue
			}
			if c.preKnown && !existed && image.id != "" && namesRequestedReference(refs, name) {
				c.removeIfUnchanged(ctx, name, image.id)
				continue
			}
			c.logger.ErrorContext(ctx, "owner policy found a pulled image with another owner's label under a name it did not compute",
				"reference", logging.SafeString(name), "image", logging.SafeString(id), "path", logging.SafeString(c.r.URL.Path))
			c.report(fmt.Sprintf(imagePullUnnamedFormat, name))
		}
	}
	return checked
}

// removeIfUnchanged untags name only if it still points at the image ID this
// pull reported. Another pull can move the name between the first inspect and
// the untag, and the name is then not this pull's to remove. An inspect that
// fails or no longer finds the name leaves it in place.
func (c *pullCheck) removeIfUnchanged(ctx context.Context, name, wantID string) {
	current, found, err := c.post.inspect(ctx, name)
	if err != nil || !found || bareImageID(current.id) != bareImageID(wantID) {
		c.logger.WarnContext(ctx, "owner policy left a name in place that no longer names the reported image",
			"reference", logging.SafeString(name), "image", logging.SafeString(wantID), "path", logging.SafeString(c.r.URL.Path))
		c.report(fmt.Sprintf(imagePullMovedFormat, name))
		return
	}
	c.remove(ctx, name, imagePullForeignLabelReason)
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

// inspectPulledImage reads the ID, names and owner label of the image a
// reference or ID names. The compat path answers on both engines.
func (u upstreamInspector) inspectPulledImage(ctx context.Context, reference string) (pulledImage, bool, error) {
	target, ok := dockerresource.InspectPath(dockerresource.KindImage, reference)
	if !ok {
		return pulledImage{}, false, fmt.Errorf("unsupported resource kind %q", dockerresource.KindImage)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil) // #nosec G704 -- the reference is a name this layer already parsed against the image reference grammar, or an image ID the engine reported.
	if err != nil {
		return pulledImage{}, false, fmt.Errorf("build inspect image request: %w", err)
	}
	resp, err := u.client.Do(req) // #nosec G704 -- the inspector client targets the local container-engine socket, not the URL host.
	if err != nil {
		return pulledImage{}, false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return pulledImage{}, false, nil
	case resp.StatusCode != http.StatusOK:
		return pulledImage{}, false, fmt.Errorf("inspect image %q: upstream returned %s", reference, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, pulledImageInspectLimit+1))
	if err != nil {
		return pulledImage{}, false, err
	}
	if len(body) > pulledImageInspectLimit {
		return pulledImage{}, false, fmt.Errorf("inspect image %q: response exceeds %d bytes", reference, pulledImageInspectLimit)
	}
	var payload struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return pulledImage{}, false, err
	}
	labels, err := dockerresource.DecodeLabels(bytes.NewReader(body), dockerresource.KindImage)
	if err != nil {
		return pulledImage{}, false, err
	}
	return pulledImage{id: payload.ID, labels: labels, repoTags: payload.RepoTags}, true, nil
}

// listImages returns the images whose names match a reference, through the
// native list filtered by reference. A list past maxPrePullImages is an error.
func (u upstreamInspector) listImages(ctx context.Context, reference string) ([]listedImage, error) {
	filters, err := json.Marshal(map[string][]string{"reference": {reference}})
	if err != nil {
		return nil, fmt.Errorf("build list filters: %w", err)
	}
	target := libpodPrefix + "images/json?" + url.Values{"filters": {string(filters)}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil) // #nosec G704 -- the filter is JSON built from a name this layer already parsed against the image reference grammar.
	if err != nil {
		return nil, fmt.Errorf("build list images request: %w", err)
	}
	resp, err := u.client.Do(req) // #nosec G704 -- the inspector client targets the local container-engine socket, not the URL host.
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list images %q: upstream returned %s", reference, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, pulledImageInspectLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > pulledImageInspectLimit {
		return nil, fmt.Errorf("list images %q: response exceeds %d bytes", reference, pulledImageInspectLimit)
	}
	var payload []struct {
		ID       string   `json:"Id"`
		Names    []string `json:"Names"`
		RepoTags []string `json:"RepoTags"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if len(payload) > maxPrePullImages {
		return nil, fmt.Errorf("list images %q: %d images, over the %d the check follows", reference, len(payload), maxPrePullImages)
	}
	images := make([]listedImage, 0, len(payload))
	for _, entry := range payload {
		images = append(images, listedImage{id: entry.ID, names: append(entry.Names, entry.RepoTags...)})
	}
	return images, nil
}

// pulledImageInspectLimit bounds an image inspect body read after a pull.
const pulledImageInspectLimit = 16 << 20

func imageRoutePrefix(libpod bool) string {
	if libpod {
		return libpodPrefix + "images/"
	}
	return "/images/"
}

// untagImage removes a reference the proxy's upstream holds. Both engines
// untag when the name is a reference, and drop the image only when it was the
// last name on it. A name that is already gone is a success.
//
// force sends force=1 and noprune=1. Without force, dockerd refuses to remove
// the only reference to an image a container uses (409, "must force"). With
// it, it removes just that name: moby's ImageDelete untags a repository
// reference first and drops the image only when no reference is left, and the
// delete of the image itself is quiet after a reference was removed, so a
// container that still uses it keeps it and the untag stands. noprune keeps
// the parent layers.
func (u upstreamInspector) untagImage(ctx context.Context, reference string, libpod, force bool) error {
	target := (&url.URL{Path: imageRoutePrefix(libpod) + reference}).EscapedPath()
	if force {
		target += "?force=1&noprune=1"
	}
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

// retagImage points a name back at an image ID, through POST
// /images/{id}/tag on the compat route and its /libpod/ equivalent. The
// "sha256:" prefix is dropped so both engines read the bare ID the same way.
func (u upstreamInspector) retagImage(ctx context.Context, imageID, reference string, libpod bool) error {
	colon := strings.LastIndex(reference, ":")
	if colon <= strings.LastIndex(reference, "/") {
		return fmt.Errorf("retag %q: reference carries no tag", reference)
	}
	repo, tag := reference[:colon], reference[colon+1:]
	target := (&url.URL{Path: imageRoutePrefix(libpod) + strings.TrimPrefix(imageID, "sha256:") + "/tag"}).EscapedPath()
	query := url.Values{"repo": {repo}, "tag": {tag}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker"+target+"?"+query, nil) // #nosec G704 -- the ID came from the engine's own inspect and the name from the reference grammar.
	if err != nil {
		return fmt.Errorf("build retag request: %w", err)
	}
	resp, err := u.client.Do(req) // #nosec G704 -- the inspector client targets the local container-engine socket, not the URL host.
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("retag %q: upstream returned %s", reference, resp.Status)
	}
	return nil
}
