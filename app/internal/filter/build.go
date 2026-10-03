package filter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/codeswhat/sockguard/app/internal/dockerfileinspect"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/queryparam"
)

const maxBuildContextBytes = 512 << 20           // 512 MiB (compressed/on-wire cap)
const maxBuildDockerfileBytes = 1 << 20          // 1 MiB
const maxBuildContextDecompressedBytes = 1 << 30 // 1 GiB (gzip-bomb guard)
const (
	defaultBuildDockerfilePath    = "Dockerfile"
	defaultBuildContainerfilePath = "Containerfile"
)

var errBuildDockerfileTooLarge = errors.New("dockerfile exceeds byte limit")
var errBuildContextDecompressedTooLarge = errors.New("decompressed build context exceeds byte limit")

// BuildOptions configures request-body/query inspection for POST /build and
// POST /libpod/build.
type BuildOptions struct {
	AllowRemoteContext   bool
	AllowHostNetwork     bool
	AllowRunInstructions bool
	// AllowBlindWrites acknowledges Podman build controls that can expose
	// host paths but do not have a narrower request_body.build policy.
	AllowBlindWrites bool
}

type buildPolicy struct {
	allowRemoteContext   bool
	allowHostNetwork     bool
	allowRunInstructions bool
	allowBlindWrites     bool
	io                   ioDeps
}

func newBuildPolicy(opts BuildOptions) buildPolicy {
	return buildPolicy{
		allowRemoteContext:   opts.AllowRemoteContext,
		allowHostNetwork:     opts.AllowHostNetwork,
		allowRunInstructions: opts.AllowRunInstructions,
		allowBlindWrites:     opts.AllowBlindWrites,
		io:                   defaultIODeps(),
	}
}

func (p buildPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !matchesBuildInspection(normalizedPath) {
		return "", nil
	}
	if p.io.CreateTempFile == nil {
		p.io = defaultIODeps()
	}

	if denyReason := denyRegistryConfigHeaderReason(r.Header.Get("X-Registry-Config"), "build"); denyReason != "" {
		return denyReason, nil
	}

	query := logging.RequestQuery(r)
	// Podman serves POST /build and POST /libpod/build from one handler that
	// honors build controls Docker's API has no field for: host volume mounts
	// (volume/volumes/transientRunMounts), url:/image: additional build
	// contexts, and the rusagelogfile daemon-host write. moby's POST /build
	// reads none of those query parameters (confirmed against moby 29.5.2), so
	// a legitimate Docker client never sends them. Gating them on the compat
	// path therefore costs a dockerd upstream nothing and closes the bypass on
	// a Podman one, where the compat /build path previously went uninspected
	// for every control gated only on the /libpod/ prefix.
	//
	// Every parameter below is read through queryparam, the same way on both
	// paths. The engines disagree per parameter: dockerd reads the first value
	// of the exact key, and Podman decodes rusagelogfile, networkmode and
	// volume with gorilla/schema (any letter case, last value) but reads
	// dockerfile and remote with url.Values.Get (exact key, first value).
	// Folding the keys on the libpod path, as this used to, made sockguard
	// inspect `?Dockerfile=decoy` while Podman built the default file. So a
	// parameter the decision depends on is refused when it is repeated or not
	// spelled as documented, and a control refused outright is refused under
	// any spelling. Read from Podman 5.8.6 (pkg/api/handlers/compat/images_build.go).
	if denyReason := p.inspectPodmanBuildControls(r, normalizedPath, query); denyReason != "" {
		return denyReason, nil
	}
	// WHY: Host-network builds are denied even when the request also uses a
	// remote context, so this must run before the remote-context branch returns
	// its own denial or allow decision.
	if !p.allowHostNetwork {
		networkMode, _, ok := queryparam.Scalar(query, "networkmode")
		if !ok {
			return ambiguousQueryReason("build", "networkmode"), nil
		}
		if strings.EqualFold(strings.TrimSpace(networkMode), "host") {
			return "build denied: host network mode is not allowed", nil
		}
	}

	if !p.allowRemoteContext || !p.allowRunInstructions {
		remote, _, ok := queryparam.Scalar(query, "remote")
		if !ok {
			return ambiguousQueryReason("build", "remote"), nil
		}
		if remote = strings.TrimSpace(remote); remote != "" {
			if p.allowRemoteContext {
				return "build denied: remote build contexts cannot be inspected while RUN instructions are restricted", nil
			}
			return fmt.Sprintf("build denied: remote build context %q is not allowed", remote), nil
		}
	}
	if p.allowRunInstructions || r.Body == nil {
		return "", nil
	}

	dockerfileParam, _, ok := queryparam.Scalar(query, "dockerfile")
	if !ok {
		return ambiguousQueryReason("build", "dockerfile"), nil
	}
	// POST /libpod/local/build has nothing in its body to inspect: Podman
	// reads its Containerfile from the daemon host, and inspectPodmanBuildControls
	// only let it this far under insecure_allow_body_blind_writes.
	if isLibpodLocalBuildPath(normalizedPath) {
		return "", nil
	}
	// The files are named, and a value that points outside the body refused,
	// before the body is read: Podman builds from a fetched or daemon-host
	// file just as readily when the request sends no context at all.
	files, denyReason := buildInstructionFiles(normalizedPath, dockerfileParam)
	if denyReason != "" {
		return denyReason, nil
	}

	spool, size, err := p.io.spoolRequestBodyToTempFile(r, "sockguard-build-", maxBuildContextBytes)
	if err != nil {
		return "", err
	}
	if spool.tooLarge {
		spool.closeAndRemove()
		return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("build denied: request body exceeds %d byte limit", maxBuildContextBytes))
	}
	if size == 0 {
		spool.closeAndRemove()
		return "", nil
	}

	denyReason, err = p.io.inspectBuildContext(spool.file, r.Header.Get("Content-Type"), files)
	if err != nil {
		spool.closeAndRemove()
		if errors.Is(err, errBuildContextDecompressedTooLarge) {
			return fmt.Sprintf("build denied: decompressed build context exceeds %d byte limit", maxBuildContextDecompressedBytes), nil
		}
		return "", fmt.Errorf("inspect build context: %w", err)
	}
	if denyReason != "" {
		spool.closeAndRemove()
		return denyReason, nil
	}

	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind build body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

type legacyPodmanAdditionalBuildContext struct {
	IsURL           bool
	IsImage         bool
	Value           string
	DownloadedCache string
}

// inspectPodmanBuildControls gates the build controls Podman honors that
// Docker's API does not define. It runs on both the compat POST /build and the
// native POST /libpod/build, because Podman serves both from one handler (see
// inspect): a control gated only on the /libpod/ prefix was ungated on the
// compat path of a Podman upstream. The daemon-host local-build check stays
// keyed on the libpod local path, the only route that names a daemon-host
// build context.
func (p buildPolicy) inspectPodmanBuildControls(r *http.Request, normalizedPath string, query url.Values) string {
	// POST /libpod/local/build names its build context with a daemon-host
	// path (`localcontextdir`) instead of shipping a tar, so every
	// body-derived control further down inspect() — the RUN-instruction
	// scan, the BuildKit syntax-frontend check, the byte caps — has nothing
	// to read and would fall through to inspect()'s empty-body allow. That
	// is the same "can expose host paths, cannot be inspected" shape as the
	// localpath: additional context and the host volume mounts gated below,
	// so it takes the same acknowledgment rather than being silently
	// forwarded as an inspected build.
	if isLibpodLocalBuildPath(normalizedPath) && !p.allowBlindWrites {
		return "build denied: Podman local build context reads a daemon-host path and requires insecure_allow_body_blind_writes"
	}

	additionalContexts, ok := queryparam.List(query, "additionalbuildcontexts")
	if !ok {
		return ambiguousQueryReason("build", "additionalbuildcontexts")
	}
	requiresRemoteContext, requiresBlindWrites, malformed := classifyPodmanAdditionalBuildContexts(additionalContexts)
	if malformed != "" {
		return "build denied: malformed additional build context: " + malformed
	}
	if requiresRemoteContext && !p.allowRemoteContext {
		return "build denied: remote additional build context is not allowed"
	}
	if requiresBlindWrites && !p.allowBlindWrites {
		return "build denied: uninspectable additional build context requires insecure_allow_body_blind_writes"
	}
	if denyReason := p.inspectPodmanRusageControls(query); denyReason != "" {
		return denyReason
	}

	if !p.allowBlindWrites && (queryparam.Present(query, "volume") || queryparam.Present(query, "volumes") || queryparam.Present(query, "transientrunmounts")) {
		return "build denied: Podman host volume mounts require insecure_allow_body_blind_writes"
	}

	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(contentType, "multipart/") && !p.allowBlindWrites {
		return "build denied: Podman multipart build context requires insecure_allow_body_blind_writes"
	}

	return ""
}

func classifyPodmanAdditionalBuildContexts(values []string) (requiresRemoteContext, requiresBlindWrites bool, malformed string) {
	seenNames := make(map[string]struct{})
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return false, false, "empty value"
		}
		if strings.HasPrefix(value, "{") {
			var contexts map[string]legacyPodmanAdditionalBuildContext
			if err := json.Unmarshal([]byte(value), &contexts); err != nil {
				return false, false, "invalid legacy JSON"
			}
			for name, context := range contexts {
				name = strings.TrimSpace(name)
				context.Value = strings.TrimSpace(context.Value)
				if name == "" || context.Value == "" || (context.IsURL && context.IsImage) {
					return false, false, "invalid legacy JSON entry"
				}
				if _, duplicate := seenNames[name]; duplicate {
					return false, false, "duplicate context name"
				}
				seenNames[name] = struct{}{}
				if context.IsURL || context.IsImage {
					requiresRemoteContext = true
				}
				if (!context.IsURL && !context.IsImage) || strings.TrimSpace(context.DownloadedCache) != "" {
					requiresBlindWrites = true
				}
			}
			continue
		}

		name, source, found := strings.Cut(value, "=")
		name = strings.TrimSpace(name)
		source = strings.TrimSpace(source)
		if !found || name == "" || source == "" {
			return false, false, "expected name=value"
		}
		if _, duplicate := seenNames[name]; duplicate {
			return false, false, "duplicate context name"
		}
		seenNames[name] = struct{}{}

		switch {
		case strings.HasPrefix(source, "url:"):
			if strings.TrimSpace(strings.TrimPrefix(source, "url:")) == "" {
				return false, false, "empty URL context"
			}
			requiresRemoteContext = true
		case strings.HasPrefix(source, "image:"):
			if strings.TrimSpace(strings.TrimPrefix(source, "image:")) == "" {
				return false, false, "empty image context"
			}
			requiresRemoteContext = true
		case strings.HasPrefix(source, "localpath:"):
			if strings.TrimSpace(strings.TrimPrefix(source, "localpath:")) == "" {
				return false, false, "empty local path context"
			}
			requiresBlindWrites = true
		default:
			return false, false, "unsupported context type"
		}
	}
	return requiresRemoteContext, requiresBlindWrites, ""
}

// inspectPodmanRusageControls validates `rusage` and gates `rusagelogfile`,
// which makes Podman's builder write its resource-usage report to that path on
// the daemon host. Podman decodes both with gorilla/schema, so a spelling such
// as `ruſagelogfile` (U+017F folds to s) names the log file there; a
// strings.ToLower fold of the key does not see it, which is how the write got
// past this check. A malformed rusage value is refused even with every
// acknowledgment, because Podman answers it with a 400 and refusing it here
// keeps the two in step.
func (p buildPolicy) inspectPodmanRusageControls(query url.Values) string {
	rusage, ok := queryparam.List(query, "rusage")
	if !ok {
		return ambiguousQueryReason("build", "rusage")
	}
	for _, value := range rusage {
		if value == "on" {
			continue
		}
		if _, err := strconv.ParseBool(value); err != nil {
			return "build denied: malformed rusage control: invalid boolean value"
		}
	}

	if p.allowBlindWrites {
		return ""
	}
	logFile, _, ok := queryparam.Scalar(query, "rusagelogfile")
	if !ok {
		return ambiguousQueryReason("build", "rusagelogfile")
	}
	if logFile != "" {
		return "build denied: Podman resource usage log requires insecure_allow_body_blind_writes"
	}
	return ""
}

type spooledRequestBody struct {
	file     *os.File
	path     string
	tooLarge bool
	io       ioDeps
}

func (io_ ioDeps) spoolRequestBodyToTempFile(r *http.Request, prefix string, maxBytes int64) (*spooledRequestBody, int64, error) {
	file, err := io_.CreateTempFile("", prefix)
	if err != nil {
		return nil, 0, fmt.Errorf("create temp file: %w", err)
	}

	limited := io.LimitReader(r.Body, maxBytes+1)
	size, copyErr := io.Copy(file, limited)
	closeErr := r.Body.Close()
	if copyErr == nil && closeErr != nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		name := file.Name()
		_ = file.Close()
		_ = io_.RemoveFilePath(name)
		return nil, 0, fmt.Errorf("spool build body: %w", copyErr)
	}

	if err := io_.SeekToStart(file); err != nil {
		name := file.Name()
		_ = file.Close()
		_ = io_.RemoveFilePath(name)
		return nil, 0, fmt.Errorf("rewind temp file: %w", err)
	}

	return &spooledRequestBody{
		file:     file,
		path:     file.Name(),
		tooLarge: size > maxBytes,
		io:       io_,
	}, size, nil
}

func (s *spooledRequestBody) requestBody() io.ReadCloser {
	return &tempFileBody{file: s.file, path: s.path, io: s.io}
}

func (s *spooledRequestBody) closeAndRemove() {
	if s == nil || s.file == nil {
		return
	}
	_ = s.file.Close()
	// s.path is always the name returned by os.CreateTemp inside this
	// package — sockguard owns every byte of it. Gosec's taint tracker
	// can't tell it's not a traversal hazard.
	//nolint:gosec // G703: path is internally generated by os.CreateTemp
	_ = s.io.RemoveFilePath(s.path)
}

// tempFileBody is a request body an inspector spooled to a temp file. Closing
// it removes the file.
//
// More than one party closes it. The reverse proxy closes the outbound body,
// the upstream transport closes it again and may do so from its own goroutine
// after the round trip has returned, and the filter middleware closes it once
// the rest of the chain has returned (see closeSpooledRequestBody). So the
// file is closed and removed once, and every later Close reports what the
// first one did. A second removal would be more than wasted work: the name is
// free again after the first, and another request can have been handed it.
type tempFileBody struct {
	file *os.File
	path string
	io   ioDeps

	closeOnce sync.Once
	closeErr  error
}

func (b *tempFileBody) Read(p []byte) (int, error) {
	return b.file.Read(p)
}

func (b *tempFileBody) Close() error {
	b.closeOnce.Do(func() {
		closeErr := b.file.Close()
		removeErr := b.io.RemoveFilePath(b.path)
		switch {
		case closeErr != nil:
			b.closeErr = closeErr
		case removeErr != nil && !os.IsNotExist(removeErr):
			b.closeErr = removeErr
		}
	})
	return b.closeErr
}

// closeSpooledRequestBody removes the temp file behind r.Body when an
// inspector spooled the body there, and returns the function that does it for
// the caller to defer. It returns nil for a request whose body was not
// spooled.
//
// An inspector that spools a body swaps it in as r.Body, and the server only
// closes the body it handed out, so the swapped one is the filter's to close.
// Nothing downstream can be relied on to: the reverse proxy closes the body
// it forwards, but a layer in between that answers the request itself returns
// without one. Owner isolation does that for a request it refuses and for one
// whose lookup fails, and each such request used to leave its body on disk.
// Closing after the chain returns matches what net/http promises a handler: a
// request body is not read once ServeHTTP has returned.
//
// The body is captured here, before the rest of the chain runs, so a layer
// that replaces r.Body in turn does not hide the file from the close.
func closeSpooledRequestBody(logger *slog.Logger, r *http.Request) func() {
	spooled, ok := r.Body.(*tempFileBody)
	if !ok {
		return nil
	}
	return func() {
		if err := spooled.Close(); err != nil {
			logRequestError(logger, r, slog.LevelWarn, "failed to remove spooled request body", err)
		}
	}
}

// buildInstructionFiles names every file in the build context that the engine
// serving normalizedPath could read build instructions from, given the
// request's `dockerfile` value, or says why the value can't be inspected.
//
// The engines read the value differently, and nothing in a POST /build says
// which one will answer it, so the compat path gets every file either engine
// could read:
//
//   - dockerd reads the value as one path in the context, Dockerfile when it
//     is empty, and reads dockerfile when a path named Dockerfile is missing
//     (moby 28.5.1 builder/remotecontext/detect.go, withDockerfileFromContext;
//     BuildKit 0.25.1 frontend/dockerui/config.go does the same for any path
//     whose base is Dockerfile).
//   - Podman reads it with url.Values.Get, decodes it as a JSON array of paths
//     and takes it as one path when it is not one, which is how podman-remote
//     sends its -f files. With no value it reads Dockerfile on the compat
//     route and Containerfile, else Dockerfile, on its libpod one (Podman 5.8.6
//     pkg/api/handlers/compat/images_build.go, processBuildContext).
//
// The libpod paths are Podman's alone. Both Containerfile and Dockerfile are
// inspected there rather than only the one Podman picks: that refuses a build
// whose unused Dockerfile carries a RUN, and in exchange the filter never has
// to predict from the tar whether Podman will find a Containerfile on disk,
// where a wrong guess in either direction builds a file nobody inspected.
func buildInstructionFiles(normalizedPath, value string) ([]string, string) {
	libpod := isLibpodBuildPath(normalizedPath)
	var files []string
	seen := make(map[string]struct{})
	add := func(name string) {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			files = append(files, name)
		}
	}
	if value == "" {
		if libpod {
			add(defaultBuildContainerfilePath)
			add(defaultBuildDockerfilePath)
		} else {
			add(defaultBuildDockerfilePath)
			add(strings.ToLower(defaultBuildDockerfilePath))
		}
		return files, ""
	}

	var podmanFiles []string
	if err := json.Unmarshal([]byte(value), &podmanFiles); err != nil {
		podmanFiles = []string{value}
	}
	for _, file := range podmanFiles {
		name, denyReason := podmanBuildContextFile(file)
		if denyReason != "" {
			return nil, denyReason
		}
		add(name)
	}
	if !libpod {
		name := buildContextEntryName(value)
		add(name)
		if path.Base(name) == defaultBuildDockerfilePath {
			add(path.Join(path.Dir(name), strings.ToLower(defaultBuildDockerfilePath)))
		}
	}
	if len(files) == 0 {
		// `[]` or `null`: buildah refuses a build with no Containerfile.
		return nil, fmt.Sprintf("build denied: dockerfile %q names no Dockerfile to inspect", value)
	}
	return files, ""
}

// podmanBuildContextFile maps one file Podman was asked to build onto the
// context entry it names. Podman joins a relative path onto the unpacked
// context, but fetches an http:// or https:// one, reads an absolute one from
// the daemon host whenever the host has that file, follows ../ out of the
// context, and runs a file whose name ends in .in through cpp before parsing
// it (processBuildContext, and buildah 1.43.2 imagebuildah.BuildDockerfiles).
// None of those can be inspected from the request, so each is refused.
// podman-remote sends an absolute path for a Containerfile outside the build
// context, which is refused here for the same reason.
func podmanBuildContextFile(file string) (string, string) {
	if strings.HasPrefix(file, "http://") || strings.HasPrefix(file, "https://") {
		return "", fmt.Sprintf("build denied: remote Dockerfile %q cannot be inspected while RUN instructions are restricted", file)
	}
	if strings.HasPrefix(file, "/") {
		return "", fmt.Sprintf("build denied: Dockerfile %q is an absolute path, which Podman reads from the daemon host, and cannot be inspected while RUN instructions are restricted", file)
	}
	name := path.Clean(file)
	if name == ".." || strings.HasPrefix(name, "../") {
		return "", fmt.Sprintf("build denied: Dockerfile %q is outside the build context and cannot be inspected while RUN instructions are restricted", file)
	}
	if strings.HasSuffix(name, ".in") {
		return "", fmt.Sprintf("build denied: Dockerfile %q is run through the C preprocessor by Podman and cannot be inspected while RUN instructions are restricted", file)
	}
	return name, ""
}

// buildContextEntryName is where a path lands in an unpacked build context:
// cleaned, with any leading slashes dropped, the way both engines' extractors
// place a tar entry and dockerd resolves its `dockerfile`. The context root
// itself is "". A name that climbs out with ../ lands at the root here; the
// extractors refuse such an entry outright, so reading it as a context file
// can only inspect more than the engine builds.
func buildContextEntryName(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// inspectBuildContext reports why the build whose body is spooled in file may
// not run while RUN instructions are restricted, or "" when every one of files
// the context carries can be read and is free of RUN.
func (io_ ioDeps) inspectBuildContext(file *os.File, contentType string, files []string) (string, error) {
	if err := io_.SeekToStart(file); err != nil {
		return "", fmt.Errorf("rewind build context reader: %w", err)
	}

	// Docker build inputs usually arrive as gzip tar, then plain tar, and only
	// sometimes as raw Dockerfile bytes, so probe in that order. A body that
	// opens as a tar is a tar: what the scan finds in it is the answer, and
	// falling through to read the archive as one Dockerfile would scan bytes
	// the engine never parses as instructions.
	if isTar, denyReason, err := io_.inspectGzipBuildContext(file, files); isTar || err != nil {
		return denyReason, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return "", fmt.Errorf("rewind build context reader: %w", err)
	}
	if isTar, denyReason, err := io_.inspectBuildContextTar(tar.NewReader(file), files); isTar || err != nil {
		return denyReason, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return "", fmt.Errorf("rewind build context reader: %w", err)
	}

	// BuildKit builds a body that is not an archive as the Dockerfile itself,
	// whatever `dockerfile` says; the classic builder and Podman refuse it.
	raw, err := io_.ReadAllLimited(file, maxBuildDockerfileBytes+1)
	if err != nil {
		return "", fmt.Errorf("read raw Dockerfile: %w", err)
	}
	// The engines decompress bzip2, xz and zstd as well as gzip before they
	// look for a tar. Sockguard only decodes gzip, so a compressed body that
	// didn't open as a tar above can't be inspected.
	if hasBuildContextCompressionMagic(raw) {
		return uninspectableBuildFilesReason(files), nil
	}
	if len(raw) > maxBuildDockerfileBytes {
		return "", fmt.Errorf("%w: %d bytes", errBuildDockerfileTooLarge, maxBuildDockerfileBytes)
	}
	if !looksLikeDockerfile(raw, contentType) {
		return uninspectableBuildFilesReason(files), nil
	}
	return buildInstructionsDenyReason(raw, ""), nil
}

func (io_ ioDeps) inspectGzipBuildContext(file *os.File, files []string) (bool, string, error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		// A body shorter than a gzip header can't be gzip; the magic check
		// before the raw read still refuses one that opens like it.
		if errors.Is(err, gzip.ErrHeader) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("create gzip reader: %w", err)
	}

	// Bound the *decompressed* byte count to defuse gzip bombs: a body within
	// the compressed maxBuildContextBytes cap can still expand to hundreds of
	// GiB. Both the tar walk and the drain below read through this limit.
	limited := &limitedReader{r: gzr, remaining: maxBuildContextDecompressedBytes}

	isTar, denyReason, err := io_.inspectBuildContextTar(tar.NewReader(limited), files)
	if err == nil && isTar && denyReason == "" {
		if drainErr := io_.DrainReader(limited); drainErr != nil {
			err = fmt.Errorf("drain gzip stream: %w", drainErr)
		}
	}
	if closeErr := io_.CloseReadCloser(gzr); err == nil && closeErr != nil {
		err = fmt.Errorf("close gzip reader: %w", closeErr)
	}
	if errors.Is(err, errBuildContextDecompressedTooLarge) {
		// Surface the sentinel unwrapped so the caller can map it to a clean
		// 403 deny reason rather than a 500.
		return true, "", errBuildContextDecompressedTooLarge
	}
	return isTar, denyReason, err
}

// limitedReader returns its tooLarge sentinel once more than `remaining` bytes
// have been read from r. Unlike io.LimitReader (which signals EOF and silently
// truncates), it fails loud so a decompression bomb is denied rather than
// mistaken for a stream that simply lacks the file being probed. A stream of
// exactly `remaining` bytes is read cleanly (no off-by-one false positive).
//
// tooLarge lets each decompression path surface its own deny message; when nil
// it defaults to errBuildContextDecompressedTooLarge so the build-path callers
// (and their tests) keep their sentinel without restating it.
type limitedReader struct {
	r         io.Reader
	remaining int64
	tooLarge  error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	limitErr := l.tooLarge
	if limitErr == nil {
		limitErr = errBuildContextDecompressedTooLarge
	}
	if l.remaining < 0 {
		return 0, limitErr
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	if l.remaining < 0 {
		return n, limitErr
	}
	return n, err
}

// dockerfileSyntaxFrontend delegates to internal/dockerfileinspect.
// SyntaxFrontend — see that package's doc comment for why the actual parser
// lives there rather than here: BuildKit gRPC mediation's Dockerfile
// hold-and-inspect (issue #185 phase 5) needs the identical logic and this
// package must not be imported the other way around.
func dockerfileSyntaxFrontend(raw []byte) string {
	return dockerfileinspect.SyntaxFrontend(raw)
}

// maxTrackedBuildContextLinks bounds how many symlink entries one tar scan
// remembers. Past it the scan stops telling links apart and refuses any later
// entry below the context root that could land on an inspected file or on a
// directory above one, so a context made of nothing but symlink headers costs
// a bounded amount of memory.
const maxTrackedBuildContextLinks = 1 << 16

// inspectBuildContextTar scans a build context tar for files and reports
// whether the stream was a tar at all, and if it was, why the build may not
// run. It reads every entry rather than stopping at the first match, because
// the engines unpack the whole archive before they read a file from it, and
// a later entry can change what is on disk at a name an earlier one wrote:
//
//   - Extraction replaces whatever is at a path with the next entry for it,
//     so a second entry at an inspected name, of any type, is refused. A
//     regular file followed by a symlink at the same name was inspected while
//     the engine read the symlink's target.
//   - Extraction writes through a symlink an earlier entry left on the path,
//     so `here -> .` followed by `here/Dockerfile` replaces Dockerfile without
//     naming it. An entry sharing an inspected file's base name, and any
//     symlink, which could chain one, is refused when it descends from a
//     symlink entry.
//   - A non-directory entry at the context root, or at a directory on the way
//     to an inspected file, moves that file somewhere else and is refused.
//
// An inspected file present only as something other than a regular file is
// refused too: following it would mean predicting where the link resolves on
// the daemon's disk. A context carrying none of files is refused as
// uninspectable, which is also how the engines answer it.
//
// The ancestor and symlink sets hold FNV-1a hashes, which keeps the scan
// linear in the length of each name however deep it is. A collision can only
// add a refusal.
func (io_ ioDeps) inspectBuildContextTar(tr *tar.Reader, files []string) (bool, string, error) {
	claims := make(map[string]int, len(files))
	basenames := make(map[string]struct{}, len(files))
	pathNames := make(map[string]struct{}, len(files))
	ancestors := make(map[uint64]struct{})
	for _, file := range files {
		claims[file] = 0
		basenames[path.Base(file)] = struct{}{}
		for _, component := range strings.Split(file, "/") {
			pathNames[component] = struct{}{}
		}
		buildContextPathAncestors(file, func(hash uint64) bool {
			ancestors[hash] = struct{}{}
			return false
		})
	}
	links := make(map[uint64]struct{})
	linksOverflowed := false
	underLink := func(hash uint64) bool {
		_, ok := links[hash]
		return ok
	}

	found := false
	for entries := 0; ; entries++ {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, errBuildContextDecompressedTooLarge) {
				return true, "", err
			}
			if entries == 0 {
				// Not a tar: the caller tries the next way of reading the body.
				return false, "", nil
			}
			return true, "", fmt.Errorf("read tar entry: %w", err)
		}

		name := buildContextEntryName(header.Name)
		isDir := header.Typeflag == tar.TypeDir
		isLink := header.Typeflag == tar.TypeSymlink
		if name == "" {
			if !isDir {
				return true, buildContextEntryReason(header.Name, "replaces the build context root"), nil
			}
			continue
		}
		if !isDir {
			if _, ok := ancestors[buildContextPathHash(name)]; ok {
				return true, buildContextEntryReason(header.Name, "replaces a directory on the path to a Dockerfile"), nil
			}
		}
		base := path.Base(name)
		if _, sharesName := basenames[base]; sharesName || isLink {
			if buildContextPathAncestors(name, underLink) {
				return true, buildContextEntryReason(header.Name, "is written through a symlink"), nil
			}
		}
		if _, onPath := pathNames[base]; onPath && linksOverflowed && strings.Contains(name, "/") {
			return true, buildContextEntryReason(header.Name, fmt.Sprintf("may be written through one of more than %d symlinks", maxTrackedBuildContextLinks)), nil
		}
		if isLink && !linksOverflowed {
			if len(links) == maxTrackedBuildContextLinks {
				linksOverflowed = true
			} else {
				links[buildContextPathHash(name)] = struct{}{}
			}
		}

		seen, wanted := claims[name]
		if !wanted {
			continue
		}
		claims[name] = seen + 1
		if seen > 0 || header.Typeflag != tar.TypeReg {
			return true, fmt.Sprintf("build denied: unable to inspect Dockerfile %q", name), nil
		}
		body, err := io_.ReadAllLimited(tr, maxBuildDockerfileBytes+1)
		if err != nil {
			return true, "", fmt.Errorf("read Dockerfile entry: %w", err)
		}
		if len(body) > maxBuildDockerfileBytes {
			return true, "", fmt.Errorf("%w: %d bytes", errBuildDockerfileTooLarge, maxBuildDockerfileBytes)
		}
		if denyReason := buildInstructionsDenyReason(body, name); denyReason != "" {
			return true, denyReason, nil
		}
		found = true
	}
	if !found {
		return true, uninspectableBuildFilesReason(files), nil
	}
	return true, "", nil
}

// buildContextPathHash is the FNV-1a hash of name.
func buildContextPathHash(name string) uint64 {
	hash := uint64(fnvOffset64)
	for i := 0; i < len(name); i++ {
		hash ^= uint64(name[i])
		hash *= fnvPrime64
	}
	return hash
}

// buildContextPathAncestors calls visit with the buildContextPathHash of each
// directory above name, outermost first, and reports whether a visit returned
// true. It hashes name once, however deep it is.
func buildContextPathAncestors(name string, visit func(uint64) bool) bool {
	hash := uint64(fnvOffset64)
	for i := 0; i < len(name); i++ {
		if name[i] == '/' && visit(hash) {
			return true
		}
		hash ^= uint64(name[i])
		hash *= fnvPrime64
	}
	return false
}

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// buildInstructionsDenyReason reports why the build instructions in body,
// read from the context file name ("" for a body that is the Dockerfile
// itself), may not run while RUN instructions are restricted.
func buildInstructionsDenyReason(body []byte, name string) string {
	// A BuildKit `# syntax=` parser directive delegates parsing to an external
	// frontend image that can treat arbitrary tokens as shell execution, so our
	// RUN-instruction scan cannot be trusted. Deny it for the same reason remote
	// contexts are denied while RUN is restricted: the content can't be inspected.
	if frontend := dockerfileSyntaxFrontend(body); frontend != "" {
		return fmt.Sprintf("build denied: BuildKit syntax frontend %q cannot be inspected while RUN instructions are restricted", frontend)
	}
	if !dockerfileContainsRunInstruction(body) {
		return ""
	}
	if name == "" {
		return "build denied: RUN instructions are not allowed"
	}
	return fmt.Sprintf("build denied: RUN instructions are not allowed in %q", name)
}

func buildContextEntryReason(entry, why string) string {
	return fmt.Sprintf("build denied: unable to inspect build context: tar entry %q %s", entry, why)
}

func uninspectableBuildFilesReason(files []string) string {
	quoted := make([]string, len(files))
	for i, file := range files {
		quoted[i] = strconv.Quote(file)
	}
	return "build denied: unable to inspect Dockerfile " + strings.Join(quoted, " or ")
}

// hasBuildContextCompressionMagic reports whether raw opens with a compression
// format the engines' archive readers detect (moby and containers/storage
// DetectCompression).
func hasBuildContextCompressionMagic(raw []byte) bool {
	for _, magic := range [][]byte{
		{0x1F, 0x8B, 0x08},                   // gzip
		{0x42, 0x5A, 0x68},                   // bzip2
		{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, // xz
		{0x28, 0xB5, 0x2F, 0xFD},             // zstd
	} {
		if bytes.HasPrefix(raw, magic) {
			return true
		}
	}
	// A zstd stream may open with a skippable frame, magic 0x184D2A50 to
	// 0x184D2A5F little-endian, which moby and BuildKit both detect.
	return len(raw) >= 8 && binary.LittleEndian.Uint32(raw)&0xFFFFFFF0 == 0x184D2A50
}

func looksLikeDockerfile(raw []byte, contentType string) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/plain") {
		return true
	}

	for _, line := range strings.Split(string(trimmed), "\n") {
		normalized := strings.TrimSpace(line)
		if normalized == "" || strings.HasPrefix(normalized, "#") {
			continue
		}
		switch dockerfileInstruction(normalized) {
		case "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM", "HEALTHCHECK", "LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL", "STOPSIGNAL", "USER", "VOLUME", "WORKDIR":
			return true
		default:
			return false
		}
	}
	return false
}

// dockerfileContainsRunInstruction and dockerfileInstruction delegate to
// internal/dockerfileinspect — see dockerfileSyntaxFrontend's comment above
// for why.
func dockerfileContainsRunInstruction(raw []byte) bool {
	return dockerfileinspect.ContainsRunInstruction(raw)
}

func dockerfileInstruction(line string) string {
	return dockerfileinspect.Instruction(line)
}
