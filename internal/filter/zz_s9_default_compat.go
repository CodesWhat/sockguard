package filter

import (
	"archive/tar"
	"bufio"
	"bytes"

	"compress/gzip"

	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/codeswhat/sockguard/internal/buildkitproxy"

	"github.com/codeswhat/sockguard/internal/dockerfileinspect"

	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/glob"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/imagefetch"
	"github.com/codeswhat/sockguard/internal/imagetrust"

	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/upstream"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"io"
	"log/slog"

	"mime"
	"mime/multipart"
	"net/http"

	"net/url"

	"os"
	"path"
	"regexp"

	"slices"

	"sort"

	"strconv"
	"strings"

	"time"
	"unicode/utf8"
)

// MaxResponseBodyBytes is the upper bound for Docker API response bodies that
// sockguard inspects and optionally redacts. Responses larger than this limit
// are rejected to avoid unbounded memory allocation.
const MaxResponseBodyBytes = 8 << 20 // 8 MiB

type bodyTooLargeError struct {
	limit int64
}

func (e *bodyTooLargeError) Error() string {
	return fmt.Sprintf("request body exceeds %d byte limit", e.limit)
}

func isBodyTooLargeError(err error) bool {
	var target *bodyTooLargeError
	return errors.As(err, &target)
}

// readBoundedBody reads up to max+1 bytes, rejecting oversized payloads before
// the request can be forwarded while still restoring safe-sized bodies for
// downstream use. Once the body has been successfully buffered, Close errors
// are ignored because forwarding can safely continue from the restored copy.
func readBoundedBody(r *http.Request, max int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}
	if r.ContentLength > max {
		if err := r.Body.Close(); err != nil {
			return nil, err
		}
		return nil, &bodyTooLargeError{limit: max}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, &bodyTooLargeError{limit: max}
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	return body, nil
}

// replaceRequestBody installs final as the request body a mutation
// committed, keeping every transport-relevant field in lockstep so a stale
// Content-Length or Transfer-Encoding cannot survive a rewrite: it closes
// the previous body, installs final via io.NopCloser(bytes.NewReader(...)),
// sets r.ContentLength (the proxy layer never reads the literal
// Content-Length header — see readBoundedBody's doc comment and
// internal/proxy/proxy.go, which relies on req.ContentLength exclusively),
// clears r.TransferEncoding plus any stale Transfer-Encoding/Content-Length
// request headers, and installs GetBody so a retried/redirected request
// re-reads the same committed bytes rather than a drained reader.
//
// Callers must only invoke this after every rule that will be applied has
// been applied without error — there is no partial-body state this function
// can be called into.
func replaceRequestBody(r *http.Request, final []byte) {
	final = bytes.Clone(final)
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(final))
	r.ContentLength = int64(len(final))
	r.TransferEncoding = nil
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Content-Length")
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(final)), nil
	}
}

const maxBuildContextBytes = 512 << 20           // 512 MiB (compressed/on-wire cap)
const maxBuildDockerfileBytes = 1 << 20          // 1 MiB
const maxBuildContextDecompressedBytes = 1 << 30 // 1 GiB (gzip-bomb guard)
const defaultBuildDockerfilePath = "Dockerfile"

var errBuildDockerfileTooLarge = errors.New("dockerfile exceeds byte limit")
var errBuildContextDecompressedTooLarge = errors.New("decompressed build context exceeds byte limit")

// BuildOptions configures request-body/query inspection for POST /build.
type BuildOptions struct {
	AllowRemoteContext   bool
	AllowHostNetwork     bool
	AllowRunInstructions bool
}

type buildPolicy struct {
	allowRemoteContext   bool
	allowHostNetwork     bool
	allowRunInstructions bool
	io                   ioDeps
}

func newBuildPolicy(opts BuildOptions) buildPolicy {
	return buildPolicy{
		allowRemoteContext:   opts.AllowRemoteContext,
		allowHostNetwork:     opts.AllowHostNetwork,
		allowRunInstructions: opts.AllowRunInstructions,
		io:                   defaultIODeps(),
	}
}

func (p buildPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/build" {
		return "", nil
	}
	if p.io.CreateTempFile == nil {
		p.io = defaultIODeps()
	}

	if denyReason := denyRegistryConfigHeaderReason(r.Header.Get("X-Registry-Config"), "build"); denyReason != "" {
		return denyReason, nil
	}

	query := r.URL.Query()

	if !p.allowHostNetwork && strings.EqualFold(strings.TrimSpace(query.Get("networkmode")), "host") {
		return "build denied: host network mode is not allowed", nil
	}

	if remote := strings.TrimSpace(query.Get("remote")); remote != "" {
		if p.allowRemoteContext {
			if p.allowRunInstructions {
				return "", nil
			}
			return "build denied: remote build contexts cannot be inspected while RUN instructions are restricted", nil
		}
		return fmt.Sprintf("build denied: remote build context %q is not allowed", remote), nil
	}

	if p.allowRunInstructions || r.Body == nil {
		return "", nil
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

	dockerfilePath := normalizeBuildDockerfilePath(query.Get("dockerfile"))
	dockerfile, ok, err := p.io.extractBuildDockerfile(spool.file, r.Header.Get("Content-Type"), dockerfilePath)
	if err != nil {
		spool.closeAndRemove()
		if errors.Is(err, errBuildContextDecompressedTooLarge) {
			return fmt.Sprintf("build denied: decompressed build context exceeds %d byte limit", maxBuildContextDecompressedBytes), nil
		}
		return "", fmt.Errorf("extract Dockerfile: %w", err)
	}
	if !ok {
		spool.closeAndRemove()
		return fmt.Sprintf("build denied: unable to inspect Dockerfile %q", dockerfilePath), nil
	}

	if frontend := dockerfileSyntaxFrontend(dockerfile); frontend != "" {
		spool.closeAndRemove()
		return fmt.Sprintf("build denied: BuildKit syntax frontend %q cannot be inspected while RUN instructions are restricted", frontend), nil
	}

	if dockerfileContainsRunInstruction(dockerfile) {
		spool.closeAndRemove()
		return "build denied: RUN instructions are not allowed", nil
	}

	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind build body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
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

	_ = s.io.RemoveFilePath(s.path)
}

type tempFileBody struct {
	file *os.File
	path string
	io   ioDeps
}

func (b *tempFileBody) Read(p []byte) (int, error) {
	return b.file.Read(p)
}

func (b *tempFileBody) Close() error {
	closeErr := b.file.Close()
	removeErr := b.io.RemoveFilePath(b.path)
	if closeErr != nil {
		return closeErr
	}
	if removeErr != nil && !os.IsNotExist(removeErr) {
		return removeErr
	}
	return nil
}

func normalizeBuildDockerfilePath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultBuildDockerfilePath
	}
	cleaned := path.Clean(strings.TrimPrefix(trimmed, "/"))
	if cleaned == "." || cleaned == "" {
		return defaultBuildDockerfilePath
	}
	return cleaned
}

func (io_ ioDeps) extractBuildDockerfile(file *os.File, contentType string, dockerfilePath string) ([]byte, bool, error) {
	if err := io_.SeekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind Dockerfile reader: %w", err)
	}

	if dockerfile, ok, err := io_.extractDockerfileFromGzipTar(file, dockerfilePath); ok || err != nil {
		return dockerfile, ok, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind Dockerfile reader: %w", err)
	}
	if dockerfile, ok, err := io_.extractDockerfileFromTar(file, dockerfilePath); ok || err != nil {
		return dockerfile, ok, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind Dockerfile reader: %w", err)
	}

	raw, err := io_.ReadAllLimited(file, maxBuildDockerfileBytes+1)
	if err != nil {
		return nil, false, fmt.Errorf("read raw Dockerfile: %w", err)
	}
	if len(raw) > maxBuildDockerfileBytes {
		return nil, false, fmt.Errorf("%w: %d bytes", errBuildDockerfileTooLarge, maxBuildDockerfileBytes)
	}
	if !looksLikeDockerfile(raw, contentType) {
		return nil, false, nil
	}
	return raw, true, nil
}

func (io_ ioDeps) extractDockerfileFromGzipTar(file *os.File, dockerfilePath string) ([]byte, bool, error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("create gzip reader: %w", err)
	}

	limited := &limitedReader{r: gzr, remaining: maxBuildContextDecompressedBytes}

	dockerfile, ok, err := io_.extractDockerfileFromTarReader(tar.NewReader(limited), dockerfilePath)
	if err == nil {
		if drainErr := io_.DrainReader(limited); drainErr != nil {
			err = fmt.Errorf("drain gzip stream: %w", drainErr)
		}
	}
	if closeErr := io_.CloseReadCloser(gzr); err == nil && closeErr != nil {
		err = fmt.Errorf("close gzip reader: %w", closeErr)
	}
	if errors.Is(err, errBuildContextDecompressedTooLarge) {

		return nil, false, errBuildContextDecompressedTooLarge
	}
	return dockerfile, ok, err
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

func (io_ ioDeps) extractDockerfileFromTar(file *os.File, dockerfilePath string) ([]byte, bool, error) {
	return io_.extractDockerfileFromTarReader(tar.NewReader(file), dockerfilePath)
}

func (io_ ioDeps) extractDockerfileFromTarReader(tr *tar.Reader, dockerfilePath string) ([]byte, bool, error) {
	want := normalizeBuildDockerfilePath(dockerfilePath)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		if err != nil {
			if strings.Contains(err.Error(), "invalid tar header") {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("read tar entry: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}
		if normalizeBuildDockerfilePath(header.Name) != want {
			continue
		}

		body, err := io_.ReadAllLimited(tr, maxBuildDockerfileBytes+1)
		if err != nil {
			return nil, false, fmt.Errorf("read Dockerfile entry: %w", err)
		}
		if len(body) > maxBuildDockerfileBytes {
			return nil, false, fmt.Errorf("%w: %d bytes", errBuildDockerfileTooLarge, maxBuildDockerfileBytes)
		}
		return body, true, nil
	}
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

// BuildkitOptions carries the ONE signal Phase 1 of issue #185 (BuildKit
// gRPC mediation) needs at the request-handling hot path: whether
// request_body.buildkit is configured for the active policy (global or a
// named client profile). It deliberately does NOT carry the richer
// buildkitproxy.Policy translation — Phase 1 ships no transport/mediator,
// so there is nothing here yet to make a per-field decision with. See
// buildkitPolicy.inspect below and cmd/rules.go's
// validateBuildkitTunnelRulesForPolicy for the startup-time half of this.
type BuildkitOptions struct {
	// TunnelConfigured is true when the operator configured
	// request_body.buildkit (top-level or on this client profile) — see
	// config.BuildkitRequestBodyConfig and buildkitproxy.Policy.Configured.
	TunnelConfigured bool
}

// buildkitTunnelPaths are the three opaque, unversioned BuildKit endpoints
// (see cmd/rules.go's buildkitTunnelEndpoints doc comment for the full
// rationale): POST /session, the frontend/session bridge; POST /grpc, the
// moby.buildkit.v1.Control service tunneled over an HTTP/1.1 hijack; and any
// direct moby.buildkit.v1.Control/<Method> path (e.g.
// /moby.buildkit.v1.Control/Solve, /moby.buildkit.v1.Control/Status) —
// cmd/rules.go's buildkitTunnelEndpoints probes these too, and once
// request_body.buildkit is configured, startup validation admits rules that
// match them, so this inspector must deny them here or they would reach the
// Docker socket completely unmediated. Matched against the ALREADY
// version-stripped normalized path, exactly like every other
// matches*Inspection function in this package.
func matchesBuildkitTunnelInspection(normalizedPath string) bool {
	return normalizedPath == "/session" || normalizedPath == "/grpc" ||
		strings.HasPrefix(normalizedPath, "/moby.buildkit.v1.Control/")
}

// IsBuildkitTunnelPath reports whether normalizedPath is one of the two
// REAL h2c-upgrade-bearing BuildKit tunnel endpoints — POST /session or
// POST /grpc, the only two paths sockguard ever hijacks (see
// internal/buildkitproxy.Mediator and cmd/serve.go's withBuildkitMediator).
// Deliberately narrower than matchesBuildkitTunnelInspection above, which
// also matches the literal /moby.buildkit.v1.Control/* probe path: that path
// carries no upgrade at all (see buildkit.go's inspect doc comment below)
// and is never handed to the mediator, so it must not be reported here.
func IsBuildkitTunnelPath(normalizedPath string) bool {
	return normalizedPath == "/session" || normalizedPath == "/grpc"
}

// buildkitPolicy is the request-time inspector for the BuildKit tunnel
// endpoints. Unlike every other inspector in this package it never reads
// the request body — there is nothing to decode at this layer even now that
// a real mediator exists; that mediator (internal/buildkitproxy) runs
// downstream, in the hijack tier of cmd/serve.go's handler chain, on
// whatever this inspector admits.
//
// Why this exists at all: cmd/rules.go's validateBuildkitTunnelRulesForPolicy
// treats a configured request_body.buildkit block as satisfying the same
// startup admission check insecure_accept_opaque_buildkit_tunnels does, so a
// rule allowing POST /session or POST /grpc no longer fails config
// validation once request_body.buildkit is set. Phase 1 (deny-only) ran
// before any mediator existed, so it denied both endpoints unconditionally
// once TunnelConfigured; Phase 2 replaces that with real admission — POST
// /session and POST /grpc pass through here (buildkitproxy.Mediator
// enforces Classify + Policy.Allowed per gRPC method downstream, once the
// h2c tunnel is actually terminated) — but the literal
// /moby.buildkit.v1.Control/<Method> probe path stays hard-denied
// regardless of TunnelConfigured: it carries no h2c upgrade for any mediator
// to terminate (sockguard's listener has no bare-h2c support outside the
// two hijack-capable endpoints — see cmd/rules.go's buildkitTunnelEndpoints
// doc comment), so there is nothing to bridge, only a bare HTTP/1.1 request
// shaped like a gRPC path.
//
// When TunnelConfigured is false (the overwhelmingly common case — no
// request_body.buildkit block at all), inspect is a no-op and the request
// falls through to whatever insecure_accept_opaque_buildkit_tunnels already
// allowed, unchanged from pre-#185 behavior.
type buildkitPolicy struct {
	tunnelConfigured bool
}

func newBuildkitPolicy(cfg BuildkitOptions) buildkitPolicy {
	return buildkitPolicy{tunnelConfigured: cfg.TunnelConfigured}
}

func (p buildkitPolicy) inspect(_ *slog.Logger, r *http.Request, _ string) (string, error) {
	if !p.tunnelConfigured {
		return "", nil
	}

	normPath := NormalizePath(r.URL.Path)
	if IsBuildkitTunnelPath(normPath) {

		return "", nil
	}

	service, method, ok := buildkitproxy.ParseGRPCPath(normPath)
	if !ok {
		return fmt.Sprintf("request_body.buildkit is configured, but %q could not be parsed as a gRPC method path", normPath), nil
	}
	disposition := buildkitproxy.Classify(buildkitproxy.EndpointGRPC, service, method)
	return fmt.Sprintf(
		"request_body.buildkit is configured; a literal moby.buildkit.v1.Control method path carries no h2c upgrade for sockguard's mediator to terminate, so %s/%s is denied regardless of its own %s classification — use the mediated POST /grpc tunnel instead",
		service, method, disposition,
	), nil
}

const maxContainerArchiveBodyBytes = 512 << 20 // 512 MiB

// ContainerArchiveOptions configures request-body/query inspection for
// PUT /containers/{id}/archive.
type ContainerArchiveOptions struct {
	AllowedPaths       []string
	AllowSetID         bool
	AllowDeviceNodes   bool
	AllowEscapingLinks bool
}

type containerArchivePolicy struct {
	allowedPaths       []string
	allowSetID         bool
	allowDeviceNodes   bool
	allowEscapingLinks bool
	io                 ioDeps
}

func newContainerArchivePolicy(opts ContainerArchiveOptions) containerArchivePolicy {
	return containerArchivePolicy{
		allowedPaths:       normalizeContainerArchiveAllowedPaths(opts.AllowedPaths),
		allowSetID:         opts.AllowSetID,
		allowDeviceNodes:   opts.AllowDeviceNodes,
		allowEscapingLinks: opts.AllowEscapingLinks,
		io:                 defaultIODeps(),
	}
}

func (p containerArchivePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !matchesContainerArchiveInspection(normalizedPath) || r.Body == nil {
		return "", nil
	}
	if p.io.CreateTempFile == nil {
		p.io = defaultIODeps()
	}

	targetPath, ok := normalizeContainerArchiveTargetPath(r.URL.Query().Get("path"))
	if !ok {
		return "container archive denied: target path must stay within the container path", nil
	}
	if !p.targetPathAllowed(targetPath) {
		return fmt.Sprintf("container archive denied: target path %q is not allowlisted", targetPath), nil
	}

	spool, size, err := p.io.spoolRequestBodyForInspection(r, "sockguard-container-archive-", maxContainerArchiveBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("container archive denied: request body exceeds %d byte limit", maxContainerArchiveBodyBytes))
		}
		return "", err
	}
	if spool == nil || size == 0 {

		spool.closeAndRemove()
		return "", nil
	}

	denyReason, err := p.inspectContainerArchiveTar(spool.file)
	if err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("inspect archive body: %w", err)
	}
	if denyReason != "" {
		spool.closeAndRemove()
		return denyReason, nil
	}

	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind archive body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

func isContainerArchivePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	_, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/containers/"), "/")
	return ok && tail == "archive"
}

func normalizeContainerArchiveTargetPath(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", true
	}
	cleaned := path.Clean(strings.TrimLeft(trimmed, "/"))
	if cleaned == "." || cleaned == "" {
		return ".", true
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func normalizeContainerArchiveRelativePath(value string) (string, bool) {
	if strings.HasPrefix(value, "/") {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func (p containerArchivePolicy) inspectContainerArchiveTar(reader io.Reader) (string, error) {
	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry: %w", err)
		}

		denyReason := p.denyReasonForContainerArchiveEntry(header)
		if denyReason != "" {
			return denyReason, nil
		}
	}
}

func (p containerArchivePolicy) denyReasonForContainerArchiveEntry(header *tar.Header) string {
	if header == nil {
		return ""
	}

	entryPath, ok := normalizeContainerArchiveEntryPath(header.Name)
	if !ok {
		return fmt.Sprintf("container archive denied: tar entry %q must be relative and stay within the archive", header.Name)
	}

	if !p.allowSetID && header.Mode&0o6000 != 0 {
		return fmt.Sprintf("container archive denied: tar entry %q sets setuid/setgid bits", header.Name)
	}

	switch header.Typeflag {
	case tar.TypeChar, tar.TypeBlock:
		if !p.allowDeviceNodes {
			return fmt.Sprintf("container archive denied: tar entry %q is a device node", header.Name)
		}
	case tar.TypeSymlink:
		if !p.allowEscapingLinks && !containerArchiveSymlinkTargetIsSafe(entryPath, header.Linkname) {
			return fmt.Sprintf("container archive denied: symlink %q escapes the archive", header.Name)
		}
	case tar.TypeLink:
		if !p.allowEscapingLinks && !containerArchiveHardlinkTargetIsSafe(header.Linkname) {
			return fmt.Sprintf("container archive denied: hardlink %q escapes the archive", header.Name)
		}
	}

	return ""
}

func normalizeContainerArchiveEntryPath(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return "", false
	}
	cleaned := path.Clean(trimmed)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func normalizeContainerArchiveAllowedPaths(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		trimmed = strings.TrimPrefix(path.Clean(trimmed), "/")
		normalized, ok := normalizeContainerArchiveRelativePath(trimmed)
		if !ok || containerArchivePathInList(normalized, allowed) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func (p containerArchivePolicy) targetPathAllowed(targetPath string) bool {
	if len(p.allowedPaths) == 0 || targetPath == "" {
		return true
	}
	return containerArchivePathInList(targetPath, p.allowedPaths)
}

func containerArchivePathInList(targetPath string, allowedPaths []string) bool {
	for _, allowed := range allowedPaths {
		if allowed == "." || targetPath == allowed || strings.HasPrefix(targetPath, allowed+"/") {
			return true
		}
	}
	return false
}

func containerArchiveSymlinkTargetIsSafe(entryPath string, linkName string) bool {
	trimmed := strings.TrimSpace(linkName)
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return trimmed == ""
	}

	combined := trimmed
	if dir := path.Dir(entryPath); dir != "." {
		combined = path.Join(dir, trimmed)
	}
	_, ok := normalizeContainerArchiveEntryPath(combined)
	return ok
}

func containerArchiveHardlinkTargetIsSafe(linkName string) bool {
	trimmed := strings.TrimSpace(linkName)
	if trimmed == "" {
		return true
	}
	_, ok := normalizeContainerArchiveEntryPath(trimmed)
	return ok
}

func (io_ ioDeps) spoolRequestBodyForInspection(r *http.Request, prefix string, maxBytes int64) (*spooledRequestBody, int64, error) {
	if r == nil || r.Body == nil {
		return nil, 0, nil
	}
	if r.ContentLength > maxBytes {
		if err := r.Body.Close(); err != nil {
			return nil, 0, err
		}
		return nil, 0, &bodyTooLargeError{limit: maxBytes}
	}

	spool, size, err := io_.spoolRequestBodyToTempFile(r, prefix, maxBytes)
	if err != nil {
		return nil, 0, err
	}
	if spool.tooLarge {
		spool.closeAndRemove()
		return nil, size, &bodyTooLargeError{limit: maxBytes}
	}
	return spool, size, nil
}

// maxContainerCreateBodyBytes caps the request body Sockguard will read when
// inspecting POST /containers/create. Docker's own container-create payloads
// are at most a few KiB even for complex specs, so a 1 MiB ceiling is
// generous while still preventing a malicious or misbehaving client from
// OOMing the proxy with an unbounded body.
const maxContainerCreateBodyBytes = 1 << 20 // 1 MiB

// ImageTrustOptions configures cosign signature verification for images
// referenced in POST /containers/create.
type ImageTrustOptions struct {
	// Mode is "off" | "warn" | "enforce". Default: off.
	Mode string
	// AllowedSigningKeys lists PEM-encoded public keys trusted to sign images.
	AllowedSigningKeys []SigningKeyOptions
	// AllowedKeyless lists Fulcio-backed identity patterns.
	AllowedKeyless []KeylessOptions
	// RequireRekorInclusion requires a Rekor tlog entry for keyless bundles.
	RequireRekorInclusion bool
	// VerifyTimeout overrides the default per-verification timeout.
	VerifyTimeout string
}

// SigningKeyOptions is one allowed signing key entry.
type SigningKeyOptions struct {
	PEM string
}

// KeylessOptions is one allowed keyless identity entry.
type KeylessOptions struct {
	Issuer         string
	SubjectPattern string
}

// imageVerifier is the narrow interface used by containerCreatePolicy so tests
// can inject a stub without a real registry or Rekor connection.
type imageVerifier interface {
	Verify(ctx context.Context, imageRef, digestHex string, entity verify.SignedEntity) error
}

// signatureFetcher resolves an image reference to the set of cosign signature
// candidates attached to it in the registry. The production implementation is
// internal/imagefetch.Fetcher; tests inject a stub to avoid registry I/O.
type signatureFetcher interface {
	FetchCandidates(ctx context.Context, logger *slog.Logger, imageRef string) ([]imagetrust.Candidate, error)
}

// ContainerCreateOptions configures request-body policy checks for
// POST /containers/create.
type ContainerCreateOptions struct {
	AllowPrivileged          bool
	AllowHostNetwork         bool
	AllowHostPID             bool
	AllowHostIPC             bool
	AllowedBindMounts        []string
	AllowAllDevices          bool
	AllowedDevices           []string
	AllowDeviceRequests      bool
	AllowedDeviceRequests    []AllowedDeviceRequestEntry
	AllowDeviceCgroupRules   bool
	AllowedDeviceCgroupRules []string

	RequireNoNewPrivileges     bool
	RequireNonRootUser         bool
	RequireReadonlyRootfs      bool
	RequireDropAllCapabilities bool
	AllowAllCapabilities       bool
	AllowedCapabilities        []string
	RequireMemoryLimit         bool
	RequireCPULimit            bool
	// RequireCPULimitHard narrows RequireCPULimit to accept only a genuine
	// CPU-time cap (NanoCpus or CpuQuota); CpuShares alone does not satisfy
	// it. Independent of RequireCPULimit — see hasHardCPULimit.
	RequireCPULimitHard     bool
	RequirePidsLimit        bool
	AllowedSeccompProfiles  []string
	DenyUnconfinedSeccomp   bool
	AllowedAppArmorProfiles []string
	DenyUnconfinedAppArmor  bool
	AllowHostUserNS         bool
	AllowHostCgroupNS       bool
	// RestrictNamespaceSharing gates HostConfig.NetworkMode/PidMode/IpcMode/
	// UsernsMode values of the form "container:<ref>" (join another
	// container's namespace) against AllowedNamespaceSharingContainers.
	// Default false: container:<ref> values continue to pass through
	// unchecked, matching today's behavior exactly — an independent,
	// orthogonal gate from AllowHostNetwork/PID/IPC/UserNS, which only ever
	// match the literal "host" value and continue to do so unchanged.
	RestrictNamespaceSharing bool
	// AllowedNamespaceSharingContainers allowlists the container:<ref>
	// targets permitted when RestrictNamespaceSharing is true. Only
	// consulted when RestrictNamespaceSharing is true; empty denies every
	// container: ref. Mirrors the AllowDeviceRequests/AllowedDeviceRequests
	// bool-escape-hatch-plus-allowlist shape, not AllowedRuntimes (which
	// denies non-empty values by default) — this field defaults to
	// pass-through, not deny-by-default.
	AllowedNamespaceSharingContainers []string
	// DenyNamespacePathMode denies HostConfig.NetworkMode values with an
	// "ns:" prefix (case-insensitive) — Docker's raw host-namespace-file
	// attachment form, which bypasses the "host" literal check entirely.
	// Scoped to NetworkMode only. Default false (pass-through).
	DenyNamespacePathMode bool
	RequiredLabels        []string

	// AllowedRuntimes allowlists HostConfig.Runtime values. An empty Runtime
	// selects the daemon default and is always permitted; any other (non-empty)
	// runtime is denied unless listed here. This prevents a client from silently
	// selecting an alternate OCI runtime with different (or absent) seccomp/
	// AppArmor defaults to escape the profile policy enforced for the default
	// runtime. Runtime names are matched case-sensitively (as in daemon.json).
	AllowedRuntimes []string

	// AllowSysctls permits setting kernel parameters via HostConfig.Sysctls.
	// Default false: any non-empty Sysctls map is denied.
	AllowSysctls bool

	// DenySelinuxDisable prevents label=disable (and label:disable) which
	// turns off SELinux confinement for the container. Default false
	// (pass-through) for backward-compatibility.
	DenySelinuxDisable bool

	// DenySelinuxLabelOverride denies label=user:, label=role:, label=type:,
	// label=level: SecurityOpt entries that customize the SELinux context.
	// Default false (pass-through). Independent of DenySelinuxDisable.
	DenySelinuxLabelOverride bool

	// DenyUnconfinedSystemPaths prevents systempaths=unconfined in SecurityOpt
	// AND rejects requests that set MaskedPaths or ReadonlyPaths to an empty
	// slice (the direct-API equivalent of systempaths=unconfined). Default false
	// for backward-compatibility.
	DenyUnconfinedSystemPaths bool

	// ImageTrust configures cosign-backed signature verification.
	ImageTrust ImageTrustOptions

	// AllowTmpfsPrivilegedOptions permits tmpfs mount options that re-enable
	// exec/dev/suid semantics: "exec", "dev", "suid" in
	// HostConfig.Mounts[].TmpfsOptions.Options (Engine API 1.46+). Default
	// false: any such option is denied.
	AllowTmpfsPrivilegedOptions bool

	// AllowEndpointConfig permits static IP, MAC address, Links, and
	// DriverOpts in NetworkingConfig.EndpointsConfig entries carried on
	// POST /containers/create. Docker connects every entry here the same way
	// POST /networks/*/connect does, so without this the same fields
	// network.AllowEndpointConfig gates at connect time were an unchecked
	// bypass via create's NetworkingConfig — put the same config on the
	// primary network at create instead of a follow-up connect call, and it
	// sailed through. Shares a single config knob
	// (request_body.network.allow_endpoint_config) with the network
	// inspector; see config.RequestBodyConfig.ToFilterOptions. Aliases are
	// never gated regardless of this flag — see denyEndpointConfigReason.
	AllowEndpointConfig bool
	// EndpointConfig narrows AllowEndpointConfig into per-field gates (#186),
	// cross-wired from request_body.network.endpoint_config the same way
	// AllowEndpointConfig is cross-wired from request_body.network.allow_endpoint_config.
	// Only consulted when AllowEndpointConfig is false.
	EndpointConfig EndpointConfigOptions
}

type containerCreatePolicy struct {
	allowPrivileged          bool
	allowHostNetwork         bool
	allowHostPID             bool
	allowHostIPC             bool
	allowedBindMounts        []string
	allowAllDevices          bool
	allowedDevices           []string
	allowDeviceRequests      bool
	allowedDeviceRequests    []allowedDeviceRequestEntry
	allowDeviceCgroupRules   bool
	allowedDeviceCgroupRules []string

	requireNoNewPrivileges            bool
	requireNonRootUser                bool
	requireReadonlyRootfs             bool
	requireDropAllCapabilities        bool
	allowAllCapabilities              bool
	allowedCapabilities               []string
	requireMemoryLimit                bool
	requireCPULimit                   bool
	requireCPULimitHard               bool
	requirePidsLimit                  bool
	allowedSeccompProfiles            []string
	denyUnconfinedSeccomp             bool
	allowedAppArmorProfiles           []string
	denyUnconfinedAppArmor            bool
	allowHostUserNS                   bool
	allowHostCgroupNS                 bool
	restrictNamespaceSharing          bool
	allowedNamespaceSharingContainers []string
	denyNamespacePathMode             bool
	requiredLabels                    []string
	allowSysctls                      bool
	allowedRuntimes                   []string

	denySelinuxDisable        bool
	denySelinuxLabelOverride  bool
	denyUnconfinedSystemPaths bool

	allowTmpfsPrivilegedOptions bool

	allowEndpointConfig bool
	endpointConfig      EndpointConfigOptions

	// Image trust — non-nil when mode != off.
	imageTrustVerifier imageVerifier
	imageFetcher       signatureFetcher
	imageTrustCfg      imagetrust.Config
	imageTrustTimeout  time.Duration
	// imageTrustInitErr holds any error that occurred while building the image
	// trust verifier at policy construction time. When non-nil, inspect returns
	// a denial reason so that a misconfigured trust policy fails closed rather
	// than silently falling through to Docker.
	imageTrustInitErr error
}

func newContainerCreatePolicy(opts ContainerCreateOptions) containerCreatePolicy {
	allowed := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeBindMount(bindMount)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	allowedDevices := make([]string, 0, len(opts.AllowedDevices))
	for _, device := range opts.AllowedDevices {
		normalized, ok := normalizeContainerCreateDevicePath(device)
		if !ok || slices.Contains(allowedDevices, normalized) {
			continue
		}
		allowedDevices = append(allowedDevices, normalized)
	}

	allowedDeviceCgroupRules := make([]string, 0, len(opts.AllowedDeviceCgroupRules))
	for _, rule := range opts.AllowedDeviceCgroupRules {
		canonical, ok := canonicalizeDeviceCgroupRule(rule)
		if !ok || slices.Contains(allowedDeviceCgroupRules, canonical) {
			continue
		}
		allowedDeviceCgroupRules = append(allowedDeviceCgroupRules, canonical)
	}

	allowedDeviceRequests := make([]allowedDeviceRequestEntry, 0, len(opts.AllowedDeviceRequests))
	for _, entry := range opts.AllowedDeviceRequests {
		driver := strings.ToLower(strings.TrimSpace(entry.Driver))
		if driver == "" {
			continue
		}
		canonCaps := canonicalizeAllowedCapabilitySets(entry.AllowedCapabilities)
		allowedDeviceRequests = append(allowedDeviceRequests, allowedDeviceRequestEntry{
			driver:              driver,
			allowedCapabilities: canonCaps,
			maxCount:            entry.MaxCount,
		})
	}

	p := containerCreatePolicy{
		allowPrivileged:                   opts.AllowPrivileged,
		allowHostNetwork:                  opts.AllowHostNetwork,
		allowHostPID:                      opts.AllowHostPID,
		allowHostIPC:                      opts.AllowHostIPC,
		allowedBindMounts:                 allowed,
		allowAllDevices:                   opts.AllowAllDevices,
		allowedDevices:                    allowedDevices,
		allowDeviceRequests:               opts.AllowDeviceRequests,
		allowedDeviceRequests:             allowedDeviceRequests,
		allowDeviceCgroupRules:            opts.AllowDeviceCgroupRules,
		allowedDeviceCgroupRules:          allowedDeviceCgroupRules,
		requireNoNewPrivileges:            opts.RequireNoNewPrivileges,
		requireNonRootUser:                opts.RequireNonRootUser,
		requireReadonlyRootfs:             opts.RequireReadonlyRootfs,
		requireDropAllCapabilities:        opts.RequireDropAllCapabilities,
		allowAllCapabilities:              opts.AllowAllCapabilities,
		allowedCapabilities:               normalizeCapabilityList(opts.AllowedCapabilities),
		requireMemoryLimit:                opts.RequireMemoryLimit,
		requireCPULimit:                   opts.RequireCPULimit,
		requireCPULimitHard:               opts.RequireCPULimitHard,
		requirePidsLimit:                  opts.RequirePidsLimit,
		allowedSeccompProfiles:            normalizeStringList(opts.AllowedSeccompProfiles),
		denyUnconfinedSeccomp:             opts.DenyUnconfinedSeccomp,
		allowedAppArmorProfiles:           normalizeStringList(opts.AllowedAppArmorProfiles),
		denyUnconfinedAppArmor:            opts.DenyUnconfinedAppArmor,
		allowHostUserNS:                   opts.AllowHostUserNS,
		allowHostCgroupNS:                 opts.AllowHostCgroupNS,
		restrictNamespaceSharing:          opts.RestrictNamespaceSharing,
		allowedNamespaceSharingContainers: normalizeStringList(opts.AllowedNamespaceSharingContainers),
		denyNamespacePathMode:             opts.DenyNamespacePathMode,
		requiredLabels:                    normalizeStringList(opts.RequiredLabels),
		allowSysctls:                      opts.AllowSysctls,
		allowedRuntimes:                   normalizeStringList(opts.AllowedRuntimes),
		denySelinuxDisable:                opts.DenySelinuxDisable,
		denySelinuxLabelOverride:          opts.DenySelinuxLabelOverride,
		denyUnconfinedSystemPaths:         opts.DenyUnconfinedSystemPaths,
		allowTmpfsPrivilegedOptions:       opts.AllowTmpfsPrivilegedOptions,
		allowEndpointConfig:               opts.AllowEndpointConfig,
		endpointConfig:                    opts.EndpointConfig,
	}

	itf := buildImageTrustFields(opts.ImageTrust)
	p.imageTrustVerifier = itf.verifier
	p.imageFetcher = itf.fetcher
	p.imageTrustCfg = itf.cfg
	p.imageTrustTimeout = itf.timeout
	p.imageTrustInitErr = itf.initErr

	return p
}

// imageTrustFields holds the constructed cosign verification machinery shared
// by the container-create and service inspectors.
type imageTrustFields struct {
	verifier imageVerifier
	fetcher  signatureFetcher
	cfg      imagetrust.Config
	timeout  time.Duration
	initErr  error
}

// buildImageTrustFields constructs the cosign verifier and signature fetcher for
// the given options. Any construction error is returned in initErr so callers
// fail closed (deny) rather than silently allowing unverified images. When the
// mode is off/empty the zero value is returned (inactive).
func buildImageTrustFields(opts ImageTrustOptions) imageTrustFields {
	var f imageTrustFields
	if mode := imagetrust.Mode(opts.Mode); mode == imagetrust.ModeOff || mode == "" {
		return f
	}
	cfg, err := imagetrust.BuildConfig(buildImageTrustRaw(opts))
	if err != nil {
		f.initErr = fmt.Errorf("image trust policy build failed: %w", err)
		return f
	}

	if len(cfg.AllowedKeyless) > 0 {
		tm, tmErr := imagetrust.LoadLiveTrustedRoot()
		if tmErr != nil {
			f.initErr = fmt.Errorf("image trust keyless trust root load failed: %w", tmErr)
			return f
		}
		cfg.TrustedMaterial = tm
	}
	v, verr := imagetrust.New(cfg)
	if verr != nil {
		f.initErr = fmt.Errorf("image trust verifier construction failed: %w", verr)
		return f
	}
	f.verifier = v
	f.fetcher = imagefetch.NewFetcher()
	f.cfg = cfg
	f.timeout = cfg.VerifyTimeout
	if f.timeout == 0 {
		f.timeout = imagetrust.VerifyTimeout
	}
	return f
}

// verifyImageTrust fetches and verifies the cosign signatures for imageRef under
// the configured mode, returning a deny reason ("" when allowed) and the
// verified image manifest digest ("" when nothing was verified, e.g. an empty
// ref or warn-mode bypass). subject prefixes the deny reason.
func verifyImageTrust(ctx context.Context, logger *slog.Logger, f imageTrustFields, imageRef, subject string) (denyReason, verifiedDigest string) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {

		return fmt.Sprintf("%s denied: image field is required when image trust is configured", subject), ""
	}
	if f.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.timeout)
		defer cancel()
	}
	// Fetch the cosign signatures attached to the image in the registry and
	// reconstruct a verifiable bundle for each, then verify under the configured
	// mode. A fetch failure (unsigned image, registry unreachable) is surfaced to
	// the verifier as a verification failure so enforce mode denies and warn mode
	// logs-and-allows.
	var (
		candidates []imagetrust.Candidate
		fetchErr   error
	)
	if f.fetcher != nil {
		candidates, fetchErr = f.fetcher.FetchCandidates(ctx, logger, imageRef)
	} else {
		fetchErr = fmt.Errorf("image trust misconfigured: no signature fetcher")
	}
	outcome := imagetrust.VerifyCandidatesWithMode(ctx, f.verifier, f.cfg, logger, imageRef, candidates, fetchErr)
	if !outcome.Allowed {
		return fmt.Sprintf("%s denied: image trust verification failed for %s: %s", subject, imageRef, outcome.FailureMsg), ""
	}
	return "", outcome.VerifiedDigest
}

// rewriteJSONImageField returns body with its (case-insensitive) "Image" field
// replaced by pinned. Other fields are preserved byte-for-byte (RawMessage) so
// large integer fields such as Memory are not corrupted by a float round-trip.
func rewriteJSONImageField(body []byte, pinned string) ([]byte, error) {
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	if err := collapseImageKey(fields, pinned); err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

// foldedRawKeys returns every key in m that case-folds to canonical. Docker
// decodes JSON object keys case-insensitively, so a security-relevant rewrite
// must find "image"/"IMAGE" as well as the canonical "Image".
func foldedRawKeys(m map[string]json.RawMessage, canonical string) []string {
	var out []string
	for k := range m {
		if strings.EqualFold(k, canonical) {
			out = append(out, k)
		}
	}
	return out
}

// collapseImageKey rewrites the (case-insensitive) image field of fields to the
// pinned digest, leaving exactly one canonical "Image" key. Docker decodes
// object keys case-insensitively and, on duplicate case-variant keys, honors
// the last one after our re-marshal — and json.Marshal emits map keys sorted,
// so a client-supplied lowercase "image" would sort AFTER the pinned "Image"
// and win at the daemon, running an image the policy check never verified. A
// body carrying two case-variant image keys is therefore ambiguous and is
// rejected fail-closed; a single variant (canonical or lowercase) is collapsed
// to the canonical key so the forwarded body pins exactly the verified image.
func collapseImageKey(fields map[string]json.RawMessage, pinned string) error {
	variants := foldedRawKeys(fields, "Image")
	if len(variants) > 1 {
		return fmt.Errorf("ambiguous container image: %d case-variant \"Image\" keys", len(variants))
	}
	encoded, err := json.Marshal(pinned)
	if err != nil {
		return err
	}
	for _, k := range variants {
		delete(fields, k)
	}
	fields["Image"] = encoded
	return nil
}

// soleFoldedRawKey returns the single key in m that case-folds to canonical.
// It errors if the key is absent (nothing to navigate into) or if more than
// one case-variant is present — an ambiguous body the daemon would resolve by
// last-key order after our re-marshal, rejected fail-closed rather than risk
// forwarding a subtree the policy check never inspected.
func soleFoldedRawKey(m map[string]json.RawMessage, canonical string) (string, error) {
	variants := foldedRawKeys(m, canonical)
	switch len(variants) {
	case 0:
		return "", fmt.Errorf("missing %s", canonical)
	case 1:
		return variants[0], nil
	default:
		return "", fmt.Errorf("ambiguous body: %d case-variant %s keys", len(variants), canonical)
	}
}

// RejectDuplicateCaseVariantJSONKeys returns an error if body contains any JSON
// object with two keys that case-fold to the same name (e.g. "HostConfig" and
// "hostconfig"). The daemon decodes object keys case-insensitively and lets the
// last duplicate win, whereas sockguard inspects a create/update body via a
// struct decode and then may re-marshal it (owner-label stamping, image-digest
// pinning) through a map whose keys json.Marshal re-sorts on the way out. That
// re-sort can move a shadow lowercase key into last position, so the daemon acts
// on a value the filter never checked — a bypass of every body-inspection rule.
// No legitimate Docker client emits duplicate case-variant keys, so any body
// that does is rejected fail-closed before it can be re-marshaled and forwarded.
func RejectDuplicateCaseVariantJSONKeys(body []byte) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	return checkDuplicateCaseVariantKeys(v, false)
}

// checkDuplicateCaseVariantKeys walks a decoded JSON value and rejects any object
// whose sibling keys case-fold to the same name. skipKeyCheck suppresses that
// sibling scan for exactly ONE level: it is set when recursing into the VALUE of
// a case-sensitive data-map field (Labels, Sysctls, LogConfig.Config, …), whose
// own keys are user-chosen case-sensitive data rather than daemon-folded struct
// fields — so two keys there differing only in case are two legitimate distinct
// entries, not a shadow-key. Crucially the walk still recurses INTO that value,
// so a struct nested inside a data map — an EndpointSettings under
// EndpointsConfig, or an IPAMConfig element under IPAM.Config (a []struct) —
// keeps its own struct-field fold check. That is what lets the exemption be keyed
// on a bare field name without opening a bypass: a duplicate of the data-map
// field's own name is still caught by the enclosing object's scan, and only the
// map's leaf keys are spared. Every non-exempt level is a struct whose fields the
// daemon folds, so it stays fully checked.
func checkDuplicateCaseVariantKeys(v any, skipKeyCheck bool) error {
	switch t := v.(type) {
	case map[string]any:
		if !skipKeyCheck {
			keys := make([]string, 0, len(t))
			for k := range t {
				for _, prev := range keys {
					if strings.EqualFold(prev, k) {
						return fmt.Errorf("duplicate case-variant JSON keys %q and %q", prev, k)
					}
				}
				keys = append(keys, k)
			}
		}
		for k, val := range t {

			childSkip := !skipKeyCheck && isCaseSensitiveDataMapField(k)
			if err := checkDuplicateCaseVariantKeys(val, childSkip); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range t {
			if err := checkDuplicateCaseVariantKeys(item, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// isCaseSensitiveDataMapField reports whether key names a Docker body field the
// daemon decodes as a case-sensitive map (map[string]V or map[nat.Port]V) rather
// than a struct. The daemon folds struct field names case-insensitively — so a
// case-variant sibling there is a genuine shadow-key hazard — but map keys are
// matched exactly, so two case-differing keys are two distinct valid entries and
// must not be rejected. Every field below is a plain data map in the Docker
// engine request types (container create Config/HostConfig/NetworkingConfig,
// swarm service, network create, volume create):
//
//	labels, annotations   Config.Labels, swarm Annotations.Labels
//	volumes               Config.Volumes            map[string]struct{}
//	exposedports          Config.ExposedPorts       map[nat.Port]struct{}
//	portbindings          HostConfig.PortBindings   map[nat.Port][]nat.PortBinding
//	sysctls               HostConfig.Sysctls        map[string]string
//	storageopt            HostConfig.StorageOpt     map[string]string
//	tmpfs                 HostConfig.Tmpfs          map[string]string
//	endpointsconfig       NetworkingConfig.EndpointsConfig map[string]*EndpointSettings
//	options               network create Options, IPAM Options   map[string]string
//	driveropts            volume DriverOpts, EndpointSettings.DriverOpts map[string]string
//	opts                  volume Opts (DriverOpts alias)         map[string]string
//	config                HostConfig.LogConfig.Config            map[string]string
//	auxiliaryaddresses    IPAMConfig.AuxAddress     map[string]string
//
// Bias is intentionally toward over-listing: a map field mistakenly omitted here
// only produces a spurious rejection (fail-closed, never a bypass). Listing a
// name that is elsewhere a struct is also safe — the exemption only suppresses
// the sibling key-scan at that field's own value and still recurses into it, so
// nested structs (e.g. the IPAMConfig elements under IPAM.Config, a []struct)
// keep their fold check; see checkDuplicateCaseVariantKeys.
func isCaseSensitiveDataMapField(key string) bool {
	switch strings.ToLower(key) {
	case "labels",
		"annotations",
		"volumes",
		"exposedports",
		"portbindings",
		"sysctls",
		"storageopt",
		"tmpfs",
		"endpointsconfig",
		"options",
		"driveropts",
		"opts",
		"config",
		"auxiliaryaddresses":
		return true
	default:
		return false
	}
}

func buildImageTrustRaw(opts ImageTrustOptions) imagetrust.RawConfig {
	keys := make([]imagetrust.SigningKeyConfig, 0, len(opts.AllowedSigningKeys))
	for _, k := range opts.AllowedSigningKeys {
		keys = append(keys, imagetrust.SigningKeyConfig{PEM: k.PEM})
	}
	kl := make([]imagetrust.KeylessConfig, 0, len(opts.AllowedKeyless))
	for _, k := range opts.AllowedKeyless {
		kl = append(kl, imagetrust.KeylessConfig{
			Issuer:         k.Issuer,
			SubjectPattern: k.SubjectPattern,
		})
	}
	return imagetrust.RawConfig{
		Mode:                  imagetrust.Mode(opts.Mode),
		AllowedSigningKeys:    keys,
		AllowedKeyless:        kl,
		RequireRekorInclusion: opts.RequireRekorInclusion,
		VerifyTimeoutStr:      opts.VerifyTimeout,
	}
}

func (p containerCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/containers/create" || r.Body == nil {
		return "", nil
	}

	if p.imageTrustInitErr != nil {
		return fmt.Sprintf("container create denied: image trust policy initialization error: %s", p.imageTrustInitErr.Error()), nil
	}
	body, err := readBoundedBody(r, maxContainerCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("container create denied: request body exceeds %d byte limit", maxContainerCreateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var createReq containerCreateRequest
	if err := json.Unmarshal(body, &createReq); err != nil {

		logRequestError(logger, r, slog.LevelDebug, "container create request body is not valid JSON; denying", err)
		return "container create denied: malformed JSON request body", nil
	}

	if !p.allowPrivileged && createReq.HostConfig.Privileged {
		return "container create denied: privileged containers are not allowed", nil
	}
	if !p.allowHostNetwork && isHostNamespaceMode(createReq.HostConfig.NetworkMode) {
		return "container create denied: host network mode is not allowed", nil
	}
	if !p.allowHostPID && isHostNamespaceMode(createReq.HostConfig.PidMode) {
		return "container create denied: host PID mode is not allowed", nil
	}
	if !p.allowHostIPC && isHostNamespaceMode(createReq.HostConfig.IpcMode) {
		return "container create denied: host IPC mode is not allowed", nil
	}
	if !p.allowHostUserNS && isHostNamespaceMode(createReq.HostConfig.UsernsMode) {
		return "container create denied: host user namespace mode is not allowed", nil
	}
	if !p.allowHostCgroupNS && isHostNamespaceMode(createReq.HostConfig.CgroupnsMode) {
		return "container create denied: host cgroup namespace mode is not allowed", nil
	}
	if denyReason := p.denyNamespaceSharingReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if p.denyNamespacePathMode && isNamespacePathMode(createReq.HostConfig.NetworkMode) {
		return "container create denied: ns: namespace path mode is not allowed", nil
	}
	if !p.allowSysctls && len(createReq.HostConfig.Sysctls) > 0 {
		return "container create denied: setting sysctls is not allowed", nil
	}
	if len(createReq.HostConfig.VolumesFrom) > 0 {
		return "container create denied: VolumesFrom is not allowed", nil
	}
	if isHostNamespaceMode(createReq.HostConfig.UTSMode) {
		return "container create denied: host UTS mode is not allowed", nil
	}
	if strings.TrimSpace(createReq.HostConfig.CgroupParent) != "" {
		return "container create denied: custom cgroup parent is not allowed", nil
	}
	if len(createReq.HostConfig.GroupAdd) > 0 {
		return "container create denied: supplemental group IDs are not allowed", nil
	}
	if len(createReq.HostConfig.ExtraHosts) > 0 {
		return "container create denied: ExtraHosts is not allowed", nil
	}
	if runtime := strings.TrimSpace(createReq.HostConfig.Runtime); runtime != "" && !slices.Contains(p.allowedRuntimes, runtime) {
		return fmt.Sprintf("container create denied: runtime %q is not allowlisted", runtime), nil
	}
	if denyReason := p.denyDeviceReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyBindMountReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyImageMountReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := denyUnknownMountTypeReason(createReq.HostConfig.Mounts, "container create"); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := denyMountSubpathReason(createReq.HostConfig.Mounts, "container create"); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyTmpfsOptionsReason(createReq.HostConfig.Mounts); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyNetworkingConfigReason(createReq.NetworkingConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyRootMacAddressReason(createReq.MacAddress); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denySecurityOptReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denySystemPathsReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyCapabilityReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyHardeningReason(createReq); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyResourceLimitReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyRequiredLabelsReason(createReq); denyReason != "" {
		return denyReason, nil
	}

	if p.imageTrustVerifier != nil {
		imageRef := strings.TrimSpace(createReq.Image)
		fields := imageTrustFields{
			verifier: p.imageTrustVerifier,
			fetcher:  p.imageFetcher,
			cfg:      p.imageTrustCfg,
			timeout:  p.imageTrustTimeout,
		}
		denyReason, verifiedDigest := verifyImageTrust(r.Context(), logger, fields, imageRef, "container create")
		if denyReason != "" {
			return denyReason, nil
		}

		if verifiedDigest != "" {
			pinned, perr := imagefetch.PinnedReference(imageRef, verifiedDigest)
			if perr != nil {

				return "", fmt.Errorf("pin verified image digest: %w", perr)
			}
			if pinned != imageRef {
				rewritten, rerr := rewriteJSONImageField(body, pinned)
				if rerr != nil {
					return "", fmt.Errorf("pin verified image digest: %w", rerr)
				}
				r.Body = io.NopCloser(bytes.NewReader(rewritten))
				r.ContentLength = int64(len(rewritten))
			}
		}
	}

	return "", nil
}

func isHostNamespaceMode(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "host")
}

// ContainerNamespaceRef reports whether mode has the form "container:<ref>"
// — Docker's syntax for joining another container's network/PID/IPC/user
// namespace — and, if so, returns the trimmed ref. The "container:" prefix
// is matched case-insensitively (as Docker itself does); the ref's case is
// preserved, since container IDs and names are case-sensitive. An empty ref
// ("container:" alone, or all-whitespace after the prefix) is rejected.
// Exported so the ownership package can reuse this exact parser instead of
// duplicating it.
func ContainerNamespaceRef(mode string) (ref string, ok bool) {
	trimmed := strings.TrimSpace(mode)
	const prefix = "container:"
	if len(trimmed) <= len(prefix) || !strings.EqualFold(trimmed[:len(prefix)], prefix) {
		return "", false
	}
	ref = strings.TrimSpace(trimmed[len(prefix):])
	if ref == "" {
		return "", false
	}
	return ref, true
}

// isNamespacePathMode reports whether mode has a case-insensitive "ns:"
// prefix — Docker's syntax for attaching to an arbitrary host network
// namespace file path, a form that bypasses the "host" literal check
// entirely.
func isNamespacePathMode(mode string) bool {
	trimmed := strings.TrimSpace(mode)
	const prefix = "ns:"
	return len(trimmed) >= len(prefix) && strings.EqualFold(trimmed[:len(prefix)], prefix)
}

// denyNamespaceSharingReason enforces restrictNamespaceSharing against every
// HostConfig field that can join another container's namespace via
// "container:<ref>": NetworkMode, PidMode, IpcMode, UTSMode, and (defensively —
// stock Docker's support for a container: form here is unconfirmed) UsernsMode.
// UTSMode is included because Docker does honor a "container:<ref>" join for it
// (moby's UTSMode has an IsContainer/Container form); the separate host-UTS mode
// is denied unconditionally above and is a different attack surface.
func (p containerCreatePolicy) denyNamespaceSharingReason(hostConfig containerCreateHostConfig) string {
	if !p.restrictNamespaceSharing {
		return ""
	}
	fields := [...]struct {
		label string
		mode  string
	}{
		{"network", hostConfig.NetworkMode},
		{"PID", hostConfig.PidMode},
		{"IPC", hostConfig.IpcMode},
		{"UTS", hostConfig.UTSMode},
		{"user", hostConfig.UsernsMode},
	}
	for _, f := range fields {
		ref, ok := ContainerNamespaceRef(f.mode)
		if !ok {
			continue
		}
		if len(p.allowedNamespaceSharingContainers) == 0 {
			return fmt.Sprintf("container create denied: %s namespace sharing with another container is not allowed", f.label)
		}
		if !slices.Contains(p.allowedNamespaceSharingContainers, ref) {
			return fmt.Sprintf("container create denied: namespace-sharing target %q is not in the allowed list", ref)
		}
	}
	return ""
}

func (p containerCreatePolicy) denyDeviceReason(hostConfig containerCreateHostConfig) string {
	if len(hostConfig.DeviceRequests) > 0 {
		if denyReason := p.denyDeviceRequestsReason(hostConfig.DeviceRequests); denyReason != "" {
			return denyReason
		}
	}
	if len(hostConfig.DeviceCgroupRules) > 0 {
		if denyReason := p.denyCgroupRulesReason(hostConfig.DeviceCgroupRules); denyReason != "" {
			return denyReason
		}
	}
	if p.allowAllDevices {
		return ""
	}
	for _, device := range hostConfig.Devices {
		rawPath := strings.TrimSpace(device.PathOnHost)
		hostPath, ok := normalizeContainerCreateDevicePath(rawPath)
		if !ok || !bindPathAllowed(hostPath, p.allowedDevices) {
			return fmt.Sprintf("container create denied: device %q is not allowlisted", rawPath)
		}
	}
	return ""
}

// denyDeviceRequestsReason checks each DeviceRequest against the policy.
// If allowDeviceRequests is true, all requests pass without inspection (escape
// hatch). If allowedDeviceRequests is non-empty, every request must match an
// entry by driver (exact, lowercase) and capabilities (each request capability
// set must be a subset of at least one allowlisted set), and optionally by
// count (max_count). Empty Driver in the request is rejected as malformed.
// If neither flag nor allowlist is set, all requests are denied (default-deny).
func (p containerCreatePolicy) denyDeviceRequestsReason(reqs []dockerDeviceRequest) string {
	if p.allowDeviceRequests {
		return ""
	}
	if len(p.allowedDeviceRequests) == 0 {
		return "container create denied: device requests are not allowed"
	}
	for i, req := range reqs {
		driver := strings.ToLower(strings.TrimSpace(req.Driver))
		if driver == "" {
			return fmt.Sprintf("container create denied: device request %d has an empty Driver field", i)
		}
		if !deviceRequestAllowed(req, driver, p.allowedDeviceRequests) {
			return fmt.Sprintf("container create denied: device request %d (driver %q) is not permitted by the allowlist", i, req.Driver)
		}
	}
	return ""
}

// deviceRequestAllowed reports whether a single DeviceRequest is permitted by
// at least one allowlist entry. The caller already computed the lowercased
// driver string.
func deviceRequestAllowed(req dockerDeviceRequest, driver string, allowlist []allowedDeviceRequestEntry) bool {
	for _, entry := range allowlist {
		if entry.driver != driver {
			continue
		}
		if !countAllowed(req.Count, entry.maxCount) {
			continue
		}
		if !capabilitySetsAllowed(req.Capabilities, entry.allowedCapabilities) {
			continue
		}
		return true
	}
	return false
}

// countAllowed reports whether the request Count is permitted by maxCount.
// If maxCount is nil, any count is allowed. Count -1 means "all devices"; it
// is only permitted when maxCount is also -1.
func countAllowed(reqCount int, maxCount *int) bool {
	if maxCount == nil {
		return true
	}
	if reqCount == -1 {
		return *maxCount == -1
	}
	return reqCount <= *maxCount
}

// capabilitySetsAllowed reports whether all capability sets in the request are
// covered by the allowlist. Each request set must be a subset of at least one
// allowlisted set (OR-of-subsets).
//
// A request with no effective capabilities (empty Capabilities, or sets that
// canonicalize to empty) is NOT treated as "no privilege": device runtimes such
// as the NVIDIA container runtime expand an empty request to a default capability
// set (gpu, utility, …). Such a request must therefore not vacuously satisfy an
// allowlist that constrains capabilities — it is permitted only when the matching
// allowlist entry itself declares no capability constraint.
func capabilitySetsAllowed(reqSets [][]string, allowedSets [][]string) bool {
	hasEffectiveCapability := false
	for _, reqSet := range reqSets {
		canonReq := canonicalizeCapabilitySet(reqSet)
		if len(canonReq) == 0 {
			continue
		}
		hasEffectiveCapability = true
		if !capabilitySetCoveredByAny(canonReq, allowedSets) {
			return false
		}
	}
	if !hasEffectiveCapability {
		return len(allowedSets) == 0
	}
	return true
}

// capabilitySetCoveredByAny reports whether the request capability set is a
// subset of at least one entry in the allowlisted sets.
func capabilitySetCoveredByAny(reqSet []string, allowedSets [][]string) bool {
	for _, allowed := range allowedSets {
		if isSubset(reqSet, allowed) {
			return true
		}
	}
	return false
}

// isSubset reports whether every element of sub is present in super.
func isSubset(sub, super []string) bool {
	for _, s := range sub {
		if !slices.Contains(super, s) {
			return false
		}
	}
	return true
}

// canonicalizeCapabilitySet sorts and deduplicates a capability set in-place
// (returns a new slice). Capabilities are lowercased.
func canonicalizeCapabilitySet(caps []string) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		lower := strings.ToLower(strings.TrimSpace(c))
		if lower == "" || slices.Contains(out, lower) {
			continue
		}
		out = append(out, lower)
	}
	sort.Strings(out)
	return out
}

// canonicalizeAllowedCapabilitySets canonicalizes each set in the allowlist.
func canonicalizeAllowedCapabilitySets(sets [][]string) [][]string {
	out := make([][]string, 0, len(sets))
	for _, set := range sets {
		canonical := canonicalizeCapabilitySet(set)
		out = append(out, canonical)
	}
	return out
}

// denyCgroupRulesReason checks each requested DeviceCgroupRule against the
// policy. If allowDeviceCgroupRules is true, all rules are allowed without
// inspection. If allowedDeviceCgroupRules is non-empty, each rule must
// canonicalize successfully and match an entry in the allowlist. Otherwise all
// rules are denied.
func (p containerCreatePolicy) denyCgroupRulesReason(rules []string) string {
	if p.allowDeviceCgroupRules {
		return ""
	}
	if len(p.allowedDeviceCgroupRules) == 0 {
		return "container create denied: device cgroup rules are not allowed"
	}
	for _, raw := range rules {
		canonical, ok := canonicalizeDeviceCgroupRule(raw)
		if !ok {
			return fmt.Sprintf("container create denied: device cgroup rule %q is malformed", raw)
		}
		if !deviceCgroupRuleAllowed(canonical, p.allowedDeviceCgroupRules) {
			return fmt.Sprintf("container create denied: device cgroup rule %q is not in the allowed list", raw)
		}
	}
	return ""
}

// deviceCgroupRuleAllowed reports whether the canonicalized request rule is
// permitted by at least one entry in the allowlist. Each allowlist entry is
// already in canonical form. Wildcards in the allowlist match any numeric
// value; wildcards in the request rule are only permitted when the matching
// allowlist entry also uses a wildcard at the same position.
func deviceCgroupRuleAllowed(canonical string, allowlist []string) bool {
	reqType, reqMajor, reqMinor, reqPerms, ok := splitDeviceCgroupRule(canonical)
	if !ok {
		return false
	}
	for _, allowEntry := range allowlist {
		alType, alMajor, alMinor, alPerms, alOK := splitDeviceCgroupRule(allowEntry)
		if !alOK {
			continue
		}
		if alType != reqType {
			continue
		}
		if alPerms != reqPerms {
			continue
		}

		if !cgroupFieldMatches(alMajor, reqMajor) {
			continue
		}
		if !cgroupFieldMatches(alMinor, reqMinor) {
			continue
		}
		return true
	}
	return false
}

// cgroupFieldMatches reports whether a request field value is permitted by an
// allowlist field value. Allowlist "*" matches any request value. Request "*"
// is only accepted when the allowlist is also "*".
func cgroupFieldMatches(allowlistField, requestField string) bool {
	if allowlistField == "*" {
		return true
	}
	if requestField == "*" {
		return false
	}
	return allowlistField == requestField
}

// canonicalizeDeviceCgroupRule parses and normalises a Docker cgroup device
// rule string. Docker's canonical form is "<type> <major>:<minor> <perms>"
// where type is one of 'a', 'b', or 'c'; major and minor are decimal numbers
// or '*'; and perms is a non-empty subset of 'r', 'w', 'm'. Canonicalization
// normalizes whitespace and sorts the permission characters so that "rwm",
// "mrw", etc. all produce the same canonical string.
func canonicalizeDeviceCgroupRule(raw string) (string, bool) {
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		return "", false
	}
	devType := fields[0]
	if devType != "a" && devType != "b" && devType != "c" {
		return "", false
	}
	majorMinor := fields[1]
	major, minor, cut := strings.Cut(majorMinor, ":")
	if !cut {
		return "", false
	}
	if !isDeviceCgroupNumber(major) || !isDeviceCgroupNumber(minor) {
		return "", false
	}
	perms := fields[2]
	if !isValidDeviceCgroupPerms(perms) {
		return "", false
	}
	sortedPerms := sortDeviceCgroupPerms(perms)
	return fmt.Sprintf("%s %s:%s %s", devType, major, minor, sortedPerms), true
}

// splitDeviceCgroupRule splits a canonical cgroup rule into its components.
func splitDeviceCgroupRule(canonical string) (devType, major, minor, perms string, ok bool) {
	fields := strings.Fields(canonical)
	if len(fields) != 3 {
		return "", "", "", "", false
	}
	devType = fields[0]
	majorMinor := fields[1]
	var cut bool
	major, minor, cut = strings.Cut(majorMinor, ":")
	if !cut {
		return "", "", "", "", false
	}
	perms = fields[2]
	return devType, major, minor, perms, true
}

// isDeviceCgroupNumber reports whether s is a valid major/minor number: a
// sequence of decimal digits or the wildcard '*'.
func isDeviceCgroupNumber(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isValidDeviceCgroupPerms reports whether perms is a non-empty string
// consisting only of 'r', 'w', and 'm' characters.
func isValidDeviceCgroupPerms(perms string) bool {
	if perms == "" {
		return false
	}
	for _, c := range perms {
		if c != 'r' && c != 'w' && c != 'm' {
			return false
		}
	}
	return true
}

// sortDeviceCgroupPerms returns the permission characters in canonical order:
// r, w, m (deduplicated). This ensures "mrw" and "rwm" both produce "rwm".
func sortDeviceCgroupPerms(perms string) string {
	chars := []byte(perms)
	sort.Slice(chars, func(i, j int) bool {
		return cgroupPermOrder(chars[i]) < cgroupPermOrder(chars[j])
	})

	deduped := chars[:0]
	seen := make(map[byte]bool)
	for _, c := range chars {
		if !seen[c] {
			seen[c] = true
			deduped = append(deduped, c)
		}
	}
	return string(deduped)
}

func cgroupPermOrder(c byte) int {
	switch c {
	case 'r':
		return 0
	case 'w':
		return 1
	case 'm':
		return 2
	default:
		return 3
	}
}

func (p containerCreatePolicy) denyBindMountReason(hostConfig containerCreateHostConfig) string {
	for _, bind := range hostConfig.Binds {
		source, ok := extractAndValidateBindSource(bind, containerCreateMount{})
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("container create denied: bind mount source %q is not allowlisted", source)
	}

	for _, mount := range hostConfig.Mounts {
		source, ok := extractAndValidateBindSource("", mount)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("container create denied: bind mount source %q is not allowlisted", source)
	}

	return ""
}

// denyImageMountReason denies any HostConfig.Mounts entry of Type "image"
// when image trust enforcement is active for this request. Docker API 1.48+
// added Type: "image" mounts, whose Source is an image reference mounted into
// the container's filesystem rather than a bind/volume path;
// extractAndValidateBindSource returns ok=false for any non-"bind" mount
// type, so an image-type mount is invisible to the bind-mount allowlist
// above. Under image_trust enforce mode that invisibility is a trust bypass:
// the create-body Image field is verified and pinned, but an image-type
// mount can smuggle in an arbitrary, entirely unverified image filesystem
// instead. Full verify+pin of mount image sources is out of scope for this
// patch; until then, enforce mode denies the request outright rather than
// silently admitting an unverified filesystem. warn mode and mode "off" are
// unaffected — this only gates the request when enforcement would otherwise
// apply.
func (p containerCreatePolicy) denyImageMountReason(hostConfig containerCreateHostConfig) string {
	if p.imageTrustCfg.Mode != imagetrust.ModeEnforce {
		return ""
	}
	for _, mount := range hostConfig.Mounts {
		if strings.EqualFold(mount.Type, "image") {
			return fmt.Sprintf("container create denied: image mount source %q is not covered by image trust verification", mount.Source)
		}
	}
	return ""
}

// denyUnknownMountTypeReason denies any HostConfig.Mounts entry whose Type is
// not one of the known set Sockguard's policy has an explicit posture for
// (see knownContainerCreateMountTypes). Shared by the container-create
// inspector (subject "container create") and reused nowhere else today, but
// kept subject-parameterized to match the pattern of the other shared deny
// helpers in this file (capabilityAddDenyReason, denyEndpointConfigReason).
func denyUnknownMountTypeReason(mounts []containerCreateMount, subject string) string {
	for _, mount := range mounts {
		mountType := strings.ToLower(strings.TrimSpace(mount.Type))
		if mountType == "" || !knownContainerCreateMountTypes[mountType] {
			return fmt.Sprintf("%s denied: mount type %q is not allowed", subject, mount.Type)
		}
	}
	return ""
}

// denyMountSubpathReason validates Mount.VolumeOptions.Subpath (Engine API
// 1.45+) and Mount.ImageOptions.Subpath (Engine API 1.55+): each must be
// empty or a clean relative path that does not escape the mount root via
// "..". Docker resolves the subpath inside the volume/image filesystem, so an
// unvalidated ".." component is a path-traversal escape from the intended
// mount root into arbitrary sibling content.
func denyMountSubpathReason(mounts []containerCreateMount, subject string) string {
	for _, mount := range mounts {
		if mount.VolumeOptions != nil && !validMountSubpath(mount.VolumeOptions.Subpath) {
			return fmt.Sprintf("%s denied: mount volume subpath %q is invalid", subject, mount.VolumeOptions.Subpath)
		}
		if mount.ImageOptions != nil && !validMountSubpath(mount.ImageOptions.Subpath) {
			return fmt.Sprintf("%s denied: mount image subpath %q is invalid", subject, mount.ImageOptions.Subpath)
		}
	}
	return ""
}

// validMountSubpath reports whether subpath is safe to pass through to
// Docker as a Mount VolumeOptions/ImageOptions Subpath: empty (no subpath),
// or a relative path that, once cleaned, does not start with a ".." escape
// component and is not itself absolute.
func validMountSubpath(subpath string) bool {
	if subpath == "" {
		return true
	}
	if path.IsAbs(subpath) {
		return false
	}
	cleaned := path.Clean(subpath)
	return cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

// tmpfsPrivilegeEscalatingOptions are the tmpfs mount option keywords that
// override Docker's default noexec/nodev/nosuid tmpfs posture. Matched
// case-insensitively against the first token of each
// TmpfsOptions.Options entry.
var tmpfsPrivilegeEscalatingOptions = map[string]bool{
	"exec": true,
	"dev":  true,
	"suid": true,
}

// denyTmpfsOptionsReason validates HostConfig.Mounts[].TmpfsOptions.Options
// (Engine API 1.46+): each entry must be a well-formed 1-or-2-element token
// list (malformed entries are rejected fail-closed rather than silently
// ignored), and exec/dev/suid-enabling options are denied unless
// allowTmpfsPrivilegedOptions is set.
func (p containerCreatePolicy) denyTmpfsOptionsReason(mounts []containerCreateMount) string {
	for _, mount := range mounts {
		if mount.TmpfsOptions == nil {
			continue
		}
		for _, option := range mount.TmpfsOptions.Options {
			if len(option) == 0 || len(option) > 2 || strings.TrimSpace(option[0]) == "" {
				return "container create denied: malformed tmpfs mount option"
			}
			key := strings.ToLower(strings.TrimSpace(option[0]))
			if tmpfsPrivilegeEscalatingOptions[key] && !p.allowTmpfsPrivilegedOptions {
				return fmt.Sprintf("container create denied: tmpfs mount option %q is not allowed", option[0])
			}
		}
	}
	return ""
}

// denyNetworkingConfigReason applies the same endpoint-config policy
// network.inspectConnect enforces on POST /networks/*/connect to every entry
// of NetworkingConfig.EndpointsConfig carried on POST /containers/create.
// Docker attaches each entry here identically to a connect call, so without
// this check the connect-time gate was a bypassable illusion: the same
// static-IP/MAC/Links/DriverOpts configuration reached the daemon unchecked
// by putting it on the primary (or any) network at create time instead of a
// follow-up connect. Map keys (network names) are iterated in sorted order
// so a request with multiple networks produces a deterministic denial
// message regardless of Go's randomized map iteration order.
func (p containerCreatePolicy) denyNetworkingConfigReason(networkingConfig containerCreateNetworkingConfig) string {
	if len(networkingConfig.EndpointsConfig) == 0 {
		return ""
	}
	names := make([]string, 0, len(networkingConfig.EndpointsConfig))
	for name := range networkingConfig.EndpointsConfig {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		endpoint := networkingConfig.EndpointsConfig[name]
		if endpoint == nil {
			continue
		}
		if reason := denyEndpointConfigReason(*endpoint, p.allowEndpointConfig, p.endpointConfig, "container create"); reason != "" {
			return reason
		}
	}
	return ""
}

// denyRootMacAddressReason gates the deprecated, top-level (pre-API-1.44)
// MacAddress field POST /containers/create still accepts alongside
// NetworkingConfig. The daemon applies it to the container's primary network
// endpoint exactly the way a NetworkingConfig.EndpointsConfig[*].MacAddress
// entry does, so it carries the identical MAC-pinning attack surface and
// must be governed by the same allow_endpoint_config / endpoint_config
// policy (#186: either the legacy whole-object allow, or the granular
// AllowMACPinning gate) — otherwise a client denied on EndpointsConfig could
// simply move the MAC address to this legacy field and sail through
// unchecked.
func (p containerCreatePolicy) denyRootMacAddressReason(macAddress string) string {
	if p.allowEndpointConfig || p.endpointConfig.AllowMACPinning {
		return ""
	}
	if strings.TrimSpace(macAddress) == "" {
		return ""
	}
	return "container create denied: container MAC address is not allowed"
}

// denyHardeningReason enforces the simple boolean "rails": no-new-privileges,
// non-root execution, and read-only root filesystem.
func (p containerCreatePolicy) denyHardeningReason(req containerCreateRequest) string {
	if p.requireNoNewPrivileges && !hasNoNewPrivileges(req.HostConfig.SecurityOpt) {
		return "container create denied: no-new-privileges is required (set HostConfig.SecurityOpt to include \"no-new-privileges:true\")"
	}
	if p.requireNonRootUser && !isNonRootUser(req.User) {
		return "container create denied: non-root user is required (set Config.User to a non-zero UID or non-root username)"
	}
	if p.requireReadonlyRootfs && !req.HostConfig.ReadonlyRootfs {
		return "container create denied: read-only root filesystem is required (set HostConfig.ReadonlyRootfs to true)"
	}
	if p.requireDropAllCapabilities && !capDropContainsAll(req.HostConfig.CapDrop) {
		return "container create denied: HostConfig.CapDrop must include \"ALL\""
	}
	return ""
}

// denyCapabilityReason enforces the CapAdd allowlist. RequireDropAll is
// handled by denyHardeningReason.
func (p containerCreatePolicy) denyCapabilityReason(hostConfig containerCreateHostConfig) string {
	return capabilityAddDenyReason(hostConfig.CapAdd, p.allowAllCapabilities, p.allowedCapabilities, "container create")
}

// capabilityAddDenyReason enforces a CapAdd-style allowlist against the
// requested capabilities, shared by the container-create and service
// inspectors. subject prefixes the deny reason; "" means allowed.
func capabilityAddDenyReason(requested []string, allowAll bool, allowed []string, subject string) string {
	if allowAll {
		return ""
	}
	for _, raw := range requested {
		capability := normalizeCapability(raw)
		if capability == "" {
			continue
		}
		if !slices.Contains(allowed, capability) {
			return fmt.Sprintf("%s denied: capability %q is not in the allowed list", subject, capability)
		}
	}
	return ""
}

// denyResourceLimitReason enforces the resource limit requirements.
func (p containerCreatePolicy) denyResourceLimitReason(hostConfig containerCreateHostConfig) string {
	reason, _ := resourceLimitDenyReason(hostConfig, p.requireMemoryLimit, p.requireCPULimit, p.requireCPULimitHard, p.requirePidsLimit, "container create")
	return reason
}

// resourceLimitDenyReason is the shared resource-limit predicate for both
// /containers/create (via the thin wrapper above) and the post-ownership
// ResourceLimitGuard's container-update and effective-state checks
// (resource_limit_guard.go). Extracted so the update path can never drift
// from create's semantics — the CpuQuota-alone-counts-as-hard-cap reasoning,
// the "PidsLimit must be a positive pointer" rule, etc. all live in exactly
// one place. subject prefixes the deny reason ("container create", "container
// update", ...); violation is a stable machine-readable class
// ("memory"|"cpu"|"hard_cpu"|"pids"|"") for audit logging — never the actual
// values, which are not safe to log.
func resourceLimitDenyReason(hostConfig containerCreateHostConfig, requireMemory, requireCPU, requireCPUHard, requirePids bool, subject string) (reason, violation string) {
	if requireMemory && hostConfig.Memory <= 0 {
		return fmt.Sprintf("%s denied: a memory limit is required (set HostConfig.Memory)", subject), "memory"
	}
	if requireCPU && !hasCPULimit(hostConfig) {
		return fmt.Sprintf("%s denied: a CPU limit is required (set HostConfig.NanoCpus, CpuQuota, CpuPeriod, or CpuShares)", subject), "cpu"
	}
	if requireCPUHard && !hasHardCPULimit(hostConfig) {
		return fmt.Sprintf("%s denied: a hard CPU cap is required (set HostConfig.NanoCpus or CpuQuota; CpuShares is a relative priority weight, not a cap, and does not satisfy this check)", subject), "hard_cpu"
	}
	if requirePids {
		if hostConfig.PidsLimit == nil || *hostConfig.PidsLimit <= 0 {
			return fmt.Sprintf("%s denied: a PIDs limit is required (set HostConfig.PidsLimit to a positive value)", subject), "pids"
		}
	}
	return "", ""
}

// denySecurityOptReason inspects each HostConfig.SecurityOpt entry for
// seccomp= / apparmor= / label= directives and enforces allowlists.
func (p containerCreatePolicy) denySecurityOptReason(hostConfig containerCreateHostConfig) string {
	seenSeccomp := false
	seenAppArmor := false
	for _, raw := range hostConfig.SecurityOpt {
		kind, value, ok := parseSecurityOpt(raw)
		if !ok {
			continue
		}
		switch kind {
		case "seccomp":
			seenSeccomp = true

			if p.denyUnconfinedSeccomp && strings.EqualFold(value, "unconfined") {
				return "container create denied: unconfined seccomp profile is not allowed"
			}
			if len(p.allowedSeccompProfiles) > 0 && !slices.Contains(p.allowedSeccompProfiles, value) {
				return fmt.Sprintf("container create denied: seccomp profile %q is not in the allowed list", value)
			}
		case "apparmor":
			seenAppArmor = true
			if p.denyUnconfinedAppArmor && strings.EqualFold(value, "unconfined") {
				return "container create denied: unconfined apparmor profile is not allowed"
			}
			if len(p.allowedAppArmorProfiles) > 0 && !slices.Contains(p.allowedAppArmorProfiles, value) {
				return fmt.Sprintf("container create denied: apparmor profile %q is not in the allowed list", value)
			}
		case "label":
			labelValue := strings.ToLower(strings.TrimSpace(value))
			if labelValue == "disable" {
				if p.denySelinuxDisable {
					return "container create denied: label=disable (SELinux disable) is not allowed"
				}

			} else {

				if p.denySelinuxLabelOverride {
					return fmt.Sprintf("container create denied: selinux label override %q is not allowed (set deny_selinux_label_override: false to permit)", value)
				}
			}
		case "systempaths":
			sysValue := strings.ToLower(strings.TrimSpace(value))
			if sysValue == "unconfined" && p.denyUnconfinedSystemPaths {
				return "container create denied: systempaths=unconfined is not allowed"
			}
		}
	}

	if len(p.allowedSeccompProfiles) > 0 && !seenSeccomp {
		if !slices.Contains(p.allowedSeccompProfiles, "default") {
			return "container create denied: a seccomp profile is required (set HostConfig.SecurityOpt to include seccomp=<profile>)"
		}
	}
	if len(p.allowedAppArmorProfiles) > 0 && !seenAppArmor {
		if !slices.Contains(p.allowedAppArmorProfiles, "default") &&
			!slices.Contains(p.allowedAppArmorProfiles, "docker-default") &&
			!slices.Contains(p.allowedAppArmorProfiles, "runtime/default") {
			return "container create denied: an apparmor profile is required (set HostConfig.SecurityOpt to include apparmor=<profile>)"
		}
	}
	return ""
}

// denySystemPathsReason rejects requests that set MaskedPaths or ReadonlyPaths
// to an explicit empty slice. The Docker CLI translates
// --security-opt systempaths=unconfined into HostConfig.MaskedPaths=[] and
// HostConfig.ReadonlyPaths=[] client-side (using the =unconfined form only).
// Direct API clients can achieve the same effect without the SecurityOpt string.
// A non-nil empty slice means the default masked/readonly path sets are being
// deliberately cleared; nil means the field was absent and daemon defaults apply.
func (p containerCreatePolicy) denySystemPathsReason(hostConfig containerCreateHostConfig) string {
	if !p.denyUnconfinedSystemPaths {
		return ""
	}
	if hostConfig.MaskedPaths != nil && len(*hostConfig.MaskedPaths) == 0 {
		return "container create denied: clearing MaskedPaths (systempaths=unconfined equivalent) is not allowed"
	}
	if hostConfig.ReadonlyPaths != nil && len(*hostConfig.ReadonlyPaths) == 0 {
		return "container create denied: clearing ReadonlyPaths (systempaths=unconfined equivalent) is not allowed"
	}
	return ""
}

func (p containerCreatePolicy) denyRequiredLabelsReason(req containerCreateRequest) string {
	for _, key := range p.requiredLabels {
		value, ok := req.Labels[key]
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Sprintf("container create denied: required label %q is missing or empty", key)
		}
	}
	return ""
}

func bindPathAllowed(source string, allowedPaths []string) bool {
	for _, allowed := range allowedPaths {
		if allowed == "/" || source == allowed || strings.HasPrefix(source, allowed+"/") {
			return true
		}
	}
	return false
}

func extractAndValidateBindSource(bind string, mount containerCreateMount) (string, bool) {
	if bind != "" {
		source, _, ok := strings.Cut(bind, ":")
		if !ok {
			return "", false
		}
		return normalizeBindMount(source)
	}

	if !strings.EqualFold(mount.Type, "bind") {
		return "", false
	}

	return normalizeBindMount(mount.Source)
}

func normalizeContainerCreateDevicePath(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	return path.Clean(value), true
}

// hasNoNewPrivileges returns true when SecurityOpt contains an entry that
// turns on Docker's no-new-privileges flag. Docker accepts both
// "no-new-privileges" (treated as true) and "no-new-privileges:true".
func hasNoNewPrivileges(securityOpt []string) bool {
	for _, raw := range securityOpt {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		key, value, hasValue := splitSecurityOptKV(entry)
		if !strings.EqualFold(key, "no-new-privileges") {
			continue
		}
		if !hasValue {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(value), "true") {
			return true
		}
	}
	return false
}

// isNonRootUser returns true when the Config.User value clearly references a
// non-root identity. Empty values default to the image's user, which Sockguard
// treats as root for safety. Numeric "0" / "0:N" or the literal name "root"
// are also rejected.
func isNonRootUser(user string) bool {
	trimmed := strings.TrimSpace(user)
	if trimmed == "" {
		return false
	}
	userPart, _, _ := strings.Cut(trimmed, ":")
	userPart = strings.TrimSpace(userPart)
	if userPart == "" {
		return false
	}
	if strings.EqualFold(userPart, "root") {
		return false
	}
	if isNumericRootUID(userPart) {
		return false
	}
	return true
}

// isNumericRootUID reports whether userPart parses as the numeric UID 0.
// Docker resolves a numeric Config.User with strconv, so "00", "000", and any
// other zero-padded form all run as root — an exact "0" string compare would
// miss them and let require_non_root_user / allow_root_user:false be bypassed.
func isNumericRootUID(userPart string) bool {
	n, err := strconv.ParseUint(userPart, 10, 32)
	return err == nil && n == 0
}

// capDropContainsAll returns true when CapDrop includes the literal "ALL"
// token (case-insensitive). Docker treats "ALL" specially to drop every
// default capability.
func capDropContainsAll(capDrop []string) bool {
	for _, raw := range capDrop {
		if strings.EqualFold(strings.TrimSpace(raw), "ALL") {
			return true
		}
	}
	return false
}

// hasCPULimit returns true when at least one of Docker's CPU-budget knobs is
// set. NanoCpus, CpuQuota, and CpuPeriod each individually carve out a CFS
// budget; CpuShares only sets relative weight, but operators sometimes use
// it for the same purpose, so we accept it as evidence of intent.
func hasCPULimit(h containerCreateHostConfig) bool {
	return h.NanoCpus > 0 || h.CpuQuota > 0 || h.CpuPeriod > 0 || h.CpuShares > 0
}

// hasHardCPULimit returns true only when a genuine CPU-time cap is set:
// NanoCpus or CpuQuota. Unlike hasCPULimit, a lone CpuPeriod does not count
// (it is only the denominator for CpuQuota and enforces nothing without it),
// and CpuShares does not count (it sets relative scheduling priority under
// contention, not an absolute ceiling — a CpuShares-only container can still
// consume 100% of every CPU it can reach on an idle host).
//
// CpuQuota is accepted without a paired CpuPeriod: per Docker's own docs
// (docs.docker.com/engine/containers/resource_constraints — "--cpu-period
// ... Defaults to 100000 microseconds (100 milliseconds)"), the CFS period
// defaults to 100000us (the same value the kernel's CFS bandwidth
// controller already applies to a cgroup) whenever CpuPeriod is left at its
// zero value, so CpuQuota alone still yields a real, computable CPU-time
// ceiling (CpuQuota / 100000).
func hasHardCPULimit(h containerCreateHostConfig) bool {
	return h.NanoCpus > 0 || h.CpuQuota > 0
}

// parseSecurityOpt extracts the (key, value) tuple from a Docker SecurityOpt
// entry like "seccomp=unconfined" or "apparmor=docker-default". Returns ok=false
// for entries that don't follow the key=value shape (e.g. "no-new-privileges"),
// which the caller handles separately.
func parseSecurityOpt(raw string) (kind, value string, ok bool) {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return "", "", false
	}
	key, val, hasValue := splitSecurityOptKV(entry)
	if !hasValue {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val), true
}

// splitSecurityOptKV splits a SecurityOpt token on the first '=' or ':'
// character. Docker accepts both separators in practice.
func splitSecurityOptKV(entry string) (key, value string, hasValue bool) {
	if idx := strings.IndexAny(entry, "=:"); idx >= 0 {
		return entry[:idx], entry[idx+1:], true
	}
	return entry, "", false
}

// normalizeCapability canonicalizes a Linux capability name into the form
// HostConfig.CapAdd/CapDrop uses on the wire. Docker accepts both "NET_ADMIN"
// and "CAP_NET_ADMIN" and treats them identically; sockguard strips the
// "CAP_" prefix so a single allowlist entry covers both. Plugin manifest
// capabilities follow a different namespace — see normalizePluginCapability.
func normalizeCapability(value string) string {
	trimmed := strings.ToUpper(strings.TrimSpace(value))
	return strings.TrimPrefix(trimmed, "CAP_")
}

func normalizeCapabilityList(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeCapability(value)
		if normalized == "" || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func normalizeStringList(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

// AllowedDeviceRequestEntry is the public wire type that operators populate
// in YAML to allowlist GPU/accelerator HostConfig.DeviceRequests entries.
type AllowedDeviceRequestEntry struct {
	Driver              string
	AllowedCapabilities [][]string
	MaxCount            *int
}

// allowedDeviceRequestEntry is the pre-processed form stored in
// containerCreatePolicy after canonicalization.
type allowedDeviceRequestEntry struct {
	driver              string     // lowercase
	allowedCapabilities [][]string // each inner slice sorted + deduped
	maxCount            *int
}

// dockerDeviceRequest mirrors the Docker API HostConfig.DeviceRequests element.
type dockerDeviceRequest struct {
	Driver       string            `json:"Driver"`
	Count        int               `json:"Count"`
	DeviceIDs    []string          `json:"DeviceIDs"`
	Capabilities [][]string        `json:"Capabilities"`
	Options      map[string]string `json:"Options"`
}

type containerCreateRequest struct {
	Image      string                    `json:"Image"`
	HostConfig containerCreateHostConfig `json:"HostConfig"`
	User       string                    `json:"User"`
	Labels     map[string]string         `json:"Labels"`
	// MacAddress is the deprecated, top-level (pre-API-1.44) container-wide
	// MAC address field. The daemon still honors it, applying it to the
	// container's primary network endpoint exactly like
	// NetworkingConfig.EndpointsConfig[*].MacAddress does — see
	// denyRootMacAddressReason in container_create.go for why it is gated
	// identically to that field rather than left as an unchecked bypass.
	MacAddress       string                          `json:"MacAddress"`
	NetworkingConfig containerCreateNetworkingConfig `json:"NetworkingConfig"`
}

// containerCreateNetworkingConfig mirrors the Docker API
// NetworkingConfig object POST /containers/create accepts alongside
// HostConfig: a per-network-name map of endpoint settings applied when the
// container is attached to each network at create time. The daemon connects
// every entry here the same way POST /networks/*/connect does, so it carries
// the identical endpoint-config attack surface (static IP, MAC, links,
// driver opts) — see denyNetworkingConfigReason.
type containerCreateNetworkingConfig struct {
	EndpointsConfig map[string]*networkEndpointConfig `json:"EndpointsConfig"`
}

type containerCreateHostConfig struct {
	Privileged        bool                    `json:"Privileged"`
	NetworkMode       string                  `json:"NetworkMode"`
	PidMode           string                  `json:"PidMode"`
	IpcMode           string                  `json:"IpcMode"`
	UsernsMode        string                  `json:"UsernsMode"`
	CgroupnsMode      string                  `json:"CgroupnsMode"`
	Binds             []string                `json:"Binds"`
	Mounts            []containerCreateMount  `json:"Mounts"`
	Devices           []containerCreateDevice `json:"Devices"`
	DeviceRequests    []dockerDeviceRequest   `json:"DeviceRequests"`
	DeviceCgroupRules []string                `json:"DeviceCgroupRules"`
	SecurityOpt       []string                `json:"SecurityOpt"`
	CapAdd            []string                `json:"CapAdd"`
	CapDrop           []string                `json:"CapDrop"`
	ReadonlyRootfs    bool                    `json:"ReadonlyRootfs"`
	Memory            int64                   `json:"Memory"`
	MemoryReservation int64                   `json:"MemoryReservation"`
	NanoCpus          int64                   `json:"NanoCpus"`
	CpuQuota          int64                   `json:"CpuQuota"`
	CpuPeriod         int64                   `json:"CpuPeriod"`
	CpuShares         int64                   `json:"CpuShares"`
	PidsLimit         *int64                  `json:"PidsLimit"`
	Sysctls           map[string]string       `json:"Sysctls"`
	VolumesFrom       []string                `json:"VolumesFrom"`
	UTSMode           string                  `json:"UTSMode"`
	CgroupParent      string                  `json:"CgroupParent"`
	GroupAdd          []string                `json:"GroupAdd"`
	ExtraHosts        []string                `json:"ExtraHosts"`
	Runtime           string                  `json:"Runtime"`
	// MaskedPaths overrides the default set of paths that Docker masks inside
	// the container. An empty slice signals systempaths=unconfined intent
	// delivered via the direct API path (the Docker CLI converts
	// --security-opt systempaths=unconfined to MaskedPaths=[] client-side).
	// The pointer distinguishes "not set" (nil) from "explicitly set to empty"
	// (non-nil, zero length).
	MaskedPaths   *[]string `json:"MaskedPaths"`
	ReadonlyPaths *[]string `json:"ReadonlyPaths"`
}

type containerCreateMount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
	// VolumeOptions.Subpath (Engine API 1.45+) mounts a subdirectory of the
	// named volume instead of its root. ImageOptions.Subpath (Engine API
	// 1.55+) does the same for image-type mounts. Both are validated by
	// denyMountSubpathReason against a path-traversal escape.
	VolumeOptions *containerCreateMountVolumeOptions `json:"VolumeOptions"`
	ImageOptions  *containerCreateMountImageOptions  `json:"ImageOptions"`
	// TmpfsOptions.Options (Engine API 1.46+) is a nested [][]string of raw
	// tmpfs mount option tokens (e.g. ["mode","1770"], ["exec"]), validated
	// by denyTmpfsOptionsReason.
	TmpfsOptions *containerCreateMountTmpfsOptions `json:"TmpfsOptions"`
}

// containerCreateMountVolumeOptions mirrors the Docker API Mount.VolumeOptions
// object, narrowed to the field the policy inspects.
type containerCreateMountVolumeOptions struct {
	Subpath string `json:"Subpath"`
}

// containerCreateMountImageOptions mirrors the Docker API Mount.ImageOptions
// object, narrowed to the field the policy inspects.
type containerCreateMountImageOptions struct {
	Subpath string `json:"Subpath"`
}

// containerCreateMountTmpfsOptions mirrors the Docker API Mount.TmpfsOptions
// object, narrowed to the field the policy inspects.
type containerCreateMountTmpfsOptions struct {
	Options [][]string `json:"Options"`
}

// knownContainerCreateMountTypes is the set of Mount.Type values Sockguard's
// policy has an explicit posture for: "bind" (allowlist-checked),
// "volume"/"tmpfs" (pass through, checked for subpath/options above), and
// "image" (image-trust-checked in enforce mode, see denyImageMountReason).
// Any other value — including future Docker Mount types this proxy has never
// seen — is denied fail-closed by denyUnknownMountTypeReason rather than
// silently passing through unchecked the way an unrecognized Type used to
// (extractAndValidateBindSource returns ok=false for it, which the bind-mount
// loop above treated as "nothing to check" rather than "deny").
var knownContainerCreateMountTypes = map[string]bool{
	"bind":   true,
	"volume": true,
	"tmpfs":  true,
	"image":  true,
}

type containerCreateDevice struct {
	PathOnHost string `json:"PathOnHost"`
}

const maxContainerUpdateBodyBytes = 1 << 20 // 1 MiB

// ContainerUpdateOptions configures request-body policy checks for
// POST /containers/{id}/update.
type ContainerUpdateOptions struct {
	AllowPrivileged      bool
	AllowAllDevices      bool
	AllowCapabilities    bool
	AllowRestartPolicy   bool
	AllowResourceUpdates bool

	// RequireMemoryLimit/RequireCPULimit/RequireCPULimitHard/RequirePidsLimit
	// are enforced by ResourceLimitGuard (resource_limit_guard.go), not by
	// containerUpdatePolicy.inspect below — they revalidate the container's
	// EFFECTIVE post-update resource state, which requires a daemon lookup
	// that only runs post-ownership. They are carried on this struct purely
	// so config.ContainerUpdateRequestBodyConfig.ToFilterOptions has a single
	// destination field per config leaf; containerUpdatePolicy itself never
	// reads them.
	RequireMemoryLimit  bool
	RequireCPULimit     bool
	RequireCPULimitHard bool
	RequirePidsLimit    bool
}

type containerUpdatePolicy struct {
	allowPrivileged      bool
	allowAllDevices      bool
	allowCapabilities    bool
	allowRestartPolicy   bool
	allowResourceUpdates bool
}

func newContainerUpdatePolicy(opts ContainerUpdateOptions) containerUpdatePolicy {
	return containerUpdatePolicy{
		allowPrivileged:      opts.AllowPrivileged,
		allowAllDevices:      opts.AllowAllDevices,
		allowCapabilities:    opts.AllowCapabilities,
		allowRestartPolicy:   opts.AllowRestartPolicy,
		allowResourceUpdates: opts.AllowResourceUpdates,
	}
}

func (p containerUpdatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !matchesContainerUpdateInspection(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxContainerUpdateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("container update denied: request body exceeds %d byte limit", maxContainerUpdateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var root map[string]json.RawMessage
	if err := decodePolicySubsetJSON(body, &root); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "container update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "container update denied: request body could not be inspected", nil
	}

	objects := containerUpdatePolicyObjects(root)
	if !p.allowPrivileged && containerUpdateHasAnyField(objects, containerUpdatePrivilegedFields...) {
		return "container update denied: privileged mode changes are not allowed", nil
	}
	if !p.allowAllDevices && containerUpdateHasAnyField(objects, containerUpdateDeviceFields...) {
		return "container update denied: device changes are not allowed", nil
	}
	if !p.allowCapabilities && containerUpdateHasAnyField(objects, containerUpdateCapabilityFields...) {
		return "container update denied: capability changes are not allowed", nil
	}
	if !p.allowRestartPolicy && containerUpdateHasAnyField(objects, containerUpdateRestartPolicyFields...) {
		return "container update denied: restart policy changes are not allowed", nil
	}
	if !p.allowResourceUpdates && containerUpdateHasAnyField(objects, containerUpdateResourceControlFields...) {
		return "container update denied: resource control changes are not allowed", nil
	}

	return "", nil
}

func isContainerUpdatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	_, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/containers/"), "/")
	return ok && tail == "update"
}

func containerUpdatePolicyObjects(root map[string]json.RawMessage) []map[string]json.RawMessage {
	if len(root) == 0 {
		return nil
	}

	objects := []map[string]json.RawMessage{root}
	for _, field := range []string{"HostConfig", "Resources"} {
		if nested, ok := decodeContainerUpdateObjectField(root, field); ok {
			objects = append(objects, nested)
		}
	}
	if hostConfig, ok := decodeContainerUpdateObjectField(root, "HostConfig"); ok {
		if nested, ok := decodeContainerUpdateObjectField(hostConfig, "Resources"); ok {
			objects = append(objects, nested)
		}
	}
	return objects
}

func decodeContainerUpdateObjectField(root map[string]json.RawMessage, name string) (map[string]json.RawMessage, bool) {
	for key, raw := range root {
		if !strings.EqualFold(key, name) || len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}

		var nested map[string]json.RawMessage
		if err := decodePolicySubsetJSON(raw, &nested); err != nil || len(nested) == 0 {
			return nil, false
		}
		return nested, true
	}
	return nil, false
}

func containerUpdateHasAnyField(objects []map[string]json.RawMessage, fields ...string) bool {
	for _, object := range objects {
		for key := range object {
			for _, field := range fields {
				if strings.EqualFold(key, field) {
					return true
				}
			}
		}
	}
	return false
}

var containerUpdatePrivilegedFields = []string{
	"Privileged",
}

var containerUpdateDeviceFields = []string{
	"Devices",
	"DeviceCgroupRules",
	"DeviceRequests",
}

var containerUpdateCapabilityFields = []string{
	"CapAdd",
	"CapDrop",
	"Capabilities",
	"NoNewPrivileges",
	"SecurityOpt",
}

var containerUpdateRestartPolicyFields = []string{
	"RestartPolicy",
}

var containerUpdateResourceControlFields = []string{
	"BlkioDeviceReadBps",
	"BlkioDeviceReadIOps",
	"BlkioDeviceWriteBps",
	"BlkioDeviceWriteIOps",
	"BlkioWeight",
	"BlkioWeightDevice",
	"CgroupParent",
	"CgroupnsMode",
	"CpuCount",
	"CpuPercent",
	"CpuPeriod",
	"CpuQuota",
	"CpuRealtimePeriod",
	"CpuRealtimeRuntime",
	"CpuShares",
	"CpusetCpus",
	"CpusetMems",
	"IOMaximumBandwidth",
	"IOMaximumIOps",
	"KernelMemory",
	"KernelMemoryTCP",
	"Memory",
	"MemoryReservation",
	"MemorySwap",
	"MemorySwappiness",
	"NanoCpus",
	"OomKillDisable",
	"PidsLimit",
	"Resources",
	"Ulimits",
}

const driverCreateMaxBodyBytes = 1 << 20 // 1 MiB

// ConfigOptions configures request-body policy checks for POST /configs/create.
type ConfigOptions struct {
	AllowCustomDrivers   bool
	AllowTemplateDrivers bool
}

// SecretOptions configures request-body policy checks for POST /secrets/create.
type SecretOptions struct {
	AllowCustomDrivers   bool
	AllowTemplateDrivers bool
}

func newConfigPolicy(opts ConfigOptions) driverCreatePolicy {
	return driverCreatePolicy{
		kind:                 "config",
		path:                 "/configs/create",
		maxBodyBytes:         driverCreateMaxBodyBytes,
		allowCustomDrivers:   opts.AllowCustomDrivers,
		allowTemplateDrivers: opts.AllowTemplateDrivers,
	}
}

func newSecretPolicy(opts SecretOptions) driverCreatePolicy {
	return driverCreatePolicy{
		kind:                 "secret",
		path:                 "/secrets/create",
		maxBodyBytes:         driverCreateMaxBodyBytes,
		allowCustomDrivers:   opts.AllowCustomDrivers,
		allowTemplateDrivers: opts.AllowTemplateDrivers,
	}
}

// driverCreatePolicy backs POST /configs/create and POST /secrets/create.
// Both endpoints share the same JSON shape and the same driver / template
// driver allow-list semantics — only the kind label, target path, and size
// cap differ. Keeping one inspect implementation prevents the two policies
// from drifting apart.
type driverCreatePolicy struct {
	kind                 string
	path                 string
	maxBodyBytes         int64
	allowCustomDrivers   bool
	allowTemplateDrivers bool
}

type driverCreateRequest struct {
	Driver         string `json:"Driver"`
	TemplateDriver string `json:"TemplateDriver"`
	Templating     struct {
		Name string `json:"Name"`
	} `json:"Templating"`
}

func (p driverCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != p.path || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, p.maxBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s create denied: request body exceeds %d byte limit", p.kind, p.maxBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req driverCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, fmt.Sprintf("%s create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", p.kind), err)
		return fmt.Sprintf("%s create denied: request body could not be inspected", p.kind), nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !p.allowCustomDrivers {
		return fmt.Sprintf("%s create denied: driver %q is not allowed", p.kind, driver), nil
	}

	templateDriver := strings.TrimSpace(req.TemplateDriver)
	if templateDriver == "" {
		templateDriver = strings.TrimSpace(req.Templating.Name)
	}
	if templateDriver != "" && !p.allowTemplateDrivers {
		return fmt.Sprintf("%s create denied: template driver %q is not allowed", p.kind, templateDriver), nil
	}

	return "", nil
}

const maxExecBodyBytes = 64 << 10 // 64 KiB

var (
	errExecMissingCmd     = errors.New("missing Cmd")
	errExecEmptyCmdArray  = errors.New("empty Cmd array")
	errExecEmptyCmdString = errors.New("empty Cmd string")
)

// ExecInspectResult captures the effective exec command metadata Docker stores
// after POST /containers/{id}/exec and returns from GET /exec/{id}/json.
//
// Env is populated only on the exec-create path: Docker's GET /exec/{id}/json
// ProcessConfig does not expose the exec's environment, so the exec-start
// re-check (inspectExisting) always leaves it nil. That is safe rather than a
// gap — exec instances are immutable after creation (same reasoning already
// documented for Cmd/Privileged/User above inspectExisting), so there is
// nothing for a start-time Env re-check to catch that create-time didn't
// already see.
type ExecInspectResult struct {
	Command    []string
	Privileged bool
	User       string
	Env        []string
}

// ExecInspectFunc looks up an existing exec instance by id.
type ExecInspectFunc func(context.Context, string) (ExecInspectResult, bool, error)

// ExecOptions configures request-body policy checks for exec creation/start.
type ExecOptions struct {
	AllowPrivileged bool
	AllowRootUser   bool
	// AllowedCommands is an allowlist of exec argv templates. Each token is a
	// sockguard glob (see internal/glob): "*" matches a run of non-slash
	// characters, "**" matches any sequence. A command is allowed when its
	// token count equals an entry's and every token matches the glob at that
	// position. Empty (the default) denies every exec unless AllowBlindWrites
	// is also set.
	AllowedCommands [][]string
	// AllowedEnvVars, when non-empty, restricts the exec-create Env array to
	// these variable names. Matching is by name only — the substring before
	// the first "=" in each Env entry — exact string comparison,
	// case-sensitive; the value is never inspected. Default empty means no
	// restriction: unlike AllowedCommands, an empty AllowedEnvVars does NOT
	// deny all Env content — this is a deliberate zero-behavior-change
	// default, since enabling exec command allowlisting should not also
	// silently start denying every exec session's environment.
	AllowedEnvVars []string
	// DeniedEnvVars variable names are always blocked and are checked before
	// AllowedEnvVars, so a name present in both lists is denied — fail
	// closed on operator misconfiguration. Default empty means nothing is
	// blocked.
	DeniedEnvVars []string
	// AllowedEnvValues pins selected variables to exact NAME=VALUE entries.
	// When at least one entry is configured for a name, every occurrence of
	// that name must exactly match one of those entries. Values are never
	// included in denial reasons or logs. Default empty means no value checks.
	AllowedEnvValues []string
	// AllowBlindWrites wires the top-level insecure_allow_body_blind_writes
	// config flag: when true AND AllowedCommands is empty, exec create/start
	// is no longer hard-denied purely for lacking a command allowlist. This
	// ONLY lifts the "no commands are allowlisted" gate — AllowPrivileged,
	// AllowRootUser, and the AllowedEnvVars/DeniedEnvVars gates below still
	// apply exactly as configured, matching the documented scope of the
	// blind-write opt-in (it acknowledges "we cannot pin the argv", not "skip
	// every other exec check"). When AllowedCommands is non-empty this field
	// has no effect: an operator who pinned commands is inspecting the body,
	// so the blind-write concern the flag addresses does not apply.
	AllowBlindWrites bool
	InspectStart     ExecInspectFunc
	// InspectStartLibpod is InspectStart's counterpart for the libpod
	// exec-start path (POST /libpod/exec/{id}/start). It exists as a
	// separate field — rather than reusing InspectStart for both routes —
	// because the two constructors issue their upstream GET against
	// different URL families (GET /exec/{id}/json vs.
	// GET /libpod/exec/{id}/json); which one a given exec-start request
	// needs is decided by which path triggered it, not by anything
	// ExecInspectFunc's (context, id) signature carries. The exec-create
	// side needs no such split: it never calls upstream, it decodes the
	// POST body directly (see inspectCreate), and libpod exec-create bodies
	// decode with the identical Go handler Docker-compat exec-create bodies
	// do (#148 design doc decision C3) — see isLibpodExecCreatePath's
	// call site in inspect below.
	InspectStartLibpod ExecInspectFunc
}

type execPolicy struct {
	allowPrivileged    bool
	allowRootUser      bool
	allowedCommands    []execCommandMatcher
	allowedEnvVars     []string
	deniedEnvVars      []string
	allowedEnvValues   map[string][]string
	allowBlindWrites   bool
	inspectStart       ExecInspectFunc
	inspectStartLibpod ExecInspectFunc
}

// execCommandMatcher is a compiled allowlist entry: one anchored regex per
// argv token. A command matches only when its token count equals len(tokens)
// and every token matches positionally.
type execCommandMatcher struct {
	tokens []*regexp.Regexp
}

func (m execCommandMatcher) matches(command []string) bool {
	if len(command) != len(m.tokens) {
		return false
	}
	for i, tok := range m.tokens {
		if !tok.MatchString(command[i]) {
			return false
		}
	}
	return true
}

type execCreateRequest struct {
	Cmd        json.RawMessage `json:"Cmd"`
	Privileged bool            `json:"Privileged"`
	User       string          `json:"User"`
	// Env is strictly typed as []string, unlike Cmd's json.RawMessage dual
	// array/string decoding: Docker's exec Env has only ever been an array of
	// strings, so a request whose Env is present but not shaped that way
	// (an object, or an array of non-strings) fails the execCreateRequest
	// unmarshal entirely and falls into the existing fail-closed "request
	// body could not be inspected" branch in inspectCreate — the same
	// outcome as any other malformed exec-create body.
	Env []string `json:"Env"`
}

type execInspectResponse struct {
	ProcessConfig struct {
		Entrypoint string   `json:"entrypoint"`
		Arguments  []string `json:"arguments"`
		Privileged bool     `json:"privileged"`
		User       string   `json:"user"`
	} `json:"ProcessConfig"`
}

func newExecPolicy(opts ExecOptions) execPolicy {
	allowed := make([]execCommandMatcher, 0, len(opts.AllowedCommands))
	for _, command := range opts.AllowedCommands {
		if len(command) == 0 {
			continue
		}
		tokens := make([]*regexp.Regexp, len(command))
		for i, token := range command {

			tokens[i] = regexp.MustCompile(`\A(?:` + GlobToRegexString(token) + `)\z`)
		}
		allowed = append(allowed, execCommandMatcher{tokens: tokens})
	}

	return execPolicy{
		allowPrivileged:    opts.AllowPrivileged,
		allowRootUser:      opts.AllowRootUser,
		allowedCommands:    allowed,
		allowedEnvVars:     normalizeExecEnvNames(opts.AllowedEnvVars),
		deniedEnvVars:      normalizeExecEnvNames(opts.DeniedEnvVars),
		allowedEnvValues:   normalizeExecEnvValues(opts.AllowedEnvValues),
		allowBlindWrites:   opts.AllowBlindWrites,
		inspectStart:       opts.InspectStart,
		inspectStartLibpod: opts.InspectStartLibpod,
	}
}

func normalizeExecEnvValues(values []string) map[string][]string {
	normalized := make(map[string][]string)
	for _, entry := range values {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" || slices.Contains(normalized[name], entry) {
			continue
		}
		normalized[name] = append(normalized[name], entry)
	}
	return normalized
}

// normalizeExecEnvNames trims whitespace and dedupes env-var name entries,
// preserving first-seen order. Matching is exact and case-sensitive per the
// v1 spec (no case-folding, no glob support) — literal-only, mirroring the
// convention used by allowed_capabilities/allowed_registries/allowed_runtimes
// elsewhere in the schema.
func normalizeExecEnvNames(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || slices.Contains(normalized, trimmed) {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func (p execPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost {
		return "", nil
	}

	switch {

	case isExecCreatePath(normalizedPath) || isLibpodExecCreatePath(normalizedPath):
		return p.inspectCreate(logger, r)
	case isExecStartPath(normalizedPath) || isLibpodExecStartPath(normalizedPath):
		return p.inspectExisting(r.Context(), normalizedPath)
	default:
		return "", nil
	}
}

func (p execPolicy) inspectCreate(logger *slog.Logger, r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxExecBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("exec denied: request body exceeds %d byte limit", maxExecBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req execCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "exec request body is not valid JSON; deferring to Docker validation", err)
		return "exec denied: request body could not be inspected", nil
	}

	command, err := decodeExecCommand(req.Cmd)
	if err != nil {
		logRequestError(logger, r, slog.LevelDebug, "exec request body has unparseable Cmd; denying", err)
		return "exec denied: request body could not be inspected", nil
	}

	return p.denyReason(ExecInspectResult{
		Command:    command,
		Privileged: req.Privileged,
		User:       req.User,
		Env:        req.Env,
	}), nil
}

func (p execPolicy) inspectExisting(ctx context.Context, normalizedPath string) (string, error) {
	execID, isLibpod, ok := execStartIdentifier(normalizedPath)
	if !ok {
		return "", nil
	}

	inspectStart := p.inspectStart
	if isLibpod {
		inspectStart = p.inspectStartLibpod
	}
	if inspectStart == nil {
		return "exec start denied: no exec inspection configured", nil
	}

	result, found, err := inspectStart(ctx, execID)
	if err != nil {
		return "", fmt.Errorf("inspect exec %q: %w", execID, err)
	}
	if !found {
		return "", nil
	}
	return p.denyReason(result), nil
}

func (p execPolicy) denyReason(result ExecInspectResult) string {
	if len(p.allowedCommands) == 0 && !p.allowBlindWrites {
		return "exec denied: no commands are allowlisted"
	}
	if !p.allowPrivileged && result.Privileged {
		return "exec denied: privileged exec is not allowed"
	}
	if !p.allowRootUser && isRootUser(result.User) {
		return "exec denied: root exec user is not allowed"
	}
	if reason := p.envDenyReason(result.Env); reason != "" {
		return reason
	}
	if len(p.allowedCommands) == 0 {

		return ""
	}
	for _, allowed := range p.allowedCommands {
		if allowed.matches(result.Command) {
			return ""
		}
	}
	return fmt.Sprintf("exec denied: command %q is not allowlisted", strings.Join(result.Command, " "))
}

// envDenyReason checks each exec-create Env entry's variable name — the
// substring before the first "=", or the whole entry when no "=" is present —
// against deniedEnvVars and then allowedEnvVars. deniedEnvVars is checked
// first, so a name present in both lists is denied (fail closed on operator
// misconfiguration). Values are never inspected or logged.
//
// When both lists are empty (the default), this always returns "" regardless
// of Env content — the core zero-behavior-change guarantee: enabling
// AllowedCommands must not also start filtering Env unless the operator
// opted into one of these two lists.
func (p execPolicy) envDenyReason(env []string) string {
	if len(p.allowedEnvVars) == 0 && len(p.deniedEnvVars) == 0 && len(p.allowedEnvValues) == 0 {
		return ""
	}
	for _, entry := range env {
		name := execEnvVarName(entry)
		if slices.Contains(p.deniedEnvVars, name) {
			return fmt.Sprintf("exec denied: environment variable %q is denylisted", name)
		}
		if len(p.allowedEnvVars) > 0 && !slices.Contains(p.allowedEnvVars, name) {
			return fmt.Sprintf("exec denied: environment variable %q is not allowlisted", name)
		}
		if allowedValues := p.allowedEnvValues[name]; len(allowedValues) > 0 && !slices.Contains(allowedValues, entry) {
			return fmt.Sprintf("exec denied: environment variable %q has a disallowed value", name)
		}
	}
	return ""
}

// execEnvVarName extracts an exec Env entry's variable name: the substring
// before the first "=", or the whole entry when no "=" is present — matching
// the os.Environ/Docker NAME=VALUE convention. The value half is discarded
// entirely; only the name is ever compared against allowed_env_vars /
// denied_env_vars, so a secret carried in a value can never leak into a
// deny reason.
func execEnvVarName(entry string) string {
	name, _, _ := strings.Cut(entry, "=")
	return name
}

func decodeExecCommand(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("decode exec command: %w", errExecMissingCmd)
	}

	var argv []string
	if err := json.Unmarshal(raw, &argv); err == nil {
		if len(argv) == 0 {
			return nil, fmt.Errorf("decode exec command: %w", errExecEmptyCmdArray)
		}
		return argv, nil
	}

	var command string

	if err := json.Unmarshal(raw, &command); err != nil {
		return nil, fmt.Errorf("decode Cmd string: %w", err)
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil, fmt.Errorf("decode exec command: %w", errExecEmptyCmdString)
	}
	return fields, nil
}

// isRootUser reports whether the exec User selects (or defaults to) root. An
// empty value means Docker runs the exec as the container's configured user,
// which is root for most base images, so Sockguard conservatively treats empty
// as root — matching isNonRootUser on the container-create path. Numeric "0" /
// "0:N" and the literal name "root" (any case) are root.
func isRootUser(user string) bool {
	name, _, _ := strings.Cut(strings.TrimSpace(user), ":")
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	return strings.EqualFold(name, "root") || isNumericRootUID(name)
}

func isExecCreatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, "/containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "exec"
}

func isExecStartPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/exec/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, "/exec/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "start"
}

// execStartIdentifier extracts the exec ID from a normalized exec-start path,
// reporting whether it came from the libpod family
// (/libpod/exec/{id}/start) or the Docker-compat one (/exec/{id}/start) —
// the two upstream inspection constructors query different URL families
// (see ExecOptions.InspectStartLibpod's doc comment), so the caller needs to
// know which one to use.
func execStartIdentifier(normalizedPath string) (id string, isLibpod bool, ok bool) {
	prefix := "/exec/"
	if strings.HasPrefix(normalizedPath, libpodPathPrefix+"exec/") {
		prefix = libpodPathPrefix + "exec/"
		isLibpod = true
	} else if !strings.HasPrefix(normalizedPath, prefix) {
		return "", false, false
	}
	rest := strings.TrimPrefix(normalizedPath, prefix)
	id, tail, cut := strings.Cut(rest, "/")
	if !cut || id == "" || tail != "start" {
		return "", false, false
	}
	return id, isLibpod, true
}

// NewDockerExecInspector returns an exec inspector backed by the Docker unix
// socket. It is the single-local-socket shorthand; the multi-endpoint/remote
// path uses NewDockerExecInspectorWithRoundTripper.
func NewDockerExecInspector(upstreamSocket string) ExecInspectFunc {
	return NewDockerExecInspectorWithRoundTripper(upstream.NewSingleSocket(upstreamSocket))
}

// NewDockerExecInspectorWithRoundTripper returns an exec inspector that issues
// its short JSON GET through the shared upstream RoundTripper (typically an
// *upstream.Resolver), so exec-identity inspection follows the same active
// endpoint as the exec-create/start it guards under failover.
func NewDockerExecInspectorWithRoundTripper(rt http.RoundTripper) ExecInspectFunc {
	return newHTTPExecInspector(rt, "http://docker/exec/")
}

// NewLibpodExecInspector returns an exec inspector backed by the Podman unix
// socket, querying GET /libpod/exec/{id}/json rather than the Docker-compat
// GET /exec/{id}/json NewDockerExecInspector uses. It is the
// single-local-socket shorthand; the multi-endpoint/remote path uses
// NewLibpodExecInspectorWithRoundTripper. Both libpod and Docker-compat
// exec-start requests are checked against the SAME execPolicy/ExecOptions
// (#148 design doc decision C3) — this constructor only changes which
// upstream URL family the exec-start re-check queries, wired based on
// which path triggered the request (see execStartIdentifier).
func NewLibpodExecInspector(upstreamSocket string) ExecInspectFunc {
	return NewLibpodExecInspectorWithRoundTripper(upstream.NewSingleSocket(upstreamSocket))
}

// NewLibpodExecInspectorWithRoundTripper is NewDockerExecInspectorWithRoundTripper's
// libpod-path counterpart: same failover-aware transport, GET
// /libpod/exec/{id}/json instead of GET /exec/{id}/json. Podman routes both
// URLs to the identical compat.ExecInspectHandler internally (confirmed
// against Podman's own route table, pkg/api/server/register_exec.go), so the
// response shape decoded here is byte-identical to the Docker-compat path —
// see execInspectResponse, shared by both constructors.
func NewLibpodExecInspectorWithRoundTripper(rt http.RoundTripper) ExecInspectFunc {
	return newHTTPExecInspector(rt, "http://docker/libpod/exec/")
}

// newHTTPExecInspector is the shared GET-and-decode implementation behind
// both NewDockerExecInspectorWithRoundTripper and
// NewLibpodExecInspectorWithRoundTripper; only the URL prefix (and therefore
// which upstream route family is queried) differs between the two.
func newHTTPExecInspector(rt http.RoundTripper, urlPrefix string) ExecInspectFunc {
	client := &http.Client{Transport: rt}

	return func(ctx context.Context, id string) (ExecInspectResult, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPrefix+url.PathEscape(id)+"/json", nil)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return ExecInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ExecInspectResult{}, false, fmt.Errorf("upstream returned %s", resp.Status)
		}

		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ExecInspectResult{}, false, err
		}

		var decoded execInspectResponse
		if err := json.Unmarshal(body, &decoded); err != nil {
			return ExecInspectResult{}, false, err
		}

		command := make([]string, 0, 1+len(decoded.ProcessConfig.Arguments))
		if decoded.ProcessConfig.Entrypoint != "" {
			command = append(command, decoded.ProcessConfig.Entrypoint)
		}
		command = append(command, decoded.ProcessConfig.Arguments...)

		return ExecInspectResult{
			Command:    command,
			Privileged: decoded.ProcessConfig.Privileged,
			User:       decoded.ProcessConfig.User,
		}, true, nil
	}
}

// IsHijackCandidatePath reports whether method+normalizedPath is one of the
// connection-upgrade endpoints — Docker-compat or libpod — that
// internal/proxy's hijack layer must recognize identically to this package's
// own routing.
//
// Exported (unlike the individual isXxxPath matchers it composes) solely so
// the cross-package parity invariant test in internal/proxy can exercise the
// real production matchers on both sides of the filter/proxy package split.
// A path this reports true for that the hijack layer treats as false (or the
// reverse) is a two-parser-drift smuggling bug, not a cosmetic mismatch: see
// internal/proxy's TestHijackFilterParity, and #148's design doc ("Agreed
// core" item 3) for why this must hold for the libpod namespace too.
func IsHijackCandidatePath(method, normalizedPath string) bool {
	if method != http.MethodPost {
		return false
	}
	return isContainerAttachPath(normalizedPath) ||
		isExecStartPath(normalizedPath) ||
		isLibpodContainerAttachPath(normalizedPath) ||
		isLibpodExecStartPath(normalizedPath)
}

const maxImageLoadBodyBytes = 512 << 20       // 512 MiB
const maxImageLoadManifestBytes = 1 << 20     // 1 MiB
const maxImageLoadDecompressedBytes = 2 << 30 // 2 GiB (gzip-bomb guard)

// errImageLoadDecompressedTooLarge is the loud sentinel returned when a
// gzip-compressed image archive expands past maxImageLoadDecompressedBytes.
var errImageLoadDecompressedTooLarge = errors.New("decompressed image archive exceeds byte limit")

// ImageLoadOptions configures request-body inspection for POST /images/load.
type ImageLoadOptions struct {
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
	AllowUntagged      bool
}

type imageLoadPolicy struct {
	allowUntagged bool
	imagePolicy   imagePullPolicy
	io            ioDeps
}

func newImageLoadPolicy(opts ImageLoadOptions) imageLoadPolicy {
	return imageLoadPolicy{
		allowUntagged: opts.AllowUntagged,
		imagePolicy: newImagePullPolicy(ImagePullOptions{
			AllowAllRegistries: opts.AllowAllRegistries,
			AllowOfficial:      opts.AllowOfficial,
			AllowedRegistries:  opts.AllowedRegistries,
		}),
		io: defaultIODeps(),
	}
}

func (p imageLoadPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !matchesImageLoadInspection(normalizedPath) {
		return "", nil
	}
	if !p.allowsAnyImageLoad() {
		return "image load denied: loading image archives is not allowed", nil
	}
	if r.Body == nil {
		return "", nil
	}
	if p.io.CreateTempFile == nil {
		p.io = defaultIODeps()
	}

	spool, size, err := p.io.spoolRequestBodyForInspection(r, "sockguard-image-load-", maxImageLoadBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("image load denied: request body exceeds %d byte limit", maxImageLoadBodyBytes))
		}
		return "", err
	}
	if spool == nil || size == 0 {

		spool.closeAndRemove()
		return "", nil
	}

	tags, foundManifest, err := p.io.extractImageLoadRepoTags(spool.file)
	if err != nil {
		spool.closeAndRemove()
		if errors.Is(err, errImageLoadDecompressedTooLarge) {
			return fmt.Sprintf("image load denied: decompressed image archive exceeds %d byte limit", maxImageLoadDecompressedBytes), nil
		}
		return "", fmt.Errorf("inspect image load manifest: %w", err)
	}
	if !foundManifest {
		if !p.allowUntagged {
			spool.closeAndRemove()
			return "image load denied: image manifest is not inspectable", nil
		}
	} else {
		if len(tags) == 0 && !p.allowUntagged {
			spool.closeAndRemove()
			return "image load denied: untagged images are not allowed", nil
		}
		for _, tag := range tags {
			if denyReason := p.denyReasonForTag(tag); denyReason != "" {
				spool.closeAndRemove()
				return denyReason, nil
			}
		}
	}

	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind image load body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

func (p imageLoadPolicy) allowsAnyImageLoad() bool {
	return p.allowUntagged || p.imagePolicy.allowAllRegistries || p.imagePolicy.allowOfficial || len(p.imagePolicy.allowedRegistries) > 0
}

func (p imageLoadPolicy) denyReasonForTag(tag string) string {
	trimmed := strings.TrimSpace(tag)
	if trimmed == "" || trimmed == "<none>:<none>" {
		if p.allowUntagged {
			return ""
		}
		return "image load denied: untagged images are not allowed"
	}
	if _, ok := parseImageReference(trimmed); !ok {
		return fmt.Sprintf("image load denied: image reference %q could not be inspected", trimmed)
	}
	return p.imagePolicy.denyReasonForReference(trimmed, "image load")
}

type imageLoadManifestEntry struct {
	RepoTags []string `json:"RepoTags"`
}

// extractImageLoadRepoTags reads manifest.json's RepoTags from a docker-save
// archive. Docker's /images/load accepts both a raw tar and a
// gzip-compressed tar (e.g. `docker save img | gzip | docker load`), so probe
// gzip first and fall back to a plain tar walk on a non-gzip header — otherwise
// a legitimate, policy-compliant gzipped archive would be falsely denied as
// "image manifest is not inspectable".
func (io_ ioDeps) extractImageLoadRepoTags(file *os.File) ([]string, bool, error) {
	if tags, found, err := io_.extractImageLoadRepoTagsFromGzip(file); found || err != nil {
		return tags, found, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind image load body: %w", err)
	}
	return io_.extractImageLoadRepoTagsFromTar(tar.NewReader(file))
}

// extractImageLoadRepoTagsFromGzip decompresses a gzip-wrapped tar through a
// loud, decompressed-byte-bounded reader (gzip-bomb guard) and walks it for
// manifest.json. A non-gzip header returns (nil,false,nil) so the caller
// rewinds and reads the body as a plain tar.
func (io_ ioDeps) extractImageLoadRepoTagsFromGzip(file *os.File) ([]string, bool, error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("create gzip reader: %w", err)
	}

	limited := &limitedReader{r: gzr, remaining: maxImageLoadDecompressedBytes, tooLarge: errImageLoadDecompressedTooLarge}
	tags, found, err := io_.extractImageLoadRepoTagsFromTar(tar.NewReader(limited))
	if err == nil {
		if drainErr := io_.DrainReader(limited); drainErr != nil {
			err = fmt.Errorf("drain gzip stream: %w", drainErr)
		}
	}
	if closeErr := io_.CloseReadCloser(gzr); err == nil && closeErr != nil {
		err = fmt.Errorf("close gzip reader: %w", closeErr)
	}
	if errors.Is(err, errImageLoadDecompressedTooLarge) {

		return nil, false, errImageLoadDecompressedTooLarge
	}
	return tags, found, err
}

func (io_ ioDeps) extractImageLoadRepoTagsFromTar(tr *tar.Reader) ([]string, bool, error) {
	var tags []string
	found := false

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return tags, found, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("read tar entry: %w", err)
		}
		if header.Typeflag != tar.TypeReg || normalizeImageLoadArchivePath(header.Name) != "manifest.json" {
			continue
		}

		body, err := io_.ReadAllLimited(tr, maxImageLoadManifestBytes+1)
		if err != nil {
			return nil, false, fmt.Errorf("read manifest.json: %w", err)
		}
		if len(body) > maxImageLoadManifestBytes {
			return nil, false, fmt.Errorf("manifest.json exceeds %d byte limit", maxImageLoadManifestBytes)
		}

		var manifest []imageLoadManifestEntry
		if err := json.Unmarshal(body, &manifest); err != nil {
			return nil, false, fmt.Errorf("decode manifest.json: %w", err)
		}
		found = true
		for _, entry := range manifest {
			tags = append(tags, entry.RepoTags...)
		}
	}
}

func normalizeImageLoadArchivePath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	cleaned := strings.TrimPrefix(trimmed, "/")
	if cleaned == "" {
		return ""
	}
	return cleaned
}

// ImagePullOptions configures query inspection for POST /images/create.
type ImagePullOptions struct {
	AllowImports       bool
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
}

type imagePullPolicy struct {
	allowImports       bool
	allowAllRegistries bool
	allowOfficial      bool
	allowedRegistries  []string
}

func newImagePullPolicy(opts ImagePullOptions) imagePullPolicy {
	allowed := make([]string, 0, len(opts.AllowedRegistries))
	for _, registry := range opts.AllowedRegistries {
		normalized, ok := normalizeRegistryHost(registry)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return imagePullPolicy{
		allowImports:       opts.AllowImports,
		allowAllRegistries: opts.AllowAllRegistries,
		allowOfficial:      opts.AllowOfficial,
		allowedRegistries:  allowed,
	}
}

func (p imagePullPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/images/create" {
		return "", nil
	}

	if denyReason := denyRegistryAuthHeaderReason(r.Header.Get("X-Registry-Auth"), p.allowAllRegistries, p.allowedRegistries, "image pull"); denyReason != "" {
		return denyReason, nil
	}

	query := r.URL.Query()
	if fromSrc := strings.TrimSpace(query.Get("fromSrc")); fromSrc != "" {
		if p.allowImports {
			return "", nil
		}
		return fmt.Sprintf("image pull denied: importing images from %q is not allowed", fromSrc), nil
	}

	fromImage := strings.TrimSpace(query.Get("fromImage"))
	if fromImage == "" {
		return "", nil
	}

	if denyReason := p.denyReasonForReference(fromImage, "image pull"); denyReason != "" {
		return denyReason, nil
	}
	return "", nil
}

func (p imagePullPolicy) denyReasonForReference(fromImage, subject string) string {
	if fromImage == "" {
		return ""
	}

	ref, ok := parseImageReference(fromImage)
	if !ok {
		return ""
	}
	if p.allowAllRegistries {
		return ""
	}
	if p.allowOfficial && ref.official {
		return ""
	}
	if slices.Contains(p.allowedRegistries, ref.registry) {
		return ""
	}

	return fmt.Sprintf("%s denied: registry %q is not allowlisted", subject, ref.registry)
}

type parsedImageReference struct {
	registry string
	official bool
}

func parseImageReference(value string) (parsedImageReference, bool) {
	ref := strings.TrimSpace(value)
	if ref == "" {
		return parsedImageReference{}, false
	}

	if withoutDigest, _, ok := strings.Cut(ref, "@"); ok {
		ref = withoutDigest
	}

	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		ref = ref[:lastColon]
	}

	parts := strings.Split(ref, "/")

	registry := "docker.io"
	repository := parts
	if len(parts) > 1 && looksLikeRegistryComponent(parts[0]) {
		registry, _ = normalizeRegistryHost(parts[0])
		repository = parts[1:]
	}
	for _, segment := range repository {
		if strings.TrimSpace(segment) == "" {
			return parsedImageReference{}, false
		}
	}

	official := registry == "docker.io" && (len(repository) == 1 || (len(repository) == 2 && repository[0] == "library"))
	return parsedImageReference{
		registry: registry,
		official: official,
	}, true
}

func looksLikeRegistryComponent(value string) bool {
	return strings.Contains(value, ".") || strings.Contains(value, ":") || strings.EqualFold(value, "localhost")
}

func normalizeRegistryHost(value string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" || strings.Contains(trimmed, "://") || strings.Contains(trimmed, "/") {
		return "", false
	}
	switch trimmed {
	case "index.docker.io":
		return "docker.io", true
	default:
		return trimmed, true
	}
}

// ioDeps groups the filesystem and stream primitives the request inspectors
// use. Threading the struct through each inspector instead of relying on
// package-level swappable globals lets tests inject stubs without mutating
// shared state, so policy-level tests can safely run under t.Parallel().
type ioDeps struct {
	CreateTempFile  func(dir, pattern string) (*os.File, error)
	RemoveFilePath  func(name string) error
	SeekToStart     func(file *os.File) error
	ReadAllLimited  func(reader io.Reader, limit int64) ([]byte, error)
	DrainReader     func(reader io.Reader) error
	CloseReadCloser func(closer io.Closer) error
}

// defaultIODeps returns the production wiring backed by the os and io
// packages. Each call returns a fresh struct so callers can mutate individual
// fields without affecting other tests.
func defaultIODeps() ioDeps {
	return ioDeps{
		CreateTempFile: os.CreateTemp,
		RemoveFilePath: os.Remove,
		SeekToStart: func(file *os.File) error {
			_, err := file.Seek(0, io.SeekStart)
			return err
		},
		ReadAllLimited: func(reader io.Reader, limit int64) ([]byte, error) {
			return io.ReadAll(io.LimitReader(reader, limit))
		},
		DrainReader: func(reader io.Reader) error {
			_, err := io.Copy(io.Discard, reader)
			return err
		},
		CloseReadCloser: func(closer io.Closer) error {
			return closer.Close()
		},
	}
}

// mutationMaxDepth caps object/array nesting depth during the admission-
// mutation engine's own strict parse, so the existing per-surface body-size
// cap cannot be turned into pathological recursion via deeply nested (but
// still small) JSON.
const mutationMaxDepth = 128

// mutationMaxNodes bounds the total object-member + array-element count the
// strict scan will walk, derived from the body length actually read so a
// small body cannot decode into an unbounded number of nodes. The minimum
// possible encoding of one additional node is two bytes (e.g. a
// comma-separated `0` or `""`), so bodyLen+1 is always a safe, generous
// upper bound that never rejects a legitimately-shaped body within the
// existing size cap.
func mutationMaxNodes(bodyLen int) int64 {
	return int64(bodyLen) + 1
}

// parseMutationDocument strictly parses body into a single non-null JSON
// object for the admission-mutation engine, failing closed on anything that
// could let a mutation write land ambiguously:
//
//   - exact duplicate object keys at any level, including inside arrays;
//   - case-variant ("folded") duplicate struct-field keys, reusing the
//     existing, already-reviewed checkDuplicateCaseVariantKeys /
//     isCaseSensitiveDataMapField exemption every other body-mutating code
//     path in this package already relies on;
//   - a non-object or null root;
//   - trailing data after the single JSON value;
//   - nesting deeper than mutationMaxDepth or more nodes than maxNodes.
//
// Numbers are preserved as json.Number (UseNumber) so large integer fields
// (Memory limits, PID caps, CPU shares) are never corrupted by a float
// round-trip on re-encode, matching every other JSON-rewriting code path in
// this codebase.
func parseMutationDocument(body []byte, maxNodes int64) (map[string]any, error) {
	if err := scanMutationJSONStrict(body, maxNodes); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if err := requireJSONDecoderEOF(dec); err != nil {
		return nil, err
	}

	doc, ok := v.(map[string]any)
	if !ok || doc == nil {
		return nil, fmt.Errorf("request body must be a single non-null JSON object")
	}

	if err := checkDuplicateCaseVariantKeys(v, false); err != nil {
		return nil, err
	}
	return doc, nil
}

// scanMutationJSONStrict token-scans body — without building a value tree —
// purely to catch what a map-decode cannot: an exact duplicate object key
// anywhere in the document (the decode silently keeps only the last one),
// and to bound nesting depth/node count and require a well-formed single
// object with no trailing data. It does not itself understand case-variant
// (folded) duplicates or field semantics; parseMutationDocument layers the
// existing fold check on top after decoding.
func scanMutationJSONStrict(body []byte, maxNodes int64) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("request body must be a single non-null JSON object")
	}

	nodes := int64(0)
	if err := scanJSONObjectMembers(dec, 1, &nodes, maxNodes); err != nil {
		return err
	}
	return requireJSONDecoderEOF(dec)
}

// scanJSONObjectMembers consumes one JSON object's members (the decoder has
// already consumed the opening '{'), rejecting an exact duplicate key at
// this level and recursing into each member's value. It consumes the
// closing '}' before returning.
func scanJSONObjectMembers(dec *json.Decoder, depth int, nodes *int64, maxNodes int64) error {
	if depth > mutationMaxDepth {
		return fmt.Errorf("json nesting exceeds max depth %d", mutationMaxDepth)
	}
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("decode json: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected JSON object key")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate JSON object key %q", key)
		}
		seen[key] = struct{}{}
		if err := incrementJSONNodeCount(nodes, maxNodes); err != nil {
			return err
		}
		if err := scanJSONValue(dec, depth, nodes, maxNodes); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

// scanJSONArrayElements consumes one JSON array's elements (the decoder has
// already consumed the opening '['), recursing into each element. It
// consumes the closing ']' before returning.
func scanJSONArrayElements(dec *json.Decoder, depth int, nodes *int64, maxNodes int64) error {
	if depth > mutationMaxDepth {
		return fmt.Errorf("json nesting exceeds max depth %d", mutationMaxDepth)
	}
	for dec.More() {
		if err := incrementJSONNodeCount(nodes, maxNodes); err != nil {
			return err
		}
		if err := scanJSONValue(dec, depth, nodes, maxNodes); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

// scanJSONValue consumes exactly one JSON value — scalar, object, or array —
// recursing for composite values.
func scanJSONValue(dec *json.Decoder, depth int, nodes *int64, maxNodes int64) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			return scanJSONObjectMembers(dec, depth+1, nodes, maxNodes)
		case '[':
			return scanJSONArrayElements(dec, depth+1, nodes, maxNodes)
		}
	}
	return nil
}

func incrementJSONNodeCount(nodes *int64, maxNodes int64) error {
	*nodes++
	if *nodes > maxNodes {
		return fmt.Errorf("json body exceeds node count cap")
	}
	return nil
}

// requireJSONDecoderEOF reports an error unless dec has no further tokens to
// offer — i.e. the JSON value(s) already consumed were the entire input.
// Used both to reject trailing data after the single top-level object this
// package requires, and (via json.Decoder.Decode's own EOF-checking use) to
// require a decode leaves nothing unconsumed.
func requireJSONDecoderEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing data after JSON value")
		}
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

// deepCloneJSONValue returns an independent copy of a value decoded by
// parseMutationDocument (map[string]any / []any / json.Number / string /
// bool / nil), so a warn/audit-mode mutation rule can be evaluated against a
// clone without ever risking a write to the document that will actually be
// forwarded. Scalar leaves (json.Number, string, bool, nil) are immutable
// value types in Go and are shared, not copied.
func deepCloneJSONValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCloneJSONValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deepCloneJSONValue(val)
		}
		return out
	default:
		return v
	}
}

// NestedObject returns the object stored under key in decoded, creating it
// when absent. Key matching is case-INSENSITIVE and collision-collapsing:
// Docker decodes JSON object keys case-insensitively and, on duplicate
// case-variant keys, lets the last one win. A client could otherwise smuggle
// a lowercase "labels" alongside a proxy-injected "Labels" and — because
// json.Marshal emits map keys in sorted order, placing "labels" after
// "Labels" — have Docker prefer the client's forged value over the one the
// proxy verified. To close that spoof, every key that case-folds to key is
// merged into a single object stored under the exact canonical key, and all
// variant keys are removed, so the re-encoded body carries exactly one
// unambiguous key that Docker reads verbatim.
//
// Exported so both the admission-mutation engine (mutation.go) and
// internal/ownership's owner-label stamping share one reviewed
// implementation instead of two independently-maintained copies of the same
// security-critical fold/merge logic.
func NestedObject(decoded map[string]any, key string) (map[string]any, error) {
	merged := map[string]any{}
	var variants []string
	for k, v := range decoded {
		if !strings.EqualFold(k, key) {
			continue
		}
		variants = append(variants, k)
		if v == nil {
			continue
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", key)
		}
		for kk, vv := range obj {
			merged[kk] = vv
		}
	}
	for _, k := range variants {
		delete(decoded, k)
	}
	decoded[key] = merged
	return merged, nil
}

// NestedObjectPath walks/creates a chain of nested objects via NestedObject,
// e.g. NestedObjectPath(decoded, "TaskTemplate", "ContainerSpec", "Labels").
func NestedObjectPath(decoded map[string]any, keys ...string) (map[string]any, error) {
	current := decoded
	for _, key := range keys {
		next, err := NestedObject(current, key)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

// FoldedObjects returns every object value in m whose key case-folds to key,
// in map-iteration order. Docker decodes duplicate case-variant keys and
// lets the last one win, so a read-side security check must inspect every
// variant rather than an exact-case single lookup.
func FoldedObjects(m map[string]any, key string) []map[string]any {
	var out []map[string]any
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if obj, ok := v.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

// FoldedStrings returns every string value in m whose key case-folds to key.
func FoldedStrings(m map[string]any, key string) []string {
	var out []string
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if value, ok := v.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

// FoldedArrays returns every array value in m whose key case-folds to key.
func FoldedArrays(m map[string]any, key string) [][]any {
	var out [][]any
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if values, ok := v.([]any); ok {
			out = append(out, values)
		}
	}
	return out
}

// FoldedStringEquals reports whether any string value in m whose key
// case-folds to key case-insensitively equals want (after trimming
// whitespace).
func FoldedStringEquals(m map[string]any, key, want string) bool {
	for _, value := range FoldedStrings(m, key) {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

// soleFoldedObject returns the object value of the sole key in m that
// case-folds to name. By the time this is called the document has already
// passed the exact/folded duplicate-key guard in parseMutationDocument, so
// at most one case-variant of name can exist; an absent key or a present key
// whose value is not a JSON object both report ok=false, matching
// "nothing to navigate into" rather than an error — the caller (image-remap
// application) treats a missing target as a no-op, not a failure.
func soleFoldedObject(m map[string]any, name string) (map[string]any, bool) {
	for k, v := range m {
		if !strings.EqualFold(k, name) {
			continue
		}
		obj, ok := v.(map[string]any)
		return obj, ok
	}
	return nil, false
}

// navigateFoldedObjectPath walks a chain of object levels via
// soleFoldedObject without creating missing levels — used by image-remap
// application, which must treat an absent TaskTemplate/ContainerSpec as "no
// image field to remap" rather than fabricating the structure the way
// NestedObjectPath does for label injection.
func navigateFoldedObjectPath(doc map[string]any, keys ...string) (map[string]any, bool) {
	current := doc
	for _, key := range keys {
		next, ok := soleFoldedObject(current, key)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

// foldedStringLeaf returns the value, presence, and string-typedness of the
// sole key in m that case-folds to name. present=false means the key is
// absent; isString=false with present=true means the key exists but its
// value is not a JSON string (a type-mismatch the caller must fail closed
// on, not silently skip).
func foldedStringLeaf(m map[string]any, name string) (value string, present, isString bool) {
	for k, v := range m {
		if !strings.EqualFold(k, name) {
			continue
		}
		s, ok := v.(string)
		return s, true, ok
	}
	return "", false, false
}

// setFoldedStringLeaf collapses any existing case-variant of name in m to
// the canonical spelling and sets it to newValue. At most one variant can
// exist by construction (see soleFoldedObject's doc comment).
func setFoldedStringLeaf(m map[string]any, name, newValue string) {
	for k := range m {
		if strings.EqualFold(k, name) {
			delete(m, k)
			break
		}
	}
	m[name] = newValue
}

// decodePolicySubsetJSON decodes only the subset of a Docker write payload
// that Sockguard currently enforces. These inspectors are intentionally not
// full-schema validators: many legitimate Docker request bodies carry fields
// that Sockguard does not inspect, so unknown fields remain Docker's job.
// Callers must therefore treat decode errors as "defer to Docker validation"
// rather than as a policy deny on their own.
func decodePolicySubsetJSON(body []byte, dst any) error {
	return json.Unmarshal(body, dst)
}

// LibpodContainerCreateOptions configures request-body policy checks for
// POST /libpod/containers/create. Field names mirror ContainerCreateOptions
// where the underlying semantics map onto a libpod equivalent, so operator
// knowledge transfers between the Docker-compat and native surfaces; two
// fields (AllowSystemdMode, AllowCustomIDMappings) have no Docker analog.
type LibpodContainerCreateOptions struct {
	AllowPrivileged   bool
	AllowHostNetwork  bool
	AllowHostPID      bool
	AllowHostIPC      bool
	AllowHostUserNS   bool
	AllowedBindMounts []string
	AllowAllDevices   bool
	AllowedDevices    []string

	// RestrictNamespaceSharing gates netns/pidns/ipcns/userns/utsns objects
	// of the form {"nsmode":"container","value":"<ref>"} (join another
	// container's namespace) against AllowedNamespaceSharingContainers.
	// Default false: such values pass through unchecked, mirroring
	// ContainerCreateOptions.RestrictNamespaceSharing's default exactly.
	RestrictNamespaceSharing          bool
	AllowedNamespaceSharingContainers []string

	AllowAllCapabilities   bool
	AllowedCapabilities    []string
	AllowedSeccompProfiles []string
	DenyUnconfinedSeccomp  bool

	AllowedAppArmorProfiles []string
	DenyUnconfinedAppArmor  bool

	DenySelinuxDisable bool

	RequireNonRootUser    bool
	RequireReadonlyRootfs bool
	RequireMemoryLimit    bool
	RequireCPULimit       bool
	// RequireCPULimitHard narrows RequireCPULimit to accept only a genuine
	// CPU-time cap (resource_limits.cpu.quota); shares alone does not
	// satisfy it — mirrors ContainerCreateOptions.RequireCPULimitHard.
	RequireCPULimitHard bool
	RequirePidsLimit    bool

	AllowSysctls bool

	// ImageTrust configures cosign-backed signature verification, reusing
	// the identical machinery container_create.go uses against the "image"
	// field.
	ImageTrust ImageTrustOptions

	// AllowSystemdMode permits POST /libpod/containers/create with a
	// "systemd" value other than "false" (SpecGenerator's own default, sent
	// even when --systemd was never passed on the CLI — see
	// testdata/libpod/basic_create.json — is "true"). systemd=true/always
	// enables Podman's systemd-aware mount/cgroup elevation for the
	// container's init process; there is no Docker Engine API analog.
	// Default false: every create is denied unless the body explicitly
	// carries "false" or this is set.
	AllowSystemdMode bool

	// AllowCustomIDMappings permits a non-default idmappings.UIDMap/GIDMap
	// or AutoUserNs (podman --uidmap/--gidmap/--userns=auto). A blunt gate
	// for v1.6 — no range-overlap or host-UID-collision analysis; see the
	// design doc's "Deferred past v1.6" list. Default false.
	AllowCustomIDMappings bool
}

type libpodContainerCreatePolicy struct {
	allowPrivileged   bool
	allowHostNetwork  bool
	allowHostPID      bool
	allowHostIPC      bool
	allowHostUserNS   bool
	allowedBindMounts []string
	allowAllDevices   bool
	allowedDevices    []string

	restrictNamespaceSharing          bool
	allowedNamespaceSharingContainers []string

	allowAllCapabilities   bool
	allowedCapabilities    []string
	allowedSeccompProfiles []string
	denyUnconfinedSeccomp  bool

	allowedAppArmorProfiles []string
	denyUnconfinedAppArmor  bool

	denySelinuxDisable bool

	requireNonRootUser    bool
	requireReadonlyRootfs bool
	requireMemoryLimit    bool
	requireCPULimit       bool
	requireCPULimitHard   bool
	requirePidsLimit      bool

	allowSysctls bool

	allowSystemdMode      bool
	allowCustomIDMappings bool

	imageTrustVerifier imageVerifier
	imageFetcher       signatureFetcher
	imageTrustCfg      imagetrust.Config
	imageTrustTimeout  time.Duration
	imageTrustInitErr  error
}

func newLibpodContainerCreatePolicy(opts LibpodContainerCreateOptions) libpodContainerCreatePolicy {
	allowedBindMounts := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeBindMount(bindMount)
		if !ok || slices.Contains(allowedBindMounts, normalized) {
			continue
		}
		allowedBindMounts = append(allowedBindMounts, normalized)
	}

	allowedDevices := make([]string, 0, len(opts.AllowedDevices))
	for _, device := range opts.AllowedDevices {
		normalized, ok := normalizeContainerCreateDevicePath(device)
		if !ok || slices.Contains(allowedDevices, normalized) {
			continue
		}
		allowedDevices = append(allowedDevices, normalized)
	}

	p := libpodContainerCreatePolicy{
		allowPrivileged:                   opts.AllowPrivileged,
		allowHostNetwork:                  opts.AllowHostNetwork,
		allowHostPID:                      opts.AllowHostPID,
		allowHostIPC:                      opts.AllowHostIPC,
		allowHostUserNS:                   opts.AllowHostUserNS,
		allowedBindMounts:                 allowedBindMounts,
		allowAllDevices:                   opts.AllowAllDevices,
		allowedDevices:                    allowedDevices,
		restrictNamespaceSharing:          opts.RestrictNamespaceSharing,
		allowedNamespaceSharingContainers: normalizeStringList(opts.AllowedNamespaceSharingContainers),
		allowAllCapabilities:              opts.AllowAllCapabilities,
		allowedCapabilities:               normalizeCapabilityList(opts.AllowedCapabilities),
		allowedSeccompProfiles:            normalizeStringList(opts.AllowedSeccompProfiles),
		denyUnconfinedSeccomp:             opts.DenyUnconfinedSeccomp,
		allowedAppArmorProfiles:           normalizeStringList(opts.AllowedAppArmorProfiles),
		denyUnconfinedAppArmor:            opts.DenyUnconfinedAppArmor,
		denySelinuxDisable:                opts.DenySelinuxDisable,
		requireNonRootUser:                opts.RequireNonRootUser,
		requireReadonlyRootfs:             opts.RequireReadonlyRootfs,
		requireMemoryLimit:                opts.RequireMemoryLimit,
		requireCPULimit:                   opts.RequireCPULimit,
		requireCPULimitHard:               opts.RequireCPULimitHard,
		requirePidsLimit:                  opts.RequirePidsLimit,
		allowSysctls:                      opts.AllowSysctls,
		allowSystemdMode:                  opts.AllowSystemdMode,
		allowCustomIDMappings:             opts.AllowCustomIDMappings,
	}

	itf := buildImageTrustFields(opts.ImageTrust)
	p.imageTrustVerifier = itf.verifier
	p.imageFetcher = itf.fetcher
	p.imageTrustCfg = itf.cfg
	p.imageTrustTimeout = itf.timeout
	p.imageTrustInitErr = itf.initErr

	return p
}

func (p libpodContainerCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isLibpodContainerCreatePath(normalizedPath) || r.Body == nil {
		return "", nil
	}
	if p.imageTrustInitErr != nil {
		return fmt.Sprintf("libpod container create denied: image trust policy initialization error: %s", p.imageTrustInitErr.Error()), nil
	}
	body, err := readBoundedBody(r, maxContainerCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod container create denied: request body exceeds %d byte limit", maxContainerCreateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var createReq libpodContainerCreateRequest
	if err := json.Unmarshal(body, &createReq); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod container create request body is not valid JSON; denying", err)
		return "libpod container create denied: malformed JSON request body", nil
	}

	if !p.allowPrivileged && createReq.Privileged {
		return "libpod container create denied: privileged containers are not allowed", nil
	}
	if !p.allowHostNetwork && createReq.NetNS.isHost() {
		return "libpod container create denied: host network namespace is not allowed", nil
	}
	if !p.allowHostPID && createReq.PidNS.isHost() {
		return "libpod container create denied: host PID namespace is not allowed", nil
	}
	if !p.allowHostIPC && createReq.IpcNS.isHost() {
		return "libpod container create denied: host IPC namespace is not allowed", nil
	}
	if !p.allowHostUserNS && createReq.UserNS.isHost() {
		return "libpod container create denied: host user namespace is not allowed", nil
	}
	if denyReason := p.denyNamespaceSharingReason(createReq); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyBindMountReason(createReq.Mounts); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyDeviceReason(createReq.Devices); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := capabilityAddDenyReason(createReq.CapAdd, p.allowAllCapabilities, p.allowedCapabilities, "libpod container create"); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denySeccompReason(createReq.SeccompProfilePath); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyAppArmorReason(createReq.ApparmorProfile); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denySelinuxReason(createReq.SelinuxOpts); denyReason != "" {
		return denyReason, nil
	}
	if p.requireNonRootUser && !isNonRootUser(createReq.User) {
		return "libpod container create denied: non-root user is required (set User to a non-zero UID or non-root username)", nil
	}
	if p.requireReadonlyRootfs && !createReq.ReadOnlyFilesystem {
		return "libpod container create denied: read-only root filesystem is required (set read_only_filesystem to true)", nil
	}
	if denyReason := p.denyResourceLimitReason(createReq.ResourceLimits); denyReason != "" {
		return denyReason, nil
	}
	if !p.allowSysctls && len(createReq.Sysctl) > 0 {
		return "libpod container create denied: setting sysctls is not allowed", nil
	}
	if denyReason := p.denySystemdModeReason(createReq.Systemd); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyIDMappingsReason(createReq.IDMapping); denyReason != "" {
		return denyReason, nil
	}

	if p.imageTrustVerifier != nil {
		imageRef := strings.TrimSpace(createReq.Image)
		fields := imageTrustFields{
			verifier: p.imageTrustVerifier,
			fetcher:  p.imageFetcher,
			cfg:      p.imageTrustCfg,
			timeout:  p.imageTrustTimeout,
		}
		denyReason, verifiedDigest := verifyImageTrust(r.Context(), logger, fields, imageRef, "libpod container create")
		if denyReason != "" {
			return denyReason, nil
		}
		if verifiedDigest != "" {
			pinned, perr := imagefetch.PinnedReference(imageRef, verifiedDigest)
			if perr != nil {
				return "", fmt.Errorf("pin verified image digest: %w", perr)
			}
			if pinned != imageRef {
				rewritten, rerr := rewriteLibpodJSONImageField(body, pinned)
				if rerr != nil {
					return "", fmt.Errorf("pin verified image digest: %w", rerr)
				}
				r.Body = io.NopCloser(bytes.NewReader(rewritten))
				r.ContentLength = int64(len(rewritten))
			}
		}
	}

	return "", nil
}

// denyNamespaceSharingReason enforces restrictNamespaceSharing against every
// namespace field that can join another container's namespace via
// {"nsmode":"container","value":"<ref>"}: netns, pidns, ipcns, userns, utsns.
// Mirrors containerCreatePolicy.denyNamespaceSharingReason's field coverage
// (cgroupns is intentionally excluded there too).
func (p libpodContainerCreatePolicy) denyNamespaceSharingReason(req libpodContainerCreateRequest) string {
	if !p.restrictNamespaceSharing {
		return ""
	}
	fields := [...]struct {
		label string
		ns    libpodNamespace
	}{
		{"network", req.NetNS},
		{"PID", req.PidNS},
		{"IPC", req.IpcNS},
		{"user", req.UserNS},
		{"UTS", req.UtsNS},
	}
	for _, f := range fields {
		ref, ok := f.ns.containerRef()
		if !ok {
			continue
		}
		if len(p.allowedNamespaceSharingContainers) == 0 {
			return fmt.Sprintf("libpod container create denied: %s namespace sharing with another container is not allowed", f.label)
		}
		if !slices.Contains(p.allowedNamespaceSharingContainers, ref) {
			return fmt.Sprintf("libpod container create denied: namespace-sharing target %q is not in the allowed list", ref)
		}
	}
	return ""
}

// denyBindMountReason enforces allowedBindMounts against every "bind"-typed
// entry of the top-level "mounts" array. Named-volume mounts (the "volumes"
// array) reference a volume by name, not a host filesystem path, so they
// carry no bind-mount attack surface and are not checked here.
func (p libpodContainerCreatePolicy) denyBindMountReason(mounts []libpodMount) string {
	for _, mount := range mounts {
		if !strings.EqualFold(mount.Type, "bind") {
			continue
		}
		source, ok := normalizeBindMount(mount.Source)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("libpod container create denied: bind mount source %q is not allowlisted", source)
	}
	return ""
}

// denyDeviceReason enforces allowAllDevices/allowedDevices against every
// entry of the top-level "devices" array.
func (p libpodContainerCreatePolicy) denyDeviceReason(devices []libpodDevice) string {
	if p.allowAllDevices {
		return ""
	}
	for _, device := range devices {
		rawHostPath, ok := splitLibpodDevicePath(device.Path)
		hostPath, normOK := normalizeContainerCreateDevicePath(rawHostPath)
		if !ok || !normOK || !bindPathAllowed(hostPath, p.allowedDevices) {
			return fmt.Sprintf("libpod container create denied: device %q is not allowlisted", device.Path)
		}
	}
	return ""
}

// denySeccompReason gates seccomp_profile_path. An empty path is
// SpecGenerator's "default profile" sentinel (see basic_create.json), mapped
// onto the allowlist's "default" entry the same way container_create.go's
// denySecurityOptReason treats an unset seccomp= SecurityOpt.
func (p libpodContainerCreatePolicy) denySeccompReason(profilePath string) string {
	profilePath = strings.TrimSpace(profilePath)
	if p.denyUnconfinedSeccomp && strings.EqualFold(profilePath, "unconfined") {
		return "libpod container create denied: unconfined seccomp profile is not allowed"
	}
	if len(p.allowedSeccompProfiles) == 0 {
		return ""
	}
	effective := profilePath
	if effective == "" {
		effective = "default"
	}
	if !slices.Contains(p.allowedSeccompProfiles, effective) {
		return fmt.Sprintf("libpod container create denied: seccomp profile %q is not in the allowed list", effective)
	}
	return ""
}

// denyAppArmorReason gates apparmor_profile. An empty profile is
// SpecGenerator's "container-default confinement" sentinel, mapped onto the
// allowlist's "default" entry — mirrors container_create.go's
// denySecurityOptReason treatment of the analogous Docker default synonyms.
func (p libpodContainerCreatePolicy) denyAppArmorReason(profile string) string {
	profile = strings.TrimSpace(profile)
	if p.denyUnconfinedAppArmor && strings.EqualFold(profile, "unconfined") {
		return "libpod container create denied: unconfined apparmor profile is not allowed"
	}
	if len(p.allowedAppArmorProfiles) == 0 {
		return ""
	}
	effective := profile
	if effective == "" {
		effective = "default"
	}
	if !slices.Contains(p.allowedAppArmorProfiles, effective) {
		return fmt.Sprintf("libpod container create denied: apparmor profile %q is not in the allowed list", effective)
	}
	return ""
}

// denySelinuxReason gates selinux_opts. The only libpod-specific SELinux
// posture PR2 scopes is "disable" (see design doc "Scope" item 2); per-field
// label overrides (user:/role:/type:/level:) are not gated here, matching
// container_create.go's DenySelinuxLabelOverride being a separate,
// independently-scoped flag this inspector does not carry.
func (p libpodContainerCreatePolicy) denySelinuxReason(opts []string) string {
	if !p.denySelinuxDisable {
		return ""
	}
	for _, raw := range opts {
		if strings.EqualFold(strings.TrimSpace(raw), "disable") {
			return "libpod container create denied: selinux disable is not allowed"
		}
	}
	return ""
}

// denyResourceLimitReason enforces requireMemoryLimit/requireCPULimit/
// requireCPULimitHard/requirePidsLimit against resource_limits. Mirrors
// container_create.go's resourceLimitDenyReason semantics: requireCPULimit
// accepts any of quota/period/shares as evidence of intent; requireCPULimitHard
// only accepts quota (a genuine CFS time cap — shares/period alone enforce
// nothing on an uncontended host).
func (p libpodContainerCreatePolicy) denyResourceLimitReason(limits libpodResourceLimits) string {
	if p.requireMemoryLimit && limits.Memory.Limit <= 0 {
		return "libpod container create denied: a memory limit is required (set resource_limits.memory.limit)"
	}
	if p.requireCPULimit && limits.CPU.Quota <= 0 && limits.CPU.Period == 0 && limits.CPU.Shares == 0 {
		return "libpod container create denied: a CPU limit is required (set resource_limits.cpu.quota, period, or shares)"
	}
	if p.requireCPULimitHard && limits.CPU.Quota <= 0 {
		return "libpod container create denied: a hard CPU cap is required (set resource_limits.cpu.quota; shares is a relative priority weight, not a cap, and does not satisfy this check)"
	}
	if p.requirePidsLimit && limits.Pids.Limit <= 0 {
		return "libpod container create denied: a PIDs limit is required (set resource_limits.pids.limit to a positive value)"
	}
	return ""
}

// denySystemdModeReason denies any "systemd" value other than the literal
// "false" unless allowSystemdMode is set. SpecGenerator sends a non-empty
// default ("true") even when --systemd was never passed on the CLI — see
// basic_create.json — so this gate denies the common case by default; that
// is the intended, deliberately strict posture for a libpod-only gate with
// no Docker Engine API analog (see LibpodContainerCreateOptions.AllowSystemdMode).
func (p libpodContainerCreatePolicy) denySystemdModeReason(systemd string) string {
	if p.allowSystemdMode {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(systemd), "false") {
		return ""
	}
	return fmt.Sprintf("libpod container create denied: systemd mode %q is not allowed (set allow_systemd_mode: true, or use systemd=false)", systemd)
}

// denyIDMappingsReason is the "blunt gate" (design doc term) on
// idmappings: any non-default UID/GID mapping or --userns=auto request is
// denied unless allowCustomIDMappings is set. No range-overlap or
// host-UID-collision analysis — see the design doc's "Deferred past v1.6"
// list.
func (p libpodContainerCreatePolicy) denyIDMappingsReason(idm libpodIDMappings) string {
	if p.allowCustomIDMappings {
		return ""
	}
	if len(idm.UIDMap) > 0 || len(idm.GIDMap) > 0 || idm.AutoUserNs {
		return "libpod container create denied: custom UID/GID mappings are not allowed (set allow_custom_id_mappings: true)"
	}
	return ""
}

// foldedRawKeysLibpod returns every key in m that case-folds to canonical.
// Podman's own client never emits case-variant keys, but a crafted body
// could — see rewriteLibpodJSONImageField's doc comment for why this must be
// checked before pinning a verified image reference into the forwarded body.
func foldedRawKeysLibpod(m map[string]json.RawMessage, canonical string) []string {
	var out []string
	for k := range m {
		if strings.EqualFold(k, canonical) {
			out = append(out, k)
		}
	}
	return out
}

// rewriteLibpodJSONImageField returns body with its (case-insensitive)
// "image" field replaced by pinned, closing the same verify->pull TOCTOU
// rewriteJSONImageField closes for Docker-shaped bodies (container_create.go)
// — here for libpod's lowercase "image" field instead of "Image". Other
// fields are preserved byte-for-byte (RawMessage).
func rewriteLibpodJSONImageField(body []byte, pinned string) ([]byte, error) {
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	variants := foldedRawKeysLibpod(fields, "image")
	if len(variants) > 1 {
		return nil, fmt.Errorf("ambiguous libpod container image: %d case-variant \"image\" keys", len(variants))
	}
	encoded, err := json.Marshal(pinned)
	if err != nil {
		return nil, err
	}
	for _, k := range variants {
		delete(fields, k)
	}
	fields["image"] = encoded
	return json.Marshal(fields)
}

// libpodContainerCreateRequest is the top-level POST /libpod/containers/create
// body. Only the fields this inspector's gates read are modeled; SpecGenerator
// sends many more (health checks, DNS, working dir, ...) that pass through
// unread and therefore unvalidated by sockguard — matching container_create's
// own posture of only modeling fields it has an explicit gate for.
type libpodContainerCreateRequest struct {
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	User       string            `json:"user"`
	Labels     map[string]string `json:"labels"`
	Privileged bool              `json:"privileged"`

	NetNS     libpodNamespace  `json:"netns"`
	PidNS     libpodNamespace  `json:"pidns"`
	IpcNS     libpodNamespace  `json:"ipcns"`
	UserNS    libpodNamespace  `json:"userns"`
	UtsNS     libpodNamespace  `json:"utsns"`
	CgroupNS  libpodNamespace  `json:"cgroupns"`
	IDMapping libpodIDMappings `json:"idmappings"`

	Mounts  []libpodMount  `json:"mounts"`
	Volumes []libpodVolume `json:"volumes"`
	Devices []libpodDevice `json:"devices"`

	CapAdd  []string `json:"cap_add"`
	CapDrop []string `json:"cap_drop"`

	SeccompProfilePath string   `json:"seccomp_profile_path"`
	ApparmorProfile    string   `json:"apparmor_profile"`
	SelinuxOpts        []string `json:"selinux_opts"`

	ResourceLimits libpodResourceLimits `json:"resource_limits"`

	Sysctl             map[string]string `json:"sysctl"`
	ReadOnlyFilesystem bool              `json:"read_only_filesystem"`
	Systemd            string            `json:"systemd"`
}

// libpodNamespace is the uniform shape SpecGenerator uses for every
// namespace-mode field (netns, pidns, ipcns, userns, utsns, cgroupns):
// {"nsmode": "host"} for the host namespace, {"nsmode": "container",
// "value": "<name-or-id>"} to join another container's namespace, {} (both
// fields absent/empty) for the private per-container default. Confirmed by
// host_network.json (nsmode only) and namespace_share_container_ref.json
// (nsmode+value) — see testdata/libpod/README.md.
type libpodNamespace struct {
	NSMode string `json:"nsmode"`
	Value  string `json:"value"`
}

// isHost reports whether this namespace object selects the host namespace.
func (n libpodNamespace) isHost() bool {
	return isHostNamespaceMode(n.NSMode)
}

// containerRef reports whether this namespace object joins another
// container's namespace ({"nsmode":"container","value":"<ref>"}) and, if so,
// returns the trimmed ref.
func (n libpodNamespace) containerRef() (ref string, ok bool) {
	if !strings.EqualFold(strings.TrimSpace(n.NSMode), "container") {
		return "", false
	}
	ref = strings.TrimSpace(n.Value)
	if ref == "" {
		return "", false
	}
	return ref, true
}

// libpodMount is one entry of the top-level "mounts" array (bind/tmpfs/image
// mounts routed through --mount or -v <host>:<container> on the CLI).
// Lowercase field names — see volumes_named.json for the contrasting
// capitalized shape of libpodVolume, a genuine SpecGenerator inconsistency
// between the two arrays.
type libpodMount struct {
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Options     []string `json:"options"`
}

// libpodVolume is one entry of the top-level "volumes" array (named-volume
// mounts routed through -v <volume-name>:<container> on the CLI). Capitalized
// field names, unlike libpodMount — see volumes_named.json.
type libpodVolume struct {
	Name        string   `json:"Name"`
	Dest        string   `json:"Dest"`
	Options     []string `json:"Options"`
	SubPath     string   `json:"SubPath"`
	IsAnonymous bool     `json:"IsAnonymous"`
}

// libpodDevice is one entry of the top-level "devices" array. Unlike Docker's
// HostConfig.Devices (which the client splits into PathOnHost/PathInContainer
// before sending), SpecGenerator sends the raw, unsplit "host[:container[:perms]]"
// CLI argument verbatim in Path — see devices.json and splitLibpodDevicePath.
type libpodDevice struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Major int64  `json:"major"`
	Minor int64  `json:"minor"`
}

// libpodResourceLimits mirrors the OCI runtime-spec-shaped "resource_limits"
// object SpecGenerator sends for --memory/--cpus/--cpu-shares/--pids-limit.
// All fields are plain values, not pointers: an absent JSON key and an
// explicit zero both mean "no limit" for every RequireX gate this inspector
// implements, so the pointer/value distinction that matters elsewhere in this
// package (e.g. containerCreateHostConfig.PidsLimit) carries no policy
// meaning here.
type libpodResourceLimits struct {
	CPU    libpodCPUResourceLimit    `json:"cpu"`
	Memory libpodMemoryResourceLimit `json:"memory"`
	Pids   libpodPidsResourceLimit   `json:"pids"`
}

// libpodCPUResourceLimit mirrors resource_limits.cpu. period/quota come from
// --cpus (both set together); shares comes from --cpu-shares independently —
// see resource_limits.json vs resource_limits_cpu_shares.json.
type libpodCPUResourceLimit struct {
	Period uint64 `json:"period"`
	Quota  int64  `json:"quota"`
	Shares uint64 `json:"shares"`
}

// libpodMemoryResourceLimit mirrors resource_limits.memory.
type libpodMemoryResourceLimit struct {
	Limit int64 `json:"limit"`
	Swap  int64 `json:"swap"`
}

// libpodPidsResourceLimit mirrors resource_limits.pids.
type libpodPidsResourceLimit struct {
	Limit int64 `json:"limit"`
}

// libpodIDMappings mirrors the top-level "idmappings" object SpecGenerator
// always sends (present, but with nil UIDMap/GIDMap and
// HostUIDMapping/HostGIDMapping true, when no custom mapping was requested —
// see basic_create.json). AutoUserNs/AutoUserNsOpts (podman --userns=auto)
// are read only for the "any custom mapping requested" test, not modeled
// field-by-field — see denyIDMappingsReason.
type libpodIDMappings struct {
	UIDMap         []libpodIDMap `json:"UIDMap"`
	GIDMap         []libpodIDMap `json:"GIDMap"`
	HostUIDMapping bool          `json:"HostUIDMapping"`
	HostGIDMapping bool          `json:"HostGIDMapping"`
	AutoUserNs     bool          `json:"AutoUserNs"`
}

// libpodIDMap is one entry of idmappings.UIDMap/GIDMap.
type libpodIDMap struct {
	ContainerID int `json:"container_id"`
	HostID      int `json:"host_id"`
	Size        int `json:"size"`
}

// splitLibpodDevicePath splits a libpodDevice.Path value into its host-side
// path. SpecGenerator does not pre-split the "host[:container[:perms]]" CLI
// form the way Docker's client does — see devices.json — so the inspector
// must do it here. A path with no ":" is the single-argument --device form
// (host path only, container path defaults to the same path).
func splitLibpodDevicePath(raw string) (hostPath string, ok bool) {
	if idx := strings.IndexByte(raw, ':'); idx >= 0 {
		return raw[:idx], true
	}
	return raw, raw != ""
}

const maxLibpodNetworkBodyBytes = 1 << 20 // 1 MiB

// libpodNetworkCreateRequest mirrors Podman's libnetwork/types.Network
// (go.podman.io/common's libnetwork/types package, pinned via Podman
// v5.8.1's go.sum — confirmed directly against upstream source per the
// design doc's C4 requirement). Its shape has almost nothing in common with
// Docker's networkCreateRequest: lowercase snake_case json tags, no nested
// IPAM object (subnets/options are top-level fields), and no
// Attachable/Ingress/ConfigOnly/ConfigFrom/Scope/EnableIPv4 concept at
// all — libpod networks predate and are independent of Docker's swarm mode.
// Subnets is decoded as raw messages only to detect presence (custom static
// IPAM config); its element shape is irrelevant to the gates below and
// deliberately not modeled. Kept as its own decode struct — never made
// "smart" for both shapes — per the design doc's C6/agreed-core guidance.
//
// Fields on the reused NetworkRequestBodyConfig with no libpod analog
// (allow_swarm_scope, allow_ingress, allow_attachable, allow_config_only,
// allow_config_from, allow_custom_ipam_drivers, allow_endpoint_config,
// endpoint_config (#186's granular per-field gates), allow_disconnect_force,
// allow_disable_ipv4) are simply never consulted here — see
// configuration.mdx's libpod_network section for the documented list,
// rather than silently reinterpreting them against unrelated fields. There
// is no libpod-native network-connect endpoint at all (Podman's compat API
// connect goes through the Docker-compat path, not libpod's own), so
// endpoint_config has nothing to gate here regardless.
type libpodNetworkCreateRequest struct {
	Driver      string            `json:"driver"`
	Options     map[string]string `json:"options"`
	IPAMOptions map[string]string `json:"ipam_options"`
	Subnets     []json.RawMessage `json:"subnets"`
}

// inspectLibpodCreate is networkPolicy's libpod-path counterpart to
// inspectCreate: config reused verbatim under the libpod_network key
// (#148), narrowed to the gates that have a libpod analog (see
// libpodNetworkCreateRequest's doc comment).
func (p networkPolicy) inspectLibpodCreate(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"networks/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxLibpodNetworkBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod network create denied: request body exceeds %d byte limit", maxLibpodNetworkBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req libpodNetworkCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod network create request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod network create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !isBuiltinNetworkDriver(driver) && !p.allowCustomDrivers {
		return fmt.Sprintf("libpod network create denied: driver %q is not allowed", driver), nil
	}
	if !p.allowDriverOptions && len(req.Options) > 0 {
		return "libpod network create denied: driver options are not allowed", nil
	}
	if !p.allowCustomIPAMConfig && len(req.Subnets) > 0 {
		return "libpod network create denied: custom subnet configuration is not allowed", nil
	}
	if !p.allowIPAMOptions && len(req.IPAMOptions) > 0 {
		return "libpod network create denied: IPAM options are not allowed", nil
	}

	return "", nil
}

// libpodPathPrefix is the literal namespace prefix for Podman's native
// libpod API, distinct from the Docker-compatibility surface sockguard
// already filters (see stripVersionPrefix's doc comment for the version-
// prefix handling that makes /v5.0.0/libpod/... normalize the same as
// /libpod/...). Every matcher in this file is exact-prefix-guarded on this
// constant so a crafted Docker-shaped path (e.g. "/containers/create") can
// never satisfy a libpod predicate, and vice versa — see
// TestLibpodMatchersNeverMatchDockerPathsAndViceVersa.
const libpodPathPrefix = "/libpod/"

// isLibpodPath reports whether normalizedPath falls under Podman's native
// libpod API namespace. normalizedPath must already have gone through
// NormalizePath (version prefix stripped, path cleaned) — this function does
// no cleaning of its own, so callers must never pass a raw request path
// straight from the wire (a literal "/libpod/../containers/create" would
// otherwise falsely match; NormalizePath collapses it to "/containers/create"
// before any matcher in this file ever sees it).
func isLibpodPath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, libpodPathPrefix)
}

// isLibpodContainerCreatePath matches POST /libpod/containers/create, the
// libpod equivalent of Docker's POST /containers/create.
func isLibpodContainerCreatePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"containers/create"
}

// isLibpodPodCreatePath matches POST /libpod/pods/create. Pods are a
// libpod-native concept with no Docker-compat equivalent.
func isLibpodPodCreatePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"pods/create"
}

// isLibpodExecCreatePath matches POST /libpod/containers/{id}/exec, the
// libpod equivalent of isExecCreatePath's /containers/{id}/exec.
func isLibpodExecCreatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, libpodPathPrefix+"containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, libpodPathPrefix+"containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "exec"
}

// isLibpodExecStartPath matches POST /libpod/exec/{id}/start, the libpod
// equivalent of isExecStartPath's /exec/{id}/start.
func isLibpodExecStartPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, libpodPathPrefix+"exec/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, libpodPathPrefix+"exec/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "start"
}

// isLibpodContainerAttachPath matches POST /libpod/containers/{id}/attach,
// the libpod equivalent of the Docker hijack endpoint
// /containers/{id}/attach (see isContainerAttachPath).
func isLibpodContainerAttachPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, libpodPathPrefix+"containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, libpodPathPrefix+"containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "attach"
}

// isLibpodPlayKubePath matches POST /libpod/play/kube. It has no Docker
// analog: a single request can create an arbitrary number of privileged
// containers from a Kubernetes-shaped manifest. Full body modeling is
// deferred (see the design doc's play/kube posture); PR2+ routes any allow
// rule for this path through the blind-write acknowledgement gate rather
// than modeling its body.
func isLibpodPlayKubePath(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"play/kube"
}

// isContainerAttachPath matches POST /containers/{id}/attach, the Docker
// counterpart of isLibpodContainerAttachPath. Unlike exec create/start,
// container-attach previously had no reusable filter-side predicate — the
// hijack layer (internal/proxy) matched it with inline logic instead. This
// gives that inline logic a named, testable counterpart on this side of the
// package split, and lets TestLibpodMatchersNeverMatchDockerPathsAndViceVersa
// assert the libpod/Docker attach matchers stay mutually exclusive.
func isContainerAttachPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, "/containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "attach"
}

const maxLibpodPodCreateBodyBytes = 1 << 20 // 1 MiB

// LibpodPodCreateOptions configures request-body policy checks for
// POST /libpod/pods/create — Podman's native pod-create endpoint. Pods have
// no Docker-compat equivalent, so this is its own inspector rather than an
// extension of container_create. See #148 and the design doc's C6 note on
// what is deliberately NOT covered here yet.
type LibpodPodCreateOptions struct {
	// AllowHostNetwork permits a pod-level NetNS of {"nsmode":"host"} — the
	// pod (and every container that joins it) shares the host network
	// namespace. Mirrors container_create.AllowHostNetwork's posture for the
	// pod-wide equivalent. Default false.
	AllowHostNetwork bool
	// AllowSharedPIDNamespace permits "pid" in the pod's SharedNamespaces
	// list, letting every container in the pod see (and signal) every other
	// container's processes — the pod-wide analog of container_create's
	// PidMode: host, scoped to the pod rather than the host. Default false.
	AllowSharedPIDNamespace bool
	// AllowedInfraImageRegistries allowlists the registry the pod's
	// infra_image reference resolves to, reusing the same host-allowlist
	// shape as ImagePullOptions.AllowedRegistries (see normalizeRegistryHost
	// / parseImageReference in image_pull.go). An empty infra_image
	// (Podman's built-in default pause image) is always allowed regardless
	// of this list. Default empty: any explicit infra_image is denied.
	AllowedInfraImageRegistries []string
}

type libpodPodCreatePolicy struct {
	allowHostNetwork            bool
	allowSharedPIDNamespace     bool
	allowedInfraImageRegistries []string
}

// libpodPodCreateRequest decodes the subset of Podman's PodSpecGenerator
// (pkg/specgen/podspecgen.go, v5.8.1) this inspector gates. PodSpecGenerator
// embeds PodBasicConfig/PodNetworkConfig/etc. as anonymous Go struct fields,
// which encoding/json flattens to the top level on the wire — so "netns",
// "shared_namespaces", and "infra_image" all appear directly in the request
// body, not nested under a sub-object.
type libpodPodCreateRequest struct {
	NetNS            libpodNamespace `json:"netns"`
	SharedNamespaces []string        `json:"shared_namespaces"`
	InfraImage       string          `json:"infra_image"`
}

func newLibpodPodCreatePolicy(opts LibpodPodCreateOptions) libpodPodCreatePolicy {
	allowed := make([]string, 0, len(opts.AllowedInfraImageRegistries))
	for _, registry := range opts.AllowedInfraImageRegistries {
		normalized, ok := normalizeRegistryHost(registry)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return libpodPodCreatePolicy{
		allowHostNetwork:            opts.AllowHostNetwork,
		allowSharedPIDNamespace:     opts.AllowSharedPIDNamespace,
		allowedInfraImageRegistries: allowed,
	}
}

func (p libpodPodCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isLibpodPodCreatePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxLibpodPodCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod pod create denied: request body exceeds %d byte limit", maxLibpodPodCreateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req libpodPodCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod pod create request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod pod create denied: request body could not be inspected", nil
	}

	if !p.allowHostNetwork && isHostNamespaceMode(req.NetNS.NSMode) {
		return "libpod pod create denied: host network namespace is not allowed", nil
	}
	if !p.allowSharedPIDNamespace && slices.ContainsFunc(req.SharedNamespaces, isSharedPIDNamespaceEntry) {
		return "libpod pod create denied: shared PID namespace is not allowed", nil
	}
	if denyReason := p.denyInfraImageReason(req.InfraImage); denyReason != "" {
		return denyReason, nil
	}

	return "", nil
}

func (p libpodPodCreatePolicy) denyInfraImageReason(infraImage string) string {
	ref := strings.TrimSpace(infraImage)
	if ref == "" {
		return ""
	}
	parsed, ok := parseImageReference(ref)
	if !ok {
		return ""
	}
	if slices.Contains(p.allowedInfraImageRegistries, parsed.registry) {
		return ""
	}
	return fmt.Sprintf("libpod pod create denied: infra image registry %q is not allowlisted", parsed.registry)
}

func isSharedPIDNamespaceEntry(ns string) bool {
	return strings.EqualFold(strings.TrimSpace(ns), "pid")
}

// libpodSecretPolicy backs POST /libpod/secrets/create. Unlike Docker's
// /secrets/create (driver/template driver read from a JSON body,
// driver_create.go), libpod's secret-create driver/driveropts/labels are URL
// QUERY parameters (pkg/bindings/secrets.CreateOptions.ToParams, pinned to
// Podman v5.8.1 — confirmed directly against upstream source per the design
// doc's C4 requirement); the request BODY is the raw secret payload bytes
// handed straight to the secret driver, not a JSON envelope. This inspector
// therefore never reads r.Body: doing so would needlessly buffer arbitrary
// (and possibly large/binary) secret material into memory for a field that
// was never there to inspect. There is no libpod analog of Docker's
// Templating/TemplateDriver secret field — Podman secrets have no template
// driver concept — so SecretOptions.AllowTemplateDrivers is a no-op here,
// documented in configuration.mdx's libpod_secret section.
type libpodSecretPolicy struct {
	allowCustomDrivers bool
}

func newLibpodSecretPolicy(opts SecretOptions) libpodSecretPolicy {
	return libpodSecretPolicy{allowCustomDrivers: opts.AllowCustomDrivers}
}

func (p libpodSecretPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"secrets/create" {
		return "", nil
	}

	if driver := strings.TrimSpace(r.URL.Query().Get("driver")); driver != "" && !p.allowCustomDrivers {
		return fmt.Sprintf("libpod secret create denied: driver %q is not allowed", driver), nil
	}

	return "", nil
}

const maxLibpodVolumeBodyBytes = 1 << 20 // 1 MiB

// libpodVolumeCreateRequest mirrors Podman's entities.VolumeCreateOptions
// (pkg/domain/entities/types/volumes.go, pinned to Podman v5.8.1 — confirmed
// directly against upstream source per the design doc's C4 requirement).
// Unlike Docker's volumeCreateRequest, libpod's type carries no json tags at
// all: encoding/json falls back to the exported Go field name, so "Driver"
// and "Options" (not Docker's "DriverOpts"/"Opts") are the wire keys. Kept
// as its own decode struct — never made "smart" for both shapes — per the
// design doc's C6/agreed-core guidance.
type libpodVolumeCreateRequest struct {
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
}

// inspectLibpod is volumePolicy's libpod-path counterpart to inspect: same
// allow_custom_drivers/allow_driver_opts gates (config reused verbatim under
// the libpod_volume key, #148), different route match and decode shape.
func (p volumePolicy) inspectLibpod(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"volumes/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxLibpodVolumeBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod volume create denied: request body exceeds %d byte limit", maxLibpodVolumeBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req libpodVolumeCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod volume create request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod volume create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !strings.EqualFold(driver, "local") && !p.allowCustomDrivers {
		return fmt.Sprintf("libpod volume create denied: driver %q is not allowed", driver), nil
	}
	if !p.allowDriverOpts && len(req.Options) > 0 {
		return "libpod volume create denied: driver options are not allowed", nil
	}

	return "", nil
}

// bodyReadTimeout is the per-request deadline applied when reading the
// request body for inspection. It guards non-streaming paths against
// slowloris-style body-stall attacks. Streaming/hijack paths are handled
// by the proxy.HijackHandler layer and are unaffected.
//
// var rather than const so the slowloris regression suite can dial it down
// to a few hundred ms without sleeping 30s of wall clock. The
// TestBodyReadTimeoutIs30Seconds mutation-kill test pins the default; any
// override must be scoped via t.Cleanup.
var bodyReadTimeout = 30 * time.Second

// DenialResponse is the JSON body returned when a request is denied.
type DenialResponse struct {
	Message string `json:"message"`
	Method  string `json:"method,omitempty"`
	Path    string `json:"path,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// DenyResponseVerbosity controls how much detail filter denial responses include.
type DenyResponseVerbosity string

const (
	// DenyResponseVerbosityVerbose includes request details in the denial response body.
	DenyResponseVerbosityVerbose DenyResponseVerbosity = "verbose"
	// DenyResponseVerbosityMinimal returns only a generic denial message.
	DenyResponseVerbosityMinimal DenyResponseVerbosity = "minimal"
)

const (
	reasonCodeMatchedAllowRule              = "matched_allow_rule"
	reasonCodeMatchedDenyRule               = "matched_deny_rule"
	reasonCodeNoMatchingAllowRule           = "no_matching_allow_rule"
	reasonCodeClientPolicyProfileUnresolved = "client_policy_profile_unresolved"
	reasonCodeRequestBodyPolicyDenied       = "request_body_policy_denied"
	reasonCodeRequestBodyTooLarge           = "request_body_too_large"
	reasonCodeRequestBodyInspectionFailed   = "request_body_inspection_failed"
)

// PolicyConfig configures deny-response behavior plus request-body inspection
// policies shared by the default middleware policy and named client profiles.
type PolicyConfig struct {
	// DenyResponseVerbosity controls how much detail denied requests include in
	// the JSON response body.
	DenyResponseVerbosity DenyResponseVerbosity
	// ContainerCreate configures request-body policy checks for
	// POST /containers/create.
	ContainerCreate ContainerCreateOptions
	// LibpodContainerCreate configures request-body policy checks for
	// POST /libpod/containers/create (Podman's native SpecGenerator create
	// endpoint, distinct from the Docker-compat ContainerCreate above).
	LibpodContainerCreate LibpodContainerCreateOptions
	// Exec configures request-body policy checks for exec create/start.
	Exec ExecOptions
	// ImagePull configures request/query inspection for POST /images/create.
	ImagePull ImagePullOptions
	// Build configures request-body/query inspection for POST /build.
	Build BuildOptions
	// ContainerUpdate configures request-body inspection for
	// POST /containers/*/update.
	ContainerUpdate ContainerUpdateOptions
	// ContainerArchive configures request-body inspection for
	// PUT /containers/*/archive.
	ContainerArchive ContainerArchiveOptions
	// ImageLoad configures request-body inspection for POST /images/load.
	ImageLoad ImageLoadOptions
	// Volume configures request-body inspection for POST /volumes/create.
	Volume VolumeOptions
	// Network configures request-body inspection for network writes.
	Network NetworkOptions
	// Secret configures request-body inspection for POST /secrets/create.
	Secret SecretOptions
	// Config configures request-body inspection for POST /configs/create.
	Config ConfigOptions
	// Service configures request-body inspection for service create/update.
	Service ServiceOptions
	// Swarm configures request-body inspection for swarm writes.
	Swarm SwarmOptions
	// Node configures request-body inspection for node update.
	Node NodeOptions
	// Plugin configures request-body inspection for plugin write endpoints.
	Plugin PluginOptions
	// LibpodPodCreate configures request-body inspection for
	// POST /libpod/pods/create. #148.
	LibpodPodCreate LibpodPodCreateOptions
	// LibpodVolume configures request-body inspection for
	// POST /libpod/volumes/create. #148.
	LibpodVolume VolumeOptions
	// LibpodNetwork configures request-body inspection for
	// POST /libpod/networks/create. #148.
	LibpodNetwork NetworkOptions
	// LibpodSecret configures request-body inspection for
	// POST /libpod/secrets/create. #148.
	LibpodSecret SecretOptions
	// Buildkit carries #185 phase 1's single deny-only signal for the
	// opaque BuildKit tunnel endpoints (POST /session, POST /grpc) — see
	// buildkitPolicy.inspect's doc comment in buildkit.go for why this
	// exists and why it is deliberately not the richer buildkitproxy.Policy
	// translation.
	Buildkit BuildkitOptions
}

// Options configures filter middleware behavior.
type Options struct {
	PolicyConfig
	// Profiles defines named per-client policy overrides selected at request time.
	Profiles map[string]Policy
	// ResolveProfile returns the named policy to apply for the request.
	ResolveProfile func(*http.Request) (string, bool)
	// Mutation configures declarative admission-mutation rules. Global —
	// applied identically regardless of which client profile is active —
	// because mutation config is not part of PolicyConfig/per-profile
	// overrides (v1 has a single mutation authority).
	Mutation MutationOptions
}

// Policy defines a named request policy profile that can override the global
// rules and request-body inspection options for a single request.
type Policy struct {
	Rules []*CompiledRule
	PolicyConfig
}

// ParseDenyResponseVerbosity normalizes a configured deny verbosity value.
// Empty or unknown values default to DenyResponseVerbosityMinimal so the proxy
// never leaks the raw request path on an unknown or missing config — verbose
// is an explicit opt-in for rule authoring and dev work only.
func ParseDenyResponseVerbosity(value string) DenyResponseVerbosity {
	switch DenyResponseVerbosity(value) {
	case DenyResponseVerbosityMinimal:
		return DenyResponseVerbosityMinimal
	case DenyResponseVerbosityVerbose:
		return DenyResponseVerbosityVerbose
	default:
		return DenyResponseVerbosityMinimal
	}
}

func (c PolicyConfig) normalized() PolicyConfig {
	c.DenyResponseVerbosity = ParseDenyResponseVerbosity(string(c.DenyResponseVerbosity))
	return c
}

func (o Options) normalized() Options {
	o.PolicyConfig = o.PolicyConfig.normalized()
	return o
}

type runtimePolicy struct {
	rules                   []*CompiledRule
	denyResponseVerbosity   DenyResponseVerbosity
	inspectPoliciesByMethod map[string][]requestInspectPolicy
}

type inspectSeverity int

const (
	inspectSeverityMedium inspectSeverity = iota
	inspectSeverityHigh
	inspectSeverityCritical
)

// Compile-time assertion: the bucket walk in inspectAllowedRequest descends
// from len(buckets)-1 to 0, so index order must match ascending severity.
// If the iota block is reordered (e.g. a new severityLow inserted before
// Medium), this assignment fails to compile because the array size becomes 0.
var _ [1]struct{} = [inspectSeverityCritical - inspectSeverityHigh]struct{}{}
var _ [1]struct{} = [inspectSeverityHigh - inspectSeverityMedium]struct{}{}

// inspectorFunc is the common signature for request-body / query inspectors
// dispatched by the filter middleware. Inspectors that don't log anything
// receive the logger but ignore it; that keeps the bucket walk in
// inspectAllowedRequest monomorphic instead of paying for a per-policy bridge.
type inspectorFunc func(*slog.Logger, *http.Request, string) (string, error)

func logRequestError(logger *slog.Logger, r *http.Request, level slog.Level, message string, err error) {
	if logger == nil || r == nil {
		return
	}
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}
	logger.Log(r.Context(), level, logging.SafeString(message),
		"error", logging.SafeString(errorText),
		"method", logging.SafeString(r.Method),
		"path", logging.SafeString(r.URL.Path),
	)
}

type requestInspectPolicy struct {
	method            string
	matches           func(string) bool
	severity          inspectSeverity
	inspect           inspectorFunc
	errorLogMessage   string
	denyReasonOnError string
}

// MiddlewareWithOptions returns HTTP middleware that evaluates each request
// against compiled rules and allows deny response detail to be configured.
func MiddlewareWithOptions(rules []*CompiledRule, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	opts = opts.normalized()

	mutationEng := newMutationEngine(opts.Mutation)
	defaultPolicy := compileRuntimePolicy(rules, opts.PolicyConfig, mutationEng)
	profilePolicies := make(map[string]runtimePolicy, len(opts.Profiles))
	for name, profile := range opts.Profiles {
		profilePolicies[name] = compileRuntimePolicy(profile.Rules, profile.PolicyConfig, mutationEng)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			meta := logging.MetaForRequest(w, r)

			if meta != nil {
				r = r.WithContext(logging.WithMeta(r.Context(), meta))
			}

			activePolicy, ok := resolveActivePolicy(opts, profilePolicies, defaultPolicy, w, r, meta, logger)
			if !ok {
				return
			}

			normPath := resolveNormalizedPath(meta, r)
			action, ruleIndex, reason := evaluateNormalized(activePolicy.rules, r.Method, normPath)
			denyStatus := http.StatusForbidden
			reasonCode := ruleDecisionReasonCode(action, reason)
			stampDecisionOnMeta(meta, action, ruleIndex, reasonCode, reason, normPath)

			if action == ActionAllow {
				denyReason, denyReasonCode, status := runAllowedInspection(activePolicy, logger, w, r, normPath)
				if denyReason != "" {
					action = ActionDeny
					reasonCode = denyReasonCode
					reason = denyReason
					if status != 0 {
						denyStatus = status
					}
					if meta != nil {
						meta.Decision = string(action)
						meta.ReasonCode = reasonCode
						meta.Reason = reason
					}
				}
			}

			if action == ActionDeny {
				if meta.AllowsPassThrough() {
					meta.Decision = logging.DecisionWouldDeny
					next.ServeHTTP(w, r)
					return
				}
				if err := httpjson.Write(w, denyStatus, denyResponse(r, reason, activePolicy.denyResponseVerbosity)); err != nil {
					logRequestError(logger, r, slog.LevelError, "failed to encode denial response", err)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// resolveActivePolicy picks the per-request runtimePolicy based on the
// optional profile resolver. Returns ok=false after writing the denial
// response when a profile was named but is not registered.
func resolveActivePolicy(opts Options, profilePolicies map[string]runtimePolicy, defaultPolicy runtimePolicy, w http.ResponseWriter, r *http.Request, meta *logging.RequestMeta, logger *slog.Logger) (runtimePolicy, bool) {
	if opts.ResolveProfile == nil {
		return defaultPolicy, true
	}
	profileName, ok := opts.ResolveProfile(r)
	if !ok {
		return defaultPolicy, true
	}
	if meta != nil && profileName != "" {
		meta.Profile = profileName
	}
	profile, found := profilePolicies[profileName]
	if !found {
		denyWithReasonCode(w, r, logger, reasonCodeClientPolicyProfileUnresolved, "client policy profile could not be resolved", defaultPolicy.denyResponseVerbosity)
		return runtimePolicy{}, false
	}
	return profile, true
}

// resolveNormalizedPath returns the cached normalized path when access logging
// already produced it; otherwise it normalizes once and lets the meta carry
// the value forward to downstream layers.
func resolveNormalizedPath(meta *logging.RequestMeta, r *http.Request) string {
	if meta != nil && meta.NormPath != "" {
		return meta.NormPath
	}
	return NormalizePath(r.URL.Path)
}

func stampDecisionOnMeta(meta *logging.RequestMeta, action Action, ruleIndex int, reasonCode, reason, normPath string) {
	if meta == nil {
		return
	}
	meta.Decision = string(action)
	meta.Rule = ruleIndex
	meta.ReasonCode = reasonCode
	meta.Reason = reason
	meta.NormPath = normPath
}

// runAllowedInspection runs the request-body inspectors under a slowloris read
// deadline. The deadline is applied only for inspection so a slow-but-honest
// streaming client isn't killed once we hand off to the upstream.
//
// ErrNotSupported on httptest / custom transports is benign; anything else
// surfaces at the usual severity — DEBUG for the set (guard simply doesn't
// apply), ERROR for the clear (a lingering deadline on a proxied connection
// can kill a streaming response mid-body).
func runAllowedInspection(activePolicy runtimePolicy, logger *slog.Logger, w http.ResponseWriter, r *http.Request, normPath string) (string, string, int) {
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(bodyReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		logger.Debug("filter: slowloris read deadline not applied", "error", err)
	}
	denyReason, denyReasonCode, status := activePolicy.inspectAllowedRequest(logger, r, normPath)
	if err := rc.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		logger.Error("filter: failed to clear slowloris read deadline", "error", err)
	}
	return denyReason, denyReasonCode, status
}

func compileRuntimePolicy(rules []*CompiledRule, cfg PolicyConfig, mutationEng *mutationEngine) runtimePolicy {
	cfg = cfg.normalized()
	all := []requestInspectPolicy{

		{http.MethodPost, matchesContainerCreateInspection, inspectSeverityCritical, newContainerCreateMutationPolicy(mutationEng).inspect, "failed to apply container create admission mutations", "unable to apply container create admission mutations"},
		{http.MethodPost, matchesContainerCreateInspection, inspectSeverityCritical, newContainerCreatePolicy(cfg.ContainerCreate).inspect, "failed to inspect container create request body", "unable to inspect container create request body"},

		{http.MethodPost, matchesLibpodContainerCreateInspection, inspectSeverityCritical, newLibpodContainerCreatePolicy(cfg.LibpodContainerCreate).inspect, "failed to inspect libpod container create request body", "unable to inspect libpod container create request body"},
		{http.MethodPost, matchesExecInspection, inspectSeverityHigh, newExecPolicy(cfg.Exec).inspect, "failed to inspect exec request body", "unable to inspect exec request body"},
		{http.MethodPost, matchesImagePullInspection, inspectSeverityHigh, newImagePullPolicy(cfg.ImagePull).inspect, "failed to inspect image pull request", "unable to inspect image pull request"},
		{http.MethodPost, matchesBuildInspection, inspectSeverityCritical, newBuildPolicy(cfg.Build).inspect, "failed to inspect build request", "unable to inspect build request"},
		{http.MethodPost, matchesContainerUpdateInspection, inspectSeverityHigh, newContainerUpdatePolicy(cfg.ContainerUpdate).inspect, "failed to inspect container update request body", "unable to inspect container update request body"},
		{http.MethodPut, matchesContainerArchiveInspection, inspectSeverityHigh, newContainerArchivePolicy(cfg.ContainerArchive).inspect, "failed to inspect container archive request body", "unable to inspect container archive request body"},
		{http.MethodPost, matchesImageLoadInspection, inspectSeverityHigh, newImageLoadPolicy(cfg.ImageLoad).inspect, "failed to inspect image load request body", "unable to inspect image load request body"},
		{http.MethodPost, matchesVolumeInspection, inspectSeverityMedium, newVolumePolicy(cfg.Volume).inspect, "failed to inspect volume create request body", "unable to inspect volume create request body"},
		{http.MethodPost, matchesNetworkInspection, inspectSeverityHigh, newNetworkPolicy(cfg.Network).inspect, "failed to inspect network request body", "unable to inspect network request body"},
		{http.MethodPost, matchesSecretInspection, inspectSeverityMedium, newSecretPolicy(cfg.Secret).inspect, "failed to inspect secret create request body", "unable to inspect secret create request body"},
		{http.MethodPost, matchesConfigInspection, inspectSeverityMedium, newConfigPolicy(cfg.Config).inspect, "failed to inspect config create request body", "unable to inspect config create request body"},
		{http.MethodPost, matchesServiceInspection, inspectSeverityCritical, newServiceMutationPolicy(mutationEng).inspect, "failed to apply service admission mutations", "unable to apply service admission mutations"},
		{http.MethodPost, matchesServiceInspection, inspectSeverityCritical, newServicePolicy(cfg.Service).inspect, "failed to inspect service request body", "unable to inspect service request body"},
		{http.MethodPost, matchesSwarmInspection, inspectSeverityCritical, newSwarmPolicy(cfg.Swarm).inspect, "failed to inspect swarm request body", "unable to inspect swarm request body"},
		{http.MethodPost, matchesNodeInspection, inspectSeverityHigh, newNodePolicy(cfg.Node).inspect, "failed to inspect node update request body", "unable to inspect node update request body"},
		{http.MethodPost, matchesPluginInspection, inspectSeverityCritical, newPluginPolicy(cfg.Plugin).inspect, "failed to inspect plugin request body", "unable to inspect plugin request body"},

		{http.MethodPost, matchesLibpodPodCreateInspection, inspectSeverityCritical, newLibpodPodCreatePolicy(cfg.LibpodPodCreate).inspect, "failed to inspect libpod pod create request body", "unable to inspect libpod pod create request body"},
		{http.MethodPost, matchesLibpodVolumeInspection, inspectSeverityMedium, newVolumePolicy(cfg.LibpodVolume).inspectLibpod, "failed to inspect libpod volume create request body", "unable to inspect libpod volume create request body"},
		{http.MethodPost, matchesLibpodNetworkInspection, inspectSeverityHigh, newNetworkPolicy(cfg.LibpodNetwork).inspectLibpodCreate, "failed to inspect libpod network create request body", "unable to inspect libpod network create request body"},
		{http.MethodPost, matchesLibpodSecretInspection, inspectSeverityMedium, newLibpodSecretPolicy(cfg.LibpodSecret).inspect, "failed to inspect libpod secret create request", "unable to inspect libpod secret create request"},

		{http.MethodPost, matchesBuildkitTunnelInspection, inspectSeverityCritical, newBuildkitPolicy(cfg.Buildkit).inspect, "failed to inspect buildkit tunnel request", "unable to inspect buildkit tunnel request"},
	}
	byMethod := groupInspectPoliciesByMethod(all)
	return runtimePolicy{
		rules:                   rules,
		denyResponseVerbosity:   cfg.DenyResponseVerbosity,
		inspectPoliciesByMethod: byMethod,
	}
}

func matchesContainerCreateInspection(normalizedPath string) bool {
	return normalizedPath == "/containers/create"
}

func matchesLibpodContainerCreateInspection(normalizedPath string) bool {
	return isLibpodContainerCreatePath(normalizedPath)
}

func matchesExecInspection(normalizedPath string) bool {

	return isExecCreatePath(normalizedPath) || isExecStartPath(normalizedPath) ||
		isLibpodExecCreatePath(normalizedPath) || isLibpodExecStartPath(normalizedPath)
}

func matchesImagePullInspection(normalizedPath string) bool {
	return normalizedPath == "/images/create"
}

func matchesBuildInspection(normalizedPath string) bool {
	return normalizedPath == "/build"
}

func matchesContainerUpdateInspection(normalizedPath string) bool {
	return isContainerUpdatePath(normalizedPath)
}

func matchesContainerArchiveInspection(normalizedPath string) bool {
	return isContainerArchivePath(normalizedPath)
}

func matchesImageLoadInspection(normalizedPath string) bool {
	return normalizedPath == "/images/load"
}

func matchesVolumeInspection(normalizedPath string) bool {
	return normalizedPath == "/volumes/create"
}

func matchesNetworkInspection(normalizedPath string) bool {
	return isNetworkWritePath(normalizedPath)
}

func matchesSecretInspection(normalizedPath string) bool {
	return normalizedPath == "/secrets/create"
}

func matchesConfigInspection(normalizedPath string) bool {
	return normalizedPath == "/configs/create"
}

func matchesServiceInspection(normalizedPath string) bool {
	return isServiceWritePath(normalizedPath)
}

func matchesSwarmInspection(normalizedPath string) bool {
	switch normalizedPath {
	case "/swarm/init", "/swarm/join", "/swarm/update", "/swarm/unlock":
		return true
	default:
		return false
	}
}

func matchesNodeInspection(normalizedPath string) bool {
	return isNodeUpdatePath(normalizedPath)
}

func matchesPluginInspection(normalizedPath string) bool {
	return normalizedPath == "/plugins/pull" || normalizedPath == "/plugins/create" || isPluginUpgradePath(normalizedPath) || isPluginSetPath(normalizedPath)
}

func matchesLibpodPodCreateInspection(normalizedPath string) bool {
	return isLibpodPodCreatePath(normalizedPath)
}

func matchesLibpodVolumeInspection(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"volumes/create"
}

func matchesLibpodNetworkInspection(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"networks/create"
}

func matchesLibpodSecretInspection(normalizedPath string) bool {
	return normalizedPath == libpodPathPrefix+"secrets/create"
}

// inspectBucketCapacity bounds how many policies of a single severity may
// match the same method in inspectAllowedRequest. Sized to comfortably hold
// the current static policy list with headroom; if a future contributor adds
// inspectors past this cap, compileRuntimePolicy panics at startup so the
// overflow is loud rather than silent.
const inspectBucketCapacity = 16

// groupInspectPoliciesByMethod buckets the static policy list by HTTP method
// and panics if any (method, severity) group would overflow inspectBuckets at
// request time. The bucket walk in inspectAllowedRequest silently drops
// overflow entries, which would disable enforcement for the dropped
// inspectors — a future contributor adding a 17th POST/critical policy must
// bump inspectBucketCapacity rather than let that happen quietly.
//
// Extracted from compileRuntimePolicy so the per-(method, severity) counting
// + overflow check are testable in isolation; calling compileRuntimePolicy
// directly only exercises the hardcoded 15-inspector list, which never
// stresses the >cap branch.
func groupInspectPoliciesByMethod(all []requestInspectPolicy) map[string][]requestInspectPolicy {
	byMethod := make(map[string][]requestInspectPolicy, 2)
	for _, p := range all {
		byMethod[p.method] = append(byMethod[p.method], p)
	}
	for method, ps := range byMethod {
		var sevCounts [3]int
		for _, p := range ps {
			sevCounts[int(p.severity)]++
		}
		for sev, n := range sevCounts {
			if n > inspectBucketCapacity {
				panic(fmt.Sprintf("filter: inspectBuckets capacity %d exceeded for method %s severity %d: %d policies", inspectBucketCapacity, method, sev, n))
			}
		}
	}
	return byMethod
}

// inspectBuckets holds matched policies grouped by severity for zero-alloc
// single-pass triage in inspectAllowedRequest. The array is stack-allocated
// because [3][16] fits on the frame and the slice backing p.inspectPolicies
// caps out at ~15 entries.
type inspectBuckets [3][inspectBucketCapacity]*requestInspectPolicy

func (p runtimePolicy) inspectAllowedRequest(logger *slog.Logger, r *http.Request, normalizedPath string) (string, string, int) {
	var buckets inspectBuckets
	var counts [3]int

	for i := range p.inspectPoliciesByMethod[r.Method] {
		policy := &p.inspectPoliciesByMethod[r.Method][i]
		if policy.matches != nil && !policy.matches(normalizedPath) {
			continue
		}
		sev := int(policy.severity)
		if counts[sev] < len(buckets[sev]) {
			buckets[sev][counts[sev]] = policy
			counts[sev]++
		}
	}

	for sev := len(buckets) - 1; sev >= 0; sev-- {
		if counts[sev] == 0 {
			continue
		}
		for _, policy := range buckets[sev][:counts[sev]] {
			denyReason, err := policy.inspect(logger, r, normalizedPath)
			if err != nil {
				if rejection, ok := requestRejectionFromError(err); ok {
					code := rejection.reasonCode
					if code == "" {
						code = requestRejectionReasonCode(rejection.status)
					}
					return rejection.reason, code, rejection.status
				}
				logRequestError(logger, r, slog.LevelError, policy.errorLogMessage, err)
				return policy.denyReasonOnError, reasonCodeRequestBodyInspectionFailed, http.StatusForbidden
			}
			if denyReason != "" {
				return denyReason, reasonCodeRequestBodyPolicyDenied, http.StatusForbidden
			}
		}
		return "", "", 0
	}
	return "", "", 0
}

func denyWithReasonCode(w http.ResponseWriter, r *http.Request, logger *slog.Logger, reasonCode, reason string, verbosity DenyResponseVerbosity) {
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.Decision = string(ActionDeny)
		meta.ReasonCode = reasonCode
		meta.Reason = reason
		if meta.NormPath == "" {
			meta.NormPath = NormalizePath(r.URL.Path)
		}
	}
	if err := httpjson.Write(w, http.StatusForbidden, denyResponse(r, reason, verbosity)); err != nil {
		logRequestError(logger, r, slog.LevelError, "failed to encode denial response", err)
	}
}

func ruleDecisionReasonCode(action Action, reason string) string {
	switch action {
	case ActionAllow:
		return reasonCodeMatchedAllowRule
	case ActionDeny:
		if reason == ReasonNoMatchingAllowRule {
			return reasonCodeNoMatchingAllowRule
		}
		return reasonCodeMatchedDenyRule
	default:
		return ""
	}
}

func requestRejectionReasonCode(status int) string {
	if status == http.StatusRequestEntityTooLarge {
		return reasonCodeRequestBodyTooLarge
	}
	return reasonCodeRequestBodyPolicyDenied
}

func denyResponse(r *http.Request, reason string, verbosity DenyResponseVerbosity) DenialResponse {
	resp := DenialResponse{
		Message: "request denied by sockguard policy",
	}
	if verbosity == DenyResponseVerbosityMinimal {
		return resp
	}

	resp.Method = r.Method
	resp.Path = redactDeniedPath(r.URL.Path)
	resp.Reason = reason
	return resp
}

func redactDeniedPath(requestPath string) string {
	if requestPath == "" {
		return ""
	}

	cleanedPath := canonicalizePath(requestPath)
	normalizedPath := stripVersionPrefix(cleanedPath)

	var versionPrefix string
	if normalizedPath != cleanedPath && strings.HasSuffix(cleanedPath, normalizedPath) {
		versionPrefix = strings.TrimSuffix(cleanedPath, normalizedPath)
	}

	switch {
	case strings.HasPrefix(normalizedPath, "/secrets/"):
		return versionPrefix + "/secrets/<redacted>"
	case normalizedPath == "/swarm/unlockkey":
		return versionPrefix + "/swarm/<redacted>"
	default:
		return requestPath
	}
}

// maxMutationBodyBytes caps the request body the mutation engine will read,
// matching every sibling per-surface cap (container-create, service).
const maxMutationBodyBytes = 1 << 20 // 1 MiB

// Mutation surface identifiers, matching the config.MutationRuleConfig
// `surfaces` enum vocabulary exactly. Duplicated here as plain strings
// (rather than imported from internal/config) because filter must not
// import config — the dependency runs the other way — matching how mode
// strings ("enforce"/"warn"/"audit") are already duplicated in a few
// packages rather than centralized.
const (
	mutationSurfaceContainerCreate = "container_create"
	mutationSurfaceServiceCreate   = "service_create"
	mutationSurfaceServiceUpdate   = "service_update"
)

// Mutation rule outcome vocabulary, matching the audit/access log schema.
const (
	mutationOutcomeApplied    = "applied"
	mutationOutcomeNoop       = "noop"
	mutationOutcomeWouldApply = "would_apply"
	mutationOutcomeWouldNoop  = "would_noop"
	mutationOutcomeFailed     = "failed"
)

// Mutation-specific reason codes (middleware.go's shared constant block also
// has the pre-existing request_body_* codes downstream inspectors continue
// to use unchanged).
const (
	reasonCodeMutationRequestInvalid      = "mutation_request_invalid"
	reasonCodeMutationRequestTooLarge     = "mutation_request_too_large"
	reasonCodeMutationApplyFailed         = "mutation_apply_failed"
	reasonCodeMutationPostconditionFailed = "mutation_postcondition_failed"
)

// MutationOptions configures declarative admission-mutation rules. It is
// global — carried on filter.Options, not filter.PolicyConfig — because
// mutation config is not part of per-client-profile overrides (v1 has a
// single mutation authority; see config.MutationsConfig's doc comment).
type MutationOptions struct {
	Rules []MutationRuleOptions
}

// MutationRuleOptions is one compiled-from-config declarative admission
// rule: exactly one of InjectLabels/RemapImage is expected to be set —
// config validation enforces this before it ever reaches the filter package.
type MutationRuleOptions struct {
	ID           string
	Mode         string // "enforce" | "warn" | "audit"; empty defaults to "enforce"
	Surfaces     []string
	InjectLabels *InjectLabelsMutationOptions
	RemapImage   *ImageRemapMutationOptions
}

// InjectLabelsMutationOptions unconditionally sets/replaces the configured
// labels on every request matching the rule's surfaces.
type InjectLabelsMutationOptions struct {
	Labels map[string]string
}

// ImageRemapMutationOptions rewrites a matched image reference.
type ImageRemapMutationOptions struct {
	Match string // "exact" | "prefix"
	From  string
	To    string
}

// mutationRuleKind discriminates the two mutation operations. Kept as an
// unexported int (rather than reusing a string) so compiledMutationRule's
// switch is exhaustive-checkable; String() renders the audit/log vocabulary.
type mutationRuleKind int

const (
	mutationRuleInjectLabels mutationRuleKind = iota
	mutationRuleRemapImage
)

func (k mutationRuleKind) String() string {
	if k == mutationRuleRemapImage {
		return "remap_image"
	}
	return "inject_labels"
}

// compiledMutationRule is one rule fanned out to one surface bucket.
type compiledMutationRule struct {
	id     string
	mode   string
	kind   mutationRuleKind
	labels map[string]string

	remapMatch string
	remapFrom  string
	remapTo    string
}

// mutationEngine is the compiled, immutable form of MutationOptions,
// bucketed by surface so each request's inspect() call does a single map
// lookup rather than re-filtering the full rule list. Compiled once per
// filter.MiddlewareWithOptions call (reload rebuilds the whole handler
// chain, including this) and shared read-only across the default policy and
// every client profile, since mutation config is global.
type mutationEngine struct {
	bySurface map[string][]compiledMutationRule
}

func newMutationEngine(opts MutationOptions) *mutationEngine {
	eng := &mutationEngine{bySurface: make(map[string][]compiledMutationRule)}
	for _, r := range opts.Rules {
		mode := strings.ToLower(strings.TrimSpace(r.Mode))
		if mode == "" {
			mode = "enforce"
		}

		var cr compiledMutationRule
		cr.id = r.ID
		cr.mode = mode
		switch {
		case r.InjectLabels != nil:
			cr.kind = mutationRuleInjectLabels
			cr.labels = r.InjectLabels.Labels
		case r.RemapImage != nil:
			cr.kind = mutationRuleRemapImage
			cr.remapMatch = strings.ToLower(strings.TrimSpace(r.RemapImage.Match))
			cr.remapFrom = r.RemapImage.From
			cr.remapTo = r.RemapImage.To
		default:

			continue
		}

		for _, surface := range r.Surfaces {
			eng.bySurface[surface] = append(eng.bySurface[surface], cr)
		}
	}
	return eng
}

func (e *mutationEngine) rulesFor(surface string) []compiledMutationRule {
	if e == nil {
		return nil
	}
	return e.bySurface[surface]
}

// mutationPolicy is the requestInspectPolicy.inspect implementation shared
// by the container-create and service mutation entries; surface resolves
// the request to a bucket key in the engine.
type mutationPolicy struct {
	engine  *mutationEngine
	surface func(normalizedPath string) string
}

func newContainerCreateMutationPolicy(engine *mutationEngine) mutationPolicy {
	return mutationPolicy{
		engine:  engine,
		surface: func(string) string { return mutationSurfaceContainerCreate },
	}
}

func newServiceMutationPolicy(engine *mutationEngine) mutationPolicy {
	return mutationPolicy{
		engine: engine,
		surface: func(normalizedPath string) string {
			if normalizedPath == "/services/create" {
				return mutationSurfaceServiceCreate
			}
			return mutationSurfaceServiceUpdate
		},
	}
}

// inspect applies every enforce-mode rule to the actual document, records
// (without applying) every warn/audit-mode rule against an independent
// cloned document, and commits the mutated body only if an enforce rule
// actually changed something. It never itself produces a deny reason for a
// well-formed request — the eventual allow/deny verdict is still decided by
// container_create/service's own inspect(), which runs immediately after
// this in the same severity bucket and has never heard of "mutation": it
// just re-reads whatever bytes are in r.Body.
func (p mutationPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil {
		return "", nil
	}

	surface := p.surface(normalizedPath)
	rules := p.engine.rulesFor(surface)
	if len(rules) == 0 {

		return "", nil
	}

	body, err := readBoundedBody(r, maxMutationBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionErrorWithCode(
				http.StatusRequestEntityTooLarge,
				reasonCodeMutationRequestTooLarge,
				fmt.Sprintf("%s denied: request body exceeds %d byte limit", surface, maxMutationBodyBytes),
			)
		}
		return "", fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {

		return "", nil
	}

	actual, err := parseMutationDocument(body, mutationMaxNodes(len(body)))
	if err != nil {
		logRequestError(logger, r, slog.LevelDebug, "mutation request body is not a well-formed, unambiguous JSON object; denying", nil)
		return "", newRequestRejectionErrorWithCode(
			http.StatusBadRequest,
			reasonCodeMutationRequestInvalid,
			fmt.Sprintf("%s denied: request body could not be safely parsed for admission mutation", surface),
		)
	}

	var shadow map[string]any
	for _, rule := range rules {
		if rule.mode != "enforce" {
			shadow, _ = deepCloneJSONValue(actual).(map[string]any)
			break
		}
	}

	trace := make([]logging.MutationRuleOutcome, 0, len(rules))
	changed := false
	warnEvaluated := false

	for _, rule := range rules {
		if rule.mode == "enforce" {
			outcome, applyErr := applyMutationRule(actual, surface, rule)
			if applyErr != nil {
				logRequestError(logger, r, slog.LevelDebug, "admission mutation rule failed to apply; denying", nil)
				return "", newRequestRejectionErrorWithCode(
					http.StatusBadRequest,
					reasonCodeMutationApplyFailed,
					fmt.Sprintf("%s denied: admission mutation rule %q could not be applied", surface, rule.id),
				)
			}
			if outcome == mutationOutcomeApplied {
				changed = true
			}
			trace = append(trace, logging.MutationRuleOutcome{ID: rule.id, Type: rule.kind.String(), Mode: rule.mode, Outcome: outcome})
			continue
		}

		if rule.mode == "warn" {
			warnEvaluated = true
		}
		outcome, applyErr := applyMutationRule(shadow, surface, rule)
		if applyErr != nil {
			trace = append(trace, logging.MutationRuleOutcome{ID: rule.id, Type: rule.kind.String(), Mode: rule.mode, Outcome: mutationOutcomeFailed})
			continue
		}
		dryOutcome := mutationOutcomeWouldNoop
		if outcome == mutationOutcomeApplied {
			dryOutcome = mutationOutcomeWouldApply
		}
		trace = append(trace, logging.MutationRuleOutcome{ID: rule.id, Type: rule.kind.String(), Mode: rule.mode, Outcome: dryOutcome})
	}

	if changed {
		final, merr := json.Marshal(actual)
		if merr != nil {
			return "", newRequestRejectionErrorWithCode(
				http.StatusInternalServerError,
				reasonCodeMutationPostconditionFailed,
				fmt.Sprintf("%s denied: admission mutation result could not be serialized", surface),
			)
		}

		if _, verr := parseMutationDocument(final, mutationMaxNodes(len(final))); verr != nil {
			return "", newRequestRejectionErrorWithCode(
				http.StatusInternalServerError,
				reasonCodeMutationPostconditionFailed,
				fmt.Sprintf("%s denied: admission mutation result failed postcondition verification", surface),
			)
		}
		replaceRequestBody(r, final)
	}

	recordMutationOutcome(r, trace, changed, warnEvaluated)

	return "", nil
}

// recordMutationOutcome attaches a pooled logging.MutationRecord to the
// request's logging.RequestMeta (stashed into r's context by
// MiddlewareWithOptions specifically so this — and any future inspector —
// can reach it without widening the inspectorFunc signature every existing
// inspector implements). A nil meta (e.g. in a unit test that drives
// inspect() directly without the outer middleware) is a silent no-op:
// mutation still applies/denies correctly, it just isn't recorded.
func recordMutationOutcome(r *http.Request, trace []logging.MutationRuleOutcome, changed, warnEvaluated bool) {
	if len(trace) == 0 {
		return
	}
	meta := logging.Meta(r.Context())
	if meta == nil {
		return
	}
	rec := logging.GetMutationRecord()
	rec.Rules = append(rec.Rules[:0], trace...)
	rec.ActualChanged = changed
	rec.HasWarnEvaluation = warnEvaluated
	meta.Mutation = rec
}

// applyMutationRule applies one rule to doc (either the actual document that
// will be committed, or an independent shadow clone for warn/audit modes)
// and reports whether it actually changed something.
func applyMutationRule(doc map[string]any, surface string, rule compiledMutationRule) (string, error) {
	if doc == nil {
		return mutationOutcomeNoop, nil
	}
	switch rule.kind {
	case mutationRuleInjectLabels:
		return applyInjectLabels(doc, surface, rule.labels)
	case mutationRuleRemapImage:
		return applyRemapImage(doc, surface, rule)
	default:
		return mutationOutcomeNoop, nil
	}
}

// mutationLabelTargets returns the label-map field paths a label-injection
// rule targets for surface, matching the v1 surface/action matrix exactly:
// container_create writes Config.Labels; service_create writes both
// Service.Labels and TaskTemplate.ContainerSpec.Labels (mirroring
// ownership.mutateServiceOwnershipBody, which stamps both for the identical
// reason — either alone is an incomplete label surface); service_update
// does not support label injection (config validation rejects an
// inject_labels rule naming it, so this returns nil defensively).
func mutationLabelTargets(surface string) [][]string {
	switch surface {
	case mutationSurfaceContainerCreate:
		return [][]string{{"Labels"}}
	case mutationSurfaceServiceCreate:
		return [][]string{{"Labels"}, {"TaskTemplate", "ContainerSpec", "Labels"}}
	default:
		return nil
	}
}

func applyInjectLabels(doc map[string]any, surface string, labels map[string]string) (string, error) {
	targets := mutationLabelTargets(surface)
	if len(targets) == 0 {
		return mutationOutcomeNoop, nil
	}

	changed := false
	for _, path := range targets {
		target, err := NestedObjectPath(doc, path...)
		if err != nil {
			return "", fmt.Errorf("inject_labels target %s: %w", strings.Join(path, "."), err)
		}
		for key, value := range labels {
			if existing, ok := target[key]; !ok || existing != value {
				changed = true
			}
			target[key] = value
		}
	}

	if changed {
		return mutationOutcomeApplied, nil
	}
	return mutationOutcomeNoop, nil
}

// mutationImagePath returns the image field path a remap-image rule targets
// for surface: container_create's root-level Image; service_create/
// service_update's TaskTemplate.ContainerSpec.Image.
func mutationImagePath(surface string) []string {
	switch surface {
	case mutationSurfaceContainerCreate:
		return []string{"Image"}
	case mutationSurfaceServiceCreate, mutationSurfaceServiceUpdate:
		return []string{"TaskTemplate", "ContainerSpec", "Image"}
	default:
		return nil
	}
}

func applyRemapImage(doc map[string]any, surface string, rule compiledMutationRule) (string, error) {
	path := mutationImagePath(surface)
	if len(path) == 0 {
		return mutationOutcomeNoop, nil
	}

	parent, ok := navigateFoldedObjectPath(doc, path[:len(path)-1]...)
	if !ok {

		return mutationOutcomeNoop, nil
	}

	leaf := path[len(path)-1]
	current, present, isString := foldedStringLeaf(parent, leaf)
	if !present {
		return mutationOutcomeNoop, nil
	}
	if !isString {
		return "", fmt.Errorf("remap_image target %s is not a string", strings.Join(path, "."))
	}

	trimmed := strings.TrimSpace(current)
	next, matched := mutationRemapMatch(trimmed, rule.remapMatch, rule.remapFrom, rule.remapTo)
	if !matched {
		return mutationOutcomeNoop, nil
	}
	if err := validateMutationImageReference(next); err != nil {
		return "", fmt.Errorf("remap_image result: %w", err)
	}
	if next == current {
		return mutationOutcomeNoop, nil
	}

	setFoldedStringLeaf(parent, leaf, next)
	return mutationOutcomeApplied, nil
}

// mutationRemapMatch reports the remapped value (and whether from actually
// matched current) for one image-remap rule. exact replaces the whole
// reference; prefix replaces the leading from once and preserves the rest —
// no chaining, no case folding, no implicit docker.io/library alias
// expansion (documented deviation from Docker CLI convenience behavior:
// "nginx" and "docker.io/library/nginx" are different literal strings here).
func mutationRemapMatch(current, match, from, to string) (string, bool) {
	switch match {
	case "exact":
		if current != from {
			return "", false
		}
		return to, true
	case "prefix":
		if !strings.HasPrefix(current, from) {
			return "", false
		}
		return to + strings.TrimPrefix(current, from), true
	default:
		return "", false
	}
}

// validateMutationImageReference confirms a computed remap result parses as
// a plausible Docker image reference before it can ever reach a
// downstream inspector or the daemon. It reuses go-containerregistry's weak
// reference grammar (name.WeakValidation) — the exact rules
// imagefetch.PinnedReference already applies when pinning a verified
// image-trust digest — rather than inventing a second, potentially
// divergent validator. This runs only when a remap_image rule is both
// configured and its `from` actually matched the current image, mirroring
// how the (also opt-in) image-trust verifier is only ever invoked when
// image_trust is configured: go-containerregistry stays off every request
// that hasn't opted into a feature that needs it.
func validateMutationImageReference(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("remapped image reference is empty")
	}
	if _, err := name.ParseReference(ref, name.WeakValidation); err != nil {
		return fmt.Errorf("invalid image reference %q: %w", ref, err)
	}
	return nil
}

const maxNetworkBodyBytes = 1 << 20 // 1 MiB

// EndpointConfigOptions narrows AllowEndpointConfig into independent
// per-field gates on Docker's EndpointSettings object (#186), so an operator
// can admit a benign field (e.g. Aliases) without also admitting address
// pinning. Only consulted when AllowEndpointConfig is false — see
// denyEndpointConfigReason's precedence doc comment. Fields with no gate
// here (Links, DriverOpts) have no individual escape hatch: only
// AllowEndpointConfig: true can admit them, fail-closed by design.
type EndpointConfigOptions struct {
	// AllowStaticAddressing permits every field endpointHasStaticAddressFields
	// checks: IPAMConfig.IPv4Address/IPv6Address and the deprecated top-level
	// Gateway/IPAddress/IPPrefixLen/IPv6Gateway/GlobalIPv6Address/
	// GlobalIPv6PrefixLen fields. Default false.
	AllowStaticAddressing bool
	// AllowLinkLocalIPs permits IPAMConfig.LinkLocalIPs, independent of
	// AllowStaticAddressing. Default false.
	AllowLinkLocalIPs bool
	// AllowMACPinning permits MacAddress — shared by network connect's
	// EndpointConfig and container-create's deprecated top-level MacAddress
	// field (see container_create.go's denyRootMacAddressReason). Default false.
	AllowMACPinning bool
	// AllowGwPriority permits GwPriority (Engine API 1.55+). Default false.
	AllowGwPriority bool
	// DenyAliases denies Aliases when true. Inverted polarity (unlike every
	// other field here) so a zero-value EndpointConfigOptions reproduces the
	// historical, unconditional "Aliases always allowed" behavior exactly —
	// see denyEndpointConfigReason's doc comment for why Aliases is never
	// gated by default. config.EndpointConfigRequestBodyConfig exposes this
	// to operators as allow_aliases (default true) and inverts it during
	// ToFilterOptions.
	DenyAliases bool
}

// NetworkOptions configures request-body policy checks for network write endpoints.
type NetworkOptions struct {
	AllowCustomDrivers     bool
	AllowSwarmScope        bool
	AllowIngress           bool
	AllowAttachable        bool
	AllowConfigOnly        bool
	AllowConfigFrom        bool
	AllowCustomIPAMDrivers bool
	AllowCustomIPAMConfig  bool
	AllowIPAMOptions       bool
	AllowDriverOptions     bool
	AllowEndpointConfig    bool
	// EndpointConfig narrows AllowEndpointConfig into per-field gates (#186).
	// Only consulted when AllowEndpointConfig is false.
	EndpointConfig       EndpointConfigOptions
	AllowDisconnectForce bool
	// AllowDisableIPv4 permits POST /networks/create with EnableIPv4
	// explicitly false (Engine API 1.48+). Default false.
	AllowDisableIPv4 bool
}

type networkPolicy struct {
	allowCustomDrivers     bool
	allowSwarmScope        bool
	allowIngress           bool
	allowAttachable        bool
	allowConfigOnly        bool
	allowConfigFrom        bool
	allowCustomIPAMDrivers bool
	allowCustomIPAMConfig  bool
	allowIPAMOptions       bool
	allowDriverOptions     bool
	allowEndpointConfig    bool
	endpointConfig         EndpointConfigOptions
	allowDisconnectForce   bool
	allowDisableIPv4       bool
}

type networkCreateRequest struct {
	Driver     string             `json:"Driver"`
	Scope      string             `json:"Scope"`
	Attachable bool               `json:"Attachable"`
	Ingress    bool               `json:"Ingress"`
	ConfigOnly bool               `json:"ConfigOnly"`
	ConfigFrom *networkConfigFrom `json:"ConfigFrom"`
	IPAM       *networkIPAM       `json:"IPAM"`
	Options    map[string]any     `json:"Options"`
	// EnableIPv4 (Engine API 1.48+) defaults to true when absent; an explicit
	// false disables IPv4 addressing on the network. A pointer distinguishes
	// "not set" from "explicitly false".
	EnableIPv4 *bool `json:"EnableIPv4"`
}

type networkConfigFrom struct {
	Network string `json:"Network"`
}

type networkIPAM struct {
	Driver  string         `json:"Driver"`
	Config  []any          `json:"Config"`
	Options map[string]any `json:"Options"`
}

type networkConnectRequest struct {
	EndpointConfig *networkEndpointConfig `json:"EndpointConfig"`
}

type networkEndpointConfig struct {
	IPAMConfig          *networkEndpointIPAMConfig `json:"IPAMConfig"`
	Links               []string                   `json:"Links"`
	Aliases             []string                   `json:"Aliases"`
	Gateway             string                     `json:"Gateway"`
	IPAddress           string                     `json:"IPAddress"`
	IPPrefixLen         int                        `json:"IPPrefixLen"`
	IPv6Gateway         string                     `json:"IPv6Gateway"`
	GlobalIPv6Address   string                     `json:"GlobalIPv6Address"`
	GlobalIPv6PrefixLen int                        `json:"GlobalIPv6PrefixLen"`
	MacAddress          string                     `json:"MacAddress"`
	DriverOpts          map[string]any             `json:"DriverOpts"`
	// GwPriority (Engine API 1.45+) selects which network provides the
	// container's default gateway when it is attached to more than one.
	// Gated by the same allow_endpoint_config posture as the other
	// endpoint-config fields — see denyEndpointConfigReason.
	GwPriority int `json:"GwPriority"`
}

type networkEndpointIPAMConfig struct {
	IPv4Address  string   `json:"IPv4Address"`
	IPv6Address  string   `json:"IPv6Address"`
	LinkLocalIPs []string `json:"LinkLocalIPs"`
}

type networkDisconnectRequest struct {
	Force bool `json:"Force"`
}

func newNetworkPolicy(opts NetworkOptions) networkPolicy {
	return networkPolicy{
		allowCustomDrivers:     opts.AllowCustomDrivers,
		allowSwarmScope:        opts.AllowSwarmScope,
		allowIngress:           opts.AllowIngress,
		allowAttachable:        opts.AllowAttachable,
		allowConfigOnly:        opts.AllowConfigOnly,
		allowConfigFrom:        opts.AllowConfigFrom,
		allowCustomIPAMDrivers: opts.AllowCustomIPAMDrivers,
		allowCustomIPAMConfig:  opts.AllowCustomIPAMConfig,
		allowIPAMOptions:       opts.AllowIPAMOptions,
		allowDriverOptions:     opts.AllowDriverOptions,
		allowEndpointConfig:    opts.AllowEndpointConfig,
		endpointConfig:         opts.EndpointConfig,
		allowDisconnectForce:   opts.AllowDisconnectForce,
		allowDisableIPv4:       opts.AllowDisableIPv4,
	}
}

func (p networkPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil || !isNetworkWritePath(normalizedPath) {
		return "", nil
	}

	body, err := readBoundedBody(r, maxNetworkBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("network denied: request body exceeds %d byte limit", maxNetworkBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	switch {
	case normalizedPath == "/networks/create":
		return p.inspectCreate(logger, r, body)
	case isNetworkActionPath(normalizedPath, "connect"):
		return p.inspectConnect(logger, r, body)
	case isNetworkActionPath(normalizedPath, "disconnect"):
		return p.inspectDisconnect(logger, r, body)
	default:
		return "", nil
	}
}

func (p networkPolicy) inspectCreate(logger *slog.Logger, r *http.Request, body []byte) (string, error) {
	var req networkCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logDeferredNetworkValidation(logger, r, err)
		return "network create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !isBuiltinNetworkDriver(driver) && !p.allowCustomDrivers {
		return fmt.Sprintf("network create denied: driver %q is not allowed", driver), nil
	}
	if !p.allowSwarmScope && strings.EqualFold(strings.TrimSpace(req.Scope), "swarm") {
		return "network create denied: swarm scope is not allowed", nil
	}
	if !p.allowIngress && req.Ingress {
		return "network create denied: ingress networks are not allowed", nil
	}
	if !p.allowAttachable && req.Attachable {
		return "network create denied: attachable networks are not allowed", nil
	}
	if !p.allowConfigOnly && req.ConfigOnly {
		return "network create denied: config-only networks are not allowed", nil
	}
	if !p.allowConfigFrom && req.ConfigFrom != nil {
		return "network create denied: config-from networks are not allowed", nil
	}
	if denyReason := p.denyCreateIPAMReason(req.IPAM); denyReason != "" {
		return denyReason, nil
	}
	if !p.allowDriverOptions && len(req.Options) > 0 {
		return "network create denied: driver options are not allowed", nil
	}
	if req.EnableIPv4 != nil && !*req.EnableIPv4 && !p.allowDisableIPv4 {
		return "network create denied: disabling IPv4 (EnableIPv4: false) is not allowed", nil
	}

	return "", nil
}

func (p networkPolicy) denyCreateIPAMReason(ipam *networkIPAM) string {
	if ipam == nil {
		return ""
	}
	if driver := strings.TrimSpace(ipam.Driver); driver != "" && !isBuiltinIPAMDriver(driver) && !p.allowCustomIPAMDrivers {
		return fmt.Sprintf("network create denied: IPAM driver %q is not allowed", driver)
	}
	if !p.allowCustomIPAMConfig && len(ipam.Config) > 0 {
		return "network create denied: custom IPAM config is not allowed"
	}
	if !p.allowIPAMOptions && len(ipam.Options) > 0 {
		return "network create denied: IPAM options are not allowed"
	}
	return ""
}

func (p networkPolicy) inspectConnect(logger *slog.Logger, r *http.Request, body []byte) (string, error) {
	var req networkConnectRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logDeferredNetworkValidation(logger, r, err)
		return "network connect denied: request body could not be inspected", nil
	}

	if req.EndpointConfig == nil {
		return "", nil
	}
	if reason := denyEndpointConfigReason(*req.EndpointConfig, p.allowEndpointConfig, p.endpointConfig, "network connect"); reason != "" {
		return reason, nil
	}

	return "", nil
}

// denyEndpointConfigReason evaluates a single Docker network endpoint config
// (EndpointSettings) against the allow_endpoint_config / endpoint_config
// policy, returning a "<subject> denied: ..." message (or "" when allowed).
// subject distinguishes the calling context in the denial grammar —
// "network connect" for POST /networks/*/connect, "container create" for the
// primary/extra networks carried in POST /containers/create's
// NetworkingConfig.EndpointsConfig — mirroring the subject-prefixed pattern
// capabilityAddDenyReason already uses to share a check between
// container-create and service inspection.
//
// Precedence (#186): allow (AllowEndpointConfig) is the legacy whole-object
// escape hatch and, when true, always wins — every field is admitted and
// granular is not consulted at all (config validation rejects a config that
// sets both, so this is never an operator surprise in practice). When allow
// is false, granular applies per field: AllowStaticAddressing,
// AllowLinkLocalIPs, AllowMACPinning, and AllowGwPriority each gate their own
// field independently. Links and DriverOpts have no granular field of their
// own — with allow false they are always denied, fail-closed, regardless of
// granular's other settings; only allow=true can admit them.
//
// Aliases are gated by granular.DenyAliases, which defaults false (allowed)
// so the historical, unconditional-allow behavior is preserved when granular
// is left at its zero value: Docker Compose sets Aliases: [serviceName] on
// every endpoint it creates, so gating aliases by default broke every
// multi-network Compose recreate. Aliases were also never enforced on
// container-create's primary network (the only inspector that previously
// existed), so gating them only at connect was a bypassable, low-value
// control rather than a real guarantee. An operator who genuinely wants
// Aliases denied can now do so explicitly via endpoint_config.allow_aliases:
// false. Links remains unconditionally gated — joining another container's
// linked alias namespace is a materially different, higher-privilege
// primitive than an Aliases DNS name.
func denyEndpointConfigReason(ep networkEndpointConfig, allow bool, granular EndpointConfigOptions, subject string) string {
	if allow {
		return ""
	}
	if !granular.AllowStaticAddressing && endpointHasStaticAddressFields(ep) {
		return fmt.Sprintf("%s denied: endpoint static IP configuration is not allowed", subject)
	}
	if !granular.AllowLinkLocalIPs && endpointHasLinkLocalIPs(ep) {
		return fmt.Sprintf("%s denied: endpoint link-local IP addresses are not allowed", subject)
	}
	if !granular.AllowMACPinning && strings.TrimSpace(ep.MacAddress) != "" {
		return fmt.Sprintf("%s denied: endpoint MAC address is not allowed", subject)
	}
	if len(ep.Links) > 0 {
		return fmt.Sprintf("%s denied: endpoint links are not allowed", subject)
	}
	if len(ep.DriverOpts) > 0 {
		return fmt.Sprintf("%s denied: endpoint driver options are not allowed", subject)
	}
	if !granular.AllowGwPriority && ep.GwPriority != 0 {
		return fmt.Sprintf("%s denied: endpoint gateway priority is not allowed", subject)
	}
	if granular.DenyAliases && len(ep.Aliases) > 0 {
		return fmt.Sprintf("%s denied: endpoint aliases are not allowed", subject)
	}
	return ""
}

func (p networkPolicy) inspectDisconnect(logger *slog.Logger, r *http.Request, body []byte) (string, error) {
	var req networkDisconnectRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logDeferredNetworkValidation(logger, r, err)
		return "network disconnect denied: request body could not be inspected", nil
	}

	if !p.allowDisconnectForce && req.Force {
		return "network disconnect denied: force disconnect is not allowed", nil
	}
	return "", nil
}

// endpointHasStaticIPConfig reports whether endpoint carries any static
// address configuration at all — either the "address" fields
// (endpointHasStaticAddressFields) or IPAMConfig.LinkLocalIPs
// (endpointHasLinkLocalIPs). Kept as the combined predicate for callers (and
// mutation-kill tests) that predate the #186 per-field split; the granular
// denyEndpointConfigReason path consults the two halves independently so
// AllowStaticAddressing and AllowLinkLocalIPs can be set independently.
func endpointHasStaticIPConfig(endpoint networkEndpointConfig) bool {
	return endpointHasStaticAddressFields(endpoint) || endpointHasLinkLocalIPs(endpoint)
}

// endpointHasStaticAddressFields reports whether endpoint sets a static
// IPv4/IPv6 address via IPAMConfig or the deprecated top-level
// Gateway/IPAddress/IPPrefixLen/IPv6Gateway/GlobalIPv6Address/
// GlobalIPv6PrefixLen fields — every static-addressing field except
// IPAMConfig.LinkLocalIPs, which endpointHasLinkLocalIPs covers separately.
func endpointHasStaticAddressFields(endpoint networkEndpointConfig) bool {
	if endpoint.IPAMConfig != nil {
		if strings.TrimSpace(endpoint.IPAMConfig.IPv4Address) != "" ||
			strings.TrimSpace(endpoint.IPAMConfig.IPv6Address) != "" {
			return true
		}
	}

	return strings.TrimSpace(endpoint.Gateway) != "" ||
		strings.TrimSpace(endpoint.IPAddress) != "" ||
		endpoint.IPPrefixLen != 0 ||
		strings.TrimSpace(endpoint.IPv6Gateway) != "" ||
		strings.TrimSpace(endpoint.GlobalIPv6Address) != "" ||
		endpoint.GlobalIPv6PrefixLen != 0
}

// endpointHasLinkLocalIPs reports whether endpoint sets IPAMConfig.LinkLocalIPs.
func endpointHasLinkLocalIPs(endpoint networkEndpointConfig) bool {
	return endpoint.IPAMConfig != nil && len(endpoint.IPAMConfig.LinkLocalIPs) > 0
}

func isNetworkWritePath(normalizedPath string) bool {
	return normalizedPath == "/networks/create" ||
		isNetworkActionPath(normalizedPath, "connect") ||
		isNetworkActionPath(normalizedPath, "disconnect")
}

func isNetworkActionPath(normalizedPath string, action string) bool {
	if !strings.HasPrefix(normalizedPath, "/networks/") {
		return false
	}
	networkID, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/networks/"), "/")
	return ok && networkID != "" && tail == action
}

func isBuiltinNetworkDriver(driver string) bool {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "bridge", "host", "ipvlan", "macvlan", "none", "null", "overlay":
		return true
	default:
		return false
	}
}

func isBuiltinIPAMDriver(driver string) bool {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "default", "null":
		return true
	default:
		return false
	}
}

func logDeferredNetworkValidation(logger *slog.Logger, r *http.Request, err error) {
	logRequestError(logger, r, slog.LevelDebug, "network request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
}

const (
	maxNodeBodyBytes       = 256 << 10 // 256 KiB
	defaultOwnerLabelKey   = "com.sockguard.owner"
	nodeUpdateDenyPrefix   = "node update denied"
	nodeDecodeDebugMessage = "node update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation"
)

// NodeOptions configures request-body inspection for node updates.
type NodeOptions struct {
	AllowNameChange         bool
	AllowRoleChange         bool
	AllowAvailabilityChange bool
	AllowLabelMutation      bool
	AllowedLabelKeys        []string
}

type nodePolicy struct {
	allowNameChange         bool
	allowRoleChange         bool
	allowAvailabilityChange bool
	allowLabelMutation      bool
	allowedLabelKeys        []string
}

type nodeUpdateRequest struct {
	Name         json.RawMessage `json:"Name"`
	Labels       json.RawMessage `json:"Labels"`
	Role         json.RawMessage `json:"Role"`
	Availability json.RawMessage `json:"Availability"`
}

func newNodePolicy(opts NodeOptions) nodePolicy {
	return nodePolicy{
		allowNameChange:         opts.AllowNameChange,
		allowRoleChange:         opts.AllowRoleChange,
		allowAvailabilityChange: opts.AllowAvailabilityChange,
		allowLabelMutation:      opts.AllowLabelMutation,
		allowedLabelKeys:        normalizeNodeAllowedLabelKeys(opts.AllowedLabelKeys),
	}
}

func (p nodePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isNodeUpdatePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxNodeBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s: request body exceeds %d byte limit", nodeUpdateDenyPrefix, maxNodeBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req nodeUpdateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logNodeDecodeDefer(logger, r, err)
		return nodeUpdateDenyPrefix + ": request body could not be inspected", nil
	}

	denyReason, err := p.denyReason(req)
	if err != nil {
		logNodeDecodeDefer(logger, r, err)
		return nodeUpdateDenyPrefix + ": request body could not be inspected", nil
	}
	return denyReason, nil
}

func (p nodePolicy) denyReason(req nodeUpdateRequest) (string, error) {
	role, rolePresent, err := nodeStringField(req.Role)
	if err != nil {
		return "", err
	}
	if rolePresent && role != "" && !p.allowRoleChange {
		return "node update denied: role changes are not allowed", nil
	}

	availability, availabilityPresent, err := nodeStringField(req.Availability)
	if err != nil {
		return "", err
	}
	if availabilityPresent && availability != "" && !p.allowAvailabilityChange {
		return "node update denied: availability changes are not allowed", nil
	}

	name, namePresent, err := nodeStringField(req.Name)
	if err != nil {
		return "", err
	}
	if namePresent && name != "" && !p.allowNameChange {
		return "node update denied: name changes are not allowed", nil
	}

	labels, labelsPresent, err := nodeLabelsField(req.Labels)
	if err != nil {
		return "", err
	}
	if labelsPresent && !p.allowLabelMutation && !p.allowsConfiguredLabelOnly(labels) {
		return "node update denied: label mutation is not allowed", nil
	}

	return "", nil
}

func (p nodePolicy) allowsConfiguredLabelOnly(labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	for key, value := range labels {
		if !slices.Contains(p.allowedLabelKeys, key) {
			return false
		}
		if key == defaultOwnerLabelKey && value == "" {
			return false
		}
	}
	return true
}

func normalizeNodeAllowedLabelKeys(values []string) []string {
	normalized := []string{defaultOwnerLabelKey}
	for _, value := range values {
		key := strings.TrimSpace(value)
		if key == "" || slices.Contains(normalized, key) {
			continue
		}
		normalized = append(normalized, key)
	}
	return normalized
}

func nodeStringField(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false, nil
	}

	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, err
	}
	return strings.TrimSpace(value), true, nil
}

func nodeLabelsField(raw json.RawMessage) (map[string]string, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true, nil
	}

	var labels map[string]string
	if err := json.Unmarshal(raw, &labels); err != nil {
		return nil, true, err
	}
	return labels, true, nil
}

func logNodeDecodeDefer(logger *slog.Logger, r *http.Request, err error) {
	logRequestError(logger, r, slog.LevelDebug, nodeDecodeDebugMessage, err)
}

func isNodeUpdatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/nodes/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/nodes/"), "/")
	return ok && identifier != "" && tail == "update"
}

// normalizeBindMount cleans an absolute bind-mount source path. It returns the
// cleaned absolute path and true when the input is non-empty and rooted at
// "/"; otherwise it returns "", false. The helper is shared by the
// container/exec, service, and plugin inspectors because all three reject
// relative bind sources for the same reason — they would resolve against the
// proxy's filesystem, not the client's.
func normalizeBindMount(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	return path.Clean(value), true
}

const maxPluginBodyBytes = 512 << 20 // 512 MiB
// maxPluginPrivilegesBodyBytes caps the JSON-only plugin endpoints
// (/plugins/pull, /plugins/{id}/upgrade, /plugins/{id}/set), whose bodies are a
// small []pluginPrivilege / []string. Far below maxPluginBodyBytes — which is
// sized for the binary plugin-create archive that spools to disk — so a single
// request cannot force a half-gigabyte heap allocation via io.ReadAll.
const maxPluginPrivilegesBodyBytes = 1 << 20 // 1 MiB
// maxPluginDecompressedBytes bounds the *decompressed* size of a plugin-create
// archive to defuse gzip bombs: a body within the compressed maxPluginBodyBytes
// cap can otherwise expand to hundreds of GiB during the tar walk + drain.
const maxPluginDecompressedBytes = 4 << 30 // 4 GiB (gzip-bomb guard)
const maxPluginConfigBytes = 64 << 10      // 64 KiB
const pluginConfigName = "config.json"

// errPluginDecompressedTooLarge is surfaced (unwrapped) by the gzip-tar probe
// when a plugin-create archive expands past maxPluginDecompressedBytes, so
// inspectPluginCreate can map it to a clean deny rather than a 500.
var errPluginDecompressedTooLarge = errors.New("decompressed plugin archive exceeds limit")

// PluginOptions configures request-body/query inspection for plugin writes.
type PluginOptions struct {
	AllowHostNetwork      bool
	AllowHostIPC          bool
	AllowHostPID          bool
	AllowAllDevices       bool
	AllowedBindMounts     []string
	AllowedDevices        []string
	AllowAllCapabilities  bool
	AllowedCapabilities   []string
	AllowAllRegistries    bool
	AllowOfficial         bool
	AllowedRegistries     []string
	AllowedSetEnvPrefixes []string
}

type pluginPolicy struct {
	allowHostNetwork      bool
	allowHostIPC          bool
	allowHostPID          bool
	allowAllDevices       bool
	allowedBindMounts     []string
	allowedDevices        []string
	allowAllCapabilities  bool
	allowedCapabilities   []string
	allowedSetEnvPrefixes []string
	imagePolicy           imagePullPolicy
	io                    ioDeps
}

type pluginPrivilege struct {
	Name        string   `json:"Name"`
	Description string   `json:"Description"`
	Value       []string `json:"Value"`
}

type pluginCreateConfig struct {
	Network struct {
		Type string `json:"Type"`
	} `json:"Network"`
	PropagatedMount string `json:"PropagatedMount"`
	IpcHost         bool   `json:"IpcHost"`
	PidHost         bool   `json:"PidHost"`
	Mounts          []struct {
		Source string `json:"Source"`
	} `json:"Mounts"`
	Linux struct {
		Capabilities    []string `json:"Capabilities"`
		AllowAllDevices bool     `json:"AllowAllDevices"`
		Devices         []struct {
			Path string `json:"Path"`
		} `json:"Devices"`
	} `json:"Linux"`
}

func newPluginPolicy(opts PluginOptions) pluginPolicy {
	allowedMounts := normalizePluginPaths(opts.AllowedBindMounts)
	allowedDevices := normalizePluginPaths(opts.AllowedDevices)
	allowedCapabilities := normalizePluginCapabilities(opts.AllowedCapabilities)
	allowedSetEnvPrefixes := normalizePluginSetEnvPrefixes(opts.AllowedSetEnvPrefixes)

	return pluginPolicy{
		allowHostNetwork:      opts.AllowHostNetwork,
		allowHostIPC:          opts.AllowHostIPC,
		allowHostPID:          opts.AllowHostPID,
		allowAllDevices:       opts.AllowAllDevices,
		allowedBindMounts:     allowedMounts,
		allowedDevices:        allowedDevices,
		allowAllCapabilities:  opts.AllowAllCapabilities,
		allowedCapabilities:   allowedCapabilities,
		allowedSetEnvPrefixes: allowedSetEnvPrefixes,
		imagePolicy: newImagePullPolicy(ImagePullOptions{
			AllowAllRegistries: opts.AllowAllRegistries,
			AllowOfficial:      opts.AllowOfficial,
			AllowedRegistries:  opts.AllowedRegistries,
		}),
		io: defaultIODeps(),
	}
}

func (p pluginPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost {
		return "", nil
	}

	switch {
	case normalizedPath == "/plugins/pull":
		return p.inspectPluginPull(logger, r)
	case isPluginUpgradePath(normalizedPath):
		return p.inspectPluginUpgrade(logger, r)
	case isPluginSetPath(normalizedPath):
		return p.inspectPluginSet(logger, r)
	case normalizedPath == "/plugins/create":
		return p.inspectPluginCreate(logger, r)
	default:
		return "", nil
	}
}

func (p pluginPolicy) inspectPluginPull(logger *slog.Logger, r *http.Request) (string, error) {
	query := r.URL.Query()
	if remote := strings.TrimSpace(query.Get("remote")); remote != "" {
		if denyReason := p.imagePolicy.denyReasonForReference(remote, "plugin pull"); denyReason != "" {
			return denyReason, nil
		}
	}

	return p.inspectPrivileges(logger, r, "plugin pull")
}

func (p pluginPolicy) inspectPluginUpgrade(logger *slog.Logger, r *http.Request) (string, error) {
	query := r.URL.Query()
	if remote := strings.TrimSpace(query.Get("remote")); remote != "" {
		if denyReason := p.imagePolicy.denyReasonForReference(remote, "plugin upgrade"); denyReason != "" {
			return denyReason, nil
		}
	}

	return p.inspectPrivileges(logger, r, "plugin upgrade")
}

func (p pluginPolicy) inspectPrivileges(logger *slog.Logger, r *http.Request, subject string) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxPluginPrivilegesBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s denied: request body exceeds %d byte limit", subject, maxPluginPrivilegesBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var privileges []pluginPrivilege
	if err := decodePolicySubsetJSON(body, &privileges); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "plugin privilege body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "plugin denied: request body could not be inspected", nil
	}

	return p.denyReasonForPrivileges(subject, privileges), nil
}

func (p pluginPolicy) inspectPluginSet(logger *slog.Logger, r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxPluginPrivilegesBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("plugin set denied: request body exceeds %d byte limit", maxPluginPrivilegesBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var settings []string
	if err := decodePolicySubsetJSON(body, &settings); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "plugin set body could not be decoded for Sockguard policy inspection; denying (fail-closed)", err)

		return "plugin set denied: request body could not be inspected", nil
	}

	for _, setting := range settings {
		key, value, ok := strings.Cut(setting, "=")
		if !ok {
			return fmt.Sprintf("plugin set denied: setting %q is not an allowed assignment", setting), nil
		}
		if kind, normalized, matched := parsePluginSetting(key, value); matched {
			switch kind {
			case pluginSettingMount:
				if !bindPathAllowed(normalized, p.allowedBindMounts) {
					return fmt.Sprintf("plugin set denied: bind mount source %q is not allowlisted", normalized), nil
				}
			case pluginSettingDevice:
				if !p.deviceAllowed(normalized) {
					return fmt.Sprintf("plugin set denied: device path %q is not allowlisted", normalized), nil
				}
			}
			continue
		}
		if !p.setEnvAllowed(setting) {
			return fmt.Sprintf("plugin set denied: setting %q is not allowlisted", setting), nil
		}
	}

	return "", nil
}

func (p pluginPolicy) inspectPluginCreate(logger *slog.Logger, r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	spool, size, err := p.io.spoolRequestBodyToTempFile(r, "sockguard-plugin-", maxPluginBodyBytes)
	if err != nil {
		return "", err
	}
	if spool.tooLarge {
		spool.closeAndRemove()
		return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("plugin create denied: request body exceeds %d byte limit", maxPluginBodyBytes))
	}
	if size == 0 {
		spool.closeAndRemove()
		return "", nil
	}

	configBytes, ok, err := p.io.extractPluginConfig(spool.file, r.Header.Get("Content-Type"))
	if err != nil {
		spool.closeAndRemove()
		if errors.Is(err, errPluginDecompressedTooLarge) {
			return fmt.Sprintf("plugin create denied: decompressed plugin archive exceeds %d byte limit", maxPluginDecompressedBytes), nil
		}
		return "", fmt.Errorf("extract plugin config: %w", err)
	}
	if !ok {

		spool.closeAndRemove()
		return "plugin create denied: plugin config could not be inspected", nil
	}

	var cfg pluginCreateConfig
	if err := decodePolicySubsetJSON(configBytes, &cfg); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "plugin config.json could not be decoded for Sockguard policy inspection", err)
		spool.closeAndRemove()
		return "plugin create denied: plugin config could not be inspected", nil
	} else if denyReason := p.denyReasonForCreateConfig(cfg); denyReason != "" {
		spool.closeAndRemove()
		return denyReason, nil
	}

	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind plugin body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

func (p pluginPolicy) denyReasonForCreateConfig(cfg pluginCreateConfig) string {
	if !p.allowHostNetwork && strings.EqualFold(strings.TrimSpace(cfg.Network.Type), "host") {
		return "plugin create denied: host network is not allowed"
	}
	if !p.allowHostIPC && cfg.IpcHost {
		return "plugin create denied: host IPC namespace is not allowed"
	}
	if !p.allowHostPID && cfg.PidHost {
		return "plugin create denied: host PID namespace is not allowed"
	}
	if denyReason := p.denyBindMounts(cfg.PropagatedMount, cfg.Mounts); denyReason != "" {
		return denyReason
	}
	if !p.allowAllCapabilities {
		if denyReason := p.denyCapabilities(cfg.Linux.Capabilities); denyReason != "" {
			return denyReason
		}
	}
	if !p.allowAllDevices {
		if cfg.Linux.AllowAllDevices {
			return "plugin create denied: allow-all-devices is not allowed"
		}
		if denyReason := p.denyDevices(cfg.Linux.Devices); denyReason != "" {
			return denyReason
		}
	}
	return ""
}

func (p pluginPolicy) denyReasonForPrivileges(subject string, privileges []pluginPrivilege) string {
	for _, privilege := range privileges {
		var reason string
		switch strings.ToLower(strings.TrimSpace(privilege.Name)) {
		case "network":
			reason = p.denyNetworkPrivilege(subject, privilege.Value)
		case "mount":
			reason = p.denyBindMountValues(subject, privilege.Value)
		case "device":
			reason = p.denyDevicePrivilege(subject, privilege.Value)
		case "capabilities":
			reason = p.denyCapabilityPrivilege(subject, privilege.Value)
		}
		if reason != "" {
			return reason
		}
	}
	return ""
}

func (p pluginPolicy) denyNetworkPrivilege(subject string, values []string) string {
	if p.allowHostNetwork {
		return ""
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), "host") {
			return fmt.Sprintf("%s denied: host network is not allowed", subject)
		}
	}
	return ""
}

func (p pluginPolicy) denyDevicePrivilege(subject string, values []string) string {
	if p.allowAllDevices {
		return ""
	}
	for _, value := range values {
		path, ok := normalizeBindMount(value)
		if !ok || p.deviceAllowed(path) {
			continue
		}
		return fmt.Sprintf("%s denied: device path %q is not allowlisted", subject, path)
	}
	return ""
}

func (p pluginPolicy) denyCapabilityPrivilege(subject string, values []string) string {
	if p.allowAllCapabilities {
		return ""
	}
	for _, value := range values {
		capability := normalizePluginCapability(value)
		if capability == "" || p.capabilityAllowed(capability) {
			continue
		}
		return fmt.Sprintf("%s denied: capability %q is not allowlisted", subject, capability)
	}
	return ""
}

func (p pluginPolicy) denyBindMounts(propagatedMount string, mounts []struct {
	Source string `json:"Source"`
}) string {
	if propagatedMount != "" {
		source, ok := normalizeBindMount(propagatedMount)
		if !ok || !bindPathAllowed(source, p.allowedBindMounts) {
			if ok {
				return fmt.Sprintf("plugin create denied: bind mount source %q is not allowlisted", source)
			}
		}
	}

	for _, mount := range mounts {
		source, ok := normalizeBindMount(mount.Source)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("plugin create denied: bind mount source %q is not allowlisted", source)
	}

	return ""
}

func (p pluginPolicy) denyBindMountValues(subject string, values []string) string {
	for _, value := range values {
		source, ok := normalizeBindMount(value)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("%s denied: bind mount source %q is not allowlisted", subject, source)
	}
	return ""
}

func (p pluginPolicy) denyDevices(devices []struct {
	Path string `json:"Path"`
}) string {
	for _, device := range devices {
		path, ok := normalizeBindMount(device.Path)
		if !ok || p.deviceAllowed(path) {
			continue
		}
		return fmt.Sprintf("plugin create denied: device path %q is not allowlisted", path)
	}
	return ""
}

func (p pluginPolicy) denyCapabilities(capabilities []string) string {
	for _, capability := range capabilities {
		normalized := normalizePluginCapability(capability)
		if normalized == "" || p.capabilityAllowed(normalized) {
			continue
		}
		return fmt.Sprintf("plugin create denied: capability %q is not allowlisted", normalized)
	}
	return ""
}

func (p pluginPolicy) deviceAllowed(devicePath string) bool {
	for _, allowed := range p.allowedDevices {
		if allowed == "/" || devicePath == allowed || strings.HasPrefix(devicePath, allowed+"/") {
			return true
		}
	}
	return false
}

func (p pluginPolicy) capabilityAllowed(capability string) bool {
	return slices.Contains(p.allowedCapabilities, capability)
}

func (p pluginPolicy) setEnvAllowed(setting string) bool {
	for _, prefix := range p.allowedSetEnvPrefixes {
		if strings.HasPrefix(setting, prefix) {
			return true
		}
	}
	return false
}

func (io_ ioDeps) extractPluginConfig(file *os.File, contentType string) ([]byte, bool, error) {
	if mediaType, params, err := mime.ParseMediaType(contentType); err == nil && strings.EqualFold(mediaType, "multipart/form-data") {
		if boundary := strings.TrimSpace(params["boundary"]); boundary != "" {
			if err := io_.SeekToStart(file); err != nil {
				return nil, false, fmt.Errorf("rewind plugin reader: %w", err)
			}
			return io_.extractPluginConfigFromMultipart(file, boundary)
		}

	}

	if err := io_.SeekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind plugin reader: %w", err)
	}

	if config, ok, err := io_.extractPluginConfigFromGzipTar(file); ok || err != nil {
		return config, ok, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind plugin reader: %w", err)
	}
	return io_.extractPluginConfigFromTar(file)
}

func (io_ ioDeps) extractPluginConfigFromMultipart(file *os.File, boundary string) ([]byte, bool, error) {
	reader := multipart.NewReader(file, boundary)
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("read multipart part: %w", err)
		}

		config, ok, err := io_.extractPluginConfigFromArchiveReader(part)
		if err != nil {
			return nil, false, err
		}
		if ok {
			return config, true, nil
		}
	}
}

func (io_ ioDeps) extractPluginConfigFromGzipTar(file *os.File) ([]byte, bool, error) {
	return io_.extractPluginConfigFromGzipReader(file)
}

func (io_ ioDeps) extractPluginConfigFromTar(file *os.File) ([]byte, bool, error) {
	return io_.extractPluginConfigFromTarReader(tar.NewReader(file))
}

func (io_ ioDeps) extractPluginConfigFromArchiveReader(reader io.Reader) ([]byte, bool, error) {
	buffered := bufio.NewReader(reader)
	header, err := buffered.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("peek archive header: %w", err)
	}
	if looksLikeGzipHeader(header) {
		return io_.extractPluginConfigFromGzipReader(buffered)
	}
	if !looksLikeTarHeader(header) {
		return nil, false, nil
	}
	return io_.extractPluginConfigFromTarReader(tar.NewReader(buffered))
}

func (io_ ioDeps) extractPluginConfigFromGzipReader(reader io.Reader) ([]byte, bool, error) {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("create gzip reader: %w", err)
	}

	limited := &limitedReader{r: gzr, remaining: maxPluginDecompressedBytes, tooLarge: errPluginDecompressedTooLarge}

	config, ok, err := io_.extractPluginConfigFromTarReader(tar.NewReader(limited))
	if err == nil {
		if drainErr := io_.DrainReader(limited); drainErr != nil {
			err = fmt.Errorf("drain gzip stream: %w", drainErr)
		}
	}
	if closeErr := io_.CloseReadCloser(gzr); err == nil && closeErr != nil {
		err = fmt.Errorf("close gzip reader: %w", closeErr)
	}
	if errors.Is(err, errPluginDecompressedTooLarge) {

		return nil, false, errPluginDecompressedTooLarge
	}
	return config, ok, err
}

func (io_ ioDeps) extractPluginConfigFromTarReader(tr *tar.Reader) ([]byte, bool, error) {
	var config []byte
	found := false

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return config, found, nil
		}
		if err != nil {
			if strings.Contains(err.Error(), "invalid tar header") {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("read tar entry: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}
		if normalizePluginConfigPath(header.Name) != pluginConfigName {
			continue
		}

		body, err := io_.ReadAllLimited(tr, maxPluginConfigBytes+1)
		if err != nil {
			return nil, false, fmt.Errorf("read plugin config entry: %w", err)
		}
		if len(body) > maxPluginConfigBytes {
			return nil, false, fmt.Errorf("plugin config exceeds %d byte limit", maxPluginConfigBytes)
		}
		if !found {
			config = body
			found = true
		}
	}
}

func looksLikeGzipHeader(header []byte) bool {
	return len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b
}

func looksLikeTarHeader(header []byte) bool {
	return len(header) >= 262 && string(header[257:262]) == "ustar"
}

func normalizePluginConfigPath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	cleaned := path.Clean(strings.TrimPrefix(trimmed, "/"))
	if cleaned == "." || cleaned == "" {
		return ""
	}
	return cleaned
}

func normalizePluginSetEnvPrefixes(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || slices.Contains(normalized, trimmed) {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

type pluginSettingType int

const (
	pluginSettingUnknown pluginSettingType = iota
	pluginSettingMount
	pluginSettingDevice
)

func parsePluginSetting(key, value string) (pluginSettingType, string, bool) {
	trimmedKey := strings.TrimSpace(key)
	trimmedValue := strings.TrimSpace(value)
	if trimmedKey == "" || trimmedValue == "" {
		return pluginSettingUnknown, "", false
	}

	lowerKey := strings.ToLower(trimmedKey)
	switch {
	case strings.HasSuffix(lowerKey, ".source"):
		if source, ok := normalizeBindMount(trimmedValue); ok {
			return pluginSettingMount, source, true
		}
		return pluginSettingUnknown, "", false
	case strings.HasSuffix(lowerKey, ".path"):
		if device, ok := normalizeBindMount(trimmedValue); ok {
			return pluginSettingDevice, device, true
		}
		return pluginSettingUnknown, "", false
	}

	if strings.ToUpper(trimmedKey) == trimmedKey {
		return pluginSettingUnknown, "", false
	}

	switch {
	case strings.HasPrefix(trimmedValue, "/dev/"):
		if device, ok := normalizeBindMount(trimmedValue); ok {
			return pluginSettingDevice, device, true
		}
	case strings.HasPrefix(trimmedValue, "/"):
		if source, ok := normalizeBindMount(trimmedValue); ok {
			return pluginSettingMount, source, true
		}
	}

	return pluginSettingUnknown, "", false
}

func normalizePluginPaths(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized, ok := normalizeBindMount(value)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func normalizePluginCapabilities(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizePluginCapability(value)
		if normalized == "" || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

// normalizePluginCapability differs from normalizeCapability deliberately: it
// does NOT strip a "CAP_" prefix. Docker plugin privileges arrive in their
// own namespace (e.g. "network", "mount: /var/run/docker.sock", "device:
// /dev/nvidia0") rather than as Linux capability names; values that happen to
// look like capabilities — for instance an allowlist that lists "CAP_NET_ADMIN"
// — must match the plugin manifest verbatim instead of being collapsed to
// "NET_ADMIN". Use normalizeCapability when matching HostConfig.CapAdd/CapDrop.
func normalizePluginCapability(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func isPluginUpgradePath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "/plugins/") && strings.HasSuffix(normalizedPath, "/upgrade")
}

func isPluginSetPath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "/plugins/") && strings.HasSuffix(normalizedPath, "/set")
}

// maxRegistryAuthHeaderBytes bounds both the base64-encoded and decoded form
// of the X-Registry-Auth / X-Registry-Config headers Docker accepts on image
// pull/push and build requests. A genuine AuthConfig or per-registry
// AuthConfig map is at most a few KiB even with a long identity token; the
// cap exists to defuse an oversized header being used to make Sockguard
// allocate or spend CPU decoding attacker-controlled data before the request
// is otherwise denied or forwarded.
const maxRegistryAuthHeaderBytes = 8 << 10 // 8 KiB

// registryAuthHeader is the subset of Docker's AuthConfig object
// (X-Registry-Auth) the policy inspects.
type registryAuthHeader struct {
	ServerAddress string `json:"serveraddress"`
}

// decodeRegistryAuthHeaderBytes bounded-decodes a base64 header value,
// accepting both standard and URL-safe alphabets (the Docker CLI and SDKs
// have used both historically). Returns an error suitable for a
// "<subject> denied: ..." deny reason on any failure.
func decodeRegistryAuthHeaderBytes(headerValue, headerName, subject string) ([]byte, error) {
	trimmed := strings.TrimSpace(headerValue)
	if len(trimmed) > maxRegistryAuthHeaderBytes {
		return nil, fmt.Errorf("%s denied: %s header exceeds %d byte limit", subject, headerName, maxRegistryAuthHeaderBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(trimmed)
	}
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(trimmed)
	}
	if err != nil {
		return nil, fmt.Errorf("%s denied: %s header is not valid base64", subject, headerName)
	}
	if len(decoded) > maxRegistryAuthHeaderBytes {
		return nil, fmt.Errorf("%s denied: %s header exceeds %d byte limit", subject, headerName, maxRegistryAuthHeaderBytes)
	}
	return decoded, nil
}

// denyRegistryAuthHeaderReason bounded-decodes the base64 X-Registry-Auth
// header (a single Docker AuthConfig JSON object) that POST /images/create
// (pull) and POST /images/{name}/push accept. An empty header is a no-op
// (anonymous pull/push, unaffected). A present header that is oversized,
// non-base64, or non-JSON is denied fail-closed rather than forwarded
// unexamined. When a registry allowlist is configured (allowAll is false and
// allowed is non-empty), the decoded ServerAddress must canonicalize to an
// allowlisted host; an empty ServerAddress or no allowlist configured passes
// through unchanged, preserving prior behavior for operators who haven't
// opted into registry allowlisting. The decoded credential fields
// (username/password/identitytoken) are never inspected, logged, or
// reflected.
func denyRegistryAuthHeaderReason(headerValue string, allowAll bool, allowed []string, subject string) string {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return ""
	}
	decoded, err := decodeRegistryAuthHeaderBytes(trimmed, "X-Registry-Auth", subject)
	if err != nil {
		return err.Error()
	}
	var auth registryAuthHeader
	if err := json.Unmarshal(decoded, &auth); err != nil {
		return fmt.Sprintf("%s denied: X-Registry-Auth header is not valid JSON", subject)
	}
	if allowAll || len(allowed) == 0 {
		return ""
	}
	server := strings.TrimSpace(auth.ServerAddress)
	if server == "" {
		return ""
	}
	host, ok := normalizeRegistryHost(stripRegistryHeaderScheme(server))
	if !ok || !slices.Contains(allowed, host) {
		return fmt.Sprintf("%s denied: X-Registry-Auth serveraddress is not allowlisted", subject)
	}
	return ""
}

// denyRegistryConfigHeaderReason bounded-decodes the base64 X-Registry-Config
// header POST /build accepts: a JSON object mapping registry host to
// AuthConfig, used by multi-registry builds that pull FROM images from more
// than one private registry. Sockguard's build policy has no registry
// allowlist of its own (BuildOptions carries none), so this only rejects
// oversized or malformed values fail-closed; it does not cross-check hosts.
// Decoded credential material is never inspected, logged, or reflected.
func denyRegistryConfigHeaderReason(headerValue, subject string) string {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return ""
	}
	decoded, err := decodeRegistryAuthHeaderBytes(trimmed, "X-Registry-Config", subject)
	if err != nil {
		return err.Error()
	}
	var registryConfig map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &registryConfig); err != nil {
		return fmt.Sprintf("%s denied: X-Registry-Config header is not valid JSON", subject)
	}
	return ""
}

// stripRegistryHeaderScheme normalizes a ServerAddress value
// ("https://myregistry.example.com/v2/", "myregistry.example.com:5000") down
// to a bare host[:port] by removing a leading scheme and any path segment.
func stripRegistryHeaderScheme(value string) string {
	v := strings.TrimSpace(value)
	if idx := strings.Index(v, "://"); idx >= 0 {
		v = v[idx+3:]
	}
	if idx := strings.Index(v, "/"); idx >= 0 {
		v = v[:idx]
	}
	return v
}

type requestRejectionError struct {
	status int
	reason string
	// reasonCode overrides requestRejectionReasonCode's status-derived
	// default when non-empty. Existing callers (e.g. the container-create/
	// service 413 body-too-large paths) leave this unset and keep exactly
	// today's status-derived code; the mutation engine sets it explicitly so
	// its four reason codes are distinguishable from the generic
	// request_body_* vocabulary even where the HTTP status overlaps (e.g.
	// mutation_request_too_large vs request_body_too_large, both 413).
	reasonCode string
}

func (e *requestRejectionError) Error() string {
	return e.reason
}

func newRequestRejectionError(status int, reason string) error {
	return &requestRejectionError{status: status, reason: reason}
}

// newRequestRejectionErrorWithCode is newRequestRejectionError plus an
// explicit reason code, for callers whose denial reason isn't adequately
// described by requestRejectionReasonCode's status-only mapping.
func newRequestRejectionErrorWithCode(status int, reasonCode, reason string) error {
	return &requestRejectionError{status: status, reason: reason, reasonCode: reasonCode}
}

func requestRejectionFromError(err error) (requestRejectionError, bool) {
	var target *requestRejectionError
	if !errors.As(err, &target) {
		return requestRejectionError{}, false
	}
	return *target, true
}

const (
	reasonCodeResourceLimitRequestInvalid     = "resource_limit_request_invalid"
	reasonCodeResourceLimitPolicyDenied       = "resource_limit_policy_denied"
	reasonCodeResourceLimitPolicyLookupFailed = "resource_limit_policy_lookup_failed"
	reasonCodeResourceLimitPolicyStateChanged = "resource_limit_policy_state_changed"
)

const (
	resourcePolicyKindContainer = "container"
	resourcePolicyKindService   = "service"
)

// ResourceLimitGuardOptions configures ResourceLimitGuardWithOptions. It
// mirrors filter.Options' shape (PolicyConfig + Profiles + ResolveProfile) so
// the guard selects the same per-client policy the request-body inspectors
// and rule evaluator already resolved, plus the runtime daemon inspectors
// only this layer needs.
type ResourceLimitGuardOptions struct {
	PolicyConfig
	// Profiles mirrors filter.Options.Profiles — the same compiled per-client
	// policy map the filter/ownership/visibility layers use, so a profile's
	// require_* flags apply identically here.
	Profiles map[string]Policy
	// ResolveProfile mirrors filter.Options.ResolveProfile (typically
	// clientacl.RequestProfile).
	ResolveProfile func(*http.Request) (string, bool)
	// InspectContainer resolves a container's current HostConfig resource
	// fields for the update-omission merge. Required for
	// require_{memory,cpu,cpu_hard,pids}_limit on container update; a nil
	// value with an active requirement fails closed (does not panic).
	InspectContainer ContainerUpdateInspectFunc
	// InspectService resolves a service's current Version/Spec/PreviousSpec
	// for rollback validation. Required for require_cpu_limit(_hard) on
	// ?rollback=previous or an automatic-rollback-capable update; a nil value
	// with an active requirement fails closed (does not panic).
	InspectService ServiceInspectFunc
}

// ResourceLimitGuardWithOptions returns the #152 resource-limit guard
// middleware. See the package-level doc comment above for placement and
// rationale.
func ResourceLimitGuardWithOptions(logger *slog.Logger, opts ResourceLimitGuardOptions) func(http.Handler) http.Handler {
	g := &resourceLimitGuard{
		defaultPolicy:    opts.normalized(),
		profiles:         opts.Profiles,
		resolveProfile:   opts.ResolveProfile,
		inspectContainer: opts.InspectContainer,
		inspectService:   opts.InspectService,
		logger:           logger,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.serve(w, r, next)
		})
	}
}

type resourceLimitGuard struct {
	defaultPolicy    PolicyConfig
	profiles         map[string]Policy
	resolveProfile   func(*http.Request) (string, bool)
	inspectContainer ContainerUpdateInspectFunc
	inspectService   ServiceInspectFunc
	logger           *slog.Logger
}

func (g *resourceLimitGuard) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if r.Method != http.MethodPost {
		next.ServeHTTP(w, r)
		return
	}

	normPath := resolveNormalizedPath(logging.MetaForRequest(w, r), r)

	policy, ok := g.policyForRequest(w, r)
	if !ok {

		return
	}

	switch {
	case isContainerUpdatePath(normPath):
		g.guardContainerUpdate(w, r, normPath, policy, next)
	case isServiceWritePath(normPath):
		g.guardServiceWrite(w, r, normPath, policy, next)
	default:
		next.ServeHTTP(w, r)
	}
}

// policyForRequest resolves the PolicyConfig for this request using the same
// profile-selection contract filter.MiddlewareWithOptions uses. ok=false
// means a response was already written (unresolved named profile).
func (g *resourceLimitGuard) policyForRequest(w http.ResponseWriter, r *http.Request) (PolicyConfig, bool) {
	if g.resolveProfile == nil {
		return g.defaultPolicy, true
	}
	name, ok := g.resolveProfile(r)
	if !ok {
		return g.defaultPolicy, true
	}
	profile, found := g.profiles[name]
	if !found {
		denyWithReasonCode(w, r, g.logger, reasonCodeClientPolicyProfileUnresolved, "client policy profile could not be resolved", g.defaultPolicy.DenyResponseVerbosity)
		return PolicyConfig{}, false
	}
	return profile.normalized(), true
}

// containerUpdateResourcePatch decodes ONLY the root-level Docker
// update-resource fields. Nested "HostConfig"/"Resources" wrappers are
// deliberately NOT part of this type: Docker's real
// POST /containers/{id}/update schema is flat at the request root, so a value
// nested under a decoy wrapper is never applied by the daemon. Reading it here
// would let a request satisfy the floor check using a number Docker will
// never actually use — a hole, not a false positive — so this type silently
// ignores anything outside the root object, exactly matching what the daemon
// itself honors.
//
// Scalars are plain int64 (not pointers): Docker's own merge treats an
// explicit 0 identically to an omitted field ("unchanged" — see the overlay in
// guardContainerUpdateResources), so sockguard does not need to distinguish
// "absent" from "present and zero" for these five fields. PidsLimit is the
// one exception — Docker uses a pointer there specifically so 0/-1 CAN be an
// explicit clear — so it stays a pointer here too.
type containerUpdateResourcePatch struct {
	Memory    int64  `json:"Memory"`
	NanoCpus  int64  `json:"NanoCpus"`
	CpuQuota  int64  `json:"CpuQuota"`
	CpuPeriod int64  `json:"CpuPeriod"`
	CpuShares int64  `json:"CpuShares"`
	PidsLimit *int64 `json:"PidsLimit"`
}

// containerUpdateIdentifier extracts the {id} path segment from a normalized
// POST /containers/{id}/update path. Assumes isContainerUpdatePath(normPath)
// already holds.
func containerUpdateIdentifier(normalizedPath string) (string, bool) {
	id, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/containers/"), "/")
	if !ok || id == "" || tail != "update" {
		return "", false
	}
	return id, true
}

func (g *resourceLimitGuard) guardContainerUpdate(w http.ResponseWriter, r *http.Request, normPath string, policy PolicyConfig, next http.Handler) {
	cu := policy.ContainerUpdate

	if !cu.AllowResourceUpdates {
		next.ServeHTTP(w, r)
		return
	}
	requirements := containerUpdateRequirementsList(cu)
	if requirements == "" {
		next.ServeHTTP(w, r)
		return
	}

	id, ok := containerUpdateIdentifier(normPath)
	if !ok {
		next.ServeHTTP(w, r)
		return
	}

	rp := logging.GetResourcePolicyMeta()
	rp.Evaluated = true
	rp.Kind = resourcePolicyKindContainer
	rp.Operation = "update"
	rp.StateSource = "effective_state"
	rp.Requirements = requirements

	body, err := readBoundedBody(r, maxContainerUpdateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.respondHardDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("container update denied: request body exceeds %d byte limit", maxContainerUpdateBodyBytes),
				policy.DenyResponseVerbosity, rp)
			return
		}
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: request body could not be read", policy.DenyResponseVerbosity, rp)
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: a request body is required to verify resource requirements", policy.DenyResponseVerbosity, rp)
		return
	}
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: request body contains ambiguous duplicate keys", policy.DenyResponseVerbosity, rp)
		return
	}

	var patch containerUpdateResourcePatch
	if err := json.Unmarshal(body, &patch); err != nil {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"container update denied: request body could not be inspected", policy.DenyResponseVerbosity, rp)
		return
	}

	if g.inspectContainer == nil {
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"container update denied: resource requirement verification unavailable", policy.DenyResponseVerbosity, rp)
		return
	}
	rp.StateLookup = true
	current, found, err := g.inspectContainer(r.Context(), id)
	if err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to inspect container for resource-limit guard", err)
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"container update denied: resource requirement verification unavailable", policy.DenyResponseVerbosity, rp)
		return
	}
	if !found {

		g.respondAllow(w, r, next, rp)
		return
	}

	effective := containerCreateHostConfig{
		Memory:    current.Memory,
		NanoCpus:  current.NanoCpus,
		CpuQuota:  current.CpuQuota,
		CpuPeriod: current.CpuPeriod,
		CpuShares: current.CpuShares,
		PidsLimit: current.PidsLimit,
	}

	if patch.Memory != 0 {
		effective.Memory = patch.Memory
	}
	if patch.NanoCpus != 0 {
		effective.NanoCpus = patch.NanoCpus
	}
	if patch.CpuQuota != 0 {
		effective.CpuQuota = patch.CpuQuota
	}
	if patch.CpuPeriod != 0 {
		effective.CpuPeriod = patch.CpuPeriod
	}
	if patch.CpuShares != 0 {
		effective.CpuShares = patch.CpuShares
	}
	if patch.PidsLimit != nil {
		effective.PidsLimit = patch.PidsLimit
	}

	reason, violation := resourceLimitDenyReason(effective, cu.RequireMemoryLimit, cu.RequireCPULimit, cu.RequireCPULimitHard, cu.RequirePidsLimit, "container update")
	if reason != "" {
		rp.Violation = violation
		g.respondPolicyDenied(w, r, next, reason, policy.DenyResponseVerbosity, rp)
		return
	}
	g.respondAllow(w, r, next, rp)
}

func containerUpdateRequirementsList(cu ContainerUpdateOptions) string {
	var parts []string
	if cu.RequireMemoryLimit {
		parts = append(parts, "memory")
	}
	if cu.RequireCPULimit {
		parts = append(parts, "cpu")
	}
	if cu.RequireCPULimitHard {
		parts = append(parts, "hard_cpu")
	}
	if cu.RequirePidsLimit {
		parts = append(parts, "pids")
	}
	return strings.Join(parts, ",")
}

// ContainerUpdateInspectResult carries the container-update-relevant subset of
// GET /containers/{id}/json's HostConfig.
type ContainerUpdateInspectResult struct {
	Memory    int64
	NanoCpus  int64
	CpuQuota  int64
	CpuPeriod int64
	CpuShares int64
	PidsLimit *int64
}

// ContainerUpdateInspectFunc looks up a container's current resource state by
// ID. found=false with err=nil means the container does not exist (404).
type ContainerUpdateInspectFunc func(ctx context.Context, id string) (ContainerUpdateInspectResult, bool, error)

// NewDockerContainerUpdateInspectorWithRoundTripper returns a container
// resource-state inspector that issues its GET through the shared upstream
// RoundTripper (typically an *upstream.Resolver), so it follows the same
// active endpoint as the update request it guards under failover. Mirrors
// NewDockerExecInspectorWithRoundTripper's shape (exec.go).
func NewDockerContainerUpdateInspectorWithRoundTripper(rt http.RoundTripper) ContainerUpdateInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, id string) (ContainerUpdateInspectResult, bool, error) {
		requestPath, ok := dockerresource.InspectPath(dockerresource.KindContainer, id)
		if !ok {
			return ContainerUpdateInspectResult{}, false, fmt.Errorf("no inspect path for container %q", id)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil)
		if err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}
		defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return ContainerUpdateInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ContainerUpdateInspectResult{}, false, fmt.Errorf("inspect container %q returned status %d", id, resp.StatusCode)
		}

		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}

		var decoded struct {
			HostConfig struct {
				Memory    int64  `json:"Memory"`
				NanoCpus  int64  `json:"NanoCpus"`
				CpuQuota  int64  `json:"CpuQuota"`
				CpuPeriod int64  `json:"CpuPeriod"`
				CpuShares int64  `json:"CpuShares"`
				PidsLimit *int64 `json:"PidsLimit"`
			} `json:"HostConfig"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return ContainerUpdateInspectResult{}, false, err
		}
		return ContainerUpdateInspectResult{
			Memory:    decoded.HostConfig.Memory,
			NanoCpus:  decoded.HostConfig.NanoCpus,
			CpuQuota:  decoded.HostConfig.CpuQuota,
			CpuPeriod: decoded.HostConfig.CpuPeriod,
			CpuShares: decoded.HostConfig.CpuShares,
			PidsLimit: decoded.HostConfig.PidsLimit,
		}, true, nil
	}
}

type serviceResourceGuardRequest struct {
	TaskTemplate struct {
		Resources *struct {
			Limits *struct {
				NanoCPUs int64 `json:"NanoCPUs"`
			} `json:"Limits"`
		} `json:"Resources"`
	} `json:"TaskTemplate"`
	UpdateConfig *struct {
		FailureAction string `json:"FailureAction"`
	} `json:"UpdateConfig"`
}

func (req serviceResourceGuardRequest) nanoCPUs() int64 {
	if req.TaskTemplate.Resources == nil || req.TaskTemplate.Resources.Limits == nil {
		return 0
	}
	return req.TaskTemplate.Resources.Limits.NanoCPUs
}

func (req serviceResourceGuardRequest) failureActionIsRollback() bool {
	return req.UpdateConfig != nil && strings.EqualFold(req.UpdateConfig.FailureAction, "rollback")
}

// serviceUpdateIdentifier extracts the {id} path segment from a normalized
// POST /services/{id}/update path.
func serviceUpdateIdentifier(normalizedPath string) (string, bool) {
	if !strings.HasPrefix(normalizedPath, "/services/") {
		return "", false
	}
	id, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/services/"), "/")
	if !ok || id == "" || tail != "update" {
		return "", false
	}
	return id, true
}

// serviceVersionQuery parses the exactly-one-value, strictly-numeric
// ?version= query parameter Docker requires on every service update. Multiple
// values or a non-numeric value is treated as invalid rather than guessed at.
func serviceVersionQuery(r *http.Request) (uint64, bool) {
	values := r.URL.Query()["version"]
	if len(values) != 1 {
		return 0, false
	}
	v, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// serviceManualRollbackQuery distinguishes an ordinary service update from a
// manual rollback request while rejecting ambiguous duplicate query values.
// Docker's request parser may choose one of multiple values, but the guard
// must never guess which daemon behavior it is validating.
func serviceManualRollbackQuery(r *http.Request) (manualRollback, valid bool) {
	values, present := r.URL.Query()["rollback"]
	if !present {
		return false, true
	}
	if len(values) != 1 {
		return false, false
	}
	return strings.EqualFold(values[0], "previous"), true
}

func serviceRequirementsList(svc ServiceOptions) string {
	var parts []string
	if svc.RequireCPULimit {
		parts = append(parts, "cpu")
	}
	if svc.RequireCPULimitHard {
		parts = append(parts, "hard_cpu")
	}
	return strings.Join(parts, ",")
}

// denyServiceCPULimitReason applies the single presence predicate shared by
// RequireCPULimit and RequireCPULimitHard (see ServiceOptions doc comment:
// Swarm's TaskTemplate.Resources.Limits has no soft/hard split the way
// container CpuShares vs NanoCpus/CpuQuota does, so both flags reduce to the
// same NanoCPUs>0 check). subject prefixes the message.
func denyServiceCPULimitReason(nanoCPUs int64, requireCPU, requireCPUHard bool, subject string) (reason, violation string) {
	if (requireCPU || requireCPUHard) && nanoCPUs <= 0 {
		return fmt.Sprintf("%s denied: a CPU limit is required (set TaskTemplate.Resources.Limits.NanoCPUs)", subject), "cpu"
	}
	return "", ""
}

func (g *resourceLimitGuard) guardServiceWrite(w http.ResponseWriter, r *http.Request, normPath string, policy PolicyConfig, next http.Handler) {
	svc := policy.Service
	requirements := serviceRequirementsList(svc)
	if requirements == "" {
		next.ServeHTTP(w, r)
		return
	}

	isCreate := normPath == "/services/create"
	updateID, isUpdate := serviceUpdateIdentifier(normPath)

	rp := logging.GetResourcePolicyMeta()
	rp.Evaluated = true
	rp.Kind = resourcePolicyKindService
	rp.Requirements = requirements
	switch {
	case isCreate:
		rp.Operation = "create"
	default:
		rp.Operation = "update"
	}
	rp.StateSource = "request"
	manualRollback := false
	if isUpdate {
		var rollbackQueryValid bool
		manualRollback, rollbackQueryValid = serviceManualRollbackQuery(r)
		if !rollbackQueryValid {
			rp.Operation = "manual_rollback"
			g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
				"service update denied: rollback query parameter must have exactly one value", policy.DenyResponseVerbosity, rp)
			return
		}
	}

	body, err := readBoundedBody(r, maxServiceBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.respondHardDeny(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("service denied: request body exceeds %d byte limit", maxServiceBodyBytes),
				policy.DenyResponseVerbosity, rp)
			return
		}
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service denied: request body could not be read", policy.DenyResponseVerbosity, rp)
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service denied: a request body is required to verify resource requirements", policy.DenyResponseVerbosity, rp)
		return
	}
	var req serviceResourceGuardRequest
	if err := json.Unmarshal(body, &req); err != nil {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service denied: request body could not be inspected", policy.DenyResponseVerbosity, rp)
		return
	}

	if manualRollback {
		g.guardServiceManualRollback(w, r, updateID, svc, policy.DenyResponseVerbosity, rp, next)
		return
	}

	reason, violation := denyServiceCPULimitReason(req.nanoCPUs(), svc.RequireCPULimit, svc.RequireCPULimitHard, "service")
	if reason != "" {
		rp.Violation = violation
		g.respondPolicyDenied(w, r, next, reason, policy.DenyResponseVerbosity, rp)
		return
	}

	if isUpdate && req.failureActionIsRollback() {

		rp.Operation = "automatic_rollback"
		if !g.guardServiceRollbackTarget(w, r, updateID, svc, policy.DenyResponseVerbosity, rp, next, "current_spec", func(res ServiceInspectResult) int64 {
			return res.SpecNanoCPUs
		}) {
			return
		}
	}

	g.respondAllow(w, r, next, rp)
}

func (g *resourceLimitGuard) guardServiceManualRollback(w http.ResponseWriter, r *http.Request, id string, svc ServiceOptions, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta, next http.Handler) {
	rp.Operation = "manual_rollback"
	if g.guardServiceRollbackTarget(w, r, id, svc, verbosity, rp, next, "previous_spec", func(res ServiceInspectResult) int64 {
		return res.PreviousSpecNanoCPUs
	}) {
		g.respondAllow(w, r, next, rp)
	}
}

// guardServiceRollbackTarget validates the version+extract(current) against
// the requirement, denying (409) on a version mismatch and (403) on a
// noncompliant target. selectNanoCPUs picks which inspected document
// (PreviousSpec for manual rollback, Spec for the automatic-rollback current-
// state check) is being validated. Returns false when a response was already
// written (deny/error) so callers must not also call respondAllow.
func (g *resourceLimitGuard) guardServiceRollbackTarget(w http.ResponseWriter, r *http.Request, id string, svc ServiceOptions, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta, next http.Handler, stateSource string, selectNanoCPUs func(ServiceInspectResult) int64) bool {
	rp.StateSource = stateSource
	version, ok := serviceVersionQuery(r)
	if !ok {
		g.respondHardDeny(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service update denied: a single numeric version query parameter is required", verbosity, rp)
		return false
	}
	if g.inspectService == nil {
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"service update denied: resource requirement verification unavailable", verbosity, rp)
		return false
	}
	rp.StateLookup = true
	current, found, err := g.inspectService(r.Context(), id)
	if err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to inspect service for resource-limit guard", err)
		g.respondHardDeny(w, r, http.StatusBadGateway, reasonCodeResourceLimitPolicyLookupFailed,
			"service update denied: resource requirement verification unavailable", verbosity, rp)
		return false
	}
	if !found {

		g.respondAllow(w, r, next, rp)
		return false
	}
	if version != current.Version {

		g.respondHardDeny(w, r, http.StatusConflict, reasonCodeResourceLimitPolicyStateChanged,
			"service update denied: the service state changed since it was inspected; retry with the current version", verbosity, rp)
		return false
	}

	nanoCPUs := selectNanoCPUs(current)
	if stateSource == "previous_spec" && !current.HasPreviousSpec {
		nanoCPUs = 0
	}
	reason, violation := "", ""
	if (svc.RequireCPULimit || svc.RequireCPULimitHard) && nanoCPUs <= 0 {
		reason = "service update denied: rollback target does not satisfy the required CPU limit"
		violation = "cpu"
	}
	if reason != "" {
		rp.Violation = violation
		g.respondPolicyDenied(w, r, next, reason, verbosity, rp)
		return false
	}
	return true
}

// ServiceInspectResult carries the resource-limit-relevant subset of
// GET /services/{id}: the optimistic-concurrency version plus the current and
// (if any) previous spec's TaskTemplate.Resources.Limits.NanoCPUs.
type ServiceInspectResult struct {
	Version              uint64
	SpecNanoCPUs         int64
	HasPreviousSpec      bool
	PreviousSpecNanoCPUs int64
}

// ServiceInspectFunc looks up a service's current version/spec/previous-spec
// resource state by ID. found=false with err=nil means the service does not
// exist (404).
type ServiceInspectFunc func(ctx context.Context, id string) (ServiceInspectResult, bool, error)

// NewDockerServiceInspectorWithRoundTripper returns a service resource-state
// inspector that issues its GET through the shared upstream RoundTripper.
func NewDockerServiceInspectorWithRoundTripper(rt http.RoundTripper) ServiceInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, id string) (ServiceInspectResult, bool, error) {
		requestPath, ok := dockerresource.InspectPath(dockerresource.KindService, id)
		if !ok {
			return ServiceInspectResult{}, false, fmt.Errorf("no inspect path for service %q", id)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil)
		if err != nil {
			return ServiceInspectResult{}, false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return ServiceInspectResult{}, false, err
		}
		defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return ServiceInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ServiceInspectResult{}, false, fmt.Errorf("inspect service %q returned status %d", id, resp.StatusCode)
		}

		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ServiceInspectResult{}, false, err
		}

		type resourceLimits struct {
			TaskTemplate struct {
				Resources struct {
					Limits struct {
						NanoCPUs int64 `json:"NanoCPUs"`
					} `json:"Limits"`
				} `json:"Resources"`
			} `json:"TaskTemplate"`
		}
		var decoded struct {
			Version struct {
				Index uint64 `json:"Index"`
			} `json:"Version"`
			Spec         resourceLimits  `json:"Spec"`
			PreviousSpec *resourceLimits `json:"PreviousSpec"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return ServiceInspectResult{}, false, err
		}

		result := ServiceInspectResult{
			Version:      decoded.Version.Index,
			SpecNanoCPUs: decoded.Spec.TaskTemplate.Resources.Limits.NanoCPUs,
		}
		if decoded.PreviousSpec != nil {
			result.HasPreviousSpec = true
			result.PreviousSpecNanoCPUs = decoded.PreviousSpec.TaskTemplate.Resources.Limits.NanoCPUs
		}
		return result, true, nil
	}
}

// readBoundedResponseBody reads a daemon inspect response up to
// MaxResponseBodyBytes+1, rejecting oversized payloads rather than risking
// unbounded memory use on an inspect response.
func readBoundedResponseBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > MaxResponseBodyBytes {
		return nil, fmt.Errorf("inspect response exceeds %d byte limit", MaxResponseBodyBytes)
	}
	return body, nil
}

// respondAllow records an evaluated-allow outcome and forwards the request.
func (g *resourceLimitGuard) respondAllow(w http.ResponseWriter, r *http.Request, next http.Handler, rp *logging.ResourcePolicyMeta) {
	rp.Result = "allow"
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.ResourcePolicy = rp
	}
	next.ServeHTTP(w, r)
}

// respondPolicyDenied handles the one reason code (resource_limit_policy_denied)
// that honors the resolved profile's warn/audit rollout posture — a genuine
// policy violation on an otherwise well-formed, successfully-inspected
// request.
func (g *resourceLimitGuard) respondPolicyDenied(w http.ResponseWriter, r *http.Request, next http.Handler, reason string, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta) {
	meta := logging.MetaForRequest(w, r)
	if meta.AllowsPassThrough() {
		rp.Result = "would_deny"
		if meta != nil {
			meta.ResourcePolicy = rp
		}
		logging.SetWouldDenyWithCode(w, r, reasonCodeResourceLimitPolicyDenied, reason, nil)
		next.ServeHTTP(w, r)
		return
	}
	rp.Result = "deny"
	if meta != nil {
		meta.ResourcePolicy = rp
	}
	logging.SetDeniedWithCode(w, r, reasonCodeResourceLimitPolicyDenied, reason, nil)
	if err := httpjson.Write(w, http.StatusForbidden, denyResponse(r, reason, verbosity)); err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to encode resource-limit denial response", err)
	}
}

// respondHardDeny handles every OTHER reason code (invalid request, lookup
// failure, stale-state conflict) — these never honor warn/audit pass-through
// in any rollout mode: a corrupt request or an unreliable state lookup must
// not silently forward just because the profile is in warn/audit mode.
func (g *resourceLimitGuard) respondHardDeny(w http.ResponseWriter, r *http.Request, status int, reasonCode, reason string, verbosity DenyResponseVerbosity, rp *logging.ResourcePolicyMeta) {
	rp.Result = resourcePolicyResultForReasonCode(reasonCode)
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.ResourcePolicy = rp
	}
	logging.SetDeniedWithCode(w, r, reasonCode, reason, nil)
	if err := httpjson.Write(w, status, denyResponse(r, reason, verbosity)); err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to encode resource-limit denial response", err)
	}
}

// resourcePolicyResultForReasonCode maps a hard-deny reason code to its
// ResourcePolicyMeta.Result class. Everything that isn't a lookup failure or
// a stale-state conflict (request-invalid, body-too-large) is "invalid".
func resourcePolicyResultForReasonCode(reasonCode string) string {
	switch reasonCode {
	case reasonCodeResourceLimitPolicyLookupFailed:
		return "lookup_failed"
	case reasonCodeResourceLimitPolicyStateChanged:
		return "state_changed"
	default:
		return "invalid"
	}
}

// regexpCompileHook is the package-level hook for regexp compilation.
// Tests can swap this to inject errors; production always uses regexp.Compile.
// All tests in this package are sequential (no t.Parallel on tests that swap
// the hook), so no additional synchronization is needed.
var regexpCompileHook = regexp.Compile

// Action represents the result of a rule evaluation.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// ReasonNoMatchingAllowRule is the human-readable reason stamped on the
// default-deny outcome (no rule matched). Exported so the reason-code
// classifier can compare against a constant rather than a magic string;
// changing this string requires updating both this constant and the
// downstream classifier.
const ReasonNoMatchingAllowRule = "no matching allow rule"

// Rule represents a single access control rule.
type Rule struct {
	Methods []string
	Pattern string
	Action  Action
	Reason  string
	Index   int
}

type httpMethodMask uint16

const (
	httpMethodMaskGet httpMethodMask = 1 << iota
	httpMethodMaskHead
	httpMethodMaskPost
	httpMethodMaskPut
	httpMethodMaskDelete
	httpMethodMaskPatch
	httpMethodMaskOptions
	httpMethodMaskConnect
	httpMethodMaskTrace
)

type pathMatcherKind uint8

const (
	pathMatcherLiteral pathMatcherKind = iota
	pathMatcherMatchAll
	pathMatcherTrailingDeep
	pathMatcherSegmentGlob
	pathMatcherRegex
)

// CompiledRule is a rule with pre-compiled matchers for efficient evaluation.
type CompiledRule struct {
	methodMask      httpMethodMask
	unknownMethods  []string
	matchAllMethods bool
	matcherKind     pathMatcherKind
	literal         string
	literalPrefix   string
	trailingPrefix  string
	segmentPatterns []string
	pattern         *regexp.Regexp
	// Action is returned when this rule matches.
	Action Action
	// Reason is attached to the decision metadata when this rule matches.
	Reason string
	// Index is the original position of the source rule in the configured rule list.
	Index int
}

// NormalizePath canonicalizes a request path into the form policy rules are
// matched against: it resolves "." and ".." segments and collapses redundant
// slashes (path.Clean), then strips a leading Docker API version prefix.
//
// It deliberately does NOT percent-decode. The path it receives is r.URL.Path,
// which net/http's request parser has already decoded exactly once — the same
// single decode the Docker daemon's request parser applies. Decoding again
// would let sockguard resolve an escape the daemon leaves literal: a
// double-encoded "%252e", for instance, would become a "." segment that
// path.Clean collapses for sockguard while the daemon still routes it as a
// real path segment, so the two would disagree on which endpoint the request
// targets. Matching the daemon's single decode keeps sockguard's policy view
// byte-identical to the daemon's routing view.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	return stripVersionPrefix(canonicalizePath(p))
}

// canonicalizePath resolves "." / ".." segments and collapses redundant
// slashes via path.Clean, fronted by the allocation-free pathNeedsClean fast
// path. It does not percent-decode — see NormalizePath for why.
func canonicalizePath(p string) string {
	if pathNeedsClean(p) {
		p = path.Clean(p)
	}
	return p
}

// pathNeedsClean is a zero-allocation fast path in front of path.Clean so
// the overwhelmingly common case — paths that are already clean, like
// `/containers/json` or `/v1.45/_ping` — skips Clean's string allocation
// entirely. `BenchmarkNormalizePath/bare` and `/clean` report 0 B/op when
// this guard returns false; calling path.Clean unconditionally made that
// ~200ns and added two heap allocations per request. We only return true
// when the path actually has a trailing slash, a doubled slash, or a `.`
// or `..` segment — exactly the cases Clean would change.
func pathNeedsClean(p string) bool {
	if p == "/" {
		return false
	}
	if len(p) > 1 && p[len(p)-1] == '/' {
		return true
	}

	absolutePath := strings.HasPrefix(p, "/")
	hasNormalSegment := false
	segmentStart := 0
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}

		needsClean, normalSegment := pathSegmentNeedsClean(p, segmentStart, i, absolutePath, hasNormalSegment, true)
		if needsClean {
			return true
		}
		hasNormalSegment = hasNormalSegment || normalSegment
		segmentStart = i + 1
	}

	needsClean, _ := pathSegmentNeedsClean(p, segmentStart, len(p), absolutePath, hasNormalSegment, false)
	return needsClean
}

func pathSegmentNeedsClean(p string, start, end int, absolutePath, hasNormalSegment, hasMoreSegments bool) (needsClean bool, normalSegment bool) {
	if end == start {
		return start != 0, false
	}

	segmentLen := end - start
	if segmentLen == 1 && p[start] == '.' {

		if start == 0 && !absolutePath && !hasMoreSegments {
			return false, false
		}
		return true, false
	}
	if segmentLen == 2 && p[start] == '.' && p[start+1] == '.' {
		return absolutePath || hasNormalSegment, false
	}

	return false, true
}

// stripVersionPrefix removes a leading /vN.N.N/, /vN.N/, or /vN/ prefix,
// returning the path from the first slash after the version. Uses a
// hand-rolled check so the common case (no prefix) avoids regexp overhead
// entirely.
//
// Docker's own API version prefix is always /vN or /vN.N (a single optional
// minor component). Podman's libpod bindings send the full three-part semver
// of the daemon, e.g. /v5.0.0/libpod/containers/json — a second optional .N
// component is required or every libpod rule pattern silently never matches
// a versioned Podman client (#148).
func stripVersionPrefix(p string) string {

	if len(p) < 4 || p[0] != '/' || p[1] != 'v' {
		return p
	}
	i := 2

	for i < len(p) && p[i] >= '0' && p[i] <= '9' {
		i++
	}
	if i == 2 {
		return p
	}

	i = consumeOptionalDotDigits(p, i)

	i = consumeOptionalDotDigits(p, i)

	if i >= len(p) || p[i] != '/' {
		return p
	}
	return p[i:]
}

// consumeOptionalDotDigits advances i past a single ".N" component starting
// at p[i], where N is one or more ASCII digits. It returns i unchanged when
// p[i] is not '.' or the '.' is not followed by at least one digit.
func consumeOptionalDotDigits(p string, i int) int {
	if i >= len(p) || p[i] != '.' {
		return i
	}
	j := i + 1
	for j < len(p) && p[j] >= '0' && p[j] <= '9' {
		j++
	}
	if j > i+1 {
		return j
	}
	return i
}

// HasVersionPrefix reports whether p begins with a Docker API version prefix
// (e.g. "/v1.45/") that NormalizePath strips before rule matching. A rule
// pattern carrying such a prefix can never match real traffic — the request
// path is normalized first — so it is almost always an authoring mistake worth
// flagging.
func HasVersionPrefix(p string) bool {
	return stripVersionPrefix(p) != p
}

// CompileRule compiles a Rule into a CompiledRule for efficient matching.
func CompileRule(r Rule) (*CompiledRule, error) {
	var methodMask httpMethodMask
	var unknownMethods []string
	matchAllMethods := false
	for _, m := range r.Methods {
		if m == "*" {
			matchAllMethods = true
			methodMask = 0
			unknownMethods = nil
			break
		}

		upperMethod := upperHTTPMethodASCII(m)
		if bit := httpMethodBit(upperMethod); bit != 0 {
			methodMask |= bit
			continue
		}
		if !slices.Contains(unknownMethods, upperMethod) {
			unknownMethods = append(unknownMethods, upperMethod)
		}
	}

	cr := &CompiledRule{
		methodMask:      methodMask,
		unknownMethods:  unknownMethods,
		matchAllMethods: matchAllMethods,
		literalPrefix:   literalPrefixForPattern(r.Pattern),
		Action:          r.Action,
		Reason:          r.Reason,
		Index:           r.Index,
	}

	if !strings.Contains(r.Pattern, "*") {
		cr.matcherKind = pathMatcherLiteral
		cr.literal = r.Pattern
		return cr, nil
	}
	if r.Pattern == "/**" {
		cr.matcherKind = pathMatcherMatchAll
		return cr, nil
	}
	if isTrailingDoubleStarPattern(r.Pattern) {
		cr.matcherKind = pathMatcherTrailingDeep
		cr.trailingPrefix = strings.TrimSuffix(r.Pattern, "/**")
		return cr, nil
	}
	if !strings.Contains(r.Pattern, "**") {
		cr.matcherKind = pathMatcherSegmentGlob
		cr.segmentPatterns = splitGlobSegments(r.Pattern)
		return cr, nil
	}

	regexPattern := globToRegex(r.Pattern)
	compiled, err := regexpCompileHook("^" + regexPattern + "$")
	if err != nil {
		return nil, err
	}
	cr.matcherKind = pathMatcherRegex
	cr.pattern = compiled

	return cr, nil
}

func (cr *CompiledRule) matchesNormalizedUpperWithBit(upperMethod string, methodBit httpMethodMask, normalizedPath string) bool {

	if !cr.matchAllMethods {
		if methodBit != 0 {
			if cr.methodMask&methodBit == 0 {
				return false
			}
		} else if !slices.Contains(cr.unknownMethods, upperMethod) {
			return false
		}
	}

	switch cr.matcherKind {
	case pathMatcherLiteral:
		return normalizedPath == cr.literal
	case pathMatcherMatchAll:
		return true
	case pathMatcherTrailingDeep:
		return matchTrailingDoubleStar(cr.trailingPrefix, normalizedPath)
	case pathMatcherSegmentGlob:
		if cr.literalPrefix != "" && !strings.HasPrefix(normalizedPath, cr.literalPrefix) {
			return false
		}
		return matchGlobSegments(cr.segmentPatterns, normalizedPath)
	case pathMatcherRegex:
		if cr.literalPrefix != "" && !strings.HasPrefix(normalizedPath, cr.literalPrefix) {
			return false
		}
		return cr.pattern.MatchString(normalizedPath)
	default:
		return false
	}
}

// Evaluate evaluates a request against an ordered list of compiled rules.
// Returns the action and the matched rule index. If no rule matches, returns deny.
func Evaluate(rules []*CompiledRule, r *http.Request) (Action, int, string) {
	return evaluateNormalized(rules, r.Method, NormalizePath(r.URL.Path))
}

func evaluateNormalized(rules []*CompiledRule, method, normalizedPath string) (Action, int, string) {
	upperMethod := upperHTTPMethodASCII(method)
	methodBit := httpMethodBit(upperMethod)
	for _, rule := range rules {
		if rule.matchesNormalizedUpperWithBit(upperMethod, methodBit, normalizedPath) {
			return rule.Action, rule.Index, rule.Reason
		}
	}
	return ActionDeny, -1, ReasonNoMatchingAllowRule
}

func httpMethodBit(method string) httpMethodMask {
	switch method {
	case http.MethodGet:
		return httpMethodMaskGet
	case http.MethodHead:
		return httpMethodMaskHead
	case http.MethodPost:
		return httpMethodMaskPost
	case http.MethodPut:
		return httpMethodMaskPut
	case http.MethodDelete:
		return httpMethodMaskDelete
	case http.MethodPatch:
		return httpMethodMaskPatch
	case http.MethodOptions:
		return httpMethodMaskOptions
	case http.MethodConnect:
		return httpMethodMaskConnect
	case http.MethodTrace:
		return httpMethodMaskTrace
	default:
		return 0
	}
}

func upperHTTPMethodASCII(method string) string {
	firstLower := -1
	for i := 0; i < len(method); i++ {
		c := method[i]
		switch {
		case c >= utf8.RuneSelf:
			return strings.ToUpper(method)
		case 'a' <= c && c <= 'z':
			if firstLower == -1 {
				firstLower = i
			}
		}
	}

	if firstLower == -1 {
		return method
	}

	buf := make([]byte, len(method))
	copy(buf, method)
	for i := firstLower; i < len(buf); i++ {
		if 'a' <= buf[i] && buf[i] <= 'z' {
			buf[i] -= 'a' - 'A'
		}
	}
	return string(buf)
}

func isTrailingDoubleStarPattern(pattern string) bool {
	return strings.HasSuffix(pattern, "/**") && !strings.Contains(pattern[:len(pattern)-3], "*")
}

func splitGlobSegments(pattern string) []string {
	return strings.Split(strings.TrimPrefix(pattern, "/"), "/")
}

func matchTrailingDoubleStar(prefix, path string) bool {
	if prefix == "" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func matchGlobSegments(patternSegments []string, path string) bool {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return len(patternSegments) == 1 && matchGlobSegment(patternSegments[0], "")
	}

	for _, patternSegment := range patternSegments {
		if path == "" {
			return false
		}

		segment, rest, hasMore := strings.Cut(path, "/")
		if !matchGlobSegment(patternSegment, segment) {
			return false
		}
		if !hasMore {
			path = ""
			continue
		}
		path = rest
	}

	return path == ""
}

func matchGlobSegment(pattern, segment string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == segment
	}

	segmentIndex := 0
	patternIndex := 0
	starIndex := -1
	segmentRetry := 0
	for segmentIndex < len(segment) {
		if patternIndex < len(pattern) && pattern[patternIndex] == segment[segmentIndex] {
			patternIndex++
			segmentIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex] == '*' {
			starIndex = patternIndex
			patternIndex++
			segmentRetry = segmentIndex
			continue
		}
		if starIndex == -1 {
			return false
		}
		patternIndex = starIndex + 1
		segmentRetry++
		segmentIndex = segmentRetry
	}

	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
}

func literalPrefixForPattern(pattern string) string {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '*' {
			continue
		}

		prefix := pattern[:i]
		if i > 0 && pattern[i-1] == '/' && i+1 < len(pattern) && pattern[i+1] == '*' {
			suffix := pattern[i+2:]
			if suffix == "" || suffix[0] != '/' {
				return strings.TrimSuffix(prefix, "/")
			}
		}
		return prefix
	}
	return pattern
}

// GlobToRegexString converts the sockguard glob dialect to a regex string.
// Kept as a thin re-export of glob.ToRegexString for callers that already
// depend on the filter package.
func GlobToRegexString(pattern string) string {
	return glob.ToRegexString(pattern)
}

func globToRegex(pattern string) string {
	return glob.ToRegexString(pattern)
}

const maxServiceBodyBytes = 1 << 20 // 1 MiB

// ServiceOptions configures request-body inspection for service create/update.
type ServiceOptions struct {
	AllowHostNetwork   bool
	AllowedBindMounts  []string
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
	// AllowAllCapabilities / AllowedCapabilities mirror the container-create
	// CapabilityAdd allowlist for swarm task containers (ContainerSpec).
	AllowAllCapabilities bool
	AllowedCapabilities  []string
	// AllowSysctls permits ContainerSpec.Sysctls; default false denies any.
	AllowSysctls bool
	// RequireNonRootUser / RequireNoNewPrivileges / RequireReadonlyRootfs /
	// RequireDropAllCapabilities mirror the container-create hardening rails for
	// swarm task containers, enforced against ContainerSpec.User,
	// ContainerSpec.Privileges.NoNewPrivileges, ContainerSpec.ReadOnly, and
	// ContainerSpec.CapabilityDrop respectively.
	RequireNonRootUser         bool
	RequireNoNewPrivileges     bool
	RequireReadonlyRootfs      bool
	RequireDropAllCapabilities bool
	// DenyUnconfinedSeccomp denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode == "unconfined". Default false.
	// Note: does not automatically deny Mode=="custom" — see DenyCustomSeccompProfiles.
	DenyUnconfinedSeccomp bool
	// DenyCustomSeccompProfiles denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode == "custom". Operators who use
	// carefully vetted custom seccomp profiles must leave this false.
	// When both DenyUnconfinedSeccomp and DenyCustomSeccompProfiles are true,
	// only Mode=="default" (or an absent Seccomp block) is permitted.
	DenyCustomSeccompProfiles bool
	// DenyUnconfinedAppArmor denies service create/update when
	// ContainerSpec.Privileges.AppArmor.Mode == "disabled". Swarm has no
	// "unconfined" AppArmor mode; "disabled" is the equivalent. Default false.
	DenyUnconfinedAppArmor bool
	// DenySelinuxDisable denies service create/update when
	// ContainerSpec.Privileges.SELinuxContext.Disable is true — the swarm
	// equivalent of the container-create SecurityOpt label=disable that turns off
	// SELinux confinement. Default false (opt-in).
	DenySelinuxDisable bool
	// DenySelinuxLabelOverride denies service create/update that customizes the
	// SELinux context via any of ContainerSpec.Privileges.SELinuxContext.{User,
	// Role,Type,Level} — the swarm equivalent of the container-create SecurityOpt
	// label=user:/role:/type:/level: override. Default false. Independent of
	// DenySelinuxDisable.
	DenySelinuxLabelOverride bool
	// ImageTrust applies cosign verification to ContainerSpec.Image, matching
	// the container-create path so swarm services cannot escape image trust.
	ImageTrust ImageTrustOptions

	// RequireCPULimit/RequireCPULimitHard are enforced by ResourceLimitGuard
	// (resource_limit_guard.go), not by servicePolicy.inspect below — service
	// create, ordinary update, and rollback all need the guard's post-ownership
	// placement (rollback validation requires a daemon lookup). Carried on this
	// struct only so config.ServiceRequestBodyConfig.ToFilterOptions has a
	// single destination field per config leaf; servicePolicy itself never
	// reads them.
	RequireCPULimit     bool
	RequireCPULimitHard bool
}

type servicePolicy struct {
	allowHostNetwork           bool
	allowedBindMounts          []string
	imagePolicy                imagePullPolicy
	allowAllCapabilities       bool
	allowedCapabilities        []string
	allowSysctls               bool
	requireNonRootUser         bool
	requireNoNewPrivileges     bool
	requireReadonlyRootfs      bool
	requireDropAllCapabilities bool
	denyUnconfinedSeccomp      bool
	denyCustomSeccompProfiles  bool
	denyUnconfinedAppArmor     bool
	denySelinuxDisable         bool
	denySelinuxLabelOverride   bool
	imageTrust                 imageTrustFields
}

type serviceRequest struct {
	TaskTemplate struct {
		ContainerSpec serviceContainerSpec `json:"ContainerSpec"`
	} `json:"TaskTemplate"`
	Networks []serviceNetwork `json:"Networks"`
}

// serviceContainerSpec mirrors the subset of Docker's swarm ContainerSpec that
// Sockguard inspects. Identity/privilege fields (User, ReadOnly, Privileges,
// CapabilityDrop) carry the swarm equivalents of the container-create hardening
// rails so service create/update cannot bypass them.
type serviceContainerSpec struct {
	Image          string                      `json:"Image"`
	User           string                      `json:"User"`
	Mounts         []serviceMount              `json:"Mounts"`
	CapabilityAdd  []string                    `json:"CapabilityAdd"`
	CapabilityDrop []string                    `json:"CapabilityDrop"`
	Sysctls        map[string]string           `json:"Sysctls"`
	ReadOnly       bool                        `json:"ReadOnly"`
	Privileges     *serviceContainerPrivileges `json:"Privileges"`
}

// serviceContainerPrivileges captures the swarm ContainerSpec.Privileges fields
// Sockguard enforces. NoNewPrivileges is a direct ContainerSpec.Privileges boolean rather than a
// SecurityOpt string; a nil Privileges block means the flag is unset (denied).
type serviceContainerPrivileges struct {
	NoNewPrivileges bool                   `json:"NoNewPrivileges"`
	Seccomp         *serviceSeccompOpts    `json:"Seccomp"`
	AppArmor        *serviceAppArmorOpts   `json:"AppArmor"`
	SELinuxContext  *serviceSELinuxContext `json:"SELinuxContext"`
}

// serviceSELinuxContext mirrors swarm ContainerSpec.Privileges.SELinuxContext.
// Disable turns off SELinux confinement (equivalent to the container-create
// SecurityOpt label=disable); User/Role/Type/Level customize the SELinux context
// (equivalent to label=user:/role:/type:/level:). A nil block means no explicit
// SELinux context was set and is always allowed.
type serviceSELinuxContext struct {
	Disable bool   `json:"Disable"`
	User    string `json:"User"`
	Role    string `json:"Role"`
	Type    string `json:"Type"`
	Level   string `json:"Level"`
}

// serviceSeccompOpts mirrors the subset of swarm SeccompOpts that Sockguard inspects.
// Profile []byte is intentionally omitted — the proxy cannot safely decode or
// evaluate the binary blob, and the presence of Mode=="custom" is sufficient to
// enforce deny_custom_seccomp_profiles without parsing the profile content.
// Exception: a non-nil Seccomp with empty Mode and non-empty Profile is treated
// as implicit "custom" (fail-closed) when deny_custom_seccomp_profiles is true.
type serviceSeccompOpts struct {
	Mode    string          `json:"Mode"`
	Profile json.RawMessage `json:"Profile,omitempty"`
}

// serviceAppArmorOpts mirrors the subset of swarm AppArmorOpts that Sockguard inspects.
type serviceAppArmorOpts struct {
	Mode string `json:"Mode"`
}

type serviceMount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
}

type serviceNetwork struct {
	Target string `json:"Target"`
}

func newServicePolicy(opts ServiceOptions) servicePolicy {
	allowed := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeBindMount(bindMount)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return servicePolicy{
		allowHostNetwork:  opts.AllowHostNetwork,
		allowedBindMounts: allowed,
		imagePolicy: newImagePullPolicy(ImagePullOptions{
			AllowAllRegistries: opts.AllowAllRegistries,
			AllowOfficial:      opts.AllowOfficial,
			AllowedRegistries:  opts.AllowedRegistries,
		}),
		allowAllCapabilities:       opts.AllowAllCapabilities,
		allowedCapabilities:        normalizeCapabilityList(opts.AllowedCapabilities),
		allowSysctls:               opts.AllowSysctls,
		requireNonRootUser:         opts.RequireNonRootUser,
		requireNoNewPrivileges:     opts.RequireNoNewPrivileges,
		requireReadonlyRootfs:      opts.RequireReadonlyRootfs,
		requireDropAllCapabilities: opts.RequireDropAllCapabilities,
		denyUnconfinedSeccomp:      opts.DenyUnconfinedSeccomp,
		denyCustomSeccompProfiles:  opts.DenyCustomSeccompProfiles,
		denyUnconfinedAppArmor:     opts.DenyUnconfinedAppArmor,
		denySelinuxDisable:         opts.DenySelinuxDisable,
		denySelinuxLabelOverride:   opts.DenySelinuxLabelOverride,
		imageTrust:                 buildImageTrustFields(opts.ImageTrust),
	}
}

// denyImageMountReason denies any ContainerSpec.Mounts entry of Type "image"
// when image trust enforcement is active for this request — the swarm
// equivalent of containerCreatePolicy.denyImageMountReason. Docker API 1.48+
// added Type: "image" mounts, whose Source is an image reference mounted into
// the task container's filesystem rather than a bind/volume path; the
// bind-mount loop above only inspects Type == "bind" entries, so an
// image-type mount is invisible to it. Under image_trust enforce mode that
// invisibility is a trust bypass: ContainerSpec.Image is verified and
// pinned, but an image-type mount can smuggle in an arbitrary, entirely
// unverified image filesystem instead.
func (p servicePolicy) denyImageMountReason(mounts []serviceMount) string {
	if p.imageTrust.cfg.Mode != imagetrust.ModeEnforce {
		return ""
	}
	for _, mount := range mounts {
		if strings.EqualFold(mount.Type, "image") {
			return fmt.Sprintf("service denied: image mount source %q is not covered by image trust verification", mount.Source)
		}
	}
	return ""
}

// denyHardeningReason enforces the swarm equivalents of the container-create
// boolean rails against ContainerSpec. It reuses the same isNonRootUser and
// capDropContainsAll helpers so service and container policy stay in lockstep.
// NoNewPrivileges is a direct ContainerSpec.Privileges boolean rather than a
// SecurityOpt string; a nil Privileges block means the flag is unset (denied).
func (p servicePolicy) denyHardeningReason(spec serviceContainerSpec) string {
	if p.requireNoNewPrivileges && (spec.Privileges == nil || !spec.Privileges.NoNewPrivileges) {
		return "service denied: no-new-privileges is required (set ContainerSpec.Privileges.NoNewPrivileges to true)"
	}
	if p.requireNonRootUser && !isNonRootUser(spec.User) {
		return "service denied: non-root user is required (set ContainerSpec.User to a non-zero UID or non-root username)"
	}
	if p.requireReadonlyRootfs && !spec.ReadOnly {
		return "service denied: read-only root filesystem is required (set ContainerSpec.ReadOnly to true)"
	}
	if p.requireDropAllCapabilities && !capDropContainsAll(spec.CapabilityDrop) {
		return "service denied: ContainerSpec.CapabilityDrop must include \"ALL\""
	}
	if denyReason := p.denySeccompModeReason(spec.Privileges); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyAppArmorModeReason(spec.Privileges); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denySelinuxContextReason(spec.Privileges); denyReason != "" {
		return denyReason
	}
	return ""
}

// denySelinuxContextReason enforces deny_selinux_disable and
// deny_selinux_label_override against ContainerSpec.Privileges.SELinuxContext,
// the swarm equivalents of the container-create SecurityOpt label=disable and
// label=user:/role:/type:/level: overrides. A nil Privileges or SELinuxContext
// block means no explicit context was set and is always allowed.
func (p servicePolicy) denySelinuxContextReason(priv *serviceContainerPrivileges) string {
	if priv == nil || priv.SELinuxContext == nil {
		return ""
	}
	sel := priv.SELinuxContext
	if p.denySelinuxDisable && sel.Disable {
		return "service denied: SELinux disable is not allowed (ContainerSpec.Privileges.SELinuxContext.Disable)"
	}
	if p.denySelinuxLabelOverride &&
		(strings.TrimSpace(sel.User) != "" || strings.TrimSpace(sel.Role) != "" ||
			strings.TrimSpace(sel.Type) != "" || strings.TrimSpace(sel.Level) != "") {
		return "service denied: SELinux context override is not allowed (ContainerSpec.Privileges.SELinuxContext.User/Role/Type/Level)"
	}
	return ""
}

// denySeccompModeReason enforces deny_unconfined_seccomp and
// deny_custom_seccomp_profiles against ContainerSpec.Privileges.Seccomp.Mode.
// A nil Seccomp block means no explicit mode was set (Docker uses its default)
// and is always allowed. Mode comparison is case-insensitive; moby emits
// lowercase constants but third-party clients may vary.
// Fail-closed: a non-nil Seccomp with empty Mode but non-empty Profile is
// treated as implicit "custom" when deny_custom_seccomp_profiles is true,
// because the proxy cannot determine confinement intent from a bare blob.
func (p servicePolicy) denySeccompModeReason(priv *serviceContainerPrivileges) string {
	if priv == nil || priv.Seccomp == nil {
		return ""
	}
	mode := strings.TrimSpace(priv.Seccomp.Mode)
	if p.denyUnconfinedSeccomp && strings.EqualFold(mode, "unconfined") {
		return "service denied: unconfined seccomp mode is not allowed (ContainerSpec.Privileges.Seccomp.Mode)"
	}
	if p.denyCustomSeccompProfiles {
		if strings.EqualFold(mode, "custom") {
			return "service denied: custom seccomp profiles are not allowed (ContainerSpec.Privileges.Seccomp.Mode)"
		}

		if mode == "" && hasSeccompProfileBlob(priv.Seccomp.Profile) {
			return "service denied: custom seccomp profiles are not allowed (ContainerSpec.Privileges.Seccomp.Mode)"
		}
	}
	return ""
}

// hasSeccompProfileBlob reports whether a raw Seccomp.Profile carries an actual
// inline profile. JSON null decodes to RawMessage("null") (len 4, non-nil), so a
// bare length check would misread "Profile": null as a custom profile.
func hasSeccompProfileBlob(profile json.RawMessage) bool {
	trimmed := bytes.TrimSpace(profile)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// denyAppArmorModeReason enforces deny_unconfined_apparmor against
// ContainerSpec.Privileges.AppArmor.Mode. Swarm uses "disabled" where
// container-create uses "unconfined"; both mean "no AppArmor confinement".
// A nil AppArmor block means no explicit mode was set and is always allowed.
func (p servicePolicy) denyAppArmorModeReason(priv *serviceContainerPrivileges) string {
	if priv == nil || priv.AppArmor == nil {
		return ""
	}
	mode := strings.TrimSpace(priv.AppArmor.Mode)
	if p.denyUnconfinedAppArmor && strings.EqualFold(mode, "disabled") {
		return "service denied: disabled apparmor mode is not allowed (ContainerSpec.Privileges.AppArmor.Mode)"
	}
	return ""
}

func (p servicePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isServiceWritePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxServiceBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("service denied: request body exceeds %d byte limit", maxServiceBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req serviceRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "service request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "service denied: request body could not be inspected", nil
	}

	if !p.allowHostNetwork {
		for _, network := range req.Networks {
			if strings.EqualFold(strings.TrimSpace(network.Target), "host") {
				return "service denied: host network is not allowed", nil
			}
		}
	}

	for _, mount := range req.TaskTemplate.ContainerSpec.Mounts {
		if !strings.EqualFold(mount.Type, "bind") {
			continue
		}
		source, ok := normalizeBindMount(mount.Source)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("service denied: bind mount source %q is not allowlisted", source), nil
	}

	if denyReason := p.denyImageMountReason(req.TaskTemplate.ContainerSpec.Mounts); denyReason != "" {
		return denyReason, nil
	}

	if denyReason := p.denyHardeningReason(req.TaskTemplate.ContainerSpec); denyReason != "" {
		return denyReason, nil
	}

	if denyReason := capabilityAddDenyReason(req.TaskTemplate.ContainerSpec.CapabilityAdd, p.allowAllCapabilities, p.allowedCapabilities, "service"); denyReason != "" {
		return denyReason, nil
	}
	if !p.allowSysctls && len(req.TaskTemplate.ContainerSpec.Sysctls) > 0 {
		return "service denied: setting sysctls is not allowed", nil
	}

	if denyReason := p.imagePolicy.denyReasonForReference(strings.TrimSpace(req.TaskTemplate.ContainerSpec.Image), "service"); denyReason != "" {
		return denyReason, nil
	}

	if p.imageTrust.initErr != nil {
		return fmt.Sprintf("service denied: image trust policy initialization error: %s", p.imageTrust.initErr.Error()), nil
	}
	if p.imageTrust.verifier != nil {
		imageRef := strings.TrimSpace(req.TaskTemplate.ContainerSpec.Image)
		denyReason, verifiedDigest := verifyImageTrust(r.Context(), logger, p.imageTrust, imageRef, "service")
		if denyReason != "" {
			return denyReason, nil
		}
		if verifiedDigest != "" {
			pinned, perr := imagefetch.PinnedReference(imageRef, verifiedDigest)
			if perr != nil {

				return "", fmt.Errorf("pin verified image digest: %w", perr)
			}
			if pinned != imageRef {
				rewritten, rerr := rewriteServiceImage(body, pinned)
				if rerr != nil {
					return "", fmt.Errorf("pin verified image digest: %w", rerr)
				}
				r.Body = io.NopCloser(bytes.NewReader(rewritten))
				r.ContentLength = int64(len(rewritten))
			}
		}
	}

	return "", nil
}

// rewriteServiceImage replaces TaskTemplate.ContainerSpec.Image with pinned,
// preserving every other field byte-for-byte (RawMessage) so resource limits
// and other numeric fields are not corrupted by a float round-trip.
//
// Every level is navigated case-insensitively, and a duplicate case-variant
// key at any level (TaskTemplate, ContainerSpec, or the Image leaf) is rejected
// fail-closed: Docker decodes these keys case-insensitively and honors the last
// duplicate after our re-marshal, so a shadow lowercase "image"/"containerspec"
// key would otherwise let a client run an image the cosign policy check — which
// decodes the same body via a struct — never verified. Collapsing the leaf to a
// single canonical "Image" key pins exactly the verified image at the daemon.
func rewriteServiceImage(body []byte, pinned string) ([]byte, error) {
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	ttKey, err := soleFoldedRawKey(top, "TaskTemplate")
	if err != nil {
		return nil, fmt.Errorf("service body: %w", err)
	}
	var taskTemplate map[string]json.RawMessage
	if err := json.Unmarshal(top[ttKey], &taskTemplate); err != nil {
		return nil, fmt.Errorf("decode TaskTemplate: %w", err)
	}
	csKey, err := soleFoldedRawKey(taskTemplate, "ContainerSpec")
	if err != nil {
		return nil, fmt.Errorf("service body: %w", err)
	}
	var containerSpec map[string]json.RawMessage
	if err := json.Unmarshal(taskTemplate[csKey], &containerSpec); err != nil {
		return nil, fmt.Errorf("decode ContainerSpec: %w", err)
	}
	if err := collapseImageKey(containerSpec, pinned); err != nil {
		return nil, err
	}

	csRaw, err := json.Marshal(containerSpec)
	if err != nil {
		return nil, err
	}
	delete(taskTemplate, csKey)
	taskTemplate["ContainerSpec"] = csRaw
	ttRaw, err := json.Marshal(taskTemplate)
	if err != nil {
		return nil, err
	}
	delete(top, ttKey)
	top["TaskTemplate"] = ttRaw
	return json.Marshal(top)
}

func isServiceWritePath(normalizedPath string) bool {
	switch {
	case normalizedPath == "/services/create":
		return true
	case strings.HasPrefix(normalizedPath, "/services/"):
		_, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/services/"), "/")
		return ok && tail == "update"
	default:
		return false
	}
}

const maxSwarmBodyBytes = 256 << 10 // 256 KiB

// SwarmOptions configures request-body inspection for swarm writes.
type SwarmOptions struct {
	AllowForceNewCluster          bool
	AllowExternalCA               bool
	AllowedJoinRemoteAddrs        []string
	AllowTokenRotation            bool
	AllowManagerUnlockKeyRotation bool
	AllowAutoLockManagers         bool
	AllowSigningCAUpdate          bool
	AllowUnlock                   bool
}

type swarmPolicy struct {
	allowForceNewCluster          bool
	allowExternalCA               bool
	allowedJoinRemoteAddrs        []string
	allowTokenRotation            bool
	allowManagerUnlockKeyRotation bool
	allowAutoLockManagers         bool
	allowSigningCAUpdate          bool
	allowUnlock                   bool
}

type swarmInitRequest struct {
	ForceNewCluster bool            `json:"ForceNewCluster"`
	Spec            swarmSpecConfig `json:"Spec"`
}

type swarmJoinRequest struct {
	ListenAddr    string   `json:"ListenAddr"`
	AdvertiseAddr string   `json:"AdvertiseAddr"`
	DataPathAddr  string   `json:"DataPathAddr"`
	RemoteAddrs   []string `json:"RemoteAddrs"`
	JoinToken     string   `json:"JoinToken"`
}

type swarmUpdateRequest struct {
	CAConfig         swarmCAConfig `json:"CAConfig"`
	EncryptionConfig struct {
		AutoLockManagers bool `json:"AutoLockManagers"`
	} `json:"EncryptionConfig"`
}

type swarmUnlockRequest struct {
	UnlockKey string `json:"UnlockKey"`
}

type swarmSpecConfig struct {
	CAConfig swarmCAConfig `json:"CAConfig"`
}

type swarmCAConfig struct {
	ExternalCAs   []json.RawMessage `json:"ExternalCAs"`
	SigningCACert string            `json:"SigningCACert"`
	SigningCAKey  string            `json:"SigningCAKey"`
	ForceRotate   uint64            `json:"ForceRotate"`
}

func newSwarmPolicy(opts SwarmOptions) swarmPolicy {
	return swarmPolicy{
		allowForceNewCluster:          opts.AllowForceNewCluster,
		allowExternalCA:               opts.AllowExternalCA,
		allowedJoinRemoteAddrs:        normalizeSwarmRemoteAddrs(opts.AllowedJoinRemoteAddrs),
		allowTokenRotation:            opts.AllowTokenRotation,
		allowManagerUnlockKeyRotation: opts.AllowManagerUnlockKeyRotation,
		allowAutoLockManagers:         opts.AllowAutoLockManagers,
		allowSigningCAUpdate:          opts.AllowSigningCAUpdate,
		allowUnlock:                   opts.AllowUnlock,
	}
}

func (p swarmPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil {
		return "", nil
	}

	switch normalizedPath {
	case "/swarm/init":
		return p.inspectInit(logger, r)
	case "/swarm/join":
		return p.inspectJoin(logger, r)
	case "/swarm/update":
		return p.inspectUpdate(logger, r)
	case "/swarm/unlock":
		return p.inspectUnlock(logger, r)
	default:
		return "", nil
	}
}

func (p swarmPolicy) inspectInit(logger *slog.Logger, r *http.Request) (string, error) {
	body, err := readBoundedBody(r, maxSwarmBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("swarm init denied: request body exceeds %d byte limit", maxSwarmBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req swarmInitRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "swarm init request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "swarm init denied: request body could not be inspected", nil
	}

	if !p.allowForceNewCluster && req.ForceNewCluster {
		return "swarm init denied: force-new-cluster is not allowed", nil
	}
	if !p.allowExternalCA && len(req.Spec.CAConfig.ExternalCAs) > 0 {
		return "swarm init denied: external CAs are not allowed", nil
	}
	if !p.allowSigningCAUpdate && hasSwarmSigningCAUpdate(req.Spec.CAConfig) {
		return "swarm init denied: signing CA updates are not allowed", nil
	}

	return "", nil
}

func (p swarmPolicy) inspectJoin(logger *slog.Logger, r *http.Request) (string, error) {
	body, err := readBoundedBody(r, maxSwarmBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("swarm join denied: request body exceeds %d byte limit", maxSwarmBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req swarmJoinRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "swarm join request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "swarm join denied: request body could not be inspected", nil
	}

	for _, remoteAddr := range req.RemoteAddrs {
		normalized := normalizeSwarmRemoteAddr(remoteAddr)
		if normalized == "" || p.joinRemoteAddrAllowed(normalized) {
			continue
		}
		return fmt.Sprintf("swarm join denied: remote address %q is not allowlisted", normalized), nil
	}

	return "", nil
}

func (p swarmPolicy) inspectUpdate(logger *slog.Logger, r *http.Request) (string, error) {
	body, err := readBoundedBody(r, maxSwarmBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("swarm update denied: request body exceeds %d byte limit", maxSwarmBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req swarmUpdateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "swarm update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "swarm update denied: request body could not be inspected", nil
	}

	if !p.allowExternalCA && len(req.CAConfig.ExternalCAs) > 0 {
		return "swarm update denied: external CAs are not allowed", nil
	}
	if !p.allowSigningCAUpdate && hasSwarmSigningCAUpdate(req.CAConfig) {
		return "swarm update denied: signing CA updates are not allowed", nil
	}
	if !p.allowAutoLockManagers && req.EncryptionConfig.AutoLockManagers {
		return "swarm update denied: manager autolock is not allowed", nil
	}
	if !p.allowTokenRotation && queryBool(r, "rotateWorkerToken") {
		return "swarm update denied: worker token rotation is not allowed", nil
	}
	if !p.allowTokenRotation && queryBool(r, "rotateManagerToken") {
		return "swarm update denied: manager token rotation is not allowed", nil
	}
	if !p.allowManagerUnlockKeyRotation && queryBool(r, "rotateManagerUnlockKey") {
		return "swarm update denied: manager unlock key rotation is not allowed", nil
	}

	return "", nil
}

func (p swarmPolicy) inspectUnlock(logger *slog.Logger, r *http.Request) (string, error) {
	body, err := readBoundedBody(r, maxSwarmBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("swarm unlock denied: request body exceeds %d byte limit", maxSwarmBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req swarmUnlockRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "swarm unlock request body could not be decoded for Sockguard policy inspection; denying", err)
		return "swarm unlock denied: request body could not be inspected", nil
	}

	if !p.allowUnlock {
		return "swarm unlock denied: swarm unlock is not allowed", nil
	}

	return "", nil
}

func normalizeSwarmRemoteAddrs(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := normalizeSwarmRemoteAddr(value)
		if trimmed == "" || slices.Contains(normalized, trimmed) {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func normalizeSwarmRemoteAddr(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (p swarmPolicy) joinRemoteAddrAllowed(remoteAddr string) bool {
	return slices.Contains(p.allowedJoinRemoteAddrs, remoteAddr)
}

func hasSwarmSigningCAUpdate(cfg swarmCAConfig) bool {
	return strings.TrimSpace(cfg.SigningCACert) != "" || strings.TrimSpace(cfg.SigningCAKey) != "" || cfg.ForceRotate > 0
}

func queryBool(r *http.Request, name string) bool {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	switch strings.ToLower(raw) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

const maxVolumeBodyBytes = 1 << 20 // 1 MiB

// VolumeOptions configures request-body policy checks for POST /volumes/create.
type VolumeOptions struct {
	AllowCustomDrivers bool
	AllowDriverOpts    bool
}

type volumePolicy struct {
	allowCustomDrivers bool
	allowDriverOpts    bool
}

type volumeCreateRequest struct {
	Driver     string            `json:"Driver"`
	DriverOpts map[string]string `json:"DriverOpts"`
	Opts       map[string]string `json:"Opts"`
}

func newVolumePolicy(opts VolumeOptions) volumePolicy {
	return volumePolicy{
		allowCustomDrivers: opts.AllowCustomDrivers,
		allowDriverOpts:    opts.AllowDriverOpts,
	}
}

func (p volumePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/volumes/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxVolumeBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("volume create denied: request body exceeds %d byte limit", maxVolumeBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req volumeCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "volume create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "volume create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !strings.EqualFold(driver, "local") && !p.allowCustomDrivers {
		return fmt.Sprintf("volume create denied: driver %q is not allowed", driver), nil
	}

	if !p.allowDriverOpts && len(req.DriverOpts)+len(req.Opts) > 0 {
		return "volume create denied: driver options are not allowed", nil
	}

	return "", nil
}
