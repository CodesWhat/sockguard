package visibility

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/app/internal/dockerclient"
	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/inspectcache"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

// patternBufferPool pools bytes.Buffer instances so the pattern-filter writer
// avoids fresh allocations + grow-copies for every list-endpoint response.
// One buffer per writer collects the upstream body; flushFiltered acquires a
// second buffer for the filtered output. Both are returned to the pool after
// the response bytes are copied into the underlying writer.
var patternBufferPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func acquirePatternBuffer() *bytes.Buffer {
	buf, _ := patternBufferPool.Get().(*bytes.Buffer)
	if buf == nil {
		buf = &bytes.Buffer{}
	}
	buf.Reset()
	return buf
}

func releasePatternBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	patternBufferPool.Put(buf)
}

const (
	reasonCodeVisibilityPolicyMisconfigured = "visibility_policy_misconfigured"
	reasonCodeVisibilityProfileUnresolved   = "visibility_profile_unresolved"
	reasonCodeVisibilityFilterInvalid       = "visibility_filter_invalid"
	reasonCodeVisibilityPolicyLookupFailed  = "visibility_policy_lookup_failed"
	reasonCodeVisibilityPolicyHidResource   = "visibility_policy_hid_resource"
	reasonCodeVisibilityResponseTooLarge    = "visibility_response_too_large"
	reasonCodeVisibilityPodmanEvents        = "visibility_podman_events_unscopeable"
	reasonCodeVisibilityLibpodDataUsage     = "visibility_libpod_data_usage_unscopeable"
)

// Options configures label-based visibility control on Docker read endpoints.
type Options struct {
	VisibleResourceLabels []string
	// NamePatterns is a list of glob patterns matched against container Names[0]
	// (leading "/" stripped) and image RepoTags short names. When non-empty,
	// a resource must match at least one pattern to be visible.
	NamePatterns []string
	// ImagePatterns is a list of glob patterns matched against the container
	// Image field and image RepoTags full references. When non-empty, a
	// resource must match at least one pattern to be visible.
	ImagePatterns  []string
	Profiles       map[string]Policy
	ResolveProfile func(*http.Request) (string, bool)
	// UpstreamFlavor is the engine behind the upstream socket, resolved at
	// startup from upstream.flavor (see internal/upstreamflavor). It changes
	// exactly one thing: how GET /events is handled, because Podman evaluates
	// several values under one event filter key disjunctively where dockerd
	// ANDs them, so the append-style injection every other list endpoint uses
	// widens that stream on Podman instead of narrowing it.
	//
	// The zero value means Docker — the semantics every construction site had
	// before this field existed. `auto` never resolves to the zero value:
	// resolveUpstreamFlavor fails startup rather than leaving it empty, so
	// production always sets it explicitly and
	// TestServeChainPassesResolvedFlavorToVisibility pins that wiring.
	UpstreamFlavor upstreamflavor.Flavor
}

// Policy defines per-profile visibility overrides.
type Policy struct {
	VisibleResourceLabels []string
	// NamePatterns is a per-profile glob pattern list. See Options.NamePatterns.
	NamePatterns []string
	// ImagePatterns is a per-profile glob pattern list. See Options.ImagePatterns.
	ImagePatterns []string
}

type compiledSelector struct {
	key      string
	value    string
	hasValue bool
}

// compiledPolicy holds the compiled visibility policy for a single scope
// (default or per-profile). All axes are ANDed: a resource must pass every
// configured axis to be considered visible.
type compiledPolicy struct {
	selectors     []compiledSelector
	namePatterns  []compiledPattern
	imagePatterns []compiledPattern
}

// hasPatternAxes reports whether either the name or image pattern axis is set.
func (p *compiledPolicy) hasPatternAxes() bool {
	return len(p.namePatterns) > 0 || len(p.imagePatterns) > 0
}

// resourceMeta holds name and image reference metadata fetched from Docker for
// pattern-axis visibility checks. Only populated when at least one pattern axis
// is configured on the active policy.
type resourceMeta struct {
	// names holds container names as returned by Docker (e.g. ["/traefik"]).
	names []string
	// image is the container's Image field (may be an image ID or ref).
	image string
	// repoTags is the image's RepoTags (e.g. ["traefik:latest"]).
	repoTags []string
}

type resourceDetails struct {
	labels map[string]string
	meta   *resourceMeta
}

type visibilityDeps struct {
	inspectResource        func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error)
	inspectExec            func(context.Context, string) (string, bool, error)
	inspectResourceMeta    func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error)
	inspectResourceDetails func(context.Context, dockerresource.Kind, string) (*resourceDetails, bool, error)
}

type upstreamInspector struct {
	client *http.Client
}

// Middleware enforces label-based visibility on list, events, and inspect
// reads. Requests to hidden resources fail closed with a 404 so callers do not
// gain an oracle for resource existence.
func Middleware(upstreamSocket string, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	return middlewareWithDeps(logger, opts, newVisibilityDeps(upstreamSocket))
}

// MiddlewareWithRoundTripper is Middleware over the shared upstream RoundTripper
// (typically an *upstream.Resolver) so visibility inspects follow the same
// active endpoint as the proxied request under failover.
func MiddlewareWithRoundTripper(rt http.RoundTripper, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	return middlewareWithDeps(logger, opts, newVisibilityDepsClient(dockerclient.NewWithRoundTripper(rt)))
}

func middlewareWithDeps(logger *slog.Logger, opts Options, deps visibilityDeps) func(http.Handler) http.Handler {
	defaultPolicy, mergedProfilePolicies, ok := compileVisibilityPolicies(logger, opts)
	if !ok {
		return misconfiguredVisibilityMiddleware()
	}

	if len(defaultPolicy.selectors) == 0 && !defaultPolicy.hasPatternAxes() && len(mergedProfilePolicies) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	// Hoisted out of the request closure: the flavor is fixed for the life of
	// the process (upstream.flavor is reload-immutable and the chain is
	// rebuilt on reload anyway), so the request path compares a bool rather
	// than a string.
	podmanUpstream := opts.UpstreamFlavor == upstreamflavor.Podman

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			effectivePolicy, ok := resolveEffectivePolicy(opts, mergedProfilePolicies, defaultPolicy, w, r)
			if !ok {
				return
			}

			hasSelectors := len(effectivePolicy.selectors) > 0
			hasPatterns := effectivePolicy.hasPatternAxes()
			if (!hasSelectors && !hasPatterns) || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
				next.ServeHTTP(w, r)
				return
			}

			normPath := normalizedPathForRequest(w, r)
			// GET /system/df enumerates every container, volume and image on
			// the host and accepts no `filters` query parameter, so it can only
			// be constrained on the response. It is deliberately NOT in
			// needsVisibilityLabelFilter: injecting a `filters=` param the
			// endpoint does not define would be meaningless at best.
			if r.Method == http.MethodGet && normPath == responsefilter.SystemDataUsagePath {
				handleVisibilitySystemDataUsageRequest(logger, next, w, r, &effectivePolicy)
				return
			}
			// On a Podman upstream the Docker-compat GET /events is the same
			// handler Podman serves /libpod/events from, and it evaluates
			// several values under one filter key disjunctively. The
			// append-style injection below would widen that stream rather
			// than narrow it, so it gets a single-selector replacement and a
			// refusal when the policy carries more. Docker upstreams take the
			// ordinary list path here, unchanged. See podmanEventsDenyReason.
			if podmanUpstream && normPath == compatEventsPath {
				handlePodmanCompatEventsRequest(next, w, r, &effectivePolicy)
				return
			}
			// Podman's native GET /libpod/system/df has the same
			// no-`filters`-parameter problem and no response the policy can be
			// applied to either: its image, container and volume entries carry
			// no labels, so neither the selector axes nor the name/image
			// pattern axes have a field to read. It is refused rather than
			// filtered — see
			// responsefilter.LibpodSystemDataUsageDenyReason.
			if r.Method == http.MethodGet && normPath == responsefilter.LibpodSystemDataUsagePath {
				denyLibpodSystemDataUsage(w, r)
				return
			}
			if needsVisibilityLabelFilter(normPath) {
				handleVisibilityListRequest(logger, next, w, r, normPath, &effectivePolicy, hasSelectors, hasPatterns)
				return
			}

			handleVisibilityInspectRequest(logger, next, deps, w, r, normPath, &effectivePolicy)
		})
	}
}

// compileVisibilityPolicies compiles the default and per-profile visibility
// policies once at construction. Profiles are reload-immutable, so cloning
// selectors/patterns on every request to compute the same merged
// compiledPolicy would be wasted work — each map entry holds the final
// merged compiledPolicy that requests reference by pointer. Returns ok=false
// after logging when any compilation fails so the caller can install the
// misconfigured-middleware fallback.
func compileVisibilityPolicies(logger *slog.Logger, opts Options) (compiledPolicy, map[string]compiledPolicy, bool) {
	defaultPolicy, err := compilePolicy(opts.VisibleResourceLabels, opts.NamePatterns, opts.ImagePatterns)
	if err != nil {
		logger.Error("invalid visibility config", "error", err)
		return compiledPolicy{}, nil, false
	}
	warnPatternsWithoutSelectors(logger, "default", defaultPolicy)
	defaultWarned := defaultPolicy.hasPatternAxes() && len(defaultPolicy.selectors) == 0
	merged := make(map[string]compiledPolicy, len(opts.Profiles))
	for name, policy := range opts.Profiles {
		compiled, err := compilePolicy(policy.VisibleResourceLabels, policy.NamePatterns, policy.ImagePatterns)
		if err != nil {
			logger.Error("invalid visibility profile config", "profile", name, "error", err)
			return compiledPolicy{}, nil, false
		}
		mergedPolicy := compiledPolicy{
			selectors:     appendUniqueSelectors(slices.Clone(defaultPolicy.selectors), compiled.selectors...),
			namePatterns:  append(slices.Clone(defaultPolicy.namePatterns), compiled.namePatterns...),
			imagePatterns: append(slices.Clone(defaultPolicy.imagePatterns), compiled.imagePatterns...),
		}
		// Skip the per-profile warning when the default already warned — every
		// profile inherits the default's pattern axes, so it would just repeat
		// the same root cause N times.
		if !defaultWarned {
			warnPatternsWithoutSelectors(logger, "profile "+name, mergedPolicy)
		}
		merged[name] = mergedPolicy
	}
	return defaultPolicy, merged, true
}

// warnPatternsWithoutSelectors logs once at construction when a visibility
// policy carries name/image patterns but no label selector. Pattern response
// filtering only covers /containers/json and /images/json (see
// needsPatternResponseFilter); every other visibility-aware list endpoint —
// /events in particular — is constrained solely by the label selectors injected
// into the upstream filter. So a patterns-only policy silently leaves /events
// (and /networks, /volumes, /services, …) unrestricted.
func warnPatternsWithoutSelectors(logger *slog.Logger, scope string, policy compiledPolicy) {
	if logger == nil || !policy.hasPatternAxes() || len(policy.selectors) > 0 {
		return
	}
	logger.Warn("visibility name/image patterns are set without any visible_resource_labels selector; "+
		"pattern filtering only applies to containers and images (/containers/json, /images/json, and the "+
		"matching sections of /system/df), so /events and the other list endpoints stay unrestricted. "+
		"Add a label selector to constrain them",
		"scope", scope)
}

func misconfiguredVisibilityMiddleware() func(http.Handler) http.Handler {
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyMisconfigured, "visibility policy misconfigured", filter.NormalizePath)
			_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility policy misconfigured"})
		})
	}
}

// resolveEffectivePolicy picks the per-request policy based on the optional
// profile resolver. Returns ok=false after writing a denial response when a
// profile was named but not registered.
func resolveEffectivePolicy(opts Options, profiles map[string]compiledPolicy, defaultPolicy compiledPolicy, w http.ResponseWriter, r *http.Request) (compiledPolicy, bool) {
	if opts.ResolveProfile == nil {
		return defaultPolicy, true
	}
	profileName, ok := opts.ResolveProfile(r)
	if !ok || profileName == "" {
		return defaultPolicy, true
	}
	profile, found := profiles[profileName]
	if !found {
		logging.SetDeniedWithCode(w, r, reasonCodeVisibilityProfileUnresolved, "visibility profile could not be resolved", filter.NormalizePath)
		_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility profile could not be resolved"})
		return compiledPolicy{}, false
	}
	return profile, true
}

// handleVisibilityListRequest applies selector-based label filter injection
// and (where supported) pattern-based response filtering for list endpoints.
func handleVisibilityListRequest(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, normPath string, policy *compiledPolicy, hasSelectors, hasPatterns bool) {
	if hasSelectors {
		forwarded, err := addVisibilityLabelFilters(r, normPath, policy.selectors)
		if err != nil {
			logging.SetDeniedWithCode(w, r, reasonCodeVisibilityFilterInvalid, err.Error(), nil)
			_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
			return
		}
		// Forward the returned request: it carries the record of which label
		// values this layer injected, which ownership reads downstream.
		r = forwarded
	}
	if hasPatterns && needsPatternResponseFilter(normPath) {
		filterResponseThroughWriter(logger, next, w, r, "visibility pattern list filter failed", func(fw *patternFilterWriter) error {
			return fw.flushFiltered(normPath, policy)
		})
		return
	}
	next.ServeHTTP(w, r)
}

// filterResponseThroughWriter runs next with a response-buffering writer,
// applies flush to the buffered body, and converts an oversized upstream
// response or a flush failure into a fail-closed 502. Both the pattern-filtered
// list endpoints and GET /system/df share this plumbing; only the flush step
// differs.
func filterResponseThroughWriter(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, failureReason string, flush func(*patternFilterWriter) error) {
	interceptingW := newPatternFilterWriter(w)
	defer interceptingW.release()
	next.ServeHTTP(interceptingW, r)
	if interceptingW.overflow {
		logger.ErrorContext(r.Context(), "visibility response filter: upstream response exceeds size limit",
			"limit_bytes", filter.MaxResponseBodyBytes, "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
		logging.SetDeniedWithCode(w, r, reasonCodeVisibilityResponseTooLarge, "upstream response too large to filter", nil)
		clearUpstreamRepresentationHeaders(w.Header())
		_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "upstream response too large to filter"})
		return
	}
	if err := flush(interceptingW); err != nil {
		logger.ErrorContext(r.Context(), failureReason, "error", logging.SafeString(err.Error()))
		if !interceptingW.headerWritten {
			// failureReason names which flush step failed, so the 502 body and
			// the log record agree. Hard-coding the pattern-filter wording here
			// told an operator debugging a /system/df 502 to go and look at the
			// pattern axes, which are not what ran.
			logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyLookupFailed, failureReason, nil)
			clearUpstreamRepresentationHeaders(w.Header())
			_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: failureReason})
		}
	}
}

// clearUpstreamRepresentationHeaders delegates to responsefilter so the header
// list has exactly one definition; the ownership middleware's /system/df
// interceptor needs the same one.
func clearUpstreamRepresentationHeaders(header http.Header) {
	responsefilter.ClearUpstreamRepresentationHeaders(header)
}

// handleVisibilityInspectRequest applies the inspect / single-resource
// visibility check and either forwards the request or returns 404 when the
// resource fails the policy.
func handleVisibilityInspectRequest(logger *slog.Logger, next http.Handler, deps visibilityDeps, w http.ResponseWriter, r *http.Request, normPath string, policy *compiledPolicy) {
	visible, err := requestVisibleWithPolicy(r.Context(), normPath, policy, deps)
	if err != nil {
		logger.ErrorContext(r.Context(), "visibility policy lookup failed", "error", logging.SafeString(err.Error()), "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
		logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyLookupFailed, "visibility policy lookup failed", nil)
		_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "visibility policy lookup failed"})
		return
	}
	if !visible {
		// #148 design doc item 5: prefix the human-readable reason for
		// libpod-family requests, matching internal/filter's libpod_*.go
		// inspectors' "libpod ... denied" convention.
		reason := "visibility policy hid resource"
		if isLibpodVisibilityPath(normPath) {
			reason = "libpod " + reason
		}
		// In warn / audit rollout mode, surface a would_deny verdict and let
		// the request reach the upstream so operators can measure visibility
		// impact before enforcing — consistent with every other deny gate.
		if meta := logging.MetaForRequest(w, r); meta.AllowsPassThrough() {
			logging.SetWouldDenyWithCode(w, r, reasonCodeVisibilityPolicyHidResource, reason, nil)
			next.ServeHTTP(w, r)
			return
		}
		logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyHidResource, reason, nil)
		_ = httpjson.Write(w, http.StatusNotFound, httpjson.ErrorResponse{Message: "resource not found"})
		return
	}
	next.ServeHTTP(w, r)
}

// needsPatternResponseFilter reports whether the given normalized path is a
// list endpoint for which we support response-body pattern filtering.
func needsPatternResponseFilter(normPath string) bool {
	return normPath == "/containers/json" || normPath == "/images/json"
}

// patternFilterWriter is a response-intercepting http.ResponseWriter that
// buffers the body so we can filter the JSON array before forwarding it.
// body is drawn from patternBufferPool and must be released via release()
// once flushFiltered has copied any retained bytes into the underlying writer.
type patternFilterWriter struct {
	underlying    http.ResponseWriter
	header        http.Header
	statusCode    int
	body          *bytes.Buffer
	headerWritten bool
	// overflow is set once the buffered body would exceed
	// filter.MaxResponseBodyBytes. Further bytes are discarded so the buffer
	// stays bounded; the caller turns the flag into a 502 once the upstream
	// copy completes.
	overflow bool
}

func newPatternFilterWriter(w http.ResponseWriter) *patternFilterWriter {
	return &patternFilterWriter{
		underlying: w,
		header:     w.Header(),
		statusCode: http.StatusOK,
		body:       acquirePatternBuffer(),
	}
}

func (p *patternFilterWriter) release() {
	releasePatternBuffer(p.body)
	p.body = nil
}

func (p *patternFilterWriter) Header() http.Header  { return p.header }
func (p *patternFilterWriter) WriteHeader(code int) { p.statusCode = code }

// Write buffers the upstream body until it reaches filter.MaxResponseBodyBytes.
// Past that cap it discards further bytes but still reports them as written so
// httputil.ReverseProxy completes its copy normally (returning an error here
// would make ReverseProxy panic with http.ErrAbortHandler, skipping the clean
// 502 path). The overflow flag bounds memory; flushFiltered / the caller turn
// it into a 502 once the copy finishes.
func (p *patternFilterWriter) Write(b []byte) (int, error) {
	if !p.overflow {
		if int64(p.body.Len())+int64(len(b)) > filter.MaxResponseBodyBytes {
			p.overflow = true
		} else {
			return p.body.Write(b)
		}
	}
	return len(b), nil
}

// mustHaveEmptyBody reports whether the given HTTP status code requires an
// empty body per RFC 9110. Writing any bytes for these codes causes Go's
// http.ResponseWriter to downgrade the response to 502.
func mustHaveEmptyBody(code int) bool {
	switch code {
	case http.StatusNoContent, http.StatusNotModified:
		return true
	default:
		return false
	}
}

// commitIfUnfilterable forwards the buffered response untouched for the status
// codes no body filter applies to, reporting committed=true when it already
// wrote the response. Shared by flushFiltered and flushSystemDataUsage so both
// treat 204/304 and non-2xx identically.
func (p *patternFilterWriter) commitIfUnfilterable() (bool, error) {
	// RFC 9110 §15.4.5 / §15.3.5: 204 and 304 must have an empty body.
	// Writing any bytes triggers an http.ResponseWriter downgrade to 502.
	if mustHaveEmptyBody(p.statusCode) {
		p.underlying.WriteHeader(p.statusCode)
		p.headerWritten = true
		return true, nil
	}

	// Only filter 2xx responses with a JSON body; pass through everything else.
	if p.statusCode < http.StatusOK || p.statusCode >= http.StatusMultipleChoices {
		p.underlying.WriteHeader(p.statusCode)
		p.headerWritten = true
		_, err := p.underlying.Write(p.body.Bytes())
		return true, err
	}
	return false, nil
}

// commitFilteredBody writes body as the final response, setting Content-Length
// so the rewritten length replaces the upstream's.
func (p *patternFilterWriter) commitFilteredBody(body []byte) error {
	p.underlying.Header().Set("Content-Length", strconv.Itoa(len(body)))
	p.underlying.WriteHeader(p.statusCode)
	p.headerWritten = true
	_, err := p.underlying.Write(body)
	return err
}

// flushFiltered filters the buffered JSON array response by pattern axes and
// writes the result to the underlying ResponseWriter.
//
// The body is streamed through a json.Decoder rather than fully Unmarshalled
// into []json.RawMessage; that avoids the outer slice allocation on
// large list responses (hundreds of containers/images) while preserving the
// per-item visibility check. Filtered items are encoded into a pooled output
// buffer so Content-Length can be set before WriteHeader.
func (p *patternFilterWriter) flushFiltered(normPath string, policy *compiledPolicy) error {
	if committed, err := p.commitIfUnfilterable(); committed {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(p.body.Bytes()))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		// Not a JSON array — pass through unchanged.
		p.underlying.WriteHeader(p.statusCode)
		p.headerWritten = true
		_, werr := p.underlying.Write(p.body.Bytes())
		return werr
	}

	out := acquirePatternBuffer()
	defer releasePatternBuffer(out)
	out.WriteByte('[')
	first := true
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		visible, err := itemVisibleByPatterns(raw, normPath, policy)
		if err != nil {
			return err
		}
		if !visible {
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		out.Write(raw)
	}
	out.WriteByte(']')

	return p.commitFilteredBody(out.Bytes())
}

// itemVisibleByPatterns checks a single JSON list item against the pattern
// axes. Returns true if the item passes all configured axes.
func itemVisibleByPatterns(raw json.RawMessage, normPath string, policy *compiledPolicy) (bool, error) {
	switch normPath {
	case "/containers/json":
		return containerItemVisibleByPatterns(raw, policy)
	case "/images/json":
		return imageItemVisibleByPatterns(raw, policy)
	default:
		return true, nil
	}
}

func containerItemVisibleByPatterns(raw json.RawMessage, policy *compiledPolicy) (bool, error) {
	var item struct {
		Names []string `json:"Names"`
		Image string   `json:"Image"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return false, fmt.Errorf("decode container list item: %w", err)
	}
	if len(policy.namePatterns) > 0 {
		name := containerNameFromNames(item.Names)
		if !matchesAnyPattern(name, policy.namePatterns) {
			return false, nil
		}
	}
	if len(policy.imagePatterns) > 0 {
		if !matchesAnyPattern(item.Image, policy.imagePatterns) {
			return false, nil
		}
	}
	return true, nil
}

func imageItemVisibleByPatterns(raw json.RawMessage, policy *compiledPolicy) (bool, error) {
	var item struct {
		RepoTags []string `json:"RepoTags"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return false, fmt.Errorf("decode image list item: %w", err)
	}
	if len(policy.namePatterns) > 0 {
		matched := false
		for _, ref := range item.RepoTags {
			if matchesAnyPattern(imageShortName(ref), policy.namePatterns) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	if len(policy.imagePatterns) > 0 {
		matched := false
		for _, ref := range item.RepoTags {
			if matchesAnyPattern(ref, policy.imagePatterns) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func newVisibilityDeps(upstreamSocket string) visibilityDeps {
	return newVisibilityDepsClient(dockerclient.New(upstreamSocket))
}

func newVisibilityDepsClient(client *http.Client) visibilityDeps {
	inspector := upstreamInspector{
		client: client,
	}
	// noMemoizeTTL disables cross-request memoization on both caches below
	// (only genuinely concurrent callers still share a result, via each
	// cache's in-flight coalescing). Docker container/network/image names and
	// tags are mutable and get freed the instant the underlying resource is
	// deleted, so memoizing a positive verdict by name — the way inspectcache
	// otherwise would for a positive TTL — could apply a since-deleted
	// resource's labels (or name/image metadata) to a same-named resource a
	// different owner creates within the TTL window, defeating the visibility
	// check it's meant to feed. Every single-resource inspect here already
	// costs the same one upstream call whether or not it's cached, so
	// disabling memoization has no throughput cost to offset against that
	// risk. Ownership's equivalent inspect path makes the identical choice —
	// see its middleware.go — for the same reason.
	const noMemoizeTTL = 0
	labelCache := inspectcache.New(
		noMemoizeTTL,
		inspectcache.DefaultMaxSize,
		time.Now,
		func(ctx context.Context, kind, identifier string) (map[string]string, bool, error) {
			return inspector.inspectResource(ctx, dockerresource.Kind(kind), identifier)
		},
	)
	// Container/image labels and pattern metadata live in the same inspect
	// response. Decode them together so a combined policy pays for one upstream
	// request, while the non-positive TTL still prevents cross-request reuse.
	detailsCache := inspectcache.New(
		noMemoizeTTL,
		inspectcache.DefaultMaxSize,
		time.Now,
		func(ctx context.Context, kind, identifier string) (*resourceDetails, bool, error) {
			return inspector.inspectResourceDetails(ctx, dockerresource.Kind(kind), identifier)
		},
	)
	lookupDetails := func(ctx context.Context, kind dockerresource.Kind, identifier string) (*resourceDetails, bool, error) {
		return detailsCache.Lookup(ctx, string(kind), identifier)
	}
	return visibilityDeps{
		inspectResource: func(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
			if kind == dockerresource.KindContainer || kind == dockerresource.KindImage {
				details, found, err := lookupDetails(ctx, kind, identifier)
				if err != nil || !found {
					return nil, found, err
				}
				return details.labels, true, nil
			}
			return labelCache.Lookup(ctx, string(kind), identifier)
		},
		inspectExec: inspector.inspectExec,
		inspectResourceMeta: func(ctx context.Context, kind dockerresource.Kind, identifier string) (*resourceMeta, bool, error) {
			details, found, err := lookupDetails(ctx, kind, identifier)
			if err != nil || !found {
				return nil, found, err
			}
			return details.meta, true, nil
		},
		inspectResourceDetails: lookupDetails,
	}
}

func compilePolicy(labels []string, nameGlobs []string, imageGlobs []string) (compiledPolicy, error) {
	compiled := compiledPolicy{
		selectors: make([]compiledSelector, 0, len(labels)),
	}
	for _, raw := range labels {
		selector, err := parseSelector(raw)
		if err != nil {
			return compiled, err
		}
		compiled.selectors = appendUniqueSelectors(compiled.selectors, selector)
	}
	var err error
	compiled.namePatterns, err = compilePatterns(nameGlobs)
	if err != nil {
		return compiledPolicy{}, fmt.Errorf("name_patterns: %w", err)
	}
	compiled.imagePatterns, err = compilePatterns(imageGlobs)
	if err != nil {
		return compiledPolicy{}, fmt.Errorf("image_patterns: %w", err)
	}
	return compiled, nil
}

func appendUniqueSelectors(dst []compiledSelector, selectors ...compiledSelector) []compiledSelector {
	for _, selector := range selectors {
		if !slices.Contains(dst, selector) {
			dst = append(dst, selector)
		}
	}
	return dst
}

func parseSelector(raw string) (compiledSelector, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return compiledSelector{}, fmt.Errorf("visibility label selector must not be empty")
	}
	if strings.Contains(value, ",") {
		return compiledSelector{}, fmt.Errorf("visibility label selector %q must not contain commas", value)
	}
	key, selected, hasValue := strings.Cut(value, "=")
	key = strings.TrimSpace(key)
	selected = strings.TrimSpace(selected)
	if key == "" {
		return compiledSelector{}, fmt.Errorf("visibility label selector %q is missing a label key", value)
	}
	if hasValue && selected == "" {
		return compiledSelector{}, fmt.Errorf("visibility label selector %q is missing a label value", value)
	}
	return compiledSelector{key: key, value: selected, hasValue: hasValue}, nil
}

func normalizedPathForRequest(w http.ResponseWriter, r *http.Request) string {
	if meta := logging.MetaForRequest(w, r); meta != nil && meta.NormPath != "" {
		return meta.NormPath
	}
	return filter.NormalizePath(r.URL.Path)
}

func needsVisibilityLabelFilter(normPath string) bool {
	switch normPath {
	case "/events", "/containers/json", "/images/json", "/networks", "/volumes", "/services", "/tasks", "/secrets", "/configs", "/nodes":
		return true
	default:
		return needsLibpodVisibilityLabelFilter(normPath)
	}
}

// addVisibilityLabelFilters merges the policy's selectors into the request's
// label filter and returns the request to forward. The returned request may be
// a context-derived copy: the selectors are recorded on it as proxy-injected
// (dockerfilters.RecordInjectedSelectors) so the ownership middleware, which
// runs after this one and drops client-supplied values from the same filter
// key, keeps them. Callers must forward the returned request, not the argument.
func addVisibilityLabelFilters(r *http.Request, normPath string, selectors []compiledSelector) (*http.Request, error) {
	query := r.URL.Query()
	filters, err := dockerfilters.Decode(query.Get("filters"))
	if err != nil {
		return r, err
	}
	filterKey := visibilityLabelFilterKey(normPath)
	injected := make([]string, 0, len(selectors))
	changed := false
	for _, selector := range selectors {
		value := selector.key
		if selector.hasValue {
			value += "=" + selector.value
		}
		injected = append(injected, value)
		if !slices.Contains(filters[filterKey], value) {
			filters[filterKey] = append(filters[filterKey], value)
			changed = true
		}
	}
	// Recorded unconditionally, including the selectors already present
	// because the client happened to send them: they are policy-enforced
	// either way, and a later layer that drops client-supplied values would
	// otherwise strip exactly the ones this loop did not have to write.
	r = dockerfilters.RecordInjectedSelectors(r, filterKey, injected)
	if !changed {
		return r, nil
	}
	encoded, err := json.Marshal(filters)
	if err != nil {
		return r, fmt.Errorf("encode filters: %w", err)
	}
	query.Set("filters", string(encoded))
	r.URL.RawQuery = query.Encode()
	return r, nil
}

func visibilityLabelFilterKey(normPath string) string {
	if normPath == "/nodes" {
		return "node.label"
	}
	return "label"
}

// requestVisibleWithPolicy checks the full policy (label selectors AND name/
// image patterns) for a single-resource inspect or log path. Returns true if
// the resource should be visible, false if it should be hidden.
func requestVisibleWithPolicy(ctx context.Context, normPath string, policy *compiledPolicy, deps visibilityDeps) (bool, error) {
	hasSelectors := len(policy.selectors) > 0
	hasPatterns := policy.hasPatternAxes()

	if !hasSelectors && !hasPatterns {
		return true, nil
	}
	if identifier, ok := containerReadIdentifier(normPath); ok {
		return resourceVisibleWithPolicy(ctx, deps, dockerresource.KindContainer, identifier, policy)
	}
	if identifier, ok := imageReadIdentifier(normPath); ok {
		return resourceVisibleWithPolicy(ctx, deps, dockerresource.KindImage, identifier, policy)
	}
	// Pattern axes only apply to containers and images. All other resource
	// kinds use label-selector checks only.
	if !hasSelectors {
		// No label selectors and no applicable pattern axes → visible.
		return true, nil
	}
	if identifier, ok := networkInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindNetwork, identifier, policy.selectors)
	}
	if identifier, ok := volumeInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindVolume, identifier, policy.selectors)
	}
	if identifier, ok := serviceInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindService, identifier, policy.selectors)
	}
	if identifier, ok := serviceLogsIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindService, identifier, policy.selectors)
	}
	if identifier, ok := taskInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindTask, identifier, policy.selectors)
	}
	if identifier, ok := taskLogsIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindTask, identifier, policy.selectors)
	}
	if identifier, ok := secretInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindSecret, identifier, policy.selectors)
	}
	if identifier, ok := configInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindConfig, identifier, policy.selectors)
	}
	if identifier, ok := nodeInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindNode, identifier, policy.selectors)
	}
	if isSwarmInspectPath(normPath) {
		return resourceVisible(ctx, deps, dockerresource.KindSwarm, "", policy.selectors)
	}
	if execID, ok := execInspectIdentifier(normPath); ok {
		containerID, found, err := deps.inspectExec(ctx, execID)
		if err != nil {
			return false, err
		}
		if !found {
			return true, nil
		}
		return resourceVisible(ctx, deps, dockerresource.KindContainer, containerID, policy.selectors)
	}
	// libpod route family (#148 PR5): containers/volumes/secrets are checked
	// against their Docker-compat inspect path (Podman's compat API is a
	// translation layer over the same underlying resource store for those
	// kinds); networks and pods use their libpod-native inspect path via
	// dockerresource.KindLibpodNetwork/KindLibpodPod — networks because
	// GET /libpod/networks/{id}/json differs in label-key casing and (per
	// design doc C6) may return a single-element array-wrapped response,
	// pods because they have no Docker-compat equivalent at all.
	if identifier, ok := libpodContainerReadIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindContainer, identifier, policy.selectors)
	}
	if identifier, ok := libpodPodReadIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindLibpodPod, identifier, policy.selectors)
	}
	if identifier, ok := libpodNetworkInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindLibpodNetwork, identifier, policy.selectors)
	}
	if identifier, ok := libpodVolumeInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindVolume, identifier, policy.selectors)
	}
	if identifier, ok := libpodSecretInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, dockerresource.KindSecret, identifier, policy.selectors)
	}
	return true, nil
}

// resourceVisibleWithPolicy checks both label selectors and name/image pattern
// axes for a single container or image resource.
func resourceVisibleWithPolicy(ctx context.Context, deps visibilityDeps, kind dockerresource.Kind, identifier string, policy *compiledPolicy) (bool, error) {
	if len(policy.selectors) > 0 && policy.hasPatternAxes() && deps.inspectResourceDetails != nil {
		details, found, err := deps.inspectResourceDetails(ctx, kind, identifier)
		if err != nil {
			return false, err
		}
		if !found {
			return true, nil
		}
		if !matchesSelectors(details.labels, policy.selectors) {
			return false, nil
		}
		return resourceMetaMatchesPatterns(details.meta, kind, policy), nil
	}
	// Check label selectors first (uses the cached inspect path).
	if len(policy.selectors) > 0 {
		labels, found, err := deps.inspectResource(ctx, kind, identifier)
		if err != nil {
			return false, err
		}
		if !found {
			return true, nil
		}
		if !matchesSelectors(labels, policy.selectors) {
			return false, nil
		}
	}
	// Check pattern axes if configured.
	if policy.hasPatternAxes() {
		if deps.inspectResourceMeta == nil {
			// No meta inspector configured (e.g. in tests without pattern deps).
			return true, nil
		}
		meta, found, err := deps.inspectResourceMeta(ctx, kind, identifier)
		if err != nil {
			return false, err
		}
		if !found {
			return true, nil
		}
		if !resourceMetaMatchesPatterns(meta, kind, policy) {
			return false, nil
		}
	}
	return true, nil
}

// resourceMetaMatchesPatterns checks a resource's name/image metadata against
// the pattern axes in the policy. Containers compare a single name/image
// against the pattern lists; images iterate every RepoTag since one image may
// expose several user-visible names.
func resourceMetaMatchesPatterns(meta *resourceMeta, kind dockerresource.Kind, policy *compiledPolicy) bool {
	switch kind {
	case dockerresource.KindContainer:
		return containerMetaMatchesPatterns(meta, policy)
	case dockerresource.KindImage:
		return imageMetaMatchesPatterns(meta, policy)
	}
	return true
}

func containerMetaMatchesPatterns(meta *resourceMeta, policy *compiledPolicy) bool {
	if len(policy.namePatterns) > 0 {
		if !matchesAnyPattern(containerNameFromNames(meta.names), policy.namePatterns) {
			return false
		}
	}
	if len(policy.imagePatterns) > 0 {
		if !matchesAnyPattern(meta.image, policy.imagePatterns) {
			return false
		}
	}
	return true
}

func imageMetaMatchesPatterns(meta *resourceMeta, policy *compiledPolicy) bool {
	if len(policy.namePatterns) > 0 && !anyRepoTagMatches(meta.repoTags, policy.namePatterns, imageShortName) {
		return false
	}
	if len(policy.imagePatterns) > 0 && !anyRepoTagMatches(meta.repoTags, policy.imagePatterns, nil) {
		return false
	}
	return true
}

// anyRepoTagMatches returns true when at least one RepoTag matches any
// pattern in patterns. When transform is non-nil it's applied to each
// RepoTag before pattern matching (e.g. imageShortName strips the
// registry/repo prefix when matching against name patterns).
func anyRepoTagMatches(repoTags []string, patterns []compiledPattern, transform func(string) string) bool {
	for _, ref := range repoTags {
		candidate := ref
		if transform != nil {
			candidate = transform(ref)
		}
		if matchesAnyPattern(candidate, patterns) {
			return true
		}
	}
	return false
}

func resourceVisible(ctx context.Context, deps visibilityDeps, kind dockerresource.Kind, identifier string, selectors []compiledSelector) (bool, error) {
	labels, found, err := deps.inspectResource(ctx, kind, identifier)
	if err != nil {
		return false, err
	}
	if !found {
		return true, nil
	}
	return matchesSelectors(labels, selectors), nil
}

func matchesSelectors(labels map[string]string, selectors []compiledSelector) bool {
	if len(selectors) == 0 {
		return true
	}
	if len(labels) == 0 {
		return false
	}
	for _, selector := range selectors {
		value, ok := labels[selector.key]
		if !ok {
			return false
		}
		if selector.hasValue && value != selector.value {
			return false
		}
	}
	return true
}

// singleSegmentIdentifier strips prefix from normPath and returns the
// remaining single segment as an identifier. It returns ok=false when the
// remainder is empty or contains "/". This matcher is reached only for
// GET/HEAD requests, so write-only collection keywords remain valid resource
// names here.
func singleSegmentIdentifier(normPath, prefix string) (string, bool) {
	if !strings.HasPrefix(normPath, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, prefix)
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

// suffixedIdentifier strips prefix and splits the remainder once on "/",
// returning the leading segment when the trailing segment matches suffix.
// Used for endpoints shaped `/<kind>/<id>/<suffix>` like `.../json` or
// `.../logs`.
func suffixedIdentifier(normPath, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(normPath, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, prefix)
	identifier, tail, ok := strings.Cut(rest, "/")
	return identifier, ok && identifier != "" && tail == suffix
}

// readSubresourceIdentifier matches `/<prefix>/<id>/<suffix>` for any of the
// given read-operation suffixes, trimming the suffix from the END so that
// identifiers which themselves contain "/" (namespaced image refs such as
// "registry.io/team/app") are preserved. The bare collection endpoints
// (e.g. "/containers/json", "/images/get") never match because their remainder
// lacks the leading "/<id>" segment.
func readSubresourceIdentifier(normPath, prefix string, suffixes ...string) (string, bool) {
	if !strings.HasPrefix(normPath, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, prefix)
	for _, suffix := range suffixes {
		trimmed := strings.TrimSuffix(rest, "/"+suffix)
		if trimmed != rest && trimmed != "" {
			return trimmed, true
		}
	}
	return "", false
}

// containerReadIdentifier matches every GET/HEAD container read endpoint that
// discloses or exfiltrates container data — inspect (/json), logs, stats, top,
// filesystem changes, export, archive (read), and websocket attach — so the
// visibility gate hides all of them for a hidden container, not just /json.
// The visibility middleware only runs on GET/HEAD, so the write variants of
// attach/archive never reach this matcher.
func containerReadIdentifier(normPath string) (string, bool) {
	return readSubresourceIdentifier(normPath, "/containers/",
		"json", "logs", "stats", "top", "changes", "export", "archive", "attach/ws")
}

// imageReadIdentifier matches every GET image read endpoint that discloses or
// exfiltrates image data — inspect (/json), history, single-image export
// (/get), and attestation listing (/attestations, Engine API 1.53+) — so a
// hidden image is hidden across all of them.
func imageReadIdentifier(normPath string) (string, bool) {
	return readSubresourceIdentifier(normPath, "/images/", "json", "history", "get", "attestations")
}

func networkInspectIdentifier(normPath string) (string, bool) {
	return singleSegmentIdentifier(normPath, "/networks/")
}

func volumeInspectIdentifier(normPath string) (string, bool) {
	return singleSegmentIdentifier(normPath, "/volumes/")
}

func execInspectIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, "/exec/", "json")
}

func serviceInspectIdentifier(normPath string) (string, bool) {
	return singleSegmentIdentifier(normPath, "/services/")
}

func serviceLogsIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, "/services/", "logs")
}

func taskInspectIdentifier(normPath string) (string, bool) {
	return singleSegmentIdentifier(normPath, "/tasks/")
}

func taskLogsIdentifier(normPath string) (string, bool) {
	return suffixedIdentifier(normPath, "/tasks/", "logs")
}

func secretInspectIdentifier(normPath string) (string, bool) {
	return singleSegmentIdentifier(normPath, "/secrets/")
}

func configInspectIdentifier(normPath string) (string, bool) {
	return singleSegmentIdentifier(normPath, "/configs/")
}

func nodeInspectIdentifier(normPath string) (string, bool) {
	return singleSegmentIdentifier(normPath, "/nodes/")
}

func isSwarmInspectPath(normPath string) bool {
	return normPath == "/swarm"
}

func (i upstreamInspector) inspectResource(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
	requestPath, ok := dockerresource.InspectPath(kind, identifier)
	if !ok {
		return nil, false, fmt.Errorf("unsupported resource kind %q", kind)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("inspect %s %q returned status %d", kind, identifier, resp.StatusCode)
	}

	labels, err := dockerresource.DecodeLabels(resp.Body, kind)
	if err != nil {
		return nil, false, err
	}
	return labels, true, nil
}

func (i upstreamInspector) inspectExec(ctx context.Context, identifier string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(identifier)+"/json", nil) // #nosec G704 -- the fixed local-engine URL contains only a path-escaped identifier.
	if err != nil {
		return "", false, err
	}
	resp, err := i.client.Do(req) // #nosec G704 -- the inspector client targets the local container-engine socket, not the URL host.
	if err != nil {
		return "", false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("inspect exec %q returned status %d", identifier, resp.StatusCode)
	}

	var payload struct {
		ContainerID string `json:"ContainerID"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", false, err
	}
	if payload.ContainerID == "" {
		return "", false, nil
	}
	return payload.ContainerID, true, nil
}

func (i upstreamInspector) inspectResourceMeta(ctx context.Context, kind dockerresource.Kind, identifier string) (*resourceMeta, bool, error) {
	var requestPath string
	switch kind {
	case dockerresource.KindContainer:
		requestPath = "/containers/" + url.PathEscape(identifier) + "/json"
	case dockerresource.KindImage:
		requestPath = "/images/" + url.PathEscape(identifier) + "/json"
	default:
		return nil, false, fmt.Errorf("unsupported resource kind %q for meta inspect", kind)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("inspect meta %s %q returned status %d", kind, identifier, resp.StatusCode)
	}
	meta, err := decodeResourceMeta(resp.Body, kind)
	if err != nil {
		return nil, false, err
	}
	return meta, true, nil
}

func (i upstreamInspector) inspectResourceDetails(ctx context.Context, kind dockerresource.Kind, identifier string) (*resourceDetails, bool, error) {
	requestPath, ok := dockerresource.InspectPath(kind, identifier)
	if !ok || kind != dockerresource.KindContainer && kind != dockerresource.KindImage {
		return nil, false, fmt.Errorf("unsupported resource kind %q for combined inspect", kind)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("inspect %s %q returned status %d", kind, identifier, resp.StatusCode)
	}
	details, err := decodeResourceDetails(resp.Body, kind)
	if err != nil {
		return nil, false, err
	}
	return details, true, nil
}

func decodeResourceDetails(body io.Reader, kind dockerresource.Kind) (*resourceDetails, error) {
	switch kind {
	case dockerresource.KindContainer:
		var payload struct {
			Name   string   `json:"Name"`
			Names  []string `json:"Names"`
			Image  string   `json:"Image"`
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		names := payload.Names
		if len(names) == 0 && payload.Name != "" {
			names = []string{payload.Name}
		}
		return &resourceDetails{
			labels: payload.Config.Labels,
			meta:   &resourceMeta{names: names, image: payload.Image},
		}, nil
	case dockerresource.KindImage:
		var payload struct {
			RepoTags []string `json:"RepoTags"`
			Config   struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
			ContainerConfig struct {
				Labels map[string]string `json:"Labels"`
			} `json:"ContainerConfig"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		labels := payload.Config.Labels
		if len(labels) == 0 {
			labels = payload.ContainerConfig.Labels
		}
		return &resourceDetails{
			labels: labels,
			meta:   &resourceMeta{repoTags: payload.RepoTags},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported resource kind %q for combined inspect", kind)
	}
}

func decodeResourceMeta(body io.Reader, kind dockerresource.Kind) (*resourceMeta, error) {
	switch kind {
	case dockerresource.KindContainer:
		var payload struct {
			Name  string   `json:"Name"`
			Names []string `json:"Names"`
			Image string   `json:"Image"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		names := payload.Names
		if len(names) == 0 && payload.Name != "" {
			names = []string{payload.Name}
		}
		return &resourceMeta{names: names, image: payload.Image}, nil
	case dockerresource.KindImage:
		var payload struct {
			RepoTags []string `json:"RepoTags"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return &resourceMeta{repoTags: payload.RepoTags}, nil
	default:
		return nil, fmt.Errorf("unsupported resource kind %q for meta decode", kind)
	}
}
