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

	"github.com/codeswhat/sockguard/internal/dockerclient"
	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/inspectcache"
	"github.com/codeswhat/sockguard/internal/logging"
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
	ImagePatterns []string
	Profiles       map[string]Policy
	ResolveProfile func(*http.Request) (string, bool)
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

type visibilityDeps struct {
	inspectResource     func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error)
	inspectExec         func(context.Context, string) (string, bool, error)
	inspectResourceMeta func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error)
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

func middlewareWithDeps(logger *slog.Logger, opts Options, deps visibilityDeps) func(http.Handler) http.Handler {
	defaultPolicy, err := compilePolicy(opts.VisibleResourceLabels, opts.NamePatterns, opts.ImagePatterns)
	if err != nil {
		logger.Error("invalid visibility config", "error", err)
		return func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyMisconfigured, "visibility policy misconfigured", filter.NormalizePath)
				_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility policy misconfigured"})
			})
		}
	}

	// Pre-merge default + profile policies once at construction. Profiles are
	// reload-immutable, so cloning the slice on every request to compute the
	// same merged compiledPolicy is wasted work. Each map entry holds the
	// final merged compiledPolicy that requests can reference by pointer.
	mergedProfilePolicies := make(map[string]compiledPolicy, len(opts.Profiles))
	for name, policy := range opts.Profiles {
		compiled, err := compilePolicy(policy.VisibleResourceLabels, policy.NamePatterns, policy.ImagePatterns)
		if err != nil {
			logger.Error("invalid visibility profile config", "profile", name, "error", err)
			return func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyMisconfigured, "visibility policy misconfigured", filter.NormalizePath)
					_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility policy misconfigured"})
				})
			}
		}
		mergedProfilePolicies[name] = compiledPolicy{
			selectors:     append(slices.Clone(defaultPolicy.selectors), compiled.selectors...),
			namePatterns:  append(slices.Clone(defaultPolicy.namePatterns), compiled.namePatterns...),
			imagePatterns: append(slices.Clone(defaultPolicy.imagePatterns), compiled.imagePatterns...),
		}
	}

	hasAnyConfig := len(defaultPolicy.selectors) > 0 || defaultPolicy.hasPatternAxes() || len(mergedProfilePolicies) > 0
	if !hasAnyConfig {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			effectivePolicy := defaultPolicy
			if opts.ResolveProfile != nil {
				if profileName, ok := opts.ResolveProfile(r); ok && profileName != "" {
					profile, found := mergedProfilePolicies[profileName]
					if !found {
						logging.SetDeniedWithCode(w, r, reasonCodeVisibilityProfileUnresolved, "visibility profile could not be resolved", filter.NormalizePath)
						_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility profile could not be resolved"})
						return
					}
					effectivePolicy = profile
				}
			}

			hasSelectors := len(effectivePolicy.selectors) > 0
			hasPatterns := effectivePolicy.hasPatternAxes()

			if !hasSelectors && !hasPatterns {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			normPath := normalizedPathForRequest(w, r)

			// Label-filter injection for list endpoints (selectors only).
			if needsVisibilityLabelFilter(normPath) {
				if hasSelectors {
					if err := addVisibilityLabelFilters(r, normPath, effectivePolicy.selectors); err != nil {
						logging.SetDeniedWithCode(w, r, reasonCodeVisibilityFilterInvalid, err.Error(), nil)
						_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
						return
					}
				}
				// Pattern-axis filtering for container/image list endpoints: wrap
				// the response writer so we can filter the returned JSON array.
				if hasPatterns && needsPatternResponseFilter(normPath) {
					interceptingW := newPatternFilterWriter(w)
					defer interceptingW.release()
					next.ServeHTTP(interceptingW, r)
					if err := interceptingW.flushFiltered(normPath, &effectivePolicy); err != nil {
						logger.ErrorContext(r.Context(), "visibility pattern list filter failed", "error", err)
						// If we haven't written a response yet, send a gateway error.
						if !interceptingW.headerWritten {
							logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyLookupFailed, "visibility pattern filter failed", nil)
							_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "visibility pattern filter failed"})
						}
					}
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Inspect/single-resource visibility check.
			visible, err := requestVisibleWithPolicy(r.Context(), normPath, &effectivePolicy, deps)
			if err != nil {
				logger.ErrorContext(r.Context(), "visibility policy lookup failed", "error", err, "method", r.Method, "path", r.URL.Path)
				logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyLookupFailed, "visibility policy lookup failed", nil)
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "visibility policy lookup failed"})
				return
			}
			if !visible {
				logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyHidResource, "visibility policy hid resource", nil)
				_ = httpjson.Write(w, http.StatusNotFound, httpjson.ErrorResponse{Message: "resource not found"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
func (p *patternFilterWriter) Write(b []byte) (int, error) {
	return p.body.Write(b)
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

// flushFiltered filters the buffered JSON array response by pattern axes and
// writes the result to the underlying ResponseWriter.
//
// The body is streamed through a json.Decoder rather than fully Unmarshalled
// into []json.RawMessage; that avoids the outer slice allocation on
// large list responses (hundreds of containers/images) while preserving the
// per-item visibility check. Filtered items are encoded into a pooled output
// buffer so Content-Length can be set before WriteHeader.
func (p *patternFilterWriter) flushFiltered(normPath string, policy *compiledPolicy) error {
	// RFC 9110 §15.4.5 / §15.3.5: 204 and 304 must have an empty body.
	// Writing any bytes triggers an http.ResponseWriter downgrade to 502.
	if mustHaveEmptyBody(p.statusCode) {
		p.underlying.WriteHeader(p.statusCode)
		return nil
	}

	// Only filter 2xx responses with a JSON body; pass through everything else.
	if p.statusCode < http.StatusOK || p.statusCode >= http.StatusMultipleChoices {
		p.underlying.WriteHeader(p.statusCode)
		_, err := p.underlying.Write(p.body.Bytes())
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(p.body.Bytes()))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		// Not a JSON array — pass through unchanged.
		p.underlying.WriteHeader(p.statusCode)
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

	p.underlying.Header().Set("Content-Length", strconv.Itoa(out.Len()))
	p.underlying.WriteHeader(p.statusCode)
	_, err = p.underlying.Write(out.Bytes())
	p.headerWritten = true
	return err
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
	inspector := upstreamInspector{
		client: dockerclient.New(upstreamSocket),
	}
	cache := inspectcache.New(
		inspectcache.DefaultTTL,
		inspectcache.DefaultMaxSize,
		time.Now,
		func(ctx context.Context, kind, identifier string) (map[string]string, bool, error) {
			return inspector.inspectResource(ctx, dockerresource.Kind(kind), identifier)
		},
	)
	return visibilityDeps{
		inspectResource: func(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
			return cache.Lookup(ctx, string(kind), identifier)
		},
		inspectExec:         inspector.inspectExec,
		inspectResourceMeta: inspector.inspectResourceMeta,
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
		compiled.selectors = append(compiled.selectors, selector)
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
		return false
	}
}

func addVisibilityLabelFilters(r *http.Request, normPath string, selectors []compiledSelector) error {
	query := r.URL.Query()
	filters, err := decodeDockerFilters(query.Get("filters"))
	if err != nil {
		return err
	}
	filterKey := visibilityLabelFilterKey(normPath)
	changed := false
	for _, selector := range selectors {
		value := selector.key
		if selector.hasValue {
			value += "=" + selector.value
		}
		if !slices.Contains(filters[filterKey], value) {
			filters[filterKey] = append(filters[filterKey], value)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	encoded, _ := json.Marshal(filters)
	query.Set("filters", string(encoded))
	r.URL.RawQuery = query.Encode()
	return nil
}

func visibilityLabelFilterKey(normPath string) string {
	if normPath == "/nodes" {
		return "node.label"
	}
	return "label"
}

// requestVisible is the original label-selector-only check. Kept for backward
// compatibility with existing tests that call it directly.
func requestVisible(ctx context.Context, normPath string, selectors []compiledSelector, deps visibilityDeps) (bool, error) {
	policy := &compiledPolicy{selectors: selectors}
	return requestVisibleWithPolicy(ctx, normPath, policy, deps)
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
	if identifier, ok := containerInspectIdentifier(normPath); ok {
		return resourceVisibleWithPolicy(ctx, deps, dockerresource.KindContainer, identifier, policy)
	}
	if identifier, ok := imageInspectIdentifier(normPath); ok {
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
	return true, nil
}

// resourceVisibleWithPolicy checks both label selectors and name/image pattern
// axes for a single container or image resource.
func resourceVisibleWithPolicy(ctx context.Context, deps visibilityDeps, kind dockerresource.Kind, identifier string, policy *compiledPolicy) (bool, error) {
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
// the pattern axes in the policy.
func resourceMetaMatchesPatterns(meta *resourceMeta, kind dockerresource.Kind, policy *compiledPolicy) bool {
	switch kind {
	case dockerresource.KindContainer:
		if len(policy.namePatterns) > 0 {
			name := containerNameFromNames(meta.names)
			if !matchesAnyPattern(name, policy.namePatterns) {
				return false
			}
		}
		if len(policy.imagePatterns) > 0 {
			if !matchesAnyPattern(meta.image, policy.imagePatterns) {
				return false
			}
		}
	case dockerresource.KindImage:
		if len(policy.namePatterns) > 0 {
			matched := false
			for _, ref := range meta.repoTags {
				if matchesAnyPattern(imageShortName(ref), policy.namePatterns) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		if len(policy.imagePatterns) > 0 {
			matched := false
			for _, ref := range meta.repoTags {
				if matchesAnyPattern(ref, policy.imagePatterns) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
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

func containerInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/containers/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/containers/")
	identifier, tail, ok := strings.Cut(rest, "/")
	return identifier, ok && identifier != "" && tail == "json"
}

func imageInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/images/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/images/")
	identifier, tail, ok := strings.Cut(rest, "/")
	return identifier, ok && identifier != "" && tail == "json"
}

func networkInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/networks/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/networks/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	switch rest {
	case "create", "prune":
		return "", false
	default:
		return rest, true
	}
}

func volumeInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/volumes/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/volumes/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	switch rest {
	case "create", "prune":
		return "", false
	default:
		return rest, true
	}
}

func execInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/exec/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/exec/")
	identifier, tail, ok := strings.Cut(rest, "/")
	return identifier, ok && identifier != "" && tail == "json"
}

func serviceInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/services/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/services/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	switch rest {
	case "create":
		return "", false
	default:
		return rest, true
	}
}

func serviceLogsIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/services/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/services/")
	identifier, tail, ok := strings.Cut(rest, "/")
	return identifier, ok && identifier != "" && tail == "logs"
}

func taskInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/tasks/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/tasks/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

func taskLogsIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/tasks/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/tasks/")
	identifier, tail, ok := strings.Cut(rest, "/")
	return identifier, ok && identifier != "" && tail == "logs"
}

func secretInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/secrets/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/secrets/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	switch rest {
	case "create":
		return "", false
	default:
		return rest, true
	}
}

func configInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/configs/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/configs/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	switch rest {
	case "create":
		return "", false
	default:
		return rest, true
	}
}

func nodeInspectIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/nodes/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

func isSwarmInspectPath(normPath string) bool {
	return normPath == "/swarm"
}

func decodeDockerFilters(encoded string) (map[string][]string, error) {
	filters := make(map[string][]string)
	if encoded == "" {
		return filters, nil
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(encoded), &raw); err != nil {
		return nil, fmt.Errorf("decode filters: %w", err)
	}

	for key, value := range raw {
		switch typed := value.(type) {
		case []any:
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				str, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("decode filters: unexpected %s filter element type %T", key, item)
				}
				values = append(values, str)
			}
			filters[key] = values
		case map[string]any:
			values := make([]string, 0, len(typed))
			for item := range typed {
				values = append(values, item)
			}
			slices.Sort(values)
			filters[key] = values
		default:
			return nil, fmt.Errorf("decode filters: unexpected %s filter type %T", key, value)
		}
	}

	return filters, nil
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
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("inspect %s %q returned status %d", kind, identifier, resp.StatusCode)
	}

	labels, err := decodeResourceLabels(resp.Body, kind)
	if err != nil {
		return nil, false, err
	}
	return labels, true, nil
}

func (i upstreamInspector) inspectExec(ctx context.Context, identifier string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(identifier)+"/json", nil)
	if err != nil {
		return "", false, err
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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

func decodeResourceLabels(body io.Reader, kind dockerresource.Kind) (map[string]string, error) {
	switch kind {
	case dockerresource.KindContainer:
		var payload struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Config.Labels, nil
	case dockerresource.KindImage:
		var payload struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
			ContainerConfig struct {
				Labels map[string]string `json:"Labels"`
			} `json:"ContainerConfig"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		if len(payload.Config.Labels) > 0 {
			return payload.Config.Labels, nil
		}
		return payload.ContainerConfig.Labels, nil
	case dockerresource.KindNetwork, dockerresource.KindVolume:
		var payload struct {
			Labels map[string]string `json:"Labels"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Labels, nil
	case dockerresource.KindService, dockerresource.KindSecret, dockerresource.KindConfig, dockerresource.KindNode, dockerresource.KindSwarm:
		var payload struct {
			Spec struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Spec"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Spec.Labels, nil
	case dockerresource.KindTask:
		var payload struct {
			Labels map[string]string `json:"Labels"`
			Spec   struct {
				ContainerSpec struct {
					Labels map[string]string `json:"Labels"`
				} `json:"ContainerSpec"`
			} `json:"Spec"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		if len(payload.Labels) > 0 {
			return payload.Labels, nil
		}
		return payload.Spec.ContainerSpec.Labels, nil
	default:
		return nil, fmt.Errorf("unsupported resource kind %q", kind)
	}
}
