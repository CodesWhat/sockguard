package visibility

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

type resourceKind string

const (
	resourceKindContainer resourceKind = "containers"
	resourceKindImage     resourceKind = "images"
	resourceKindNetwork   resourceKind = "networks"
	resourceKindVolume    resourceKind = "volumes"
)

// Options configures label-based visibility control on Docker read endpoints.
type Options struct {
	VisibleResourceLabels []string
	Profiles              map[string]Policy
	ResolveProfile        func(*http.Request) (string, bool)
}

// Policy defines per-profile visibility overrides.
type Policy struct {
	VisibleResourceLabels []string
}

type compiledSelector struct {
	key      string
	value    string
	hasValue bool
}

type compiledPolicy struct {
	selectors []compiledSelector
}

type visibilityDeps struct {
	inspectResource func(context.Context, resourceKind, string) (map[string]string, bool, error)
	inspectExec     func(context.Context, string) (string, bool, error)
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
	defaultPolicy, err := compilePolicy(opts.VisibleResourceLabels)
	if err != nil {
		logger.Error("invalid visibility config", "error", err)
		return func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logging.SetDenied(w, r, "visibility policy misconfigured", filter.NormalizePath)
				_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility policy misconfigured"})
			})
		}
	}

	profilePolicies := make(map[string]compiledPolicy, len(opts.Profiles))
	for name, policy := range opts.Profiles {
		compiled, err := compilePolicy(policy.VisibleResourceLabels)
		if err != nil {
			logger.Error("invalid visibility profile config", "profile", name, "error", err)
			return func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					logging.SetDenied(w, r, "visibility policy misconfigured", filter.NormalizePath)
					_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility policy misconfigured"})
				})
			}
		}
		profilePolicies[name] = compiled
	}

	if len(defaultPolicy.selectors) == 0 && len(profilePolicies) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			selectors := defaultPolicy.selectors
			if opts.ResolveProfile != nil {
				if profileName, ok := opts.ResolveProfile(r); ok && profileName != "" {
					profile, found := profilePolicies[profileName]
					if !found {
						logging.SetDenied(w, r, "visibility profile could not be resolved", filter.NormalizePath)
						_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "visibility profile could not be resolved"})
						return
					}
					selectors = append(slices.Clone(selectors), profile.selectors...)
				}
			}

			if len(selectors) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			normPath := normalizedPathForRequest(w, r)
			if needsVisibilityLabelFilter(normPath) {
				if err := addVisibilityLabelFilters(r, selectors); err != nil {
					logging.SetDenied(w, r, err.Error(), nil)
					_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			visible, err := requestVisible(r.Context(), normPath, selectors, deps)
			if err != nil {
				logger.ErrorContext(r.Context(), "visibility policy lookup failed", "error", err, "method", r.Method, "path", r.URL.Path)
				logging.SetDenied(w, r, "visibility policy lookup failed", nil)
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "visibility policy lookup failed"})
				return
			}
			if !visible {
				logging.SetDenied(w, r, "visibility policy hid resource", nil)
				_ = httpjson.Write(w, http.StatusNotFound, httpjson.ErrorResponse{Message: "resource not found"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func newVisibilityDeps(upstreamSocket string) visibilityDeps {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", upstreamSocket)
		},
	}
	inspector := upstreamInspector{
		client: &http.Client{Transport: transport},
	}
	return visibilityDeps{
		inspectResource: inspector.inspectResource,
		inspectExec:     inspector.inspectExec,
	}
}

func compilePolicy(values []string) (compiledPolicy, error) {
	compiled := compiledPolicy{
		selectors: make([]compiledSelector, 0, len(values)),
	}
	for _, raw := range values {
		selector, err := parseSelector(raw)
		if err != nil {
			return compiled, err
		}
		compiled.selectors = append(compiled.selectors, selector)
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
	case "/events", "/containers/json", "/images/json", "/networks", "/volumes":
		return true
	default:
		return false
	}
}

func addVisibilityLabelFilters(r *http.Request, selectors []compiledSelector) error {
	query := r.URL.Query()
	filters, err := decodeDockerFilters(query.Get("filters"))
	if err != nil {
		return err
	}
	for _, selector := range selectors {
		value := selector.key
		if selector.hasValue {
			value += "=" + selector.value
		}
		if !slices.Contains(filters["label"], value) {
			filters["label"] = append(filters["label"], value)
		}
	}
	encoded, _ := json.Marshal(filters)
	query.Set("filters", string(encoded))
	r.URL.RawQuery = query.Encode()
	return nil
}

func requestVisible(ctx context.Context, normPath string, selectors []compiledSelector, deps visibilityDeps) (bool, error) {
	if len(selectors) == 0 {
		return true, nil
	}
	if identifier, ok := containerInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, resourceKindContainer, identifier, selectors)
	}
	if identifier, ok := imageInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, resourceKindImage, identifier, selectors)
	}
	if identifier, ok := networkInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, resourceKindNetwork, identifier, selectors)
	}
	if identifier, ok := volumeInspectIdentifier(normPath); ok {
		return resourceVisible(ctx, deps, resourceKindVolume, identifier, selectors)
	}
	if execID, ok := execInspectIdentifier(normPath); ok {
		containerID, found, err := deps.inspectExec(ctx, execID)
		if err != nil {
			return false, err
		}
		if !found {
			return true, nil
		}
		return resourceVisible(ctx, deps, resourceKindContainer, containerID, selectors)
	}
	return true, nil
}

func resourceVisible(ctx context.Context, deps visibilityDeps, kind resourceKind, identifier string, selectors []compiledSelector) (bool, error) {
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

func decodeDockerFilters(encoded string) (map[string][]string, error) {
	filters := make(map[string][]string)
	if encoded == "" {
		return filters, nil
	}

	var raw map[string]any
	if err := json.NewDecoder(strings.NewReader(encoded)).Decode(&raw); err != nil {
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
			filters[key] = values
		default:
			return nil, fmt.Errorf("decode filters: unexpected %s filter type %T", key, value)
		}
	}

	return filters, nil
}

func (i upstreamInspector) inspectResource(ctx context.Context, kind resourceKind, identifier string) (map[string]string, bool, error) {
	var requestPath string
	switch kind {
	case resourceKindContainer:
		requestPath = "/containers/" + url.PathEscape(identifier) + "/json"
	case resourceKindImage:
		requestPath = "/images/" + url.PathEscape(identifier) + "/json"
	case resourceKindNetwork:
		requestPath = "/networks/" + url.PathEscape(identifier)
	case resourceKindVolume:
		requestPath = "/volumes/" + url.PathEscape(identifier)
	default:
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

func decodeResourceLabels(body io.Reader, kind resourceKind) (map[string]string, error) {
	switch kind {
	case resourceKindContainer:
		var payload struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Config.Labels, nil
	case resourceKindImage:
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
	case resourceKindNetwork, resourceKindVolume:
		var payload struct {
			Labels map[string]string `json:"Labels"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Labels, nil
	default:
		return nil, fmt.Errorf("unsupported resource kind %q", kind)
	}
}
