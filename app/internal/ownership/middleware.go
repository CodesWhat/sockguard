package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

const DefaultLabelKey = "com.sockguard.owner"

// maxOwnershipBodyBytes caps the request body the ownership middleware will
// read when it mutates a container/network/volume create body or a build
// query to inject the owner label. Docker's own create payloads are at most
// a few KiB, so 1 MiB is generous while preventing an allowlisted client
// from OOMing the proxy with an unbounded JSON body.
const maxOwnershipBodyBytes = 1 << 20 // 1 MiB

// ownershipVerdict is the outcome of an ownership policy check against an
// inbound request. Callers should forward `verdictPassThrough` and
// `verdictAllow` unchanged to the next handler; `verdictDeny` should short
// circuit with a 403 and the accompanying reason.
type ownershipVerdict int

const (
	// verdictPassThrough means the request does not target a resource that
	// the ownership middleware knows how to inspect, so it is forwarded
	// unchanged to the next handler.
	verdictPassThrough ownershipVerdict = iota
	// verdictAllow means the request targets a labeled resource that matches
	// the configured owner.
	verdictAllow
	// verdictDeny means the request targets a labeled resource that belongs
	// to a different owner identity.
	verdictDeny
)

type resourceKind string

const (
	resourceKindContainer resourceKind = "containers"
	resourceKindImage     resourceKind = "images"
	resourceKindNetwork   resourceKind = "networks"
	resourceKindVolume    resourceKind = "volumes"
)

// Options configures per-proxy resource ownership labeling and enforcement.
type Options struct {
	Owner              string
	LabelKey           string
	AllowUnownedImages bool
}

type ownerDeps struct {
	inspectResource func(context.Context, resourceKind, string) (map[string]string, bool, error)
	inspectExec     func(context.Context, string) (string, bool, error)
}

type upstreamInspector struct {
	client *http.Client
}

// Middleware applies owner-label mutation and enforcement for a single proxy
// identity. When Owner is empty, it is a no-op.
func Middleware(upstreamSocket string, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	return middlewareWithDeps(logger, opts, newOwnerDeps(upstreamSocket))
}

func middlewareWithDeps(logger *slog.Logger, opts Options, deps ownerDeps) func(http.Handler) http.Handler {
	opts = opts.normalized()
	if opts.Owner == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			normPath := filter.NormalizePath(r.URL.Path)

			if err := mutateOwnershipRequest(r, normPath, opts); err != nil {
				setDeniedMeta(w, r, err.Error())
				_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
				return
			}

			verdict, reason, err := allowOwnershipRequest(r.Context(), normPath, opts, deps)
			if err != nil {
				logger.ErrorContext(r.Context(), "owner policy lookup failed", "error", err, "method", r.Method, "path", r.URL.Path)
				setDeniedMeta(w, r, "owner policy lookup failed")
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "owner policy lookup failed"})
				return
			}
			if verdict != verdictDeny {
				next.ServeHTTP(w, r)
				return
			}

			setDeniedMeta(w, r, reason)
			_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
		})
	}
}

func newOwnerDeps(upstreamSocket string) ownerDeps {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", upstreamSocket)
		},
	}
	inspector := upstreamInspector{
		client: &http.Client{Transport: transport},
	}
	return ownerDeps{
		inspectResource: inspector.inspectResource,
		inspectExec:     inspector.inspectExec,
	}
}

func (o Options) normalized() Options {
	if o.LabelKey == "" {
		o.LabelKey = DefaultLabelKey
	}
	return o
}

func mutateOwnershipRequest(r *http.Request, normPath string, opts Options) error {
	switch {
	case normPath == "/containers/create", normPath == "/networks/create", normPath == "/volumes/create":
		return addOwnerLabelToBody(r, opts.LabelKey, opts.Owner)
	case normPath == "/build":
		return addOwnerLabelToBuildQuery(r, opts.LabelKey, opts.Owner)
	case needsOwnerFilter(normPath):
		return addOwnerLabelFilter(r, opts.LabelKey, opts.Owner)
	default:
		return nil
	}
}

func allowOwnershipRequest(ctx context.Context, normPath string, opts Options, deps ownerDeps) (ownershipVerdict, string, error) {
	if identifier, ok := containerIdentifier(normPath); ok {
		return checkOwnedResource(ctx, deps, resourceKindContainer, identifier, opts, false)
	}
	if execID, ok := execIdentifier(normPath); ok {
		containerID, found, err := deps.inspectExec(ctx, execID)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if !found {
			return verdictPassThrough, "", nil
		}
		return checkOwnedResource(ctx, deps, resourceKindContainer, containerID, opts, false)
	}
	if identifier, ok := networkIdentifier(normPath); ok {
		return checkOwnedResource(ctx, deps, resourceKindNetwork, identifier, opts, false)
	}
	if identifier, ok := volumeIdentifier(normPath); ok {
		return checkOwnedResource(ctx, deps, resourceKindVolume, identifier, opts, false)
	}
	if identifier, ok := imageIdentifier(normPath); ok {
		return checkOwnedResource(ctx, deps, resourceKindImage, identifier, opts, opts.AllowUnownedImages)
	}
	return verdictPassThrough, "", nil
}

func checkOwnedResource(ctx context.Context, deps ownerDeps, kind resourceKind, identifier string, opts Options, allowUnowned bool) (ownershipVerdict, string, error) {
	labels, found, err := deps.inspectResource(ctx, kind, identifier)
	if err != nil {
		return verdictPassThrough, "", err
	}
	if !found {
		return verdictPassThrough, "", nil
	}
	if ownerMatches(labels, opts.LabelKey, opts.Owner, allowUnowned) {
		return verdictAllow, "", nil
	}
	return verdictDeny, fmt.Sprintf("owner policy denied access to %s", singularResource(kind)), nil
}

func ownerMatches(labels map[string]string, labelKey, owner string, allowUnowned bool) bool {
	if labels == nil {
		return allowUnowned
	}
	value, ok := labels[labelKey]
	if !ok || value == "" {
		return allowUnowned
	}
	return value == owner
}

func singularResource(kind resourceKind) string {
	switch kind {
	case resourceKindContainer:
		return "container"
	case resourceKindImage:
		return "image"
	case resourceKindNetwork:
		return "network"
	case resourceKindVolume:
		return "volume"
	default:
		return string(kind)
	}
}

func setDeniedMeta(w http.ResponseWriter, r *http.Request, reason string) {
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.Decision = "deny"
		meta.Reason = reason
	}
}

func needsOwnerFilter(normPath string) bool {
	switch normPath {
	case "/events", "/containers/json", "/containers/prune", "/images/json", "/images/prune", "/networks", "/networks/prune", "/volumes", "/volumes/prune":
		return true
	default:
		return false
	}
}

func containerIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/containers/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/containers/"), "/")
	switch identifier {
	case "", "create", "json", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func execIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/exec/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/exec/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func networkIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/networks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/networks/"), "/")
	switch identifier {
	case "", "create", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func volumeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/volumes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/volumes/"), "/")
	switch identifier {
	case "", "create", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func imageIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/images/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/images/")
	switch rest {
	case "", "json", "create", "search", "get", "load", "prune":
		return "", false
	}

	for _, suffix := range []string{"/json", "/history", "/push", "/tag"} {
		if strings.HasSuffix(rest, suffix) {
			return strings.TrimSuffix(rest, suffix), true
		}
	}
	return rest, true
}

func addOwnerLabelToBody(r *http.Request, labelKey, owner string) error {
	return mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := nestedObject(decoded, "Labels")
		if err != nil {
			return err
		}
		labels[labelKey] = owner
		return nil
	})
}

func addOwnerLabelToBuildQuery(r *http.Request, labelKey, owner string) error {
	query := r.URL.Query()
	labels := make(map[string]string)
	if encoded := query.Get("labels"); encoded != "" {
		if err := json.NewDecoder(strings.NewReader(encoded)).Decode(&labels); err != nil {
			return fmt.Errorf("decode build labels: %w", err)
		}
	}
	labels[labelKey] = owner
	encoded, _ := json.Marshal(labels)
	query.Set("labels", string(encoded))
	r.URL.RawQuery = query.Encode()
	return nil
}

func addOwnerLabelFilter(r *http.Request, labelKey, owner string) error {
	query := r.URL.Query()
	filters, err := decodeDockerFilters(query.Get("filters"))
	if err != nil {
		return err
	}
	label := labelKey + "=" + owner
	if !containsString(filters["label"], label) {
		filters["label"] = append(filters["label"], label)
	}
	encoded, _ := json.Marshal(filters)
	query.Set("filters", string(encoded))
	r.URL.RawQuery = query.Encode()
	return nil
}

// decodeDockerFilters parses Docker's `filters` query parameter into a
// normalized map[string][]string that we can append our owner-label
// filter to. Docker's wire format for filters has two shapes in use:
//
//  1. map[string][]string — the modern encoding, e.g.
//     `{"label":["com.sockguard.owner=alice","status=running"]}`.
//     Negation (`label!=foo`) lives inside the string value, so it's
//     transparent to us — we don't need to parse the `!=` sentinel.
//
//  2. map[string]map[string]bool — the legacy encoding still accepted by
//     the Docker daemon, e.g.
//     `{"label":{"com.sockguard.owner=alice":true}}`. We flatten the
//     object's keys into a []string so downstream code sees one shape.
//
// Any other encoding returns an error: a filter type we don't know how to
// render safely is a fail-fast, not a silent drop, so a future Docker API
// extension surfaces here instead of silently skipping ownership checks.
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

func mutateJSONBody(r *http.Request, mutate func(map[string]any) error) error {
	if r.Body == nil {
		return fmt.Errorf("request body is required")
	}
	// Read one byte past the limit so we can distinguish at-limit from
	// over-limit without giving the client room to OOM the proxy.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxOwnershipBodyBytes+1))
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if int64(len(body)) > maxOwnershipBodyBytes {
		return fmt.Errorf("request body exceeds %d byte limit", maxOwnershipBodyBytes)
	}
	if len(body) == 0 {
		return fmt.Errorf("request body is required")
	}

	// UseNumber preserves JSON numbers as json.Number (underlying string)
	// instead of coercing them to float64. That matters because the default
	// map[string]any decode path silently truncates any Docker container
	// create field with a 53-bit-or-larger integer — memory limits, pid
	// caps, CPU shares — on the re-encode pass. json.Number round-trips
	// exact digits whether we touch the field or not.
	var decoded map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	if err := mutate(decoded); err != nil {
		return err
	}

	encoded, err := json.Marshal(decoded)
	if err != nil {
		return fmt.Errorf("encode request body: %w", err)
	}
	r.ContentLength = int64(len(encoded))
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	return nil
}

func nestedObject(decoded map[string]any, key string) (map[string]any, error) {
	value, ok := decoded[key]
	if !ok || value == nil {
		obj := map[string]any{}
		decoded[key] = obj
		return obj, nil
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	return obj, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (u upstreamInspector) inspectResource(ctx context.Context, kind resourceKind, identifier string) (map[string]string, bool, error) {
	var target string
	switch kind {
	case resourceKindContainer:
		target = "/containers/" + url.PathEscape(identifier) + "/json"
	case resourceKindImage:
		target = "/images/" + url.PathEscape(identifier) + "/json"
	case resourceKindNetwork:
		target = "/networks/" + url.PathEscape(identifier)
	case resourceKindVolume:
		target = "/volumes/" + url.PathEscape(identifier)
	default:
		return nil, false, fmt.Errorf("unsupported resource kind %q", kind)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("inspect %s %q: upstream returned %s", kind, identifier, resp.Status)
	}

	if kind == resourceKindContainer || kind == resourceKindImage {
		var body struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, false, err
		}
		return body.Config.Labels, true, nil
	}

	var body struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, err
	}
	return body.Labels, true, nil
}

func (u upstreamInspector) inspectExec(ctx context.Context, identifier string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(identifier)+"/json", nil)
	if err != nil {
		return "", false, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("inspect exec %q: upstream returned %s", identifier, resp.Status)
	}

	var body struct {
		ContainerID string `json:"ContainerID"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", false, err
	}
	if body.ContainerID == "" {
		return "", false, fmt.Errorf("inspect exec %q: empty container id", identifier)
	}
	return body.ContainerID, true, nil
}
