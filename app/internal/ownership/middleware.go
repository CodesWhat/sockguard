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

	"github.com/codeswhat/sockguard/internal/dockerclient"
	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/inspectcache"
	"github.com/codeswhat/sockguard/internal/logging"
)

const DefaultLabelKey = "com.sockguard.owner"

const (
	reasonCodeOwnerRequestInvalid     = "owner_request_invalid"
	reasonCodeOwnerPolicyLookupFailed = "owner_policy_lookup_failed"
	reasonCodeOwnerPolicyDeniedAccess = "owner_policy_denied_access"
)

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

// Options configures per-proxy resource ownership labeling and enforcement.
type Options struct {
	Owner              string
	LabelKey           string
	AllowUnownedImages bool
}

type upstreamInspector struct {
	client *http.Client
}

// Middleware applies owner-label mutation and enforcement for a single proxy
// identity. When Owner is empty, it is a no-op.
func Middleware(upstreamSocket string, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
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
	inspectResource := func(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
		return cache.Lookup(ctx, string(kind), identifier)
	}
	return middlewareWithDeps(logger, opts, inspectResource, inspector.inspectExec)
}

func middlewareWithDeps(
	logger *slog.Logger,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
) func(http.Handler) http.Handler {
	opts = opts.normalized()
	if opts.Owner == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prefer the normalized path the filter middleware already stamped
			// on the access-log meta so we don't re-run NormalizePath on the
			// hot path. If ownership runs outside a filter chain (rare — tests
			// and isolated usage), fall back to computing it here.
			var normPath string
			if meta := logging.MetaForRequest(w, r); meta != nil && meta.NormPath != "" {
				normPath = meta.NormPath
			} else {
				normPath = filter.NormalizePath(r.URL.Path)
			}

			if err := mutateOwnershipRequest(r, normPath, opts); err != nil {
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerRequestInvalid, err.Error(), nil)
				_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
				return
			}

			verdict, reason, err := allowOwnershipRequest(r.Context(), normPath, opts, inspectResource, inspectExec)
			if err != nil {
				logger.ErrorContext(r.Context(), "owner policy lookup failed", "error", err, "method", r.Method, "path", r.URL.Path)
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerPolicyLookupFailed, "owner policy lookup failed", nil)
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "owner policy lookup failed"})
				return
			}
			if verdict != verdictDeny {
				next.ServeHTTP(w, r)
				return
			}

			meta := logging.MetaForRequest(w, r)
			if meta.AllowsPassThrough() {
				logging.SetWouldDenyWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, reason, nil)
				next.ServeHTTP(w, r)
				return
			}
			logging.SetDeniedWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, reason, nil)
			_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
		})
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
	case normPath == "/containers/create", normPath == "/networks/create", normPath == "/volumes/create", normPath == "/secrets/create", normPath == "/configs/create":
		return addOwnerLabelToBody(r, opts.LabelKey, opts.Owner)
	case normPath == "/services/create", isServiceUpdatePath(normPath):
		return addOwnerLabelToServiceBody(r, opts.LabelKey, opts.Owner)
	case isNodeUpdatePath(normPath), isSwarmUpdatePath(normPath):
		return addOwnerLabelToBody(r, opts.LabelKey, opts.Owner)
	case normPath == "/build":
		return addOwnerLabelToBuildQuery(r, opts.LabelKey, opts.Owner)
	case needsOwnerFilter(normPath):
		return addOwnerLabelFilter(r, opts.LabelKey, opts.Owner)
	default:
		return nil
	}
}

func allowOwnershipRequest(
	ctx context.Context,
	normPath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
) (ownershipVerdict, string, error) {
	if identifier, ok := containerIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, identifier, opts, false)
	}
	if execID, ok := execIdentifier(normPath); ok {
		containerID, found, err := inspectExec(ctx, execID)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if !found {
			return verdictPassThrough, "", nil
		}
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, containerID, opts, false)
	}
	if identifier, ok := networkIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNetwork, identifier, opts, false)
	}
	if identifier, ok := volumeIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindVolume, identifier, opts, false)
	}
	if identifier, ok := imageIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, opts.AllowUnownedImages)
	}
	if identifier, ok := serviceIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindService, identifier, opts, false)
	}
	if identifier, ok := taskIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindTask, identifier, opts, false)
	}
	if identifier, ok := secretIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindSecret, identifier, opts, false)
	}
	if identifier, ok := configIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindConfig, identifier, opts, false)
	}
	if identifier, ok := nodeIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNode, identifier, opts, isNodeUpdatePath(normPath))
	}
	if isSwarmPath(normPath) || isSwarmUpdatePath(normPath) {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindSwarm, "", opts, isSwarmUpdatePath(normPath))
	}
	return verdictPassThrough, "", nil
}

func checkOwnedResource(ctx context.Context, inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error), kind dockerresource.Kind, identifier string, opts Options, allowUnowned bool) (ownershipVerdict, string, error) {
	labels, found, err := inspectResource(ctx, kind, identifier)
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

func singularResource(kind dockerresource.Kind) string {
	switch kind {
	case dockerresource.KindContainer:
		return "container"
	case dockerresource.KindImage:
		return "image"
	case dockerresource.KindNetwork:
		return "network"
	case dockerresource.KindVolume:
		return "volume"
	case dockerresource.KindService:
		return "service"
	case dockerresource.KindTask:
		return "task"
	case dockerresource.KindSecret:
		return "secret"
	case dockerresource.KindConfig:
		return "config"
	case dockerresource.KindNode:
		return "node"
	case dockerresource.KindSwarm:
		return "swarm"
	default:
		return string(kind)
	}
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

func addOwnerLabelToServiceBody(r *http.Request, labelKey, owner string) error {
	return mutateJSONBody(r, func(decoded map[string]any) error {
		serviceLabels, err := nestedObject(decoded, "Labels")
		if err != nil {
			return err
		}
		serviceLabels[labelKey] = owner

		containerLabels, err := nestedObjectPath(decoded, "TaskTemplate", "ContainerSpec", "Labels")
		if err != nil {
			return err
		}
		containerLabels[labelKey] = owner
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
	filterKey := ownerFilterKey(filter.NormalizePath(r.URL.Path))
	label := labelKey + "=" + owner
	if !slices.Contains(filters[filterKey], label) {
		filters[filterKey] = append(filters[filterKey], label)
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
	// json.Decode into map[string]any does not error on a JSON null literal —
	// it simply leaves the map as nil. Reject it explicitly: a null body is
	// not a valid Docker API payload, and passing nil to the mutate callback
	// would panic when it tries to write into the map.
	if decoded == nil {
		return fmt.Errorf("decode request body: JSON null is not a valid object")
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

func nestedObjectPath(decoded map[string]any, keys ...string) (map[string]any, error) {
	current := decoded
	for _, key := range keys {
		next, err := nestedObject(current, key)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func (u upstreamInspector) inspectResource(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
	target, ok := dockerresource.InspectPath(kind, identifier)
	if !ok {
		return nil, false, fmt.Errorf("unsupported resource kind %q", kind)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil)
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

	labels, err := decodeResourceLabels(resp.Body, kind)
	if err != nil {
		return nil, false, err
	}
	return labels, true, nil
}

func (u upstreamInspector) inspectExec(ctx context.Context, identifier string) (string, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(identifier)+"/json", nil)
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
