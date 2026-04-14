package responsefilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	requestfilter "github.com/codeswhat/sockguard/internal/filter"
)

const (
	maxResponseBodyBytes = 8 << 20
	redactedValue        = "<redacted>"
)

// ErrResponseRejected indicates Sockguard intentionally rejected an upstream
// response because a protected payload could not be sanitized safely.
var ErrResponseRejected = errors.New("upstream Docker response rejected by sockguard policy")

// Options configures response-side redaction policy.
type Options struct {
	RedactContainerEnv    bool
	RedactMountPaths      bool
	RedactNetworkTopology bool
}

// Filter applies response redactions to selected Docker read endpoints.
type Filter struct {
	opts Options
}

// New constructs a response filter with the provided options.
func New(opts Options) *Filter {
	return &Filter{opts: opts}
}

// Enabled reports whether any response-side policy is active.
func (f *Filter) Enabled() bool {
	if f == nil {
		return false
	}
	return f.opts.RedactContainerEnv || f.opts.RedactMountPaths || f.opts.RedactNetworkTopology
}

// ModifyResponse rewrites supported Docker JSON responses in place.
func (f *Filter) ModifyResponse(resp *http.Response) error {
	if !f.Enabled() || resp == nil || resp.Request == nil {
		return nil
	}
	if resp.Request.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return nil
	}

	normPath := requestfilter.NormalizePath(resp.Request.URL.Path)

	switch {
	case isContainerInspectPath(normPath):
		return f.modifyContainerInspect(resp)
	case normPath == "/containers/json":
		return f.modifyContainerList(resp)
	case normPath == "/networks":
		return f.modifyNetworkList(resp)
	case isNetworkInspectPath(normPath):
		return f.modifyNetworkInspect(resp)
	case normPath == "/volumes":
		return f.modifyVolumeList(resp)
	case isVolumeInspectPath(normPath):
		return f.modifyVolumeInspect(resp)
	default:
		return nil
	}
}

func (f *Filter) modifyContainerInspect(resp *http.Response) error {
	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}

	if f.opts.RedactContainerEnv {
		if err := redactNestedValue(payload, "Config", "Env", []string{}); err != nil {
			return rejectResponse(err)
		}
	}
	if f.opts.RedactMountPaths {
		if err := redactMountObjects(payload, "Mounts"); err != nil {
			return rejectResponse(err)
		}
		if err := redactHostConfigBinds(payload); err != nil {
			return rejectResponse(err)
		}
	}
	if f.opts.RedactNetworkTopology {
		if err := redactContainerNetworkTopology(payload); err != nil {
			return rejectResponse(err)
		}
	}

	return writeResponseBody(resp, payload)
}

func (f *Filter) modifyContainerList(resp *http.Response) error {
	if !f.opts.RedactMountPaths && !f.opts.RedactNetworkTopology {
		return nil
	}

	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload []map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}

	for _, container := range payload {
		if f.opts.RedactMountPaths {
			if err := redactMountObjects(container, "Mounts"); err != nil {
				return rejectResponse(err)
			}
		}
		if f.opts.RedactNetworkTopology {
			if err := redactContainerNetworkTopology(container); err != nil {
				return rejectResponse(err)
			}
		}
	}

	return writeResponseBody(resp, payload)
}

func (f *Filter) modifyNetworkList(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology {
		return nil
	}

	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload []map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}

	for _, network := range payload {
		if err := redactNetworkTopology(network); err != nil {
			return rejectResponse(err)
		}
	}

	return writeResponseBody(resp, payload)
}

func (f *Filter) modifyNetworkInspect(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology {
		return nil
	}

	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}

	if err := redactNetworkTopology(payload); err != nil {
		return rejectResponse(err)
	}
	return writeResponseBody(resp, payload)
}

func (f *Filter) modifyVolumeList(resp *http.Response) error {
	if !f.opts.RedactMountPaths {
		return nil
	}

	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}

	volumesValue, ok := payload["Volumes"]
	if !ok || volumesValue == nil {
		return writeResponseBody(resp, payload)
	}
	volumes, ok := volumesValue.([]any)
	if !ok {
		return rejectResponse(fmt.Errorf("volumes payload has unexpected Volumes type %T", volumesValue))
	}
	for _, volumeValue := range volumes {
		volume, ok := volumeValue.(map[string]any)
		if !ok {
			return rejectResponse(fmt.Errorf("volume entry has unexpected type %T", volumeValue))
		}
		redactStringField(volume, "Mountpoint")
	}

	return writeResponseBody(resp, payload)
}

func (f *Filter) modifyVolumeInspect(resp *http.Response) error {
	if !f.opts.RedactMountPaths {
		return nil
	}

	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}

	redactStringField(payload, "Mountpoint")
	return writeResponseBody(resp, payload)
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, errors.New("missing response body")
	}

	defer func() { _ = resp.Body.Close() }()

	reader := &io.LimitedReader{R: resp.Body, N: maxResponseBodyBytes + 1}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxResponseBodyBytes)
	}
	return body, nil
}

func writeResponseBody(resp *http.Response, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.TransferEncoding = nil
	return nil
}

func redactNestedValue(payload map[string]any, objectKey, fieldKey string, replacement any) error {
	objectValue, ok := payload[objectKey]
	if !ok || objectValue == nil {
		return nil
	}

	object, ok := objectValue.(map[string]any)
	if !ok {
		return fmt.Errorf("%s has unexpected type %T", objectKey, objectValue)
	}
	object[fieldKey] = replacement
	return nil
}

func redactMountObjects(payload map[string]any, field string) error {
	mountsValue, ok := payload[field]
	if !ok || mountsValue == nil {
		return nil
	}

	mounts, ok := mountsValue.([]any)
	if !ok {
		return fmt.Errorf("%s has unexpected type %T", field, mountsValue)
	}

	for _, mountValue := range mounts {
		mount, ok := mountValue.(map[string]any)
		if !ok {
			return fmt.Errorf("mount entry has unexpected type %T", mountValue)
		}
		redactStringField(mount, "Source")
	}

	return nil
}

func redactHostConfigBinds(payload map[string]any) error {
	hostConfigValue, ok := payload["HostConfig"]
	if !ok || hostConfigValue == nil {
		return nil
	}

	hostConfig, ok := hostConfigValue.(map[string]any)
	if !ok {
		return fmt.Errorf("HostConfig has unexpected type %T", hostConfigValue)
	}

	bindsValue, ok := hostConfig["Binds"]
	if !ok || bindsValue == nil {
		return nil
	}

	binds, ok := bindsValue.([]any)
	if !ok {
		return fmt.Errorf("HostConfig.Binds has unexpected type %T", bindsValue)
	}

	for i, bindValue := range binds {
		bind, ok := bindValue.(string)
		if !ok {
			return fmt.Errorf("HostConfig.Binds entry has unexpected type %T", bindValue)
		}
		binds[i] = redactBindSpec(bind)
	}

	return nil
}

func redactStringField(payload map[string]any, key string) {
	value, ok := payload[key]
	if !ok || value == nil {
		return
	}
	payload[key] = redactedValue
}

func redactBindSpec(bind string) string {
	source, rest := splitBindSpec(bind)
	if !isSensitiveHostPath(source) {
		return bind
	}
	return redactedValue + rest
}

func splitBindSpec(bind string) (string, string) {
	if bind == "" {
		return "", ""
	}

	if isWindowsAbsolutePath(bind) {
		if idx := strings.IndexByte(bind[2:], ':'); idx >= 0 {
			cut := idx + 2
			return bind[:cut], bind[cut:]
		}
		return bind, ""
	}

	if idx := strings.IndexByte(bind, ':'); idx >= 0 {
		return bind[:idx], bind[idx:]
	}
	return bind, ""
}

func isSensitiveHostPath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, "//") {
		return true
	}
	return isWindowsAbsolutePath(value)
}

func isWindowsAbsolutePath(value string) bool {
	if len(value) < 3 {
		return false
	}
	drive := value[0]
	return ((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) &&
		value[1] == ':' &&
		(value[2] == '\\' || value[2] == '/')
}

func isContainerInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/containers/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/containers/")
	identifier, tail, ok := strings.Cut(rest, "/")
	return ok && identifier != "" && tail == "json"
}

func isVolumeInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/volumes/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/volumes/")
	return rest != "" && !strings.Contains(rest, "/")
}

func isNetworkInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/networks/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/networks/")
	return rest != "" && !strings.Contains(rest, "/")
}

func redactContainerNetworkTopology(payload map[string]any) error {
	if err := redactNestedStringValue(payload, "HostConfig", "NetworkMode"); err != nil {
		return err
	}

	networkSettingsValue, ok := payload["NetworkSettings"]
	if !ok || networkSettingsValue == nil {
		return nil
	}
	networkSettings, ok := networkSettingsValue.(map[string]any)
	if !ok {
		return fmt.Errorf("NetworkSettings has unexpected type %T", networkSettingsValue)
	}

	redactNetworkAddressFields(networkSettings,
		[]string{
			"Bridge",
			"EndpointID",
			"Gateway",
			"GlobalIPv6Address",
			"IPAddress",
			"IPv6Gateway",
			"LinkLocalIPv6Address",
			"MacAddress",
			"SandboxID",
			"SandboxKey",
		},
		[]string{
			"GlobalIPv6PrefixLen",
			"IPPrefixLen",
			"LinkLocalIPv6PrefixLen",
		},
	)
	redactArrayField(networkSettings, "SecondaryIPAddresses")
	redactArrayField(networkSettings, "SecondaryIPv6Addresses")

	networksValue, ok := networkSettings["Networks"]
	if !ok || networksValue == nil {
		return nil
	}
	networks, ok := networksValue.(map[string]any)
	if !ok {
		return fmt.Errorf("NetworkSettings.Networks has unexpected type %T", networksValue)
	}
	for name, networkValue := range networks {
		network, ok := networkValue.(map[string]any)
		if !ok {
			return fmt.Errorf("NetworkSettings.Networks[%s] has unexpected type %T", name, networkValue)
		}
		redactNetworkAddressFields(network,
			[]string{
				"EndpointID",
				"Gateway",
				"GlobalIPv6Address",
				"IPAddress",
				"IPv6Gateway",
				"MacAddress",
				"NetworkID",
			},
			[]string{
				"GlobalIPv6PrefixLen",
				"IPPrefixLen",
			},
		)
	}
	return nil
}

func redactNetworkTopology(payload map[string]any) error {
	ipamValue, ok := payload["IPAM"]
	if ok && ipamValue != nil {
		ipam, ok := ipamValue.(map[string]any)
		if !ok {
			return fmt.Errorf("IPAM has unexpected type %T", ipamValue)
		}
		ipam["Config"] = []any{}
	}

	if containersValue, ok := payload["Containers"]; ok && containersValue != nil {
		if _, ok := containersValue.(map[string]any); !ok {
			return fmt.Errorf("containers field has unexpected type %T", containersValue)
		}
		payload["Containers"] = map[string]any{}
	}

	if peersValue, ok := payload["Peers"]; ok && peersValue != nil {
		if _, ok := peersValue.([]any); !ok {
			return fmt.Errorf("peers field has unexpected type %T", peersValue)
		}
		payload["Peers"] = []any{}
	}

	return nil
}

func redactNestedStringValue(payload map[string]any, objectKey, fieldKey string) error {
	objectValue, ok := payload[objectKey]
	if !ok || objectValue == nil {
		return nil
	}

	object, ok := objectValue.(map[string]any)
	if !ok {
		return fmt.Errorf("%s has unexpected type %T", objectKey, objectValue)
	}
	redactStringField(object, fieldKey)
	return nil
}

func redactNumberField(payload map[string]any, key string) {
	value, ok := payload[key]
	if !ok || value == nil {
		return
	}
	switch value.(type) {
	case float64, json.Number, int, int32, int64:
		payload[key] = 0
	}
}

func redactArrayField(payload map[string]any, key string) {
	value, ok := payload[key]
	if !ok || value == nil {
		return
	}
	if _, ok := value.([]any); ok {
		payload[key] = []any{}
	}
}

func redactNetworkAddressFields(payload map[string]any, stringKeys, numberKeys []string) {
	for _, key := range stringKeys {
		redactStringField(payload, key)
	}
	for _, key := range numberKeys {
		redactNumberField(payload, key)
	}
}

func rejectResponse(err error) error {
	if err == nil {
		return ErrResponseRejected
	}
	return fmt.Errorf("%w: %w", ErrResponseRejected, err)
}
