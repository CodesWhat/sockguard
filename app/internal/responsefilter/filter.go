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
	RedactContainerEnv bool
	RedactMountPaths   bool
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
	return f.opts.RedactContainerEnv || f.opts.RedactMountPaths
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

	return writeResponseBody(resp, payload)
}

func (f *Filter) modifyContainerList(resp *http.Response) error {
	if !f.opts.RedactMountPaths {
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
		if err := redactMountObjects(container, "Mounts"); err != nil {
			return rejectResponse(err)
		}
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

	defer resp.Body.Close()

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

func rejectResponse(err error) error {
	if err == nil {
		return ErrResponseRejected
	}
	return fmt.Errorf("%w: %v", ErrResponseRejected, err)
}
