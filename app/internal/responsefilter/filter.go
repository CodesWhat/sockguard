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
	RedactSensitiveData   bool
}

// Filter applies response redactions to selected Docker JSON response shapes.
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
	return f.opts.RedactContainerEnv || f.opts.RedactMountPaths || f.opts.RedactNetworkTopology || f.opts.RedactSensitiveData
}

// ModifyResponse rewrites supported successful Docker JSON responses in place.
func (f *Filter) ModifyResponse(resp *http.Response) error {
	if !f.Enabled() || resp == nil || resp.Request == nil {
		return nil
	}
	if resp.Request.Method == http.MethodHead || !isSuccessfulBodyResponse(resp.StatusCode) {
		return nil
	}

	normPath := requestfilter.NormalizePath(resp.Request.URL.Path)

	switch {
	case isContainerInspectPath(normPath):
		return f.modifyContainerInspect(resp)
	case normPath == "/containers/json":
		return f.modifyContainerList(resp)
	case normPath == "/services":
		return f.modifyServiceList(resp)
	case isServiceInspectPath(normPath):
		return f.modifyServiceInspect(resp)
	case normPath == "/tasks":
		return f.modifyTaskList(resp)
	case isTaskInspectPath(normPath):
		return f.modifyTaskInspect(resp)
	case normPath == "/networks":
		return f.modifyNetworkList(resp)
	case isNetworkInspectPath(normPath):
		return f.modifyNetworkInspect(resp)
	case normPath == "/volumes":
		return f.modifyVolumeList(resp)
	case isVolumeInspectPath(normPath):
		return f.modifyVolumeInspect(resp)
	case normPath == "/secrets":
		return f.modifySecretList(resp)
	case isSecretInspectPath(normPath):
		return f.modifySecretInspect(resp)
	case normPath == "/configs":
		return f.modifyConfigList(resp)
	case isConfigInspectPath(normPath):
		return f.modifyConfigInspect(resp)
	case normPath == "/plugins":
		return f.modifyPluginList(resp)
	case isPluginInspectPath(normPath):
		return f.modifyPluginInspect(resp)
	case normPath == "/nodes":
		return f.modifyNodeList(resp)
	case isNodeInspectPath(normPath):
		return f.modifyNodeInspect(resp)
	case normPath == "/swarm":
		return f.modifySwarmInspect(resp)
	case normPath == "/swarm/unlockkey":
		return f.modifySwarmUnlockKey(resp)
	case normPath == "/info":
		return f.modifyInfo(resp)
	case normPath == "/system/df":
		return f.modifySystemDataUsage(resp)
	default:
		return nil
	}
}

func isSuccessfulBodyResponse(statusCode int) bool {
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return false
	}
	return statusCode != http.StatusNoContent && statusCode != http.StatusResetContent
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

func (f *Filter) modifyServiceList(resp *http.Response) error {
	if !f.opts.RedactContainerEnv && !f.opts.RedactMountPaths && !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyListResponse(resp, f.redactServicePayload)
}

func (f *Filter) modifyServiceInspect(resp *http.Response) error {
	if !f.opts.RedactContainerEnv && !f.opts.RedactMountPaths && !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, f.redactServicePayload)
}

func (f *Filter) modifyTaskList(resp *http.Response) error {
	if !f.opts.RedactContainerEnv && !f.opts.RedactMountPaths && !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyListResponse(resp, f.redactTaskPayload)
}

func (f *Filter) modifyTaskInspect(resp *http.Response) error {
	if !f.opts.RedactContainerEnv && !f.opts.RedactMountPaths && !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, f.redactTaskPayload)
}

func (f *Filter) modifySecretList(resp *http.Response) error {
	if !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyListResponse(resp, redactSecretPayload)
}

func (f *Filter) modifySecretInspect(resp *http.Response) error {
	if !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, redactSecretPayload)
}

func (f *Filter) modifyConfigList(resp *http.Response) error {
	if !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyListResponse(resp, redactConfigPayload)
}

func (f *Filter) modifyConfigInspect(resp *http.Response) error {
	if !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, redactConfigPayload)
}

func (f *Filter) modifyPluginList(resp *http.Response) error {
	if !f.opts.RedactContainerEnv && !f.opts.RedactMountPaths {
		return nil
	}
	return modifyListResponse(resp, f.redactPluginPayload)
}

func (f *Filter) modifyPluginInspect(resp *http.Response) error {
	if !f.opts.RedactContainerEnv && !f.opts.RedactMountPaths {
		return nil
	}
	return modifyMapResponse(resp, f.redactPluginPayload)
}

func (f *Filter) modifyNodeList(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyListResponse(resp, f.redactNodePayload)
}

func (f *Filter) modifyNodeInspect(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, f.redactNodePayload)
}

func (f *Filter) modifySwarmInspect(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, f.redactSwarmPayload)
}

func (f *Filter) modifySwarmUnlockKey(resp *http.Response) error {
	if !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, func(payload map[string]any) error {
		redactStringField(payload, "UnlockKey")
		return nil
	})
}

func (f *Filter) modifyInfo(resp *http.Response) error {
	if !f.opts.RedactNetworkTopology && !f.opts.RedactSensitiveData {
		return nil
	}
	return modifyMapResponse(resp, f.redactInfoPayload)
}

func (f *Filter) modifySystemDataUsage(resp *http.Response) error {
	if !f.opts.RedactMountPaths && !f.opts.RedactNetworkTopology {
		return nil
	}
	return modifyMapResponse(resp, f.redactSystemDataUsagePayload)
}

func modifyMapResponse(resp *http.Response, mutate func(map[string]any) error) error {
	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}
	if err := mutate(payload); err != nil {
		return rejectResponse(err)
	}
	return writeResponseBody(resp, payload)
}

func modifyListResponse(resp *http.Response, mutate func(map[string]any) error) error {
	body, err := readResponseBody(resp)
	if err != nil {
		return rejectResponse(err)
	}

	var payload []map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return rejectResponse(err)
	}
	for _, item := range payload {
		if err := mutate(item); err != nil {
			return rejectResponse(err)
		}
	}
	return writeResponseBody(resp, payload)
}

func (f *Filter) redactServicePayload(payload map[string]any) error {
	containerSpec, found, err := nestedMapValue(payload, "Spec", "TaskTemplate", "ContainerSpec")
	if err != nil {
		return err
	}
	if found {
		if f.opts.RedactContainerEnv {
			redactArrayField(containerSpec, "Env")
		}
		if f.opts.RedactMountPaths {
			if err := redactMountObjects(containerSpec, "Mounts"); err != nil {
				return err
			}
		}
		if f.opts.RedactSensitiveData {
			if err := redactReferenceObjects(containerSpec, "Secrets", "SecretID", "SecretName"); err != nil {
				return err
			}
			if err := redactReferenceObjects(containerSpec, "Configs", "ConfigID", "ConfigName"); err != nil {
				return err
			}
		}
	}
	if f.opts.RedactNetworkTopology {
		if err := redactVirtualIPs(payload, "Endpoint", "VirtualIPs"); err != nil {
			return err
		}
	}
	return nil
}

func (f *Filter) redactTaskPayload(payload map[string]any) error {
	containerSpec, found, err := nestedMapValue(payload, "Spec", "ContainerSpec")
	if err != nil {
		return err
	}
	if found {
		if f.opts.RedactContainerEnv {
			redactArrayField(containerSpec, "Env")
		}
		if f.opts.RedactMountPaths {
			if err := redactMountObjects(containerSpec, "Mounts"); err != nil {
				return err
			}
		}
		if f.opts.RedactSensitiveData {
			if err := redactReferenceObjects(containerSpec, "Secrets", "SecretID", "SecretName"); err != nil {
				return err
			}
			if err := redactReferenceObjects(containerSpec, "Configs", "ConfigID", "ConfigName"); err != nil {
				return err
			}
		}
	}
	if f.opts.RedactNetworkTopology {
		redactStringField(payload, "ServiceID")
		redactStringField(payload, "NodeID")
		if err := redactTaskStatus(payload); err != nil {
			return err
		}
		if err := redactTaskNetworkAttachments(payload); err != nil {
			return err
		}
	}
	return nil
}

func redactSecretPayload(payload map[string]any) error {
	spec, found, err := nestedMapValue(payload, "Spec")
	if err != nil || !found {
		return err
	}
	redactStringField(spec, "Data")
	return nil
}

func redactConfigPayload(payload map[string]any) error {
	spec, found, err := nestedMapValue(payload, "Spec")
	if err != nil || !found {
		return err
	}
	redactStringField(spec, "Data")
	return nil
}

func (f *Filter) redactPluginPayload(payload map[string]any) error {
	if settings, found, err := nestedMapValue(payload, "Settings"); err != nil {
		return err
	} else if found {
		if f.opts.RedactContainerEnv {
			if err := redactEnvStrings(settings, "Env"); err != nil {
				return err
			}
		}
		if f.opts.RedactMountPaths {
			if err := redactMountObjects(settings, "Mounts"); err != nil {
				return err
			}
			if err := redactReferenceObjects(settings, "Devices", "Path"); err != nil {
				return err
			}
		}
	}
	if config, found, err := nestedMapValue(payload, "Config"); err != nil {
		return err
	} else if found {
		if f.opts.RedactContainerEnv {
			if err := redactPluginEnvObjects(config, "Env"); err != nil {
				return err
			}
		}
		if f.opts.RedactMountPaths {
			if err := redactMountObjects(config, "Mounts"); err != nil {
				return err
			}
			redactStringField(config, "PropagatedMount")
			if linux, found, err := nestedMapValue(config, "Linux"); err != nil {
				return err
			} else if found {
				if err := redactReferenceObjects(linux, "Devices", "Path"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (f *Filter) redactNodePayload(payload map[string]any) error {
	if f.opts.RedactNetworkTopology {
		if status, found, err := nestedMapValue(payload, "Status"); err != nil {
			return err
		} else if found {
			redactStringField(status, "Addr")
		}
		if status, found, err := nestedMapValue(payload, "ManagerStatus"); err != nil {
			return err
		} else if found {
			redactStringField(status, "Addr")
		}
	}
	if f.opts.RedactSensitiveData {
		if tlsInfo, found, err := nestedMapValue(payload, "Description", "TLSInfo"); err != nil {
			return err
		} else if found {
			redactTLSInfo(tlsInfo)
		}
	}
	return nil
}

func (f *Filter) redactSwarmPayload(payload map[string]any) error {
	if f.opts.RedactSensitiveData {
		if joinTokens, found, err := nestedMapValue(payload, "JoinTokens"); err != nil {
			return err
		} else if found {
			redactStringField(joinTokens, "Worker")
			redactStringField(joinTokens, "Manager")
		}
		if tlsInfo, found, err := nestedMapValue(payload, "TLSInfo"); err != nil {
			return err
		} else if found {
			redactTLSInfo(tlsInfo)
		}
		if caConfig, found, err := nestedMapValue(payload, "Spec", "CAConfig"); err != nil {
			return err
		} else if found {
			redactStringField(caConfig, "SigningCACert")
			redactStringField(caConfig, "SigningCAKey")
			redactArrayField(caConfig, "ExternalCAs")
		}
	}
	if f.opts.RedactNetworkTopology {
		redactArrayField(payload, "DefaultAddrPool")
	}
	return nil
}

func (f *Filter) redactInfoPayload(payload map[string]any) error {
	swarmInfo, found, err := nestedMapValue(payload, "Swarm")
	if err != nil || !found {
		return err
	}
	if f.opts.RedactNetworkTopology {
		redactStringField(swarmInfo, "NodeID")
		redactStringField(swarmInfo, "NodeAddr")
		redactArrayField(swarmInfo, "RemoteManagers")
		if cluster, found, err := nestedMapValue(swarmInfo, "Cluster"); err != nil {
			return err
		} else if found {
			redactArrayField(cluster, "DefaultAddrPool")
		}
	}
	if f.opts.RedactSensitiveData {
		if cluster, found, err := nestedMapValue(swarmInfo, "Cluster"); err != nil {
			return err
		} else if found {
			if tlsInfo, found, err := nestedMapValue(cluster, "TLSInfo"); err != nil {
				return err
			} else if found {
				redactTLSInfo(tlsInfo)
			}
		}
	}
	return nil
}

func (f *Filter) redactSystemDataUsagePayload(payload map[string]any) error {
	if containerUsage, found, err := nestedMapValue(payload, "ContainerUsage"); err != nil {
		return err
	} else if found {
		items, ok := containerUsage["Items"]
		if ok && items != nil {
			containers, ok := items.([]any)
			if !ok {
				return fmt.Errorf("ContainerUsage.Items has unexpected type %T", items)
			}
			for _, value := range containers {
				container, ok := value.(map[string]any)
				if !ok {
					return fmt.Errorf("ContainerUsage.Items entry has unexpected type %T", value)
				}
				if f.opts.RedactMountPaths {
					if err := redactMountObjects(container, "Mounts"); err != nil {
						return err
					}
				}
				if f.opts.RedactNetworkTopology {
					if err := redactContainerNetworkTopology(container); err != nil {
						return err
					}
				}
			}
		}
	}
	if volumeUsage, found, err := nestedMapValue(payload, "VolumeUsage"); err != nil {
		return err
	} else if found {
		items, ok := volumeUsage["Items"]
		if ok && items != nil {
			volumes, ok := items.([]any)
			if !ok {
				return fmt.Errorf("VolumeUsage.Items has unexpected type %T", items)
			}
			for _, value := range volumes {
				volume, ok := value.(map[string]any)
				if !ok {
					return fmt.Errorf("VolumeUsage.Items entry has unexpected type %T", value)
				}
				if f.opts.RedactMountPaths {
					redactStringField(volume, "Mountpoint")
				}
			}
		}
	}
	return nil
}

func nestedMapValue(payload map[string]any, keys ...string) (map[string]any, bool, error) {
	current := payload
	for index, key := range keys {
		value, ok := current[key]
		if !ok || value == nil {
			return nil, false, nil
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("%s has unexpected type %T", strings.Join(keys[:index+1], "."), value)
		}
		current = object
	}
	return current, true, nil
}

func redactReferenceObjects(payload map[string]any, field string, keys ...string) error {
	values, ok := payload[field]
	if !ok || values == nil {
		return nil
	}
	items, ok := values.([]any)
	if !ok {
		return fmt.Errorf("%s has unexpected type %T", field, values)
	}
	for _, value := range items {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s entry has unexpected type %T", field, value)
		}
		for _, key := range keys {
			redactStringField(object, key)
		}
	}
	return nil
}

func redactVirtualIPs(payload map[string]any, keys ...string) error {
	values, found, err := nestedArrayValue(payload, keys...)
	if err != nil || !found {
		return err
	}
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s entry has unexpected type %T", strings.Join(keys, "."), value)
		}
		redactStringField(object, "NetworkID")
		redactStringField(object, "Addr")
	}
	return nil
}

func nestedArrayValue(payload map[string]any, keys ...string) ([]any, bool, error) {
	if len(keys) == 0 {
		return nil, false, nil
	}
	current := payload
	for index, key := range keys[:len(keys)-1] {
		value, ok := current[key]
		if !ok || value == nil {
			return nil, false, nil
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("%s has unexpected type %T", strings.Join(keys[:index+1], "."), value)
		}
		current = object
	}
	value, ok := current[keys[len(keys)-1]]
	if !ok || value == nil {
		return nil, false, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, false, fmt.Errorf("%s has unexpected type %T", strings.Join(keys, "."), value)
	}
	return array, true, nil
}

func redactTaskStatus(payload map[string]any) error {
	containerStatus, found, err := nestedMapValue(payload, "Status", "ContainerStatus")
	if err != nil || !found {
		return err
	}
	redactStringField(containerStatus, "ContainerID")
	redactNumberField(containerStatus, "PID")
	return nil
}

func redactTaskNetworkAttachments(payload map[string]any) error {
	values, ok := payload["NetworksAttachments"]
	if !ok || values == nil {
		return nil
	}
	attachments, ok := values.([]any)
	if !ok {
		return fmt.Errorf("NetworksAttachments has unexpected type %T", values)
	}
	for _, value := range attachments {
		attachment, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("NetworksAttachments entry has unexpected type %T", value)
		}
		redactArrayField(attachment, "Addresses")
		if network, found, err := nestedMapValue(attachment, "Network"); err != nil {
			return err
		} else if found {
			redactStringField(network, "ID")
			if ipam, found, err := nestedMapValue(network, "IPAMOptions"); err != nil {
				return err
			} else if found {
				redactArrayField(ipam, "Configs")
			}
		}
	}
	return nil
}

func redactEnvStrings(payload map[string]any, field string) error {
	values, ok := payload[field]
	if !ok || values == nil {
		return nil
	}
	items, ok := values.([]any)
	if !ok {
		return fmt.Errorf("%s has unexpected type %T", field, values)
	}
	for index, value := range items {
		entry, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s entry has unexpected type %T", field, value)
		}
		items[index] = redactEnvVar(entry)
	}
	return nil
}

func redactPluginEnvObjects(payload map[string]any, field string) error {
	values, ok := payload[field]
	if !ok || values == nil {
		return nil
	}
	items, ok := values.([]any)
	if !ok {
		return fmt.Errorf("%s has unexpected type %T", field, values)
	}
	for _, value := range items {
		entry, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s entry has unexpected type %T", field, value)
		}
		redactStringField(entry, "Value")
	}
	return nil
}

func redactEnvVar(value string) string {
	name, _, hasValue := strings.Cut(value, "=")
	if !hasValue {
		return redactedValue
	}
	return name + "=" + redactedValue
}

func redactTLSInfo(payload map[string]any) {
	redactStringField(payload, "TrustRoot")
	redactStringField(payload, "CertIssuerSubject")
	redactStringField(payload, "CertIssuerPublicKey")
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

func isServiceInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/services/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/services/")
	return rest != "" && !strings.Contains(rest, "/")
}

func isTaskInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/tasks/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/tasks/")
	return rest != "" && !strings.Contains(rest, "/")
}

func isNetworkInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/networks/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/networks/")
	return rest != "" && !strings.Contains(rest, "/")
}

func isSecretInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/secrets/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/secrets/")
	return rest != "" && !strings.Contains(rest, "/")
}

func isConfigInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/configs/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/configs/")
	return rest != "" && !strings.Contains(rest, "/")
}

func isPluginInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/plugins/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/plugins/")
	identifier, tail, ok := strings.Cut(rest, "/")
	return ok && identifier != "" && tail == "json"
}

func isNodeInspectPath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return false
	}
	rest := strings.TrimPrefix(normPath, "/nodes/")
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
