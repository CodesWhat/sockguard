package responsefilter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	requestfilter "github.com/codeswhat/sockguard/internal/filter"
)

type readFailAfterCloser struct {
	remaining []byte
	err       error
}

func (r *readFailAfterCloser) Read(p []byte) (int, error) {
	if len(r.remaining) > 0 {
		n := copy(p, r.remaining)
		r.remaining = r.remaining[n:]
		if len(r.remaining) == 0 {
			return n, r.err
		}
		return n, nil
	}
	return 0, r.err
}

func (r *readFailAfterCloser) Close() error {
	return nil
}

func newResponseForTest(t *testing.T, method, path, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, "http://sockguard.test"+path, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func decodeBodyForTest(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v\nbody: %s", err, string(body))
	}
	return got
}

func TestFilterModifyResponse_RedactsContainerInspectResponse(t *testing.T) {
	filter := New(Options{
		RedactContainerEnv: true,
		RedactMountPaths:   true,
	})

	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", `{
		"Config":{"Env":["SECRET_TOKEN=shh","PATH=/usr/bin"]},
		"HostConfig":{"Binds":["/srv/secrets:/run/secrets:ro","named-cache:/cache"]},
		"Mounts":[
			{"Type":"bind","Source":"/srv/secrets","Destination":"/run/secrets"},
			{"Type":"volume","Name":"named-cache","Source":"/var/lib/docker/volumes/named-cache/_data","Destination":"/cache"}
		]
	}`)

	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	got := decodeBodyForTest(t, resp)

	config, _ := got["Config"].(map[string]any)
	env, _ := config["Env"].([]any)
	if len(env) != 0 {
		t.Fatalf("Config.Env = %#v, want empty redacted array", config["Env"])
	}

	hostConfig, _ := got["HostConfig"].(map[string]any)
	binds, _ := hostConfig["Binds"].([]any)
	if len(binds) != 2 {
		t.Fatalf("HostConfig.Binds len = %d, want 2", len(binds))
	}
	if gotBind, _ := binds[0].(string); gotBind != "<redacted>:/run/secrets:ro" {
		t.Fatalf("HostConfig.Binds[0] = %q, want %q", gotBind, "<redacted>:/run/secrets:ro")
	}
	if gotBind, _ := binds[1].(string); gotBind != "named-cache:/cache" {
		t.Fatalf("HostConfig.Binds[1] = %q, want named volume bind unchanged", gotBind)
	}

	mounts, _ := got["Mounts"].([]any)
	if len(mounts) != 2 {
		t.Fatalf("Mounts len = %d, want 2", len(mounts))
	}
	for i, mountValue := range mounts {
		mount, _ := mountValue.(map[string]any)
		if gotSource, _ := mount["Source"].(string); gotSource != "<redacted>" {
			t.Fatalf("Mounts[%d].Source = %q, want %q", i, gotSource, "<redacted>")
		}
	}
}

func TestFilterModifyResponse_RedactsContainerListAndVolumes(t *testing.T) {
	filter := New(Options{
		RedactMountPaths: true,
	})

	containerListResp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/json", `[
		{
			"Id":"abc123",
			"Mounts":[
				{"Type":"bind","Source":"/srv/secrets","Destination":"/run/secrets"},
				{"Type":"volume","Source":"/var/lib/docker/volumes/cache/_data","Destination":"/cache"}
			]
		}
	]`)

	if err := filter.ModifyResponse(containerListResp); err != nil {
		t.Fatalf("ModifyResponse(container list) error = %v, want nil", err)
	}

	containerListBody, err := io.ReadAll(containerListResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(container list): %v", err)
	}

	var containers []map[string]any
	if err := json.Unmarshal(containerListBody, &containers); err != nil {
		t.Fatalf("json.Unmarshal(container list): %v\nbody: %s", err, string(containerListBody))
	}
	mounts, _ := containers[0]["Mounts"].([]any)
	for i, mountValue := range mounts {
		mount, _ := mountValue.(map[string]any)
		if gotSource, _ := mount["Source"].(string); gotSource != "<redacted>" {
			t.Fatalf("containers[0].Mounts[%d].Source = %q, want %q", i, gotSource, "<redacted>")
		}
	}

	volumesResp := newResponseForTest(t, http.MethodGet, "/v1.53/volumes", `{
		"Volumes":[
			{"Name":"cache","Mountpoint":"/var/lib/docker/volumes/cache/_data"},
			{"Name":"remote","Mountpoint":"nfs://storage.example/cache"}
		]
	}`)

	if err := filter.ModifyResponse(volumesResp); err != nil {
		t.Fatalf("ModifyResponse(volumes list) error = %v, want nil", err)
	}

	volumesBody := decodeBodyForTest(t, volumesResp)
	volumes, _ := volumesBody["Volumes"].([]any)
	for i, volumeValue := range volumes {
		volume, _ := volumeValue.(map[string]any)
		if gotMountpoint, _ := volume["Mountpoint"].(string); gotMountpoint != "<redacted>" {
			t.Fatalf("Volumes[%d].Mountpoint = %q, want %q", i, gotMountpoint, "<redacted>")
		}
	}
}

func TestFilterModifyResponse_RejectsMalformedProtectedJSON(t *testing.T) {
	filter := New(Options{
		RedactContainerEnv: true,
	})

	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", `{"Config":`)

	err := filter.ModifyResponse(resp)
	if err == nil {
		t.Fatal("ModifyResponse() error = nil, want rejection error")
	}
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want errors.Is(..., ErrResponseRejected)", err)
	}
}

func TestFilterRejectsOversizedResponse(t *testing.T) {
	filter := New(Options{
		RedactContainerEnv: true,
	})

	body := `{"Config":{"Env":["` + strings.Repeat("A", requestfilter.MaxResponseBodyBytes) + `"]}}`
	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", body)

	err := filter.ModifyResponse(resp)
	if err == nil {
		t.Fatal("ModifyResponse() error = nil, want rejection error")
	}
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want errors.Is(..., ErrResponseRejected)", err)
	}
	if !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("ModifyResponse() error = %v, want size-limit context", err)
	}
}

func TestFilterRejectsOversizedSwarmInspectResponse(t *testing.T) {
	filter := New(Options{
		RedactSensitiveData: true,
	})

	body := `{"JoinTokens":{"Worker":"` + strings.Repeat("A", requestfilter.MaxResponseBodyBytes) + `"}}`
	resp := newResponseForTest(t, http.MethodGet, "/v1.53/swarm", body)

	err := filter.ModifyResponse(resp)
	if err == nil {
		t.Fatal("ModifyResponse() error = nil, want rejection error")
	}
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want errors.Is(..., ErrResponseRejected)", err)
	}
	if !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("ModifyResponse() error = %v, want size-limit context", err)
	}
}

func TestFilterHandlesChunkedEncoding(t *testing.T) {
	filter := New(Options{
		RedactContainerEnv: true,
	})

	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", `{
		"Config":{"Env":["SECRET_TOKEN=shh"]}
	}`)
	resp.ContentLength = -1
	resp.TransferEncoding = []string{"chunked"}

	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	if resp.ContentLength <= 0 {
		t.Fatalf("ContentLength = %d, want rewritten positive length", resp.ContentLength)
	}
	if got := resp.Header.Get("Content-Length"); got == "" {
		t.Fatal("Content-Length header = empty, want rewritten length")
	}
	if resp.TransferEncoding != nil {
		t.Fatalf("TransferEncoding = %#v, want nil after rewrite", resp.TransferEncoding)
	}

	got := decodeBodyForTest(t, resp)
	config, _ := got["Config"].(map[string]any)
	env, _ := config["Env"].([]any)
	if len(env) != 0 {
		t.Fatalf("Config.Env = %#v, want empty redacted array", config["Env"])
	}
}

func TestFilterRejectsChunkedSwarmInspectReadFailure(t *testing.T) {
	filter := New(Options{
		RedactSensitiveData: true,
	})

	readErr := errors.New("chunked upstream read failed")
	resp := newResponseForTest(t, http.MethodGet, "/v1.53/swarm", "")
	resp.Body = &readFailAfterCloser{
		remaining: []byte(`{"JoinTokens":{"Worker":"worker-token"}`),
		err:       readErr,
	}
	resp.ContentLength = -1
	resp.TransferEncoding = []string{"chunked"}

	err := filter.ModifyResponse(resp)
	if err == nil {
		t.Fatal("ModifyResponse() error = nil, want rejection error")
	}
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want errors.Is(..., ErrResponseRejected)", err)
	}
	if !errors.Is(err, readErr) {
		t.Fatalf("ModifyResponse() error = %v, want errors.Is(..., readErr)", err)
	}
}

func TestFilterRejectsMidStreamReadFailure(t *testing.T) {
	filter := New(Options{
		RedactContainerEnv: true,
	})

	readErr := errors.New("upstream read failed")
	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", "")
	resp.Body = &readFailAfterCloser{
		remaining: []byte(`{"Config":{"Env":["SECRET_TOKEN=shh"]}`),
		err:       readErr,
	}
	resp.ContentLength = -1

	err := filter.ModifyResponse(resp)
	if err == nil {
		t.Fatal("ModifyResponse() error = nil, want rejection error")
	}
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want errors.Is(..., ErrResponseRejected)", err)
	}
	if !errors.Is(err, readErr) {
		t.Fatalf("ModifyResponse() error = %v, want errors.Is(..., readErr)", err)
	}
}

func TestFilterModifyResponse_RedactsNetworkTopologyFromContainerAndNetworkReads(t *testing.T) {
	filter := New(Options{
		RedactNetworkTopology: true,
	})

	containerInspectResp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", `{
		"HostConfig":{"NetworkMode":"bridge"},
		"NetworkSettings":{
			"IPAddress":"172.18.0.5",
			"Gateway":"172.18.0.1",
			"GlobalIPv6Address":"2001:db8::5",
			"MacAddress":"02:42:ac:12:00:05",
			"SandboxID":"sandbox-123",
			"SandboxKey":"/var/run/docker/netns/sandbox-123",
			"Networks":{
				"default":{
					"NetworkID":"network-123",
					"EndpointID":"endpoint-123",
					"Gateway":"172.18.0.1",
					"IPAddress":"172.18.0.5",
					"IPPrefixLen":16,
					"IPv6Gateway":"2001:db8::1",
					"GlobalIPv6Address":"2001:db8::5",
					"GlobalIPv6PrefixLen":64,
					"MacAddress":"02:42:ac:12:00:05"
				}
			}
		}
	}`)

	if err := filter.ModifyResponse(containerInspectResp); err != nil {
		t.Fatalf("ModifyResponse(container inspect) error = %v, want nil", err)
	}

	containerInspect := decodeBodyForTest(t, containerInspectResp)
	hostConfig, _ := containerInspect["HostConfig"].(map[string]any)
	if got, _ := hostConfig["NetworkMode"].(string); got != "<redacted>" {
		t.Fatalf("HostConfig.NetworkMode = %q, want %q", got, "<redacted>")
	}
	networkSettings, _ := containerInspect["NetworkSettings"].(map[string]any)
	if got, _ := networkSettings["IPAddress"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.IPAddress = %q, want %q", got, "<redacted>")
	}
	if got, _ := networkSettings["Gateway"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.Gateway = %q, want %q", got, "<redacted>")
	}
	networks, _ := networkSettings["Networks"].(map[string]any)
	defaultNetwork, _ := networks["default"].(map[string]any)
	if got, _ := defaultNetwork["IPAddress"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.Networks.default.IPAddress = %q, want %q", got, "<redacted>")
	}
	if got, _ := defaultNetwork["NetworkID"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.Networks.default.NetworkID = %q, want %q", got, "<redacted>")
	}

	networkInspectResp := newResponseForTest(t, http.MethodGet, "/v1.53/networks/net-123", `{
		"Name":"default",
		"IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]},
		"Containers":{
			"abc123":{"Name":"app","EndpointID":"endpoint-123","MacAddress":"02:42:ac:12:00:05","IPv4Address":"172.18.0.5/16","IPv6Address":""}
		},
		"Peers":[{"Name":"peer-1","IP":"10.0.0.2"}]
	}`)

	if err := filter.ModifyResponse(networkInspectResp); err != nil {
		t.Fatalf("ModifyResponse(network inspect) error = %v, want nil", err)
	}

	networkInspect := decodeBodyForTest(t, networkInspectResp)
	ipam, _ := networkInspect["IPAM"].(map[string]any)
	if config, _ := ipam["Config"].([]any); len(config) != 0 {
		t.Fatalf("IPAM.Config = %#v, want empty redacted array", ipam["Config"])
	}
	containers, _ := networkInspect["Containers"].(map[string]any)
	if len(containers) != 0 {
		t.Fatalf("Containers = %#v, want empty redacted object", containers)
	}
	peers, _ := networkInspect["Peers"].([]any)
	if len(peers) != 0 {
		t.Fatalf("Peers = %#v, want empty redacted array", peers)
	}
}

func TestFilterModifyResponse_RedactsNetworkTopologyFromContainerListWithoutMountRedaction(t *testing.T) {
	filter := New(Options{
		RedactNetworkTopology: true,
	})

	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/json", `[
		{
			"Id":"abc123",
			"NetworkSettings":{
				"Networks":{
					"default":{
						"NetworkID":"network-123",
						"IPAddress":"172.18.0.5"
					}
				}
			}
		}
	]`)

	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse(container list) error = %v, want nil", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(container list): %v", err)
	}

	var containers []map[string]any
	if err := json.Unmarshal(body, &containers); err != nil {
		t.Fatalf("json.Unmarshal(container list): %v\nbody: %s", err, string(body))
	}

	networkSettings, _ := containers[0]["NetworkSettings"].(map[string]any)
	networks, _ := networkSettings["Networks"].(map[string]any)
	defaultNetwork, _ := networks["default"].(map[string]any)
	if got, _ := defaultNetwork["NetworkID"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.Networks.default.NetworkID = %q, want %q", got, "<redacted>")
	}
	if got, _ := defaultNetwork["IPAddress"].(string); got != "<redacted>" {
		t.Fatalf("NetworkSettings.Networks.default.IPAddress = %q, want %q", got, "<redacted>")
	}
}

func TestFilterModifyResponse_RedactsExpandedControlPlaneReads(t *testing.T) {
	filter := New(Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
	})

	serviceResp := newResponseForTest(t, http.MethodGet, "/v1.53/services", `[
		{
			"ID":"service-1",
			"Spec":{
				"TaskTemplate":{
					"ContainerSpec":{
						"Env":["SECRET_TOKEN=shh"],
						"Mounts":[{"Type":"bind","Source":"/srv/services","Target":"/app"}],
						"Secrets":[{"SecretID":"sec-123","SecretName":"prod-db"}],
						"Configs":[{"ConfigID":"cfg-123","ConfigName":"nginx.conf"}]
					}
				}
			},
			"Endpoint":{
				"VirtualIPs":[{"NetworkID":"net-123","Addr":"10.0.0.2/24"}]
			}
		}
	]`)

	if err := filter.ModifyResponse(serviceResp); err != nil {
		t.Fatalf("ModifyResponse(service list) error = %v, want nil", err)
	}

	var services []map[string]any
	serviceBody, err := io.ReadAll(serviceResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(service list): %v", err)
	}
	if err := json.Unmarshal(serviceBody, &services); err != nil {
		t.Fatalf("json.Unmarshal(service list): %v\nbody: %s", err, string(serviceBody))
	}

	containerSpec := nestedMapForTest(t, services[0], "Spec", "TaskTemplate", "ContainerSpec")
	if env, _ := containerSpec["Env"].([]any); len(env) != 0 {
		t.Fatalf("Service ContainerSpec.Env = %#v, want empty redacted array", containerSpec["Env"])
	}
	mounts, _ := containerSpec["Mounts"].([]any)
	firstMount, _ := mounts[0].(map[string]any)
	if got, _ := firstMount["Source"].(string); got != "<redacted>" {
		t.Fatalf("Service Mounts[0].Source = %q, want %q", got, "<redacted>")
	}
	secrets, _ := containerSpec["Secrets"].([]any)
	firstSecret, _ := secrets[0].(map[string]any)
	if got, _ := firstSecret["SecretID"].(string); got != "<redacted>" {
		t.Fatalf("Service Secrets[0].SecretID = %q, want %q", got, "<redacted>")
	}
	if got, _ := firstSecret["SecretName"].(string); got != "<redacted>" {
		t.Fatalf("Service Secrets[0].SecretName = %q, want %q", got, "<redacted>")
	}
	configs, _ := containerSpec["Configs"].([]any)
	firstConfig, _ := configs[0].(map[string]any)
	if got, _ := firstConfig["ConfigID"].(string); got != "<redacted>" {
		t.Fatalf("Service Configs[0].ConfigID = %q, want %q", got, "<redacted>")
	}
	if got, _ := firstConfig["ConfigName"].(string); got != "<redacted>" {
		t.Fatalf("Service Configs[0].ConfigName = %q, want %q", got, "<redacted>")
	}
	virtualIPs := nestedSliceForTest(t, services[0], "Endpoint", "VirtualIPs")
	firstVIP, _ := virtualIPs[0].(map[string]any)
	if got, _ := firstVIP["NetworkID"].(string); got != "<redacted>" {
		t.Fatalf("Service VirtualIPs[0].NetworkID = %q, want %q", got, "<redacted>")
	}
	if got, _ := firstVIP["Addr"].(string); got != "<redacted>" {
		t.Fatalf("Service VirtualIPs[0].Addr = %q, want %q", got, "<redacted>")
	}

	taskResp := newResponseForTest(t, http.MethodGet, "/v1.53/tasks/task-1", `{
		"ID":"task-1",
		"ServiceID":"service-1",
		"NodeID":"node-1",
		"Spec":{
			"ContainerSpec":{
				"Env":["SECRET_TOKEN=shh"],
				"Mounts":[{"Type":"bind","Source":"/srv/tasks","Target":"/work"}]
			}
		},
		"Status":{
			"ContainerStatus":{"ContainerID":"ctr-123","PID":677}
		},
		"NetworksAttachments":[
			{
				"Addresses":["10.0.0.10/24"],
				"Network":{"ID":"net-123"}
			}
		]
	}`)

	if err := filter.ModifyResponse(taskResp); err != nil {
		t.Fatalf("ModifyResponse(task inspect) error = %v, want nil", err)
	}

	task := decodeBodyForTest(t, taskResp)
	taskContainerSpec := nestedMapForTest(t, task, "Spec", "ContainerSpec")
	if env, _ := taskContainerSpec["Env"].([]any); len(env) != 0 {
		t.Fatalf("Task ContainerSpec.Env = %#v, want empty redacted array", taskContainerSpec["Env"])
	}
	taskMounts, _ := taskContainerSpec["Mounts"].([]any)
	taskMount, _ := taskMounts[0].(map[string]any)
	if got, _ := taskMount["Source"].(string); got != "<redacted>" {
		t.Fatalf("Task Mounts[0].Source = %q, want %q", got, "<redacted>")
	}
	if got, _ := task["ServiceID"].(string); got != "<redacted>" {
		t.Fatalf("Task ServiceID = %q, want %q", got, "<redacted>")
	}
	if got, _ := task["NodeID"].(string); got != "<redacted>" {
		t.Fatalf("Task NodeID = %q, want %q", got, "<redacted>")
	}
	containerStatus := nestedMapForTest(t, task, "Status", "ContainerStatus")
	if got, _ := containerStatus["ContainerID"].(string); got != "<redacted>" {
		t.Fatalf("Task Status.ContainerStatus.ContainerID = %q, want %q", got, "<redacted>")
	}
	if got, _ := containerStatus["PID"].(float64); got != 0 {
		t.Fatalf("Task Status.ContainerStatus.PID = %v, want 0", got)
	}
	attachments, _ := task["NetworksAttachments"].([]any)
	firstAttachment, _ := attachments[0].(map[string]any)
	addresses, _ := firstAttachment["Addresses"].([]any)
	if len(addresses) != 0 {
		t.Fatalf("Task NetworksAttachments[0].Addresses = %#v, want empty redacted array", firstAttachment["Addresses"])
	}
	taskNetwork, _ := firstAttachment["Network"].(map[string]any)
	if got, _ := taskNetwork["ID"].(string); got != "<redacted>" {
		t.Fatalf("Task NetworksAttachments[0].Network.ID = %q, want %q", got, "<redacted>")
	}
}

func TestFilterModifyResponse_RedactsSensitivePlatformMetadata(t *testing.T) {
	filter := New(Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
	})

	configResp := newResponseForTest(t, http.MethodGet, "/v1.53/configs/cfg-1", `{
		"ID":"cfg-1",
		"Spec":{"Data":"c2VjcmV0LWNvbmZpZw=="}
	}`)
	if err := filter.ModifyResponse(configResp); err != nil {
		t.Fatalf("ModifyResponse(config inspect) error = %v, want nil", err)
	}
	configPayload := decodeBodyForTest(t, configResp)
	spec, _ := configPayload["Spec"].(map[string]any)
	if got, _ := spec["Data"].(string); got != "<redacted>" {
		t.Fatalf("Config Spec.Data = %q, want %q", got, "<redacted>")
	}

	pluginResp := newResponseForTest(t, http.MethodGet, "/v1.53/plugins/example/json", `{
		"Settings":{
			"Env":["API_KEY=secret"],
			"Mounts":[{"Type":"bind","Source":"/var/lib/docker/plugins","Destination":"/mnt/state"}],
			"Devices":[{"Path":"/dev/fuse"}]
		},
		"Config":{
			"Env":[{"Name":"API_KEY","Value":"secret"}],
			"Mounts":[{"Type":"bind","Source":"/var/lib/docker/plugins","Destination":"/mnt/state"}],
			"PropagatedMount":"/var/lib/docker/plugins",
			"Linux":{"Devices":[{"Path":"/dev/fuse"}]}
		}
	}`)
	if err := filter.ModifyResponse(pluginResp); err != nil {
		t.Fatalf("ModifyResponse(plugin inspect) error = %v, want nil", err)
	}
	plugin := decodeBodyForTest(t, pluginResp)
	settings := nestedMapForTest(t, plugin, "Settings")
	settingsEnv, _ := settings["Env"].([]any)
	if got, _ := settingsEnv[0].(string); got != "API_KEY=<redacted>" {
		t.Fatalf("Plugin Settings.Env[0] = %q, want %q", got, "API_KEY=<redacted>")
	}
	settingsMounts, _ := settings["Mounts"].([]any)
	settingsMount, _ := settingsMounts[0].(map[string]any)
	if got, _ := settingsMount["Source"].(string); got != "<redacted>" {
		t.Fatalf("Plugin Settings.Mounts[0].Source = %q, want %q", got, "<redacted>")
	}
	settingsDevices, _ := settings["Devices"].([]any)
	settingsDevice, _ := settingsDevices[0].(map[string]any)
	if got, _ := settingsDevice["Path"].(string); got != "<redacted>" {
		t.Fatalf("Plugin Settings.Devices[0].Path = %q, want %q", got, "<redacted>")
	}
	configObj := nestedMapForTest(t, plugin, "Config")
	configEnv, _ := configObj["Env"].([]any)
	configEnvEntry, _ := configEnv[0].(map[string]any)
	if got, _ := configEnvEntry["Value"].(string); got != "<redacted>" {
		t.Fatalf("Plugin Config.Env[0].Value = %q, want %q", got, "<redacted>")
	}
	if got, _ := configObj["PropagatedMount"].(string); got != "<redacted>" {
		t.Fatalf("Plugin Config.PropagatedMount = %q, want %q", got, "<redacted>")
	}

	nodeResp := newResponseForTest(t, http.MethodGet, "/v1.53/nodes/node-1", `{
		"Status":{"Addr":"10.0.0.5"},
		"ManagerStatus":{"Addr":"10.0.0.5:2377"},
		"Description":{"TLSInfo":{"TrustRoot":"pem","CertIssuerSubject":"subject","CertIssuerPublicKey":"pub"}}
	}`)
	if err := filter.ModifyResponse(nodeResp); err != nil {
		t.Fatalf("ModifyResponse(node inspect) error = %v, want nil", err)
	}
	node := decodeBodyForTest(t, nodeResp)
	status := nestedMapForTest(t, node, "Status")
	if got, _ := status["Addr"].(string); got != "<redacted>" {
		t.Fatalf("Node Status.Addr = %q, want %q", got, "<redacted>")
	}
	managerStatus := nestedMapForTest(t, node, "ManagerStatus")
	if got, _ := managerStatus["Addr"].(string); got != "<redacted>" {
		t.Fatalf("Node ManagerStatus.Addr = %q, want %q", got, "<redacted>")
	}
	tlsInfo := nestedMapForTest(t, node, "Description", "TLSInfo")
	if got, _ := tlsInfo["TrustRoot"].(string); got != "<redacted>" {
		t.Fatalf("Node Description.TLSInfo.TrustRoot = %q, want %q", got, "<redacted>")
	}

	swarmResp := newResponseForTest(t, http.MethodGet, "/v1.53/swarm", `{
		"JoinTokens":{"Worker":"worker-token","Manager":"manager-token"},
		"TLSInfo":{"TrustRoot":"pem","CertIssuerSubject":"subject","CertIssuerPublicKey":"pub"},
		"DefaultAddrPool":["10.10.0.0/16"],
		"Spec":{
			"CAConfig":{
				"ExternalCAs":[{"URL":"https://ca.example.com","CACert":"pem"}],
				"SigningCACert":"pem-cert",
				"SigningCAKey":"pem-key"
			}
		}
	}`)
	if err := filter.ModifyResponse(swarmResp); err != nil {
		t.Fatalf("ModifyResponse(swarm inspect) error = %v, want nil", err)
	}
	swarm := decodeBodyForTest(t, swarmResp)
	joinTokens := nestedMapForTest(t, swarm, "JoinTokens")
	if got, _ := joinTokens["Worker"].(string); got != "<redacted>" {
		t.Fatalf("Swarm JoinTokens.Worker = %q, want %q", got, "<redacted>")
	}
	if got, _ := joinTokens["Manager"].(string); got != "<redacted>" {
		t.Fatalf("Swarm JoinTokens.Manager = %q, want %q", got, "<redacted>")
	}
	swarmTLS := nestedMapForTest(t, swarm, "TLSInfo")
	if got, _ := swarmTLS["TrustRoot"].(string); got != "<redacted>" {
		t.Fatalf("Swarm TLSInfo.TrustRoot = %q, want %q", got, "<redacted>")
	}
	if pools, _ := swarm["DefaultAddrPool"].([]any); len(pools) != 0 {
		t.Fatalf("Swarm DefaultAddrPool = %#v, want empty redacted array", swarm["DefaultAddrPool"])
	}

	unlockResp := newResponseForTest(t, http.MethodGet, "/v1.53/swarm/unlockkey", `{"UnlockKey":"SWMKEY-123"}`)
	if err := filter.ModifyResponse(unlockResp); err != nil {
		t.Fatalf("ModifyResponse(swarm unlockkey) error = %v, want nil", err)
	}
	unlock := decodeBodyForTest(t, unlockResp)
	if got, _ := unlock["UnlockKey"].(string); got != "<redacted>" {
		t.Fatalf("UnlockKey = %q, want %q", got, "<redacted>")
	}

	infoResp := newResponseForTest(t, http.MethodGet, "/v1.53/info", `{
		"Swarm":{
			"NodeID":"node-1",
			"NodeAddr":"10.0.0.5",
			"RemoteManagers":[{"NodeID":"node-2","Addr":"10.0.0.6:2377"}],
			"Cluster":{
				"TLSInfo":{"TrustRoot":"pem","CertIssuerSubject":"subject","CertIssuerPublicKey":"pub"},
				"DefaultAddrPool":["10.10.0.0/16"]
			}
		}
	}`)
	if err := filter.ModifyResponse(infoResp); err != nil {
		t.Fatalf("ModifyResponse(info) error = %v, want nil", err)
	}
	info := decodeBodyForTest(t, infoResp)
	swarmInfo := nestedMapForTest(t, info, "Swarm")
	if got, _ := swarmInfo["NodeID"].(string); got != "<redacted>" {
		t.Fatalf("Info Swarm.NodeID = %q, want %q", got, "<redacted>")
	}
	if got, _ := swarmInfo["NodeAddr"].(string); got != "<redacted>" {
		t.Fatalf("Info Swarm.NodeAddr = %q, want %q", got, "<redacted>")
	}
	if managers, _ := swarmInfo["RemoteManagers"].([]any); len(managers) != 0 {
		t.Fatalf("Info Swarm.RemoteManagers = %#v, want empty redacted array", swarmInfo["RemoteManagers"])
	}

	systemDFResp := newResponseForTest(t, http.MethodGet, "/v1.53/system/df", `{
		"ContainerUsage":{
			"Items":[
				{
					"Mounts":[{"Type":"bind","Source":"/srv/data","Destination":"/data"}],
					"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"net-123","IPAddress":"172.18.0.5"}}}
				}
			]
		},
		"VolumeUsage":{
			"Items":[
				{"Mountpoint":"/var/lib/docker/volumes/cache/_data"}
			]
		}
	}`)
	if err := filter.ModifyResponse(systemDFResp); err != nil {
		t.Fatalf("ModifyResponse(system df) error = %v, want nil", err)
	}
	systemDF := decodeBodyForTest(t, systemDFResp)
	containerItems := nestedSliceForTest(t, systemDF, "ContainerUsage", "Items")
	firstContainer, _ := containerItems[0].(map[string]any)
	containerMounts, _ := firstContainer["Mounts"].([]any)
	containerMount, _ := containerMounts[0].(map[string]any)
	if got, _ := containerMount["Source"].(string); got != "<redacted>" {
		t.Fatalf("SystemDF ContainerUsage.Items[0].Mounts[0].Source = %q, want %q", got, "<redacted>")
	}
	containerNetworks := nestedMapForTest(t, firstContainer, "NetworkSettings", "Networks", "bridge")
	if got, _ := containerNetworks["NetworkID"].(string); got != "<redacted>" {
		t.Fatalf("SystemDF ContainerUsage.Items[0].NetworkSettings.Networks.bridge.NetworkID = %q, want %q", got, "<redacted>")
	}
	volumeItems := nestedSliceForTest(t, systemDF, "VolumeUsage", "Items")
	firstVolume, _ := volumeItems[0].(map[string]any)
	if got, _ := firstVolume["Mountpoint"].(string); got != "<redacted>" {
		t.Fatalf("SystemDF VolumeUsage.Items[0].Mountpoint = %q, want %q", got, "<redacted>")
	}
}

func nestedMapForTest(t *testing.T, payload map[string]any, keys ...string) map[string]any {
	t.Helper()

	current := payload
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			t.Fatalf("payload[%q] = %#v, want object", key, current[key])
		}
		current = next
	}
	return current
}

func nestedSliceForTest(t *testing.T, payload map[string]any, keys ...string) []any {
	t.Helper()

	if len(keys) == 0 {
		t.Fatal("nestedSliceForTest requires at least one key")
	}
	current := payload
	for _, key := range keys[:len(keys)-1] {
		next, ok := current[key].(map[string]any)
		if !ok {
			t.Fatalf("payload[%q] = %#v, want object", key, current[key])
		}
		current = next
	}
	values, ok := current[keys[len(keys)-1]].([]any)
	if !ok {
		t.Fatalf("payload[%q] = %#v, want array", keys[len(keys)-1], current[keys[len(keys)-1]])
	}
	return values
}
