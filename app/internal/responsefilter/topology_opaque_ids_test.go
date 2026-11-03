package responsefilter

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func defaultRedactionOptions() Options {
	return Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
	}
}

// TestTraefikSwarmFlowSurvivesDefaultRedaction walks the join keys Traefik's
// Swarm provider uses: service VirtualIPs[].NetworkID against the network
// list, task NodeID into node inspect, and NetworksAttachments[].Network.ID.
// Addresses on the same bodies are still redacted.
func TestTraefikSwarmFlowSurvivesDefaultRedaction(t *testing.T) {
	t.Parallel()
	filter := New(defaultRedactionOptions())

	serviceResp := newResponseForTest(t, http.MethodGet, "/v1.53/services/svc-1", `{
		"ID":"svc-1",
		"Endpoint":{"VirtualIPs":[{"NetworkID":"net-ingress","Addr":"10.0.0.5/24"}]}
	}`)
	if err := filter.ModifyResponse(serviceResp); err != nil {
		t.Fatalf("ModifyResponse(service inspect) error = %v", err)
	}
	service := decodeBodyForTest(t, serviceResp)
	vip, _ := nestedSliceForTest(t, service, "Endpoint", "VirtualIPs")[0].(map[string]any)
	if got := vip["NetworkID"]; got != "net-ingress" {
		t.Errorf("VirtualIPs[0].NetworkID = %#v, want net-ingress", got)
	}
	if got := vip["Addr"]; got != "" {
		t.Errorf("VirtualIPs[0].Addr = %#v, want empty string", got)
	}

	taskResp := newResponseForTest(t, http.MethodGet, "/v1.53/tasks", `[{
		"ID":"task-1",
		"ServiceID":"svc-1",
		"NodeID":"node-7",
		"Status":{"ContainerStatus":{"ContainerID":"ctr-1","PID":42}},
		"NetworksAttachments":[{"Network":{"ID":"net-ingress"},"Addresses":["10.0.0.9/24"]}]
	}]`)
	if err := filter.ModifyResponse(taskResp); err != nil {
		t.Fatalf("ModifyResponse(task list) error = %v", err)
	}
	taskBody, _ := io.ReadAll(taskResp.Body)
	var tasks []map[string]any
	if err := json.Unmarshal(taskBody, &tasks); err != nil {
		t.Fatalf("unmarshal tasks: %v", err)
	}
	task := tasks[0]
	if got := task["ServiceID"]; got != "svc-1" {
		t.Errorf("ServiceID = %#v, want svc-1", got)
	}
	if got := task["NodeID"]; got != "node-7" {
		t.Errorf("NodeID = %#v, want node-7", got)
	}
	if got, _ := nestedMapForTest(t, task, "Status", "ContainerStatus")["ContainerID"].(string); got != "ctr-1" {
		t.Errorf("ContainerStatus.ContainerID = %q, want ctr-1", got)
	}
	attachment, _ := task["NetworksAttachments"].([]any)[0].(map[string]any)
	if got, _ := nestedMapForTest(t, attachment, "Network")["ID"].(string); got != "net-ingress" {
		t.Errorf("NetworksAttachments[0].Network.ID = %q, want net-ingress", got)
	}
	if addrs, _ := attachment["Addresses"].([]any); len(addrs) != 0 {
		t.Errorf("NetworksAttachments[0].Addresses = %#v, want empty", attachment["Addresses"])
	}

	infoResp := newResponseForTest(t, http.MethodGet, "/v1.53/info", `{"Swarm":{"NodeID":"node-7","NodeAddr":"10.0.0.7"}}`)
	if err := filter.ModifyResponse(infoResp); err != nil {
		t.Fatalf("ModifyResponse(info) error = %v", err)
	}
	swarm := nestedMapForTest(t, decodeBodyForTest(t, infoResp), "Swarm")
	if got := swarm["NodeID"]; got != "node-7" {
		t.Errorf("Swarm.NodeID = %#v, want node-7", got)
	}
	if got := swarm["NodeAddr"]; got != "<redacted>" {
		t.Errorf("Swarm.NodeAddr = %#v, want <redacted>", got)
	}
}

func TestContainerInspectKeepsOpaqueIDsAndRedactsAddresses(t *testing.T) {
	t.Parallel()
	filter := New(defaultRedactionOptions())

	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/abc/json", `{
		"Id":"abc",
		"HostConfig":{
			"NetworkMode":"container:other",
			"MaskedPaths":["/proc/kcore","/proc/keys"],
			"ReadonlyPaths":["/proc/bus"],
			"Mounts":[
				{"Type":"bind","Source":"/host/secret","Target":"/s"},
				{"Type":"volume","Source":"data-vol","Target":"/d"}
			]
		},
		"NetworkSettings":{
			"SandboxKey":"/var/run/docker/netns/abc",
			"Networks":{"net":{"NetworkID":"net-1","EndpointID":"ep-1","IPAddress":"10.0.0.2","MacAddress":"02:42:0a:00:00:02"}}
		}
	}`)
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse error = %v", err)
	}
	body := decodeBodyForTest(t, resp)
	hostConfig := nestedMapForTest(t, body, "HostConfig")
	if got := hostConfig["NetworkMode"]; got != "container:other" {
		t.Errorf("NetworkMode = %#v, want container:other", got)
	}
	if got, _ := hostConfig["MaskedPaths"].([]any); len(got) != 2 {
		t.Errorf("MaskedPaths = %#v, want both entries preserved", hostConfig["MaskedPaths"])
	}
	if got, _ := hostConfig["ReadonlyPaths"].([]any); len(got) != 1 {
		t.Errorf("ReadonlyPaths = %#v, want the entry preserved", hostConfig["ReadonlyPaths"])
	}
	mounts, _ := hostConfig["Mounts"].([]any)
	if got, _ := mounts[0].(map[string]any)["Source"].(string); got != "<redacted>" {
		t.Errorf("bind Mounts[0].Source = %q, want <redacted>", got)
	}
	if got, _ := mounts[1].(map[string]any)["Source"].(string); got != "data-vol" {
		t.Errorf("volume Mounts[1].Source = %q, want data-vol", got)
	}

	settings := nestedMapForTest(t, body, "NetworkSettings")
	if got := settings["SandboxKey"]; got != "<redacted>" {
		t.Errorf("SandboxKey = %#v, want <redacted>", got)
	}
	network := nestedMapForTest(t, settings, "Networks", "net")
	if network["NetworkID"] != "net-1" || network["EndpointID"] != "ep-1" {
		t.Errorf("NetworkID/EndpointID = %#v/%#v, want net-1/ep-1", network["NetworkID"], network["EndpointID"])
	}
	if network["IPAddress"] != "" || network["MacAddress"] != "" {
		t.Errorf("IPAddress/MacAddress = %#v/%#v, want empty strings", network["IPAddress"], network["MacAddress"])
	}
}
