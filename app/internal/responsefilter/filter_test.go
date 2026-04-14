package responsefilter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
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

	body := `{"Config":{"Env":["` + strings.Repeat("A", maxResponseBodyBytes) + `"]}}`
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
