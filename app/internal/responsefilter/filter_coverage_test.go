package responsefilter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ─── Enabled ────────────────────────────────────────────────────────────────

func TestEnabled(t *testing.T) {
	tests := []struct {
		name string
		f    *Filter
		want bool
	}{
		{"nil filter", nil, false},
		{"all false", New(Options{}), false},
		{"RedactContainerEnv", New(Options{RedactContainerEnv: true}), true},
		{"RedactMountPaths", New(Options{RedactMountPaths: true}), true},
		{"RedactNetworkTopology", New(Options{RedactNetworkTopology: true}), true},
		{"RedactSensitiveData", New(Options{RedactSensitiveData: true}), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.Enabled(); got != tc.want {
				t.Fatalf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── ModifyResponse – early-return branches ──────────────────────────────────

func TestModifyResponse_NilReturns(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})

	// nil resp
	if err := f.ModifyResponse(nil); err != nil {
		t.Fatalf("nil resp: %v", err)
	}

	// resp with nil Request
	if err := f.ModifyResponse(&http.Response{StatusCode: http.StatusOK}); err != nil {
		t.Fatalf("nil Request: %v", err)
	}
}

func TestModifyResponse_RedactsSuccessfulProtectedResponsesAcrossMethodsAnd2xxStatuses(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})

	req, _ := http.NewRequest(http.MethodPost, "http://x/containers/abc/json", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    req,
		Body:       io.NopCloser(strings.NewReader(`{"Config":{"Env":["X=Y"]}}`)),
	}
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("POST: %v", err)
	}
	got := decodeBodyForTest(t, resp)
	config, _ := got["Config"].(map[string]any)
	if env, _ := config["Env"].([]any); len(env) != 0 {
		t.Fatalf("POST Config.Env = %#v, want empty redacted array", config["Env"])
	}

	req2, _ := http.NewRequest(http.MethodGet, "http://x/containers/abc/json", nil)
	resp2 := &http.Response{
		StatusCode: 201,
		Request:    req2,
		Body:       io.NopCloser(strings.NewReader(`{"Config":{"Env":["X=Y"]}}`)),
	}
	if err := f.ModifyResponse(resp2); err != nil {
		t.Fatalf("201: %v", err)
	}
	got = decodeBodyForTest(t, resp2)
	config, _ = got["Config"].(map[string]any)
	if env, _ := config["Env"].([]any); len(env) != 0 {
		t.Fatalf("201 Config.Env = %#v, want empty redacted array", config["Env"])
	}

	req3, _ := http.NewRequest(http.MethodPut, "http://x/containers/abc/json", nil)
	resp3 := &http.Response{
		StatusCode: http.StatusAccepted,
		Request:    req3,
		Body:       io.NopCloser(strings.NewReader(`{"Config":{"Env":["X=Y"]}}`)),
	}
	if err := f.ModifyResponse(resp3); err != nil {
		t.Fatalf("202: %v", err)
	}
	got = decodeBodyForTest(t, resp3)
	config, _ = got["Config"].(map[string]any)
	if env, _ := config["Env"].([]any); len(env) != 0 {
		t.Fatalf("202 Config.Env = %#v, want empty redacted array", config["Env"])
	}
}

func TestModifyResponse_SkipsHeadProtectedResponses(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})

	req, _ := http.NewRequest(http.MethodHead, "http://x/containers/abc/json", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    req,
		Body:       io.NopCloser(strings.NewReader("")),
	}
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("HEAD: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != "" {
		t.Fatalf("HEAD body = %q, want empty", string(body))
	}
}

func TestModifyResponse_SkipsNonSuccessfulProtectedResponses(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})

	req, _ := http.NewRequest(http.MethodGet, "http://x/containers/abc/json", nil)
	resp := &http.Response{
		StatusCode: http.StatusNotFound,
		Request:    req,
		Body:       io.NopCloser(strings.NewReader(`{"message":"No such container: abc"}`)),
	}
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("404: %v", err)
	}
}

func TestModifyResponse_SkipsNoBodySuccessStatuses(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})

	tests := []struct {
		name   string
		status int
	}{
		{name: "204", status: http.StatusNoContent},
		{name: "205", status: http.StatusResetContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://x/containers/abc/json", nil)
			resp := &http.Response{
				StatusCode: tt.status,
				Request:    req,
				Body:       io.NopCloser(strings.NewReader(`{"Config":`)),
			}
			if err := f.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v, want nil", err)
			}
		})
	}
}

func TestModifyResponse_DisabledFilterNoOp(t *testing.T) {
	f := New(Options{}) // all false
	resp := newResponseForTest(t, http.MethodGet, "/containers/abc/json", `{"Config":{"Env":["X=Y"]}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("disabled filter: %v", err)
	}
}

func TestModifyResponse_DefaultPathReturnsNil(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/_ping", `OK`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("default path: %v", err)
	}
}

// ─── modifyNetworkList ───────────────────────────────────────────────────────

func TestModifyNetworkList_SkipsWhenNetworkTopologyDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true}) // RedactNetworkTopology = false
	resp := newResponseForTest(t, http.MethodGet, "/networks", `[{"IPAM":{"Config":[{"Subnet":"10.0.0.0/8"}]}}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyNetworkList_RedactsTopology(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/networks", `[
		{
			"Name":"bridge",
			"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]},
			"Containers":{"abc123":{"Name":"app","IPv4Address":"172.17.0.2/16"}},
			"Peers":[{"Name":"peer1","IP":"10.0.0.1"}]
		}
	]`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	var networks []map[string]any
	if err := json.Unmarshal(body, &networks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ipam := networks[0]["IPAM"].(map[string]any)
	if cfg, _ := ipam["Config"].([]any); len(cfg) != 0 {
		t.Fatalf("IPAM.Config = %v, want empty", cfg)
	}
	containers := networks[0]["Containers"].(map[string]any)
	if len(containers) != 0 {
		t.Fatalf("Containers = %v, want empty", containers)
	}
	peers := networks[0]["Peers"].([]any)
	if len(peers) != 0 {
		t.Fatalf("Peers = %v, want empty", peers)
	}
}

func TestModifyNetworkList_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/networks", `{not-array}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyNetworkList_RejectsBadTopologyType(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	// Containers is a string instead of object — triggers redactNetworkTopology error
	resp := newResponseForTest(t, http.MethodGet, "/networks", `[{"Containers":"bad"}]`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyVolumeInspect ─────────────────────────────────────────────────────

func TestModifyVolumeInspect_SkipsWhenMountPathsDisabled(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true}) // RedactMountPaths = false
	resp := newResponseForTest(t, http.MethodGet, "/volumes/myvol", `{"Mountpoint":"/var/lib/docker/volumes/myvol/_data"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyVolumeInspect_RedactsMountpoint(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/volumes/myvol", `{
		"Name":"myvol",
		"Mountpoint":"/var/lib/docker/volumes/myvol/_data",
		"Driver":"local"
	}`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	got := decodeBodyForTest(t, resp)
	if v, _ := got["Mountpoint"].(string); v != "<redacted>" {
		t.Fatalf("Mountpoint = %q, want <redacted>", v)
	}
	if v, _ := got["Name"].(string); v != "myvol" {
		t.Fatalf("Name = %q, want myvol (unmodified)", v)
	}
}

func TestModifyVolumeInspect_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/volumes/myvol", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyServiceInspect ────────────────────────────────────────────────────

func TestModifyServiceInspect_SkipsWhenAllDisabled(t *testing.T) {
	f := New(Options{})
	resp := newResponseForTest(t, http.MethodGet, "/services/svc-1", `{"ID":"svc-1"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyServiceInspect_RedactsPayload(t *testing.T) {
	f := New(Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
	})
	resp := newResponseForTest(t, http.MethodGet, "/services/svc-1", `{
		"ID":"svc-1",
		"Spec":{
			"TaskTemplate":{
				"ContainerSpec":{
					"Env":["SECRET=val"],
					"Mounts":[{"Type":"bind","Source":"/host/path","Target":"/mount"}],
					"Secrets":[{"SecretID":"sec-1","SecretName":"mysecret"}],
					"Configs":[{"ConfigID":"cfg-1","ConfigName":"myconfig"}]
				}
			}
		},
		"Endpoint":{
			"VirtualIPs":[{"NetworkID":"net-123","Addr":"10.0.0.2/24"}]
		}
	}`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	got := decodeBodyForTest(t, resp)
	containerSpec := nestedMapForTest(t, got, "Spec", "TaskTemplate", "ContainerSpec")
	if env, _ := containerSpec["Env"].([]any); len(env) != 0 {
		t.Fatalf("Env = %v, want empty", env)
	}
	mounts, _ := containerSpec["Mounts"].([]any)
	mount0, _ := mounts[0].(map[string]any)
	if v, _ := mount0["Source"].(string); v != "<redacted>" {
		t.Fatalf("Mounts[0].Source = %q, want <redacted>", v)
	}
	secrets, _ := containerSpec["Secrets"].([]any)
	secret0, _ := secrets[0].(map[string]any)
	if v, _ := secret0["SecretID"].(string); v != "<redacted>" {
		t.Fatalf("SecretID = %q, want <redacted>", v)
	}
	vips := nestedSliceForTest(t, got, "Endpoint", "VirtualIPs")
	vip0, _ := vips[0].(map[string]any)
	if v, _ := vip0["Addr"].(string); v != "<redacted>" {
		t.Fatalf("VirtualIPs[0].Addr = %q, want <redacted>", v)
	}
}

func TestModifyServiceInspect_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/services/svc-1", `[not-object]`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyTaskList ──────────────────────────────────────────────────────────

func TestModifyTaskList_SkipsWhenAllDisabled(t *testing.T) {
	f := New(Options{})
	resp := newResponseForTest(t, http.MethodGet, "/tasks", `[{"ID":"task-1"}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyTaskList_RedactsPayload(t *testing.T) {
	f := New(Options{
		RedactContainerEnv:    true,
		RedactNetworkTopology: true,
	})
	resp := newResponseForTest(t, http.MethodGet, "/tasks", `[
		{
			"ID":"task-1",
			"ServiceID":"svc-1",
			"NodeID":"node-1",
			"Spec":{
				"ContainerSpec":{
					"Env":["SECRET=val"]
				}
			},
			"Status":{
				"ContainerStatus":{"ContainerID":"ctr-1","PID":1234}
			}
		}
	]`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	var tasks []map[string]any
	if err := json.Unmarshal(body, &tasks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if v, _ := tasks[0]["ServiceID"].(string); v != "<redacted>" {
		t.Fatalf("ServiceID = %q, want <redacted>", v)
	}
	if v, _ := tasks[0]["NodeID"].(string); v != "<redacted>" {
		t.Fatalf("NodeID = %q, want <redacted>", v)
	}
	containerSpec := nestedMapForTest(t, tasks[0], "Spec", "ContainerSpec")
	if env, _ := containerSpec["Env"].([]any); len(env) != 0 {
		t.Fatalf("Env = %v, want empty", env)
	}
}

func TestModifyTaskList_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/tasks", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifySecretList ────────────────────────────────────────────────────────

func TestModifySecretList_SkipsWhenSensitiveDataDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true}) // RedactSensitiveData = false
	resp := newResponseForTest(t, http.MethodGet, "/secrets", `[{"ID":"sec-1","Spec":{"Data":"secret"}}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifySecretList_RedactsData(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/secrets", `[
		{
			"ID":"sec-1",
			"Spec":{"Name":"mysecret","Data":"c2VjcmV0LWRhdGE="}
		}
	]`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	var secrets []map[string]any
	if err := json.Unmarshal(body, &secrets); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	spec, _ := secrets[0]["Spec"].(map[string]any)
	if v, _ := spec["Data"].(string); v != "<redacted>" {
		t.Fatalf("Spec.Data = %q, want <redacted>", v)
	}
	if v, _ := spec["Name"].(string); v != "mysecret" {
		t.Fatalf("Spec.Name = %q, want mysecret (unchanged)", v)
	}
}

func TestModifySecretList_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/secrets", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifySecretInspect ─────────────────────────────────────────────────────

func TestModifySecretInspect_SkipsWhenSensitiveDataDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/secrets/sec-1", `{"ID":"sec-1","Spec":{"Data":"secret"}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifySecretInspect_RedactsData(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/secrets/sec-1", `{
		"ID":"sec-1",
		"Spec":{"Name":"prod-db","Data":"c2VjcmV0LWRhdGE="}
	}`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	got := decodeBodyForTest(t, resp)
	spec, _ := got["Spec"].(map[string]any)
	if v, _ := spec["Data"].(string); v != "<redacted>" {
		t.Fatalf("Spec.Data = %q, want <redacted>", v)
	}
}

func TestModifySecretInspect_NoSpecField(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/secrets/sec-1", `{"ID":"sec-1"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("no Spec field: %v", err)
	}
}

func TestModifySecretInspect_RejectsBadSpecType(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/secrets/sec-1", `{"Spec":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyConfigList ────────────────────────────────────────────────────────

func TestModifyConfigList_SkipsWhenSensitiveDataDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/configs", `[{"ID":"cfg-1","Spec":{"Data":"secret"}}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyConfigList_RedactsData(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/configs", `[
		{
			"ID":"cfg-1",
			"Spec":{"Name":"nginx.conf","Data":"c29tZWNvbmZpZw=="}
		}
	]`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	var configs []map[string]any
	if err := json.Unmarshal(body, &configs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	spec, _ := configs[0]["Spec"].(map[string]any)
	if v, _ := spec["Data"].(string); v != "<redacted>" {
		t.Fatalf("Spec.Data = %q, want <redacted>", v)
	}
}

func TestModifyConfigList_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/configs", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyPluginList ────────────────────────────────────────────────────────

func TestModifyPluginList_SkipsWhenBothDisabled(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true}) // no env/mount flags
	resp := newResponseForTest(t, http.MethodGet, "/plugins", `[{"Name":"myplugin"}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyPluginList_RedactsEnvAndMounts(t *testing.T) {
	f := New(Options{RedactContainerEnv: true, RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/plugins", `[
		{
			"Name":"myplugin",
			"Settings":{
				"Env":["API_KEY=secret"],
				"Mounts":[{"Type":"bind","Source":"/host/plugin-data","Destination":"/data"}],
				"Devices":[{"Path":"/dev/fuse"}]
			},
			"Config":{
				"Env":[{"Name":"API_KEY","Value":"secret"}],
				"Mounts":[{"Type":"bind","Source":"/host/plugin-data","Destination":"/data"}],
				"PropagatedMount":"/plugin/propagated"
			}
		}
	]`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	var plugins []map[string]any
	if err := json.Unmarshal(body, &plugins); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	settings, _ := plugins[0]["Settings"].(map[string]any)
	settingsEnv, _ := settings["Env"].([]any)
	if got, _ := settingsEnv[0].(string); got != "API_KEY=<redacted>" {
		t.Fatalf("Settings.Env[0] = %q, want API_KEY=<redacted>", got)
	}
	settingsMounts, _ := settings["Mounts"].([]any)
	m0, _ := settingsMounts[0].(map[string]any)
	if v, _ := m0["Source"].(string); v != "<redacted>" {
		t.Fatalf("Settings.Mounts[0].Source = %q, want <redacted>", v)
	}
	settingsDevices, _ := settings["Devices"].([]any)
	d0, _ := settingsDevices[0].(map[string]any)
	if v, _ := d0["Path"].(string); v != "<redacted>" {
		t.Fatalf("Settings.Devices[0].Path = %q, want <redacted>", v)
	}
}

func TestModifyPluginList_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/plugins", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyNodeList ──────────────────────────────────────────────────────────

func TestModifyNodeList_SkipsWhenBothDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/nodes", `[{"ID":"node-1"}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyNodeList_RedactsTopologyAndTLS(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true, RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/nodes", `[
		{
			"ID":"node-1",
			"Status":{"Addr":"10.0.0.1"},
			"ManagerStatus":{"Addr":"10.0.0.1:2377"},
			"Description":{"TLSInfo":{"TrustRoot":"pem","CertIssuerSubject":"subj","CertIssuerPublicKey":"pub"}}
		}
	]`)

	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	var nodes []map[string]any
	if err := json.Unmarshal(body, &nodes); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	status, _ := nodes[0]["Status"].(map[string]any)
	if v, _ := status["Addr"].(string); v != "<redacted>" {
		t.Fatalf("Status.Addr = %q, want <redacted>", v)
	}
	managerStatus, _ := nodes[0]["ManagerStatus"].(map[string]any)
	if v, _ := managerStatus["Addr"].(string); v != "<redacted>" {
		t.Fatalf("ManagerStatus.Addr = %q, want <redacted>", v)
	}
	tlsInfo := nestedMapForTest(t, nodes[0], "Description", "TLSInfo")
	if v, _ := tlsInfo["TrustRoot"].(string); v != "<redacted>" {
		t.Fatalf("TLSInfo.TrustRoot = %q, want <redacted>", v)
	}
}

func TestModifyNodeList_RejectsMalformed(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/nodes", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── redactSecretPayload ─────────────────────────────────────────────────────

func TestRedactSecretPayload_RedactsData(t *testing.T) {
	payload := map[string]any{
		"ID":   "sec-1",
		"Spec": map[string]any{"Name": "mysecret", "Data": "c2VjcmV0"},
	}
	if err := redactSecretPayload(payload); err != nil {
		t.Fatalf("error: %v", err)
	}
	spec, _ := payload["Spec"].(map[string]any)
	if v, _ := spec["Data"].(string); v != "<redacted>" {
		t.Fatalf("Data = %q, want <redacted>", v)
	}
	if v, _ := spec["Name"].(string); v != "mysecret" {
		t.Fatalf("Name = %q, want unchanged", v)
	}
}

func TestRedactSecretPayload_NoSpec(t *testing.T) {
	payload := map[string]any{"ID": "sec-1"}
	if err := redactSecretPayload(payload); err != nil {
		t.Fatalf("no Spec: %v", err)
	}
}

func TestRedactSecretPayload_NilSpec(t *testing.T) {
	payload := map[string]any{"Spec": nil}
	if err := redactSecretPayload(payload); err != nil {
		t.Fatalf("nil Spec: %v", err)
	}
}

func TestRedactSecretPayload_BadSpecType(t *testing.T) {
	payload := map[string]any{"Spec": "not-a-map"}
	err := redactSecretPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Spec type, got nil")
	}
}

// ─── splitBindSpec ───────────────────────────────────────────────────────────

func TestSplitBindSpec(t *testing.T) {
	tests := []struct {
		name       string
		bind       string
		wantSource string
		wantRest   string
	}{
		{"empty", "", "", ""},
		{"unix absolute no colon", "/srv/data", "/srv/data", ""},
		{"unix absolute with target", "/srv/data:/mnt/data", "/srv/data", ":/mnt/data"},
		{"unix absolute with options", "/srv/data:/mnt/data:ro", "/srv/data", ":/mnt/data:ro"},
		{"named volume", "myvolume:/mnt/data", "myvolume", ":/mnt/data"},
		{"windows absolute backslash", `C:\data:/mnt/data`, `C:\data`, ":/mnt/data"},
		{"windows absolute forward slash", "C:/data:/mnt/data", "C:/data", ":/mnt/data"},
		{"windows absolute no target", `C:\data`, `C:\data`, ""},
		{"windows lowercase drive", `c:\data:/mnt`, `c:\data`, ":/mnt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSource, gotRest := splitBindSpec(tc.bind)
			if gotSource != tc.wantSource {
				t.Fatalf("source = %q, want %q", gotSource, tc.wantSource)
			}
			if gotRest != tc.wantRest {
				t.Fatalf("rest = %q, want %q", gotRest, tc.wantRest)
			}
		})
	}
}

// ─── isSensitiveHostPath ──────────────────────────────────────────────────────

func TestIsSensitiveHostPath(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty", "", false},
		{"whitespace only", "   ", false},
		{"unix absolute", "/srv/data", true},
		{"unc path backslash", `\\server\share`, true},
		{"unc path forward slash", "//server/share", true},
		{"windows absolute backslash", `C:\data`, true},
		{"windows absolute forward slash", "C:/data", true},
		{"named volume", "myvolume", false},
		{"relative path", "relative/path", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSensitiveHostPath(tc.value); got != tc.want {
				t.Fatalf("isSensitiveHostPath(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// ─── isWindowsAbsolutePath ────────────────────────────────────────────────────

func TestIsWindowsAbsolutePath(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"too short", "C:", false},
		{"empty", "", false},
		{"unix absolute", "/srv", false},
		{"windows backslash uppercase", `C:\data`, true},
		{"windows forward slash uppercase", "C:/data", true},
		{"windows backslash lowercase", `c:\data`, true},
		{"windows forward slash lowercase", "c:/data", true},
		{"non-letter drive", `1:\data`, false},
		{"no colon after drive", `CC\data`, false},
		{"drive colon no sep", "C:data", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWindowsAbsolutePath(tc.value); got != tc.want {
				t.Fatalf("isWindowsAbsolutePath(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// ─── isVolumeInspectPath ──────────────────────────────────────────────────────

func TestIsVolumeInspectPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/volumes/", false},        // empty rest
		{"/volumes/myvol", true},    // simple id
		{"/volumes/myvol/", false},  // trailing slash makes it have "/"
		{"/volumes/vol/sub", false}, // sub-path
		{"/networks/foo", false},    // wrong prefix
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isVolumeInspectPath(tc.path); got != tc.want {
				t.Fatalf("isVolumeInspectPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// ─── isServiceInspectPath ─────────────────────────────────────────────────────

func TestIsServiceInspectPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/services/", false},
		{"/services/svc-1", true},
		{"/services/svc-1/tasks", false},
		{"/nodes/foo", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isServiceInspectPath(tc.path); got != tc.want {
				t.Fatalf("isServiceInspectPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// ─── isSecretInspectPath ──────────────────────────────────────────────────────

func TestIsSecretInspectPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/secrets/", false},
		{"/secrets/sec-1", true},
		{"/secrets/sec-1/sub", false},
		{"/configs/foo", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isSecretInspectPath(tc.path); got != tc.want {
				t.Fatalf("isSecretInspectPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// ─── rejectResponse ──────────────────────────────────────────────────────────

func TestRejectResponse_NilErr(t *testing.T) {
	err := rejectResponse(nil)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
	if err.Error() != ErrResponseRejected.Error() {
		t.Fatalf("unexpected message: %v", err)
	}
}

func TestRejectResponse_WithErr(t *testing.T) {
	inner := errors.New("inner error")
	err := rejectResponse(inner)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected wrapped, got %v", err)
	}
	if !errors.Is(err, inner) {
		t.Fatalf("want inner error wrapped, got %v", err)
	}
}

// ─── readResponseBody – nil body ─────────────────────────────────────────────

func TestReadResponseBody_NilBody(t *testing.T) {
	resp := &http.Response{Body: nil}
	_, err := readResponseBody(resp)
	if err == nil {
		t.Fatal("want error for nil body, got nil")
	}
}

// ─── writeResponseBody – nil header ─────────────────────────────────────────

func TestWriteResponseBody_NilHeader(t *testing.T) {
	resp := &http.Response{
		Body:   io.NopCloser(strings.NewReader("")),
		Header: nil,
	}
	payload := map[string]any{"key": "value"}
	if err := writeResponseBody(resp, payload); err != nil {
		t.Fatalf("writeResponseBody with nil header: %v", err)
	}
	if resp.Header == nil {
		t.Fatal("Header should have been initialized")
	}
}

// ─── nestedMapValue – wrong type ─────────────────────────────────────────────

func TestNestedMapValue_WrongType(t *testing.T) {
	payload := map[string]any{"Spec": "not-a-map"}
	_, _, err := nestedMapValue(payload, "Spec")
	if err == nil {
		t.Fatal("want error for wrong type, got nil")
	}
}

// ─── nestedArrayValue – various branches ─────────────────────────────────────

func TestNestedArrayValue_NoKeys(t *testing.T) {
	payload := map[string]any{}
	vals, found, err := nestedArrayValue(payload)
	if err != nil || found || vals != nil {
		t.Fatalf("no keys: got vals=%v found=%v err=%v", vals, found, err)
	}
}

func TestNestedArrayValue_MissingIntermediate(t *testing.T) {
	payload := map[string]any{}
	vals, found, err := nestedArrayValue(payload, "Endpoint", "VirtualIPs")
	if err != nil || found {
		t.Fatalf("missing intermediate: got found=%v err=%v", found, err)
	}
	_ = vals
}

func TestNestedArrayValue_WrongIntermediateType(t *testing.T) {
	payload := map[string]any{"Endpoint": "bad"}
	_, _, err := nestedArrayValue(payload, "Endpoint", "VirtualIPs")
	if err == nil {
		t.Fatal("want error for wrong intermediate type, got nil")
	}
}

func TestNestedArrayValue_MissingLeaf(t *testing.T) {
	payload := map[string]any{"Endpoint": map[string]any{}}
	vals, found, err := nestedArrayValue(payload, "Endpoint", "VirtualIPs")
	if err != nil || found || vals != nil {
		t.Fatalf("missing leaf: got found=%v err=%v", found, err)
	}
}

func TestNestedArrayValue_WrongLeafType(t *testing.T) {
	payload := map[string]any{"Endpoint": map[string]any{"VirtualIPs": "bad"}}
	_, _, err := nestedArrayValue(payload, "Endpoint", "VirtualIPs")
	if err == nil {
		t.Fatal("want error for wrong leaf type, got nil")
	}
}

// ─── redactNestedValue – wrong object type ───────────────────────────────────

func TestRedactNestedValue_WrongType(t *testing.T) {
	payload := map[string]any{"Config": "not-a-map"}
	err := redactNestedValue(payload, "Config", "Env", []string{})
	if err == nil {
		t.Fatal("want error for wrong type, got nil")
	}
}

// ─── redactMountObjects – error paths ────────────────────────────────────────

func TestRedactMountObjects_WrongType(t *testing.T) {
	payload := map[string]any{"Mounts": "not-array"}
	err := redactMountObjects(payload, "Mounts")
	if err == nil {
		t.Fatal("want error for wrong Mounts type, got nil")
	}
}

func TestRedactMountObjects_EntryWrongType(t *testing.T) {
	payload := map[string]any{"Mounts": []any{"not-a-map"}}
	err := redactMountObjects(payload, "Mounts")
	if err == nil {
		t.Fatal("want error for wrong mount entry type, got nil")
	}
}

// ─── redactHostConfigBinds – error paths ─────────────────────────────────────

func TestRedactHostConfigBinds_WrongHostConfigType(t *testing.T) {
	payload := map[string]any{"HostConfig": "bad"}
	err := redactHostConfigBinds(payload)
	if err == nil {
		t.Fatal("want error for wrong HostConfig type, got nil")
	}
}

func TestRedactHostConfigBinds_WrongBindsType(t *testing.T) {
	payload := map[string]any{"HostConfig": map[string]any{"Binds": "bad"}}
	err := redactHostConfigBinds(payload)
	if err == nil {
		t.Fatal("want error for wrong Binds type, got nil")
	}
}

func TestRedactHostConfigBinds_WrongBindEntryType(t *testing.T) {
	payload := map[string]any{"HostConfig": map[string]any{"Binds": []any{123}}}
	err := redactHostConfigBinds(payload)
	if err == nil {
		t.Fatal("want error for wrong bind entry type, got nil")
	}
}

// ─── redactContainerNetworkTopology – error paths ────────────────────────────

func TestRedactContainerNetworkTopology_WrongNetworkSettingsType(t *testing.T) {
	payload := map[string]any{"NetworkSettings": "bad"}
	err := redactContainerNetworkTopology(payload)
	if err == nil {
		t.Fatal("want error for wrong NetworkSettings type, got nil")
	}
}

func TestRedactContainerNetworkTopology_WrongNetworksType(t *testing.T) {
	payload := map[string]any{"NetworkSettings": map[string]any{"Networks": "bad"}}
	err := redactContainerNetworkTopology(payload)
	if err == nil {
		t.Fatal("want error for wrong Networks type, got nil")
	}
}

func TestRedactContainerNetworkTopology_WrongNetworkEntryType(t *testing.T) {
	payload := map[string]any{
		"NetworkSettings": map[string]any{
			"Networks": map[string]any{"bridge": "bad"},
		},
	}
	err := redactContainerNetworkTopology(payload)
	if err == nil {
		t.Fatal("want error for wrong network entry type, got nil")
	}
}

func TestRedactContainerNetworkTopology_WrongHostConfigType(t *testing.T) {
	payload := map[string]any{"HostConfig": "bad"}
	err := redactContainerNetworkTopology(payload)
	if err == nil {
		t.Fatal("want error for wrong HostConfig type in nested string redact, got nil")
	}
}

// ─── redactNetworkTopology – error paths ─────────────────────────────────────

func TestRedactNetworkTopology_WrongIPAMType(t *testing.T) {
	payload := map[string]any{"IPAM": "bad"}
	err := redactNetworkTopology(payload)
	if err == nil {
		t.Fatal("want error for wrong IPAM type, got nil")
	}
}

func TestRedactNetworkTopology_WrongPeersType(t *testing.T) {
	payload := map[string]any{"Peers": "bad"}
	err := redactNetworkTopology(payload)
	if err == nil {
		t.Fatal("want error for wrong Peers type, got nil")
	}
}

// ─── redactNestedStringValue – wrong type ────────────────────────────────────

func TestRedactNestedStringValue_WrongType(t *testing.T) {
	payload := map[string]any{"HostConfig": "bad"}
	err := redactNestedStringValue(payload, "HostConfig", "NetworkMode")
	if err == nil {
		t.Fatal("want error for wrong type, got nil")
	}
}

// ─── redactEnvStrings – error paths ─────────────────────────────────────────

func TestRedactEnvStrings_WrongType(t *testing.T) {
	payload := map[string]any{"Env": "bad"}
	err := redactEnvStrings(payload, "Env")
	if err == nil {
		t.Fatal("want error for wrong Env type, got nil")
	}
}

func TestRedactEnvStrings_EntryWrongType(t *testing.T) {
	payload := map[string]any{"Env": []any{123}}
	err := redactEnvStrings(payload, "Env")
	if err == nil {
		t.Fatal("want error for wrong entry type, got nil")
	}
}

func TestRedactEnvStrings_NoEquals(t *testing.T) {
	payload := map[string]any{"Env": []any{"NOEQUALS"}}
	if err := redactEnvStrings(payload, "Env"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items, _ := payload["Env"].([]any)
	if items[0] != "<redacted>" {
		t.Fatalf("entry without '=' should become <redacted>, got %v", items[0])
	}
}

// ─── redactPluginEnvObjects – error paths ────────────────────────────────────

func TestRedactPluginEnvObjects_WrongType(t *testing.T) {
	payload := map[string]any{"Env": "bad"}
	err := redactPluginEnvObjects(payload, "Env")
	if err == nil {
		t.Fatal("want error for wrong Env type, got nil")
	}
}

func TestRedactPluginEnvObjects_EntryWrongType(t *testing.T) {
	payload := map[string]any{"Env": []any{"not-a-map"}}
	err := redactPluginEnvObjects(payload, "Env")
	if err == nil {
		t.Fatal("want error for wrong entry type, got nil")
	}
}

// ─── redactReferenceObjects – error paths ────────────────────────────────────

func TestRedactReferenceObjects_WrongType(t *testing.T) {
	payload := map[string]any{"Secrets": "bad"}
	err := redactReferenceObjects(payload, "Secrets", "SecretID")
	if err == nil {
		t.Fatal("want error for wrong Secrets type, got nil")
	}
}

func TestRedactReferenceObjects_EntryWrongType(t *testing.T) {
	payload := map[string]any{"Secrets": []any{"not-a-map"}}
	err := redactReferenceObjects(payload, "Secrets", "SecretID")
	if err == nil {
		t.Fatal("want error for wrong entry type, got nil")
	}
}

// ─── redactVirtualIPs – error paths ─────────────────────────────────────────

func TestRedactVirtualIPs_EntryWrongType(t *testing.T) {
	payload := map[string]any{
		"Endpoint": map[string]any{
			"VirtualIPs": []any{"not-a-map"},
		},
	}
	err := redactVirtualIPs(payload, "Endpoint", "VirtualIPs")
	if err == nil {
		t.Fatal("want error for wrong VirtualIP entry type, got nil")
	}
}

// ─── redactTaskStatus – missing ContainerStatus ───────────────────────────────

func TestRedactTaskStatus_MissingContainerStatus(t *testing.T) {
	payload := map[string]any{"Status": map[string]any{}}
	if err := redactTaskStatus(payload); err != nil {
		t.Fatalf("missing ContainerStatus: %v", err)
	}
}

func TestRedactTaskStatus_BadStatusType(t *testing.T) {
	payload := map[string]any{"Status": "bad"}
	err := redactTaskStatus(payload)
	if err == nil {
		t.Fatal("want error for bad Status type, got nil")
	}
}

// ─── redactTaskNetworkAttachments – error paths ───────────────────────────────

func TestRedactTaskNetworkAttachments_WrongType(t *testing.T) {
	payload := map[string]any{"NetworksAttachments": "bad"}
	err := redactTaskNetworkAttachments(payload)
	if err == nil {
		t.Fatal("want error for wrong NetworksAttachments type, got nil")
	}
}

func TestRedactTaskNetworkAttachments_EntryWrongType(t *testing.T) {
	payload := map[string]any{"NetworksAttachments": []any{"not-a-map"}}
	err := redactTaskNetworkAttachments(payload)
	if err == nil {
		t.Fatal("want error for wrong attachment entry type, got nil")
	}
}

func TestRedactTaskNetworkAttachments_BadNetworkType(t *testing.T) {
	payload := map[string]any{
		"NetworksAttachments": []any{
			map[string]any{"Network": "bad"},
		},
	}
	err := redactTaskNetworkAttachments(payload)
	if err == nil {
		t.Fatal("want error for wrong Network type, got nil")
	}
}

func TestRedactTaskNetworkAttachments_BadIPAMType(t *testing.T) {
	payload := map[string]any{
		"NetworksAttachments": []any{
			map[string]any{
				"Network": map[string]any{
					"IPAMOptions": "bad",
				},
			},
		},
	}
	err := redactTaskNetworkAttachments(payload)
	if err == nil {
		t.Fatal("want error for wrong IPAMOptions type, got nil")
	}
}

// ─── redactPluginPayload – Linux.Devices path ────────────────────────────────

func TestRedactPluginPayload_LinuxDevices(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Config": map[string]any{
			"Mounts":          []any{},
			"PropagatedMount": "/mnt",
			"Linux": map[string]any{
				"Devices": []any{
					map[string]any{"Path": "/dev/fuse"},
				},
			},
		},
	}
	if err := f.redactPluginPayload(payload); err != nil {
		t.Fatalf("error: %v", err)
	}
	linux, _ := payload["Config"].(map[string]any)["Linux"].(map[string]any)
	devices, _ := linux["Devices"].([]any)
	device0, _ := devices[0].(map[string]any)
	if v, _ := device0["Path"].(string); v != "<redacted>" {
		t.Fatalf("Linux.Devices[0].Path = %q, want <redacted>", v)
	}
}

// ─── VolumeList edge cases ───────────────────────────────────────────────────

func TestModifyVolumeList_NilVolumes(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/volumes", `{"Volumes":null}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("nil Volumes: %v", err)
	}
}

func TestModifyVolumeList_WrongVolumesType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/volumes", `{"Volumes":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyVolumeList_WrongVolumeEntryType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/volumes", `{"Volumes":["not-a-map"]}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyContainerList – error paths ───────────────────────────────────────

func TestModifyContainerList_RejectsMalformedMounts(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/json", `[{"Mounts":"bad"}]`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyContainerList_RejectsMalformedNetworkSettings(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/json", `[{"NetworkSettings":"bad"}]`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyContainerInspect – error paths ────────────────────────────────────

func TestModifyContainerInspect_RejectsBadHostConfigType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/abc/json", `{"HostConfig":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyContainerInspect_RejectsBadConfigType(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/abc/json", `{"Config":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyContainerInspect_RejectsBadNetworkSettings(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/abc/json", `{"NetworkSettings":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyNetworkInspect – error paths ──────────────────────────────────────

func TestModifyNetworkInspect_SkipsWhenTopologyDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/networks/net-1", `{"IPAM":{"Config":[{"Subnet":"10.0.0.0/8"}]}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyNetworkInspect_RejectsBadIPAMType(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/networks/net-1", `{"IPAM":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifySwarmInspect – no opts ────────────────────────────────────────────

func TestModifySwarmInspect_SkipsWhenBothDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/swarm", `{"JoinTokens":{"Worker":"token"}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── modifySwarmUnlockKey – skip when disabled ────────────────────────────────

func TestModifySwarmUnlockKey_SkipsWhenSensitiveDataDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/swarm/unlockkey", `{"UnlockKey":"SWMKEY-123"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── modifyInfo – skip when disabled ──────────────────────────────────────────

func TestModifyInfo_SkipsWhenBothDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/info", `{"Swarm":{"NodeID":"node-1"}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyInfo_NoSwarmKey(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/info", `{"ID":"daemon-1"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyInfo_BadSwarmType(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/info", `{"Swarm":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifySystemDataUsage – error paths ─────────────────────────────────────

func TestModifySystemDataUsage_SkipsWhenBothDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/system/df", `{"ContainerUsage":{"Items":[]}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifySystemDataUsage_BadContainerItemsType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/system/df", `{"ContainerUsage":{"Items":"bad"}}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifySystemDataUsage_BadContainerItemEntryType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/system/df", `{"ContainerUsage":{"Items":["bad"]}}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifySystemDataUsage_BadVolumeItemsType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/system/df", `{"VolumeUsage":{"Items":"bad"}}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifySystemDataUsage_BadVolumeItemEntryType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/system/df", `{"VolumeUsage":{"Items":["bad"]}}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyMapResponse / modifyListResponse error paths ──────────────────────

func TestModifyMapResponse_BadJSON(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/configs/cfg-1", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyListResponse_BadJSON(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/configs", `not-json`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── redactSwarmPayload – no JoinTokens / no TLSInfo ─────────────────────────

func TestRedactSwarmPayload_MissingOptionalFields(t *testing.T) {
	f := New(Options{RedactSensitiveData: true, RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/swarm", `{"ID":"swarm-1"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRedactSwarmPayload_BadCAConfigType(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/swarm", `{"Spec":{"CAConfig":"bad"}}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── redactInfoPayload – cluster TLS ─────────────────────────────────────────

func TestRedactInfoPayload_ClusterTLSInfo(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/info", `{
		"Swarm":{
			"Cluster":{
				"TLSInfo":{"TrustRoot":"pem","CertIssuerSubject":"subj","CertIssuerPublicKey":"pub"}
			}
		}
	}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}
	info := decodeBodyForTest(t, resp)
	tlsInfo := nestedMapForTest(t, info, "Swarm", "Cluster", "TLSInfo")
	if v, _ := tlsInfo["TrustRoot"].(string); v != "<redacted>" {
		t.Fatalf("TrustRoot = %q, want <redacted>", v)
	}
}

// ─── modifyConfigInspect – skip when disabled ─────────────────────────────────

func TestModifyConfigInspect_SkipsWhenSensitiveDataDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/configs/cfg-1", `{"Spec":{"Data":"secret"}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── modifyPluginInspect – skip when disabled ────────────────────────────────

func TestModifyPluginInspect_SkipsWhenBothDisabled(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/plugins/myplugin/json", `{"Name":"myplugin"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── modifyNodeInspect – skip when disabled ───────────────────────────────────

func TestModifyNodeInspect_SkipsWhenBothDisabled(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/nodes/node-1", `{"Status":{"Addr":"10.0.0.1"}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── redactTaskPayload – Secrets/Configs ─────────────────────────────────────

func TestRedactTaskPayload_SecretsAndConfigs(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/tasks/task-1", `{
		"Spec":{
			"ContainerSpec":{
				"Secrets":[{"SecretID":"sec-1","SecretName":"mysecret"}],
				"Configs":[{"ConfigID":"cfg-1","ConfigName":"myconfig"}]
			}
		}
	}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}
	got := decodeBodyForTest(t, resp)
	spec := nestedMapForTest(t, got, "Spec", "ContainerSpec")
	secrets, _ := spec["Secrets"].([]any)
	s0, _ := secrets[0].(map[string]any)
	if v, _ := s0["SecretID"].(string); v != "<redacted>" {
		t.Fatalf("SecretID = %q, want <redacted>", v)
	}
	configs, _ := spec["Configs"].([]any)
	c0, _ := configs[0].(map[string]any)
	if v, _ := c0["ConfigID"].(string); v != "<redacted>" {
		t.Fatalf("ConfigID = %q, want <redacted>", v)
	}
}

// ─── service/task list+inspect – skip guard when all flags disabled ───────────
// Previously these called unexported methods directly. Now that the dispatch
// table owns the guard, we exercise the same path via ModifyResponse with a
// Filter that has at least one flag set so Enabled() passes, then verify that
// the table entry's own active() guard returns nil when the relevant flags are off.

func TestModifyServiceList_InternalSkipGuard(t *testing.T) {
	// Pass through ModifyResponse with all flags false → Enabled() is false → nil.
	f := New(Options{})
	resp := newResponseForTest(t, http.MethodGet, "/services", `[{"ID":"svc-1"}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyServiceInspect_InternalSkipGuard(t *testing.T) {
	f := New(Options{})
	resp := newResponseForTest(t, http.MethodGet, "/services/svc-1", `{"ID":"svc-1"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyTaskList_InternalSkipGuard(t *testing.T) {
	f := New(Options{})
	resp := newResponseForTest(t, http.MethodGet, "/tasks", `[{"ID":"task-1"}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyTaskInspect_InternalSkipGuard(t *testing.T) {
	f := New(Options{})
	resp := newResponseForTest(t, http.MethodGet, "/tasks/task-1", `{"ID":"task-1"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── modifyTaskInspect – skip when all disabled ───────────────────────────────

func TestModifyTaskInspect_SkipsWhenAllDisabled(t *testing.T) {
	f := New(Options{})
	resp := newResponseForTest(t, http.MethodGet, "/tasks/task-1", `{"ID":"task-1"}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── modifyListResponse / modifyMapResponse read-body-failure paths ───────────

func makeNilBodyResponse(t *testing.T, method, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, "http://sockguard.test"+path, nil)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       nil, // triggers "missing response body" in readResponseBody
		Request:    req,
	}
}

func TestModifyServiceList_ReadBodyError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/services")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyServiceInspect_ReadBodyError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/services/svc-1")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyTaskList_ReadBodyError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/tasks")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyTaskInspect_ReadBodyError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/tasks/task-1")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyNetworkList_ReadBodyError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/networks")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyNetworkInspect_ReadBodyError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/networks/net-1")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyVolumeList_ReadBodyError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/volumes")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyVolumeInspect_ReadBodyError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/volumes/myvol")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyContainerList_ReadBodyError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/containers/json")
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyListResponse mutate-error path ─────────────────────────────────────

// modifyServiceList propagates a mutate error from redactServicePayload when
// the nested map has a wrong type.
func TestModifyServiceList_MutateError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	// "Spec" is a string, not a map → nestedMapValue returns an error inside redactServicePayload
	resp := newResponseForTest(t, http.MethodGet, "/services", `[{"ID":"svc-1","Spec":"bad"}]`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyServiceInspect_MutateError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/services/svc-1", `{"ID":"svc-1","Spec":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyTaskList_MutateError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	// "Spec" is a string, not a map → nestedMapValue returns an error inside redactTaskPayload
	resp := newResponseForTest(t, http.MethodGet, "/tasks", `[{"ID":"task-1","Spec":"bad"}]`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyTaskInspect_MutateError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/tasks/task-1", `{"ID":"task-1","Spec":"bad"}`)
	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── redactServicePayload – error branches ────────────────────────────────────

func TestRedactServicePayload_MountsError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Spec": map[string]any{
			"TaskTemplate": map[string]any{
				"ContainerSpec": map[string]any{
					"Mounts": "bad", // not []any
				},
			},
		},
	}
	err := f.redactServicePayload(payload)
	if err == nil {
		t.Fatal("want error for bad Mounts type, got nil")
	}
}

func TestRedactServicePayload_SecretsError(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{
		"Spec": map[string]any{
			"TaskTemplate": map[string]any{
				"ContainerSpec": map[string]any{
					"Secrets": "bad", // not []any
				},
			},
		},
	}
	err := f.redactServicePayload(payload)
	if err == nil {
		t.Fatal("want error for bad Secrets type, got nil")
	}
}

func TestRedactServicePayload_ConfigsError(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{
		"Spec": map[string]any{
			"TaskTemplate": map[string]any{
				"ContainerSpec": map[string]any{
					"Secrets": []any{},
					"Configs": "bad", // not []any
				},
			},
		},
	}
	err := f.redactServicePayload(payload)
	if err == nil {
		t.Fatal("want error for bad Configs type, got nil")
	}
}

func TestRedactServicePayload_VirtualIPsError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	payload := map[string]any{
		"Endpoint": map[string]any{
			"VirtualIPs": []any{"not-a-map"}, // entry wrong type
		},
	}
	err := f.redactServicePayload(payload)
	if err == nil {
		t.Fatal("want error for bad VirtualIPs entry type, got nil")
	}
}

func TestRedactServicePayload_BadSpecType(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	payload := map[string]any{"Spec": "bad"}
	err := f.redactServicePayload(payload)
	if err == nil {
		t.Fatal("want error for bad Spec type, got nil")
	}
}

// ─── redactTaskPayload – error branches ───────────────────────────────────────

func TestRedactTaskPayload_MountsError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Spec": map[string]any{
			"ContainerSpec": map[string]any{
				"Mounts": "bad",
			},
		},
	}
	err := f.redactTaskPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Mounts type, got nil")
	}
}

func TestRedactTaskPayload_SecretsError(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{
		"Spec": map[string]any{
			"ContainerSpec": map[string]any{
				"Secrets": "bad",
			},
		},
	}
	err := f.redactTaskPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Secrets type, got nil")
	}
}

func TestRedactTaskPayload_ConfigsError(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{
		"Spec": map[string]any{
			"ContainerSpec": map[string]any{
				"Secrets": []any{},
				"Configs": "bad",
			},
		},
	}
	err := f.redactTaskPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Configs type, got nil")
	}
}

func TestRedactTaskPayload_TaskStatusError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	payload := map[string]any{
		"Status": "bad", // wrong type → redactTaskStatus errors
	}
	err := f.redactTaskPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Status type, got nil")
	}
}

func TestRedactTaskPayload_NetworkAttachmentsError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	payload := map[string]any{
		"NetworksAttachments": "bad",
	}
	err := f.redactTaskPayload(payload)
	if err == nil {
		t.Fatal("want error for bad NetworksAttachments type, got nil")
	}
}

func TestRedactTaskPayload_BadSpecType(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	payload := map[string]any{"Spec": "bad"}
	err := f.redactTaskPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Spec type, got nil")
	}
}

// ─── redactConfigPayload – no Spec / nil Spec ─────────────────────────────────

func TestRedactConfigPayload_NoSpec(t *testing.T) {
	payload := map[string]any{"ID": "cfg-1"}
	if err := redactConfigPayload(payload); err != nil {
		t.Fatalf("no Spec: %v", err)
	}
}

func TestRedactConfigPayload_BadSpecType(t *testing.T) {
	payload := map[string]any{"Spec": "bad"}
	if err := redactConfigPayload(payload); err == nil {
		t.Fatal("want error for bad Spec type, got nil")
	}
}

// ─── redactPluginPayload – Settings error branches ───────────────────────────

func TestRedactPluginPayload_BadSettingsType(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	payload := map[string]any{"Settings": "bad"}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Settings type, got nil")
	}
}

func TestRedactPluginPayload_SettingsEnvError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	payload := map[string]any{
		"Settings": map[string]any{"Env": "bad"},
	}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Settings.Env type, got nil")
	}
}

func TestRedactPluginPayload_SettingsMountsError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Settings": map[string]any{"Mounts": "bad"},
	}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Settings.Mounts type, got nil")
	}
}

func TestRedactPluginPayload_SettingsDevicesError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Settings": map[string]any{
			"Mounts":  []any{},
			"Devices": "bad",
		},
	}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Settings.Devices type, got nil")
	}
}

func TestRedactPluginPayload_BadConfigType(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	payload := map[string]any{"Config": "bad"}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Config type, got nil")
	}
}

func TestRedactPluginPayload_ConfigEnvError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	payload := map[string]any{
		"Config": map[string]any{"Env": "bad"},
	}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Config.Env type, got nil")
	}
}

func TestRedactPluginPayload_ConfigMountsError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Config": map[string]any{"Mounts": "bad"},
	}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Config.Mounts type, got nil")
	}
}

func TestRedactPluginPayload_BadLinuxType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Config": map[string]any{
			"Mounts": []any{},
			"Linux":  "bad",
		},
	}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Linux type, got nil")
	}
}

func TestRedactPluginPayload_LinuxDevicesError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"Config": map[string]any{
			"Mounts": []any{},
			"Linux": map[string]any{
				"Devices": "bad",
			},
		},
	}
	err := f.redactPluginPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Linux.Devices type, got nil")
	}
}

// ─── redactNodePayload – error branches ──────────────────────────────────────

func TestRedactNodePayload_BadStatusType(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	payload := map[string]any{"Status": "bad"}
	err := f.redactNodePayload(payload)
	if err == nil {
		t.Fatal("want error for bad Status type, got nil")
	}
}

func TestRedactNodePayload_BadManagerStatusType(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	payload := map[string]any{"ManagerStatus": "bad"}
	err := f.redactNodePayload(payload)
	if err == nil {
		t.Fatal("want error for bad ManagerStatus type, got nil")
	}
}

func TestRedactNodePayload_BadTLSInfoType(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{
		"Description": map[string]any{"TLSInfo": "bad"},
	}
	err := f.redactNodePayload(payload)
	if err == nil {
		t.Fatal("want error for bad TLSInfo type, got nil")
	}
}

// ─── redactSwarmPayload – error branches ─────────────────────────────────────

func TestRedactSwarmPayload_BadJoinTokensType(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{"JoinTokens": "bad"}
	err := f.redactSwarmPayload(payload)
	if err == nil {
		t.Fatal("want error for bad JoinTokens type, got nil")
	}
}

func TestRedactSwarmPayload_BadTLSInfoType(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{"TLSInfo": "bad"}
	err := f.redactSwarmPayload(payload)
	if err == nil {
		t.Fatal("want error for bad TLSInfo type, got nil")
	}
}

func TestRedactSwarmPayload_BadSpecType(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{"Spec": "bad"}
	err := f.redactSwarmPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Spec type, got nil")
	}
}

// ─── redactInfoPayload – error branches ──────────────────────────────────────

func TestRedactInfoPayload_BadClusterType(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	payload := map[string]any{
		"Swarm": map[string]any{"Cluster": "bad"},
	}
	err := f.redactInfoPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Cluster type, got nil")
	}
}

func TestRedactInfoPayload_BadTLSInfoType(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	payload := map[string]any{
		"Swarm": map[string]any{
			"Cluster": map[string]any{"TLSInfo": "bad"},
		},
	}
	err := f.redactInfoPayload(payload)
	if err == nil {
		t.Fatal("want error for bad TLSInfo type, got nil")
	}
}

// ─── redactSystemDataUsagePayload – ContainerUsage/VolumeUsage type errors ───

func TestRedactSystemDataUsagePayload_BadContainerUsageType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{"ContainerUsage": "bad"}
	err := f.redactSystemDataUsagePayload(payload)
	if err == nil {
		t.Fatal("want error for bad ContainerUsage type, got nil")
	}
}

func TestRedactSystemDataUsagePayload_BadVolumeUsageType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{"VolumeUsage": "bad"}
	err := f.redactSystemDataUsagePayload(payload)
	if err == nil {
		t.Fatal("want error for bad VolumeUsage type, got nil")
	}
}

// ─── writeResponseBody – marshal error ──────────────────────────────────────

func TestWriteResponseBody_MarshalError(t *testing.T) {
	// json.Marshal fails on channels
	resp := &http.Response{
		Body:   io.NopCloser(strings.NewReader("")),
		Header: make(http.Header),
	}
	// Use a channel value which json.Marshal cannot handle
	payload := map[string]any{"bad": make(chan int)}
	err := writeResponseBody(resp, payload)
	if err == nil {
		t.Fatal("want marshal error, got nil")
	}
}

// ─── redactNestedValue – nil objectValue ─────────────────────────────────────

func TestRedactNestedValue_NilObject(t *testing.T) {
	payload := map[string]any{"Config": nil}
	if err := redactNestedValue(payload, "Config", "Env", []string{}); err != nil {
		t.Fatalf("nil object value: %v", err)
	}
}

// ─── redactHostConfigBinds – nil binds ───────────────────────────────────────

func TestRedactHostConfigBinds_NilBinds(t *testing.T) {
	payload := map[string]any{
		"HostConfig": map[string]any{"Binds": nil},
	}
	if err := redactHostConfigBinds(payload); err != nil {
		t.Fatalf("nil Binds: %v", err)
	}
}

// ─── modifyContainerList – no-op when neither flag set ───────────────────────

func TestModifyContainerList_SkipsWhenNeitherFlagSet(t *testing.T) {
	f := New(Options{RedactContainerEnv: true, RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/json",
		`[{"Id":"abc","Mounts":[{"Source":"/host/path"}]}]`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The body should be unchanged since neither RedactMountPaths nor RedactNetworkTopology are set
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/host/path") {
		t.Errorf("expected mount source /host/path to be present in body (filter should be no-op), got: %s", string(body))
	}
}

// ─── redactContainerNetworkTopology – nil NetworkSettings ────────────────────

func TestRedactContainerNetworkTopology_NilNetworkSettings(t *testing.T) {
	payload := map[string]any{"NetworkSettings": nil}
	if err := redactContainerNetworkTopology(payload); err != nil {
		t.Fatalf("nil NetworkSettings: %v", err)
	}
}

func TestRedactContainerNetworkTopology_NilNetworks(t *testing.T) {
	payload := map[string]any{
		"NetworkSettings": map[string]any{"Networks": nil},
	}
	if err := redactContainerNetworkTopology(payload); err != nil {
		t.Fatalf("nil Networks: %v", err)
	}
}

// ─── modifyNetworkInspect – direct-call internal paths ───────────────────────

func TestModifyNetworkInspect_InternalSkipGuard(t *testing.T) {
	f := New(Options{}) // RedactNetworkTopology = false
	resp := newResponseForTest(t, http.MethodGet, "/networks/net-1", `{"Name":"bridge"}`)
	if err := f.modifyNetworkInspect(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyNetworkInspect_InternalReadBodyError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/networks/net-1")
	err := f.modifyNetworkInspect(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyNetworkInspect_InternalUnmarshalError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	resp := newResponseForTest(t, http.MethodGet, "/networks/net-1", `not-json`)
	err := f.modifyNetworkInspect(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyVolumeList – direct-call internal paths ────────────────────────────

func TestModifyVolumeList_InternalSkipGuard(t *testing.T) {
	f := New(Options{}) // RedactMountPaths = false
	resp := newResponseForTest(t, http.MethodGet, "/volumes", `{"Volumes":[]}`)
	if err := f.modifyVolumeList(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestModifyVolumeList_InternalReadBodyError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/volumes")
	err := f.modifyVolumeList(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyVolumeList_InternalUnmarshalError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/volumes", `not-json`)
	err := f.modifyVolumeList(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── modifyContainerInspect – direct-call body-read error ────────────────────

func TestModifyContainerInspect_InternalReadBodyError(t *testing.T) {
	f := New(Options{RedactContainerEnv: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/containers/abc/json")
	err := f.modifyContainerInspect(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyContainerInspect_MountsWrongType(t *testing.T) {
	// Mounts is a string, not []any — triggers rejectResponse from redactMountObjects
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/abc/json", `{"Mounts":"bad"}`)
	err := f.modifyContainerInspect(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected for bad Mounts type, got %v", err)
	}
}

// ─── modifyContainerList – direct-call body-read error ───────────────────────

func TestModifyContainerList_InternalReadBodyError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := makeNilBodyResponse(t, http.MethodGet, "/containers/json")
	err := f.modifyContainerList(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

func TestModifyContainerList_InternalUnmarshalError(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	resp := newResponseForTest(t, http.MethodGet, "/containers/json", `not-json`)
	err := f.modifyContainerList(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("want ErrResponseRejected, got %v", err)
	}
}

// ─── redactInfoPayload – Cluster nestedMapValue error path ───────────────────

func TestRedactInfoPayload_ClusterNestedMapError(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	// Cluster is a string → nestedMapValue returns error
	payload := map[string]any{
		"Swarm": map[string]any{"Cluster": "bad"},
	}
	err := f.redactInfoPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Cluster type in NetworkTopology path, got nil")
	}
}

func TestRedactInfoPayload_SensitiveDataClusterNestedMapError(t *testing.T) {
	f := New(Options{RedactSensitiveData: true})
	// Cluster is a string → nestedMapValue returns error in the RedactSensitiveData branch
	payload := map[string]any{
		"Swarm": map[string]any{"Cluster": "bad"},
	}
	err := f.redactInfoPayload(payload)
	if err == nil {
		t.Fatal("want error for bad Cluster type in SensitiveData path, got nil")
	}
}

// ─── redactVirtualIPs – nestedArrayValue error ───────────────────────────────

func TestRedactVirtualIPs_NestedArrayError(t *testing.T) {
	// Endpoint is a string → nestedArrayValue returns error at intermediate
	payload := map[string]any{"Endpoint": "bad"}
	err := redactVirtualIPs(payload, "Endpoint", "VirtualIPs")
	if err == nil {
		t.Fatal("want error for bad Endpoint type, got nil")
	}
}

// ─── redactEnvStrings – nil / missing field returns nil ──────────────────────

func TestRedactEnvStrings_NilField(t *testing.T) {
	payload := map[string]any{"Env": nil}
	if err := redactEnvStrings(payload, "Env"); err != nil {
		t.Fatalf("nil field: %v", err)
	}
}

func TestRedactEnvStrings_MissingField(t *testing.T) {
	payload := map[string]any{}
	if err := redactEnvStrings(payload, "Env"); err != nil {
		t.Fatalf("missing field: %v", err)
	}
}

// ─── redactPluginEnvObjects – nil / missing field returns nil ────────────────

func TestRedactPluginEnvObjects_NilField(t *testing.T) {
	payload := map[string]any{"Env": nil}
	if err := redactPluginEnvObjects(payload, "Env"); err != nil {
		t.Fatalf("nil field: %v", err)
	}
}

func TestRedactPluginEnvObjects_MissingField(t *testing.T) {
	payload := map[string]any{}
	if err := redactPluginEnvObjects(payload, "Env"); err != nil {
		t.Fatalf("missing field: %v", err)
	}
}

// ─── redactHostConfigBinds – no HostConfig key ───────────────────────────────

func TestRedactHostConfigBinds_NoHostConfigKey(t *testing.T) {
	payload := map[string]any{"Other": "value"}
	if err := redactHostConfigBinds(payload); err != nil {
		t.Fatalf("no HostConfig key: %v", err)
	}
}

// ─── redactSystemDataUsagePayload – nil ContainerUsage / VolumeUsage ──────────

func TestRedactSystemDataUsagePayload_NilContainerUsageItems(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"ContainerUsage": map[string]any{"Items": nil},
	}
	if err := f.redactSystemDataUsagePayload(payload); err != nil {
		t.Fatalf("nil ContainerUsage.Items: %v", err)
	}
}

func TestRedactSystemDataUsagePayload_NilVolumeUsageItems(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"VolumeUsage": map[string]any{"Items": nil},
	}
	if err := f.redactSystemDataUsagePayload(payload); err != nil {
		t.Fatalf("nil VolumeUsage.Items: %v", err)
	}
}

func TestRedactSystemDataUsagePayload_ContainerMountsWrongType(t *testing.T) {
	f := New(Options{RedactMountPaths: true})
	payload := map[string]any{
		"ContainerUsage": map[string]any{
			"Items": []any{
				map[string]any{"Mounts": "bad"}, // wrong type → rejectResponse
			},
		},
	}
	if err := f.redactSystemDataUsagePayload(payload); err == nil {
		t.Fatal("want error for bad Mounts type in ContainerUsage, got nil")
	}
}

func TestRedactSystemDataUsagePayload_ContainerNetworkSettingsWrongType(t *testing.T) {
	f := New(Options{RedactNetworkTopology: true})
	payload := map[string]any{
		"ContainerUsage": map[string]any{
			"Items": []any{
				map[string]any{"NetworkSettings": "bad"}, // wrong type → rejectResponse
			},
		},
	}
	if err := f.redactSystemDataUsagePayload(payload); err == nil {
		t.Fatal("want error for bad NetworkSettings type in ContainerUsage, got nil")
	}
}

// ─── redactTaskNetworkAttachments – Network with IPAMOptions ──────────────────

func TestRedactTaskNetworkAttachments_WithIPAMOptions(t *testing.T) {
	payload := map[string]any{
		"NetworksAttachments": []any{
			map[string]any{
				"Addresses": []any{"10.0.0.1/24"},
				"Network": map[string]any{
					"ID": "net-1",
					"IPAMOptions": map[string]any{
						"Configs": []any{"config-1"},
					},
				},
			},
		},
	}
	if err := redactTaskNetworkAttachments(payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	attachments := payload["NetworksAttachments"].([]any)
	a0 := attachments[0].(map[string]any)
	if addr, _ := a0["Addresses"].([]any); len(addr) != 0 {
		t.Fatalf("Addresses = %v, want empty", addr)
	}
	network := a0["Network"].(map[string]any)
	if v, _ := network["ID"].(string); v != "<redacted>" {
		t.Fatalf("Network.ID = %q, want <redacted>", v)
	}
	ipam := network["IPAMOptions"].(map[string]any)
	if cfg, _ := ipam["Configs"].([]any); len(cfg) != 0 {
		t.Fatalf("IPAMOptions.Configs = %v, want empty", cfg)
	}
}
