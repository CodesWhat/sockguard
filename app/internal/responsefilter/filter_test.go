package responsefilter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
