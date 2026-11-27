package filter

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func intPtr(v int) *int { return &v }

// TestDockerDeviceRequestExactGrants drives the exact device_ids and count
// contract through the real create middleware, on both the bare and the
// versioned route.
func TestDockerDeviceRequestExactGrants(t *testing.T) {
	entry := AllowedDeviceRequestEntry{Driver: "cdi", DeviceIDs: []string{"nvidia.com/gpu=0", "nvidia.com/gpu=1"}}
	tests := []struct {
		name   string
		entry  AllowedDeviceRequestEntry
		req    string
		denied bool
	}{
		{"listed id", entry, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0"]}`, false},
		{"both listed ids", entry, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0","nvidia.com/gpu=1"]}`, false},
		{"unlisted id", entry, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=2"]}`, true},
		{"one listed one not", entry, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0","nvidia.com/gpu=all"]}`, true},
		{"all is not a wildcard", entry, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=all"]}`, true},
		{"case differs", entry, `{"Driver":"cdi","DeviceIDs":["NVIDIA.com/gpu=0"]}`, true},
		{"padded id", entry, `{"Driver":"cdi","DeviceIDs":[" nvidia.com/gpu=0"]}`, true},
		{"prefix of a listed id", entry, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0:1"]}`, true},
		{"no ids", entry, `{"Driver":"cdi"}`, true},
		{"count instead of ids", entry, `{"Driver":"cdi","Count":-1}`, true},
		{"ids plus count", entry, `{"Driver":"cdi","Count":1,"DeviceIDs":["nvidia.com/gpu=0"]}`, true},
		{"other driver", entry, `{"Driver":"nvidia","DeviceIDs":["nvidia.com/gpu=0"]}`, true},
		{"one good request one bad", entry, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0"]},{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=9"]}`, true},
		{"exact count match", AllowedDeviceRequestEntry{Driver: "nvidia", Count: intPtr(2)}, `{"Driver":"nvidia","Count":2}`, false},
		{"count below exact", AllowedDeviceRequestEntry{Driver: "nvidia", Count: intPtr(2)}, `{"Driver":"nvidia","Count":1}`, true},
		{"count above exact", AllowedDeviceRequestEntry{Driver: "nvidia", Count: intPtr(2)}, `{"Driver":"nvidia","Count":3}`, true},
		{"all against exact", AllowedDeviceRequestEntry{Driver: "nvidia", Count: intPtr(2)}, `{"Driver":"nvidia","Count":-1}`, true},
		{"exact all", AllowedDeviceRequestEntry{Driver: "nvidia", Count: intPtr(-1)}, `{"Driver":"nvidia","Count":-1}`, false},
		{"legacy entry still accepts any ids", AllowedDeviceRequestEntry{Driver: "cdi"}, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=7"]}`, false},
		{"legacy entry still accepts any count", AllowedDeviceRequestEntry{Driver: "nvidia"}, `{"Driver":"nvidia","Count":9}`, false},
	}
	for _, path := range []string{"/containers/create", "/v1.47/containers/create"} {
		for _, tc := range tests {
			t.Run(fmt.Sprintf("%s/%s", path, tc.name), func(t *testing.T) {
				cfg := PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowedDeviceRequests: []AllowedDeviceRequestEntry{tc.entry}}}
				body := fmt.Sprintf(`{"HostConfig":{"DeviceRequests":[%s]}}`, tc.req)
				assertFilterCreateRoundTrip(t, path, body, cfg, tc.denied)
			})
		}
	}
}

// TestDockerDeviceRequestExactGrantsFallThroughEntries pins that a second
// entry can still grant what the first refuses, and that the blanket bool
// keeps skipping the exact lists.
func TestDockerDeviceRequestExactGrantsFallThroughEntries(t *testing.T) {
	cfg := PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowedDeviceRequests: []AllowedDeviceRequestEntry{
		{Driver: "cdi", DeviceIDs: []string{"nvidia.com/gpu=0"}},
		{Driver: "cdi", DeviceIDs: []string{"nvidia.com/gpu=1"}},
	}}}
	assertFilterCreateRoundTrip(t, "/containers/create", `{"HostConfig":{"DeviceRequests":[{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=1"]}]}}`, cfg, false)
	assertFilterCreateRoundTrip(t, "/containers/create", `{"HostConfig":{"DeviceRequests":[{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0","nvidia.com/gpu=1"]}]}}`, cfg, true)

	blanket := PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowDeviceRequests: true, AllowedDeviceRequests: cfg.ContainerCreate.AllowedDeviceRequests}}
	assertFilterCreateRoundTrip(t, "/containers/create", `{"HostConfig":{"DeviceRequests":[{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=5"]}]}}`, blanket, false)
}

func TestLibpodExactGPUGrants(t *testing.T) {
	body := func(gpus string) []byte {
		return []byte(fmt.Sprintf(`{"image":"alpine:latest","systemd":"false","gpus":%s}`, gpus))
	}
	tests := []struct {
		name string
		opts LibpodContainerCreateOptions
		gpus string
		want string
	}{
		{"default denies", LibpodContainerCreateOptions{}, `["all"]`, "libpod container create denied: device requests are not allowed"},
		{"listed", LibpodContainerCreateOptions{AllowedGPUs: []string{"nvidia.com/gpu=0"}}, `["nvidia.com/gpu=0"]`, ""},
		{"unlisted", LibpodContainerCreateOptions{AllowedGPUs: []string{"nvidia.com/gpu=0"}}, `["nvidia.com/gpu=1"]`, `libpod container create denied: gpus entry "nvidia.com/gpu=1" is not allowlisted`},
		{"all is not implied", LibpodContainerCreateOptions{AllowedGPUs: []string{"nvidia.com/gpu=0"}}, `["all"]`, `libpod container create denied: gpus entry "all" is not allowlisted`},
		{"one bad entry denies", LibpodContainerCreateOptions{AllowedGPUs: []string{"nvidia.com/gpu=0"}}, `["nvidia.com/gpu=0","nvidia.com/gpu=1"]`, `libpod container create denied: gpus entry "nvidia.com/gpu=1" is not allowlisted`},
		{"case differs", LibpodContainerCreateOptions{AllowedGPUs: []string{"nvidia.com/gpu=0"}}, `["NVIDIA.com/gpu=0"]`, `libpod container create denied: gpus entry "NVIDIA.com/gpu=0" is not allowlisted`},
		{"explicit all listed", LibpodContainerCreateOptions{AllowedGPUs: []string{"all"}}, `["all"]`, ""},
		{"blanket bool wins", LibpodContainerCreateOptions{AllowDeviceRequests: true}, `["anything"]`, ""},
		{"no gpus untouched", LibpodContainerCreateOptions{}, `[]`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := newLibpodContainerCreatePolicy(tc.opts)
			if got := inspectLibpod(t, policy, body(tc.gpus)); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLibpodExactCDIDeviceGrants(t *testing.T) {
	body := func(path string) []byte {
		return []byte(fmt.Sprintf(`{"image":"alpine:latest","systemd":"false","devices":[{"path":%q}]}`, path))
	}
	cdi := LibpodContainerCreateOptions{AllowedCDIDevices: []string{"nvidia.com/gpu=0", "vendor.example/gpu=GPU-1:2"}, AllowedDevices: []string{"/dev/null"}}
	tests := []struct {
		name   string
		opts   LibpodContainerCreateOptions
		path   string
		denied bool
	}{
		{"default denies", LibpodContainerCreateOptions{}, "nvidia.com/gpu=0", true},
		{"listed", cdi, "nvidia.com/gpu=0", false},
		{"listed with colon", cdi, "vendor.example/gpu=GPU-1:2", false},
		{"unlisted", cdi, "nvidia.com/gpu=1", true},
		{"all is not implied", cdi, "nvidia.com/gpu=all", true},
		{"colon suffix is not a prefix match", cdi, "nvidia.com/gpu=0:1", true},
		{"case differs", cdi, "NVIDIA.com/gpu=0", true},
		{"cdi list does not grant host paths", cdi, "/dev/sda", true},
		{"host path allowlist still works", cdi, "/dev/null", false},
		{"host path allowlist does not grant cdi", LibpodContainerCreateOptions{AllowedDevices: []string{"/dev/null"}}, "nvidia.com/gpu=0", true},
		{"allow all devices skips the list", LibpodContainerCreateOptions{AllowAllDevices: true}, "nvidia.com/gpu=7", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectLibpod(t, newLibpodContainerCreatePolicy(tc.opts), body(tc.path))
			if (got != "") != tc.denied {
				t.Fatalf("reason = %q, denied want %v", got, tc.denied)
			}
		})
	}
}

// TestDockerDeviceRequestExactOptions pins the exact Options contract on the
// bare and versioned create routes.
func TestDockerDeviceRequestExactOptions(t *testing.T) {
	entry := AllowedDeviceRequestEntry{Driver: "nvidia", Count: intPtr(1), Options: map[string]string{"visible": "0"}}
	tests := []struct {
		name   string
		entry  AllowedDeviceRequestEntry
		req    string
		denied bool
	}{
		{"listed pair", entry, `{"Driver":"nvidia","Count":1,"Options":{"visible":"0"}}`, false},
		{"no options", entry, `{"Driver":"nvidia","Count":1}`, false},
		{"empty options", entry, `{"Driver":"nvidia","Count":1,"Options":{}}`, false},
		{"other value", entry, `{"Driver":"nvidia","Count":1,"Options":{"visible":"1"}}`, true},
		{"unlisted key", entry, `{"Driver":"nvidia","Count":1,"Options":{"visible":"0","mig":"all"}}`, true},
		{"only unlisted key", entry, `{"Driver":"nvidia","Count":1,"Options":{"mig":"all"}}`, true},
		{"key case differs", entry, `{"Driver":"nvidia","Count":1,"Options":{"Visible":"0"}}`, true},
		{"value padded", entry, `{"Driver":"nvidia","Count":1,"Options":{"visible":"0 "}}`, true},
		{"legacy entry accepts any options", AllowedDeviceRequestEntry{Driver: "nvidia"}, `{"Driver":"nvidia","Options":{"x":"y"}}`, false},
		{"cdi ids with unlisted option", AllowedDeviceRequestEntry{Driver: "cdi", DeviceIDs: []string{"nvidia.com/gpu=0"}, Options: map[string]string{"a": "b"}}, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0"],"Options":{"c":"d"}}`, true},
		{"cdi ids with listed option", AllowedDeviceRequestEntry{Driver: "cdi", DeviceIDs: []string{"nvidia.com/gpu=0"}, Options: map[string]string{"a": "b"}}, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=0"],"Options":{"a":"b"}}`, false},
	}
	for _, path := range []string{"/containers/create", "/v1.47/containers/create"} {
		for _, tc := range tests {
			t.Run(fmt.Sprintf("%s/%s", path, tc.name), func(t *testing.T) {
				cfg := PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowedDeviceRequests: []AllowedDeviceRequestEntry{tc.entry}}}
				body := fmt.Sprintf(`{"HostConfig":{"DeviceRequests":[%s]}}`, tc.req)
				assertFilterCreateRoundTrip(t, path, body, cfg, tc.denied)
			})
		}
	}
}

// TestLibpodGPUGrantHasNoOptionsChannel pins that a libpod gpus string can't
// smuggle options past the exact list: a value carrying extra settings is a
// different string and is denied.
func TestLibpodGPUGrantHasNoOptionsChannel(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedGPUs: []string{"nvidia.com/gpu=0"}})
	for _, gpu := range []string{"nvidia.com/gpu=0,visible=1", "nvidia.com/gpu=0,", "nvidia.com/gpu=0 "} {
		body := []byte(fmt.Sprintf(`{"image":"alpine:latest","systemd":"false","gpus":[%q]}`, gpu))
		if got := inspectLibpod(t, policy, body); got == "" {
			t.Errorf("gpus %q was allowed", gpu)
		}
	}
}

// TestDockerDeviceRequestCountCeiling pins that max_count and a numeric count
// stay ceilings: any negative Count means "all devices" to the daemon, and
// DeviceIDs name devices without going through Count at all, so neither may
// slip past a bounded entry.
func TestDockerDeviceRequestCountCeiling(t *testing.T) {
	gpu := [][]string{{"gpu"}}
	nv := func(maxCount *int) AllowedDeviceRequestEntry {
		return AllowedDeviceRequestEntry{Driver: "nvidia", AllowedCapabilities: gpu, MaxCount: maxCount}
	}
	tests := []struct {
		name   string
		entry  AllowedDeviceRequestEntry
		req    string
		denied bool
	}{
		{"max 1, count -2", nv(intPtr(1)), `{"Driver":"nvidia","Count":-2,"Capabilities":[["gpu"]]}`, true},
		{"max 1, count min int", nv(intPtr(1)), fmt.Sprintf(`{"Driver":"nvidia","Count":%d,"Capabilities":[["gpu"]]}`, math.MinInt), true},
		{"max 0, count -5", nv(intPtr(0)), `{"Driver":"nvidia","Count":-5,"Capabilities":[["gpu"]]}`, true},
		{"max 1, count -1", nv(intPtr(1)), `{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}`, true},
		{"max -1, count -2", nv(intPtr(-1)), `{"Driver":"nvidia","Count":-2,"Capabilities":[["gpu"]]}`, false},
		{"max -1, count -1", nv(intPtr(-1)), `{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}`, false},
		{"max -1, count 3", nv(intPtr(-1)), `{"Driver":"nvidia","Count":3,"Capabilities":[["gpu"]]}`, false},
		{"max 2, count 2", nv(intPtr(2)), `{"Driver":"nvidia","Count":2,"Capabilities":[["gpu"]]}`, false},
		{"max 2, count 3", nv(intPtr(2)), `{"Driver":"nvidia","Count":3,"Capabilities":[["gpu"]]}`, true},
		{"no ceiling, count -2", nv(nil), `{"Driver":"nvidia","Count":-2,"Capabilities":[["gpu"]]}`, false},
		{"max 1, count 0, ids all", nv(intPtr(1)), `{"Driver":"nvidia","Count":0,"DeviceIDs":["all"],"Capabilities":[["gpu"]]}`, true},
		{"max 1, count 0, ids list", nv(intPtr(1)), `{"Driver":"nvidia","Count":0,"DeviceIDs":["0","1"],"Capabilities":[["gpu"]]}`, true},
		{"max 1, ids all", nv(intPtr(1)), `{"Driver":"nvidia","DeviceIDs":["all"],"Capabilities":[["gpu"]]}`, true},
		{"max 1, ids 0..3", nv(intPtr(1)), `{"Driver":"nvidia","DeviceIDs":["0","1","2","3"],"Capabilities":[["gpu"]]}`, true},
		{"max 1, ids comma list", nv(intPtr(1)), `{"Driver":"nvidia","DeviceIDs":["0,1"],"Capabilities":[["gpu"]]}`, true},
		{"max 1, count 1", nv(intPtr(1)), `{"Driver":"nvidia","Count":1,"Capabilities":[["gpu"]]}`, false},
		{"exact count 0, ids all", AllowedDeviceRequestEntry{Driver: "nvidia", Count: intPtr(0)}, `{"Driver":"nvidia","DeviceIDs":["all"]}`, true},
		{"max -1, ids all", AllowedDeviceRequestEntry{Driver: "nvidia", MaxCount: intPtr(-1)}, `{"Driver":"nvidia","DeviceIDs":["all"]}`, false},
		{"cdi max 1, ids all", AllowedDeviceRequestEntry{Driver: "cdi", MaxCount: intPtr(1)}, `{"Driver":"cdi","DeviceIDs":["nvidia.com/gpu=all"]}`, true},
		{"device_ids grant, no ceiling", AllowedDeviceRequestEntry{Driver: "nvidia", DeviceIDs: []string{"GPU-a"}}, `{"Driver":"nvidia","DeviceIDs":["GPU-a"]}`, false},
		{"legacy entry still accepts any ids", AllowedDeviceRequestEntry{Driver: "nvidia"}, `{"Driver":"nvidia","DeviceIDs":["all"]}`, false},
	}
	for _, path := range []string{"/containers/create", "/v1.47/containers/create"} {
		for _, tc := range tests {
			t.Run(fmt.Sprintf("%s/%s", path, tc.name), func(t *testing.T) {
				cfg := PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowedDeviceRequests: []AllowedDeviceRequestEntry{tc.entry}}}
				body := fmt.Sprintf(`{"HostConfig":{"DeviceRequests":[%s]}}`, tc.req)
				assertFilterCreateRoundTrip(t, path, body, cfg, tc.denied)
			})
		}
	}
}

// TestDeviceRequestCountNegativeIsAllDevices drives the issue's scenario
// through the create inspector and checks the deny reason.
func TestDeviceRequestCountNegativeIsAllDevices(t *testing.T) {
	policy := newContainerCreatePolicy(ContainerCreateOptions{AllowedDeviceRequests: []AllowedDeviceRequestEntry{
		{Driver: "nvidia", AllowedCapabilities: [][]string{{"gpu"}}, MaxCount: intPtr(1)},
	}})
	reason, err := policy.inspect(nil, makeInspectRequest(t, `{"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-2,"Capabilities":[["gpu"]]}]}}`), "/containers/create")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if reason == "" || !strings.Contains(reason, "not permitted by the allowlist") {
		t.Fatalf("reason = %q, want a not-permitted-by-the-allowlist deny", reason)
	}
}
